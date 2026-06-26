---
title: "PKI.Next Part 4: Tamper-Evident Audit Logs"
date: 2026-05-09
draft: false
tags: ["pki", "audit", "security", "common-criteria", "hmac", "tamper-detection", "pki-next", "kipuka"]
description: "How PKI.Next implements HMAC hash-chained audit logs for Common Criteria FAU_STG.2 compliance, the timestamp precision bug that silently broke chain verification, and why audit integrity is the hardest part of running a CA."
series: ["PKI.Next"]
---

Every CA operation is an audit event. Certificate issued. Certificate revoked. CRL generated. User created. Profile modified. If you cannot prove that the audit log is complete and unmodified, you cannot prove that the CA has been operated correctly. This is not a theoretical concern --- it is a certification requirement.

Common Criteria Protection Profile for Certification Authorities (PP_CA v2.1) includes requirement **FAU_STG.2**: the CA must detect modification of stored audit records. PKI.Next implements this through HMAC-based hash chaining, where every audit record includes a cryptographic hash that depends on the previous record, creating a tamper-evident chain that detects insertion, deletion, or modification of any record.

This post explains the implementation, the verification API, and the timestamp precision bug that silently broke chain verification in the first deployment.

## The Chain Model

The audit chain is conceptually simple: each record's hash depends on the previous record's hash, creating a linked chain where tampering with any single record invalidates every record that follows.

{{< mermaid >}}
graph LR
    subgraph "Audit Chain"
        E1["Event 1<br/><b>system_startup</b><br/>hash: a7f3..."]
        E2["Event 2<br/><b>certificate_issued</b><br/>hash: 2b91..."]
        E3["Event 3<br/><b>certificate_revoked</b><br/>hash: e4c8..."]
        E4["Event 4<br/><b>crl_generated</b><br/>hash: 91d2..."]
        E5["Event 5<br/><b>certificate_issued</b><br/>hash: f0a7..."]
    end

    E1 -->|"previous_hash: GENESIS"| E1
    E1 -->|"previous_hash: a7f3..."| E2
    E2 -->|"previous_hash: 2b91..."| E3
    E3 -->|"previous_hash: e4c8..."| E4
    E4 -->|"previous_hash: 91d2..."| E5

    style E1 fill:#e8f5e9
    style E2 fill:#e3f2fd
    style E3 fill:#ffcdd2
    style E4 fill:#fff3cd
    style E5 fill:#e3f2fd
{{< /mermaid >}}

Each hash is computed as:

```
record_hash = HMAC-SHA256(
    key,
    previous_hash || "|" ||
    event_type    || "|" ||
    outcome       || "|" ||
    timestamp     || "|" ||
    actor         || "|" ||
    subject       || "|" ||
    detail
)
```

The first record in the chain uses `"GENESIS"` as its previous hash. This makes the first record's hash deterministic given the same key and event data, and provides a known anchor for chain verification.

## Why HMAC, Not a Digital Signature

A natural question is: why HMAC (a symmetric MAC) instead of a digital signature? A digital signature would let anyone verify the chain without knowing the signing key. HMAC requires the key for both creation and verification.

The answer is threat model:

**HMAC protects against database tampering.** If an attacker gains write access to the PostgreSQL database, they can modify audit records. But without the HMAC key, they cannot recompute the hashes to cover their tracks. A modified record will have a hash mismatch, and every subsequent record will also fail verification.

**HMAC does not protect against a compromised CA process.** If an attacker controls the CA process (which holds the HMAC key in memory), they can compute valid hashes for falsified records. But at that point, they also control the signing key, and the audit log is the least of your problems.

Digital signatures would add protection against the second scenario at the cost of a signing operation per audit event. For a busy CA issuing thousands of certificates per day, that is thousands of signature operations just for audit records. HMAC is a hash function --- roughly 1,000x faster than ECDSA signing --- and provides the right security for the threat model.

The HMAC key is loaded from an environment variable at startup and never written to disk:

```toml
[audit]
chain_enabled = true
chain_hmac_key_env = "PKI_AUDIT_HMAC_KEY"
```

```bash
# Generate a 256-bit HMAC key
export PKI_AUDIT_HMAC_KEY=$(openssl rand -hex 32)
```

The key is hex-encoded (64 characters for 32 bytes). It must be the same across all instances of the CA that write to the same audit log, and it must be preserved for as long as the audit records need to be verifiable.

## The Implementation

The hash computation is in `pki-store/src/audit_chain.rs`:

```rust
pub fn compute_record_hash(
    hmac_key: &[u8],
    previous_hash: Option<&str>,
    event_type: &str,
    outcome: &str,
    timestamp: &str,
    actor: Option<&str>,
    subject: Option<&str>,
    detail: Option<&str>,
) -> String {
    let mut mac = HmacSha256::new_from_slice(hmac_key)
        .expect("HMAC accepts any key length");

    mac.update(previous_hash.unwrap_or("GENESIS").as_bytes());
    mac.update(b"|");
    mac.update(event_type.as_bytes());
    mac.update(b"|");
    mac.update(outcome.as_bytes());
    mac.update(b"|");
    mac.update(timestamp.as_bytes());
    mac.update(b"|");
    mac.update(actor.unwrap_or("").as_bytes());
    mac.update(b"|");
    mac.update(subject.unwrap_or("").as_bytes());
    mac.update(b"|");
    mac.update(detail.unwrap_or("").as_bytes());

    hex::encode(mac.finalize().into_bytes())
}
```

The pipe delimiters prevent field confusion --- without them, an event with `event_type = "system"` and `outcome = "startup_success"` would produce the same input as `event_type = "system_startup"` and `outcome = "success"`.

The hash is stored alongside the audit record in PostgreSQL:

```sql
INSERT INTO audit_log (
    event_type, outcome, created_at,
    actor, subject, detail,
    record_hash, previous_hash
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
```

## Chain Verification

The `GET /v1/admin/audit/verify` endpoint reads all audit records in chronological order and recomputes every hash:

{{< mermaid >}}
sequenceDiagram
    participant Client as Dashboard / CLI
    participant API as CA API
    participant DB as PostgreSQL

    Client->>API: GET /v1/admin/audit/verify
    API->>DB: SELECT * FROM audit_log ORDER BY id ASC
    DB-->>API: All audit records

    loop For each record
        API->>API: Recompute HMAC from fields
        alt Hash matches stored hash
            API->>API: Record intact ✓
        else Hash mismatch
            API->>API: Chain broken at record N ✗
        end
    end

    API-->>Client: { intact: true/false, records_checked: N, first_broken_id: ... }
{{< /mermaid >}}

The verification walks the chain from the genesis record forward. For each record:

1. Get the `previous_hash` (from the prior record, or `"GENESIS"` for the first)
2. Format the timestamp from the database `created_at` column
3. Recompute `HMAC-SHA256(key, previous_hash || "|" || event_type || "|" || ...)`
4. Compare the computed hash with the stored `record_hash`

If any hash does not match, the chain is broken. The response identifies the first mismatched record, which tells the operator where tampering (or a bug) occurred.

A successful verification response:

```json
{
  "intact": true,
  "records_checked": 847,
  "first_broken_id": null,
  "break_reason": null,
  "verified_at": "2026-05-05T14:32:01Z"
}
```

A failed verification:

```json
{
  "intact": false,
  "records_checked": 847,
  "first_broken_id": 423,
  "break_reason": "HMAC mismatch: computed hash does not match stored record_hash",
  "verified_at": "2026-05-05T14:32:01Z"
}
```

## The Timestamp Precision Bug

The first deployment of the audit chain produced this:

```json
{
  "intact": false,
  "records_checked": 5,
  "first_mismatch": 1
}
```

Every single record failed verification, starting with the very first one. The HMAC key was correct. The event data was correct. The chain logic was correct. But the hashes did not match.

The root cause was a precision mismatch between Rust's `chrono` library and PostgreSQL's timestamp type.

### What Happened

When an audit event is created, the timestamp comes from `chrono::Utc::now()`, which returns nanosecond precision:

```
2026-04-21T19:23:45.123456789+00:00
```

The default `to_rfc3339()` method formats this as a string with **9 fractional digits** (nanoseconds). This string is used to compute the HMAC hash, and the resulting hash is stored in the database along with the event.

But PostgreSQL's `timestamptz` type stores timestamps with **microsecond** precision (6 digits). When the timestamp is stored and later read back:

```
2026-04-21T19:23:45.123456+00:00
```

The trailing `789` nanoseconds are silently truncated. When verification reads the record back from PostgreSQL and calls `to_rfc3339()` on the stored timestamp, it gets the 6-digit version. The HMAC input is different. The hash does not match.

{{< mermaid >}}
graph LR
    subgraph "INSERT Path"
        ts1["chrono::Utc::now()<br/><code>...45.123456789</code>"]
        hash1["HMAC input includes<br/><code>...45.123456789</code>"]
        store["Store hash in DB"]
    end

    subgraph "PostgreSQL"
        pg["timestamptz stores<br/><code>...45.123456</code><br/><i>truncated to μs</i>"]
    end

    subgraph "VERIFY Path"
        ts2["Read created_at<br/><code>...45.123456</code>"]
        hash2["HMAC input includes<br/><code>...45.123456</code>"]
        compare["Compare hashes<br/><b>MISMATCH ✗</b>"]
    end

    ts1 --> hash1 --> store --> pg --> ts2 --> hash2 --> compare

    style compare fill:#ffcdd2
    style pg fill:#fff3cd
{{< /mermaid >}}

### The Fix

The fix is one line in two places: force microsecond precision in the timestamp string before computing the HMAC.

```rust
// Before (INSERT path):
let ts_str = event.timestamp.to_rfc3339();

// After:
let ts_str = event.timestamp.to_rfc3339_opts(
    chrono::SecondsFormat::Micros, false
);
```

`SecondsFormat::Micros` forces exactly 6 fractional digits:

```
2026-04-21T19:23:45.123456+00:00
```

This matches what PostgreSQL stores and what the verify path reads back. The same change was applied to the verification path to ensure both sides use identical formatting.

### Why This Bug Was Subtle

This bug was not caught by unit tests because the test timestamps were hardcoded strings with consistent precision. It was not caught by integration tests because the tests computed and verified hashes in the same process, using the same `chrono::DateTime` object --- the truncation only happens after a PostgreSQL round-trip.

The bug only manifested in a real deployment where:
1. Events were written to PostgreSQL
2. The process was restarted (clearing in-memory state)
3. Verification read the timestamps back from PostgreSQL

The timestamp difference between `123456789` and `123456` nanoseconds is 789 nanoseconds --- less than a microsecond. But HMAC is a cryptographic function. A single bit of difference in the input produces a completely different output. There is no "close enough" in cryptographic verification.

### Lessons

1. **Serialize before hashing.** The HMAC input should be the serialized form of the data, not the in-memory representation. If you hash a `DateTime` object and then store it in a database that reduces precision, you have introduced a hidden transformation between the hash input and the stored data.

2. **Test with round-trips.** Cryptographic chain verification must be tested with data that has actually been stored in and retrieved from the database. In-process tests that skip the persistence layer will miss serialization mismatches.

3. **Pin your precision.** When a string representation of a value is part of a cryptographic input, fix the format. `to_rfc3339()` is a convenience method that makes its own decisions about precision. `to_rfc3339_opts(SecondsFormat::Micros, false)` is a commitment to a specific format.

## The Dashboard Integration

The PKI.Next dashboard includes an audit log page with a "Verify Chain Integrity" button that calls the verification endpoint and displays the result:

{{< mermaid >}}
graph TB
    subgraph "Audit Log Dashboard"
        header["Audit Events<br/><i>Filterable by type, actor, date range</i>"]
        verify["🔒 Verify Chain Integrity"]
        
        subgraph "Verification Result"
            intact["✓ Chain intact<br/>847 records verified"]
        end

        subgraph "Event List"
            e1["system_startup — success — 2026-04-21 19:23:45"]
            e2["certificate_issued — success — 2026-04-21 19:24:01"]
            e3["certificate_revoked — success — 2026-04-21 19:25:33"]
        end
    end

    verify --> intact
    header --> e1
    header --> e2
    header --> e3

    style intact fill:#e8f5e9
    style verify fill:#e3f2fd
{{< /mermaid >}}

The `record_hash` and `previous_hash` fields are intentionally **not exposed** in the audit event API responses. They are internal to the chain verification mechanism and have no meaning to API consumers. Exposing them would create a false sense of transparency --- an attacker who can modify the database can also modify the stored hashes, so displaying them in the UI adds no security. The verification endpoint is the authoritative check.

## Event Types

PKI.Next logs audit events for every significant operation:

| Event Type | Trigger |
|---|---|
| `system_startup` | CA process starts |
| `certificate_issued` | Certificate signed and stored |
| `certificate_revoked` | Certificate revocation recorded |
| `certificate_unrevoked` | Certificate hold removed |
| `crl_generated` | Full or delta CRL signed |
| `profile_created` | New certificate profile added |
| `profile_modified` | Profile configuration changed |
| `profile_deleted` | Profile removed |
| `user_created` | New RBAC user added |
| `user_updated` | User properties changed |
| `user_deleted` | User removed |
| `role_assigned` | RBAC role granted |
| `role_removed` | RBAC role revoked |
| `authentication_success` | Authentication succeeded |
| `authentication_failure` | Authentication failed |

Every event includes:
- **event_type**: What happened
- **outcome**: `success` or `failure`
- **actor**: Who initiated the action (certificate DN or username)
- **subject**: What was acted upon (certificate serial, profile ID, user ID)
- **detail**: Additional context (reason code, algorithm, error message)

The chain verification catches any modification to any of these fields. Changing a `certificate_revoked` event to hide a revocation would break the chain. Inserting a fake `authentication_success` event to cover unauthorized access would break the chain. Deleting any event would break the chain (the next record's `previous_hash` would reference a non-existent record).

## Operational Considerations

### Key Management

The HMAC key is the root of trust for audit integrity. If the key is compromised, an attacker with database access can rewrite the entire chain. If the key is lost, existing records remain in the database but can never be verified again.

Recommendations:
- Store the HMAC key in a secrets manager (Vault, AWS Secrets Manager, Kubernetes secrets), not in a config file
- Rotate the key periodically by starting a new chain epoch (record the chain break point so verification knows to reset)
- Back up the key separately from the database backup

### Performance

HMAC-SHA256 is fast --- roughly 500 ns per computation on modern hardware. Even a CA logging 10,000 events per day adds only 5 ms of total overhead to audit operations. The serialization overhead of the chain (fetching the previous hash for each INSERT) adds one extra SELECT per audit event, which is negligible compared to the INSERT itself.

### Chain Breaks

Legitimate chain breaks occur when:
- The HMAC key is rotated
- The database is restored from backup (the in-flight events at backup time may have different hashes)
- The CA is migrated to a new database

The verification endpoint reports the first mismatch, allowing operators to distinguish between a chain break at a known operational boundary (expected) and a chain break in the middle of normal operations (suspicious).

---

**Update (June 2026):** The audit logging pattern described here is also implemented in [kipuka](https://kipuka.dev), the EST/CMP enrollment server, with NIAP FAU_GEN.1-compliant structured audit trails. See the [kipuka blog post](/posts/kipuka-est-server-and-infrastructure/) for details. Source: [codeberg.org/czinda/kipuka](https://codeberg.org/czinda/kipuka)

*Next in the series: [Part 5: One CA, Six Protocols](/posts/pki-next-part5-protocol-servers/) --- how the Registration Authority pattern lets a single CA serve EST, ACME, CoAP, SPIFFE, Vault, and Dogtag simultaneously.*

*Previous: [Part 3: FIPS 140-3 and the Crypto Pluggability Problem](/posts/pki-next-part3-fips-and-hsm/)*
