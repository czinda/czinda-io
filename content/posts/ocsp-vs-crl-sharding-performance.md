---
title: "OCSP vs CRL Sharding: Measuring Revocation Checking at Scale"
date: 2026-02-17
draft: false
tags: ["pki", "ocsp", "crl", "performance", "certificates", "security", "revocation"]
description: "A hands-on comparison of OCSP and CRL sharding for certificate revocation checking, with real measurements of wire size, latency, and TLS overhead from a live PKI deployment."
---

Certificate revocation is the part of PKI that everyone knows matters and nobody wants to think about. You issue a certificate. Sometime later, that certificate needs to stop being trusted --- a key is compromised, an employee leaves, a device is decommissioned. The hard part is not recording the revocation. The hard part is telling everyone about it, fast, without drowning them in data.

There are two dominant approaches: OCSP (Online Certificate Status Protocol) and CRLs (Certificate Revocation Lists). Each has well-documented trade-offs. But with the emergence of CRL sharding --- partitioning a CRL into smaller segments --- the calculus changes in ways that are worth measuring rather than assuming.

This post presents real measurements from a live PKI deployment running 1,000 certificates with 300 revocations, comparing OCSP, CRL sharding, and full CRLs on wire size, latency, and TLS overhead.

## The Revocation Problem

When a relying party (a browser, an API gateway, a mutual TLS proxy) validates a certificate, it needs to answer one question: **has this certificate been revoked?** There are only two ways to get the answer:

1. **Ask someone** --- send an OCSP request and get a signed yes/no answer in real time
2. **Check a list** --- download a CRL and search it locally

Each approach has a cost model:

| | OCSP | Full CRL | CRL Shard |
|---|---|---|---|
| **Request model** | Per-certificate query | Download entire list | Download partition |
| **Freshness** | Real-time | Periodic (hours) | Periodic (hours) |
| **Privacy** | CA sees which certs you check | CA sees nothing | CA sees nothing |
| **Cacheability** | Limited (per-cert) | High (one download) | High (one download) |
| **Failure mode** | Soft-fail = skip check | Stale list = miss recent revocations | Same as full CRL |

OCSP gives you real-time answers but tells the CA (or anyone watching) which certificates you are validating. CRLs preserve privacy but can grow large. CRL sharding splits the difference: download a small partition of the CRL that covers just your certificate, without revealing which specific certificate you are checking.

## CRL Sharding: How It Works

CRL sharding partitions revoked certificates across multiple smaller CRLs based on a deterministic hash of the serial number. A client that needs to check whether certificate `ABC123` is revoked does not download the full list of all revocations --- it downloads only the shard that could contain `ABC123`.

The assignment is straightforward:

```text
shard_id = SHA-256(serial_number)[0..4] % shard_count
```

Take the first 4 bytes of the SHA-256 hash of the certificate's serial number, interpret them as a big-endian unsigned integer, and modulo by the number of shards. With 128 shards and 300 revocations, each shard contains roughly 2-3 entries instead of 300.

The CA embeds the shard's CRL Distribution Point URL in each certificate at issuance time:

```text
X509v3 CRL Distribution Points:
    Full Name:
        URI:http://crl.example.com/crl/shard/97
```

The relying party does not need to compute the hash. It reads the distribution point from the certificate and fetches that URL. The shard is a standard X.509 CRL --- any existing CRL processing code works without modification.

## Test Setup

The measurements come from a PKI deployment running in containers (Podman Compose) with the following architecture:

| Layer | Component | Role |
|---|---|---|
| **TLS termination** | Traefik | Handles TLS 1.3, mTLS client cert verification |
| **Application** | CA API (Axum) | Certificate management, CRL shard serving |
| | OCSP Responder | Responds to OCSP status queries |
| | CRL Worker | Periodic CRL and shard generation |
| **Data** | PostgreSQL | Certificate store, revocation records |
| | Redis | OCSP pre-signed response cache |

- **CA**: RSA-4096 signing key, SHA-256
- **Certificates**: 1,000 issued, 300 revoked (reason: keyCompromise)
- **CRL sharding**: 128 shards, ~2-3 revoked entries per shard
- **OCSP**: Pre-signed responses cached in Redis, refreshed hourly
- **TLS**: TLS 1.3, AES-128-GCM-SHA256, mTLS with client certificates
- **Network**: Localhost (eliminates network variance, isolates processing cost)

## What I Measured

For each method, I ran 5 requests and recorded:

- **TCP connect time** --- baseline socket establishment
- **TLS handshake time** --- mTLS negotiation including client certificate exchange
- **Time to first byte** --- when the first byte of the application response arrived
- **Total time** --- full request-response cycle
- **Upload/download bytes** --- application-layer payload, excluding TLS framing
- **TLS handshake bytes** --- measured separately via `openssl s_client`

## Results

### TLS Session Overhead (Both Methods)

Both endpoints use identical TLS 1.3 mTLS sessions:

| Direction | Bytes |
|---|---|
| Client → Server (handshake) | 4,417 |
| Server → Client (handshake) | 1,537 |
| **Total TLS overhead** | **5,954** |

This is the fixed cost of establishing a new connection. It includes the server certificate (1,170 bytes), client certificate (1,139 bytes), key exchange, and Finished messages. This cost is the same whether you are making an OCSP request or downloading a CRL shard.

### OCSP Performance

| Metric | Valid Cert | Revoked Cert |
|---|---|---|
| Request size | 87 B | 87 B |
| Response size | 2,134 B | 2,156 B |
| **Total payload** | **2,221 B** | **2,243 B** |
| Median total time | 5.72 ms | 5.67 ms |
| Median first byte | 5.58 ms | 5.54 ms |
| Server processing | ~0.8 ms | ~0.9 ms |

The OCSP response is dominated by the RSA-4096 signature (512 bytes) plus the signed response structure. The request is compact at 87 bytes --- just the issuer hash, serial number hash, and hash algorithm identifier. Note that these responses are pre-signed and served from Redis cache, so the server processing time reflects a cache lookup, not a live signing operation.

The response for a revoked certificate is slightly larger (2,156 vs 2,134 bytes) because it includes the revocation time and reason code.

### CRL Shard Performance

| Metric | Shard 83 (2 entries) | Shard 97 (3 entries) |
|---|---|---|
| Request size | 0 B (GET) | 0 B (GET) |
| Response size | 877 B | 931 B |
| **Total payload** | **877 B** | **931 B** |
| Median total time | 6.17 ms | 6.25 ms |
| Median first byte | 6.07 ms | 6.17 ms |
| Server processing | ~1.6 ms | ~1.8 ms |

A CRL shard is a complete, signed X.509 CRL containing only the revoked certificates assigned to that shard. The shard includes the same RSA-4096 signature as the OCSP response, but amortizes it across all entries in the shard rather than paying it per certificate.

### Full CRL (Baseline)

| Metric | Value |
|---|---|
| Response size | 16,598 B |
| Revoked entries | 300 |
| Median total time | 5.75 ms |

### Comparison

| Method | Payload | TLS + Payload | vs OCSP | Cacheable | Privacy |
|---|---|---|---|---|---|
| **OCSP** | 2,221 B | ~8,175 B | 1x | Per-cert, limited | CA sees queries |
| **CRL shard** | 931 B | ~6,885 B | 0.42x | 24 hours | Shard only |
| **Full CRL** | 16,598 B | ~22,552 B | 7.5x | 24 hours | Full privacy |

## Analysis

### CRL shards are 2.4x smaller than OCSP on the wire

This is the most surprising result. Conventional wisdom says OCSP is the lightweight option --- you ask about one certificate and get a small answer. But the answer is not small. An OCSP response with an RSA-4096 signature is 2,134 bytes regardless of what it says. A CRL shard with 2-3 entries is 877-931 bytes because it pays the signature cost once across all entries.

At larger scale, this gap widens. A shard covering 20-30 revocations would still be a single signed CRL, while checking those same 20-30 certificates via OCSP would require 20-30 separate 2,221-byte exchanges.

### TLS handshake dominates total cost

The mTLS handshake accounts for 75-80% of total request time (~4.5 ms out of ~5.7 ms). Application processing is under 2 ms for both methods. This means the choice between OCSP and CRL sharding has minimal impact on latency for individual requests. The difference shows up in aggregate: how many connections do you need, and how much data crosses the wire over time?

### OCSP is faster on first byte, CRL shards are faster on repeated checks

OCSP responses arrive about 0.5 ms sooner (5.5 ms vs 6.1 ms first byte) because the OCSP pre-signer stores pre-computed responses in Redis, while CRL shards require a database query and on-the-fly assembly. But an OCSP response covers one certificate. A CRL shard covers every certificate assigned to that shard and remains valid for 24 hours. For a relying party that validates multiple certificates in the same shard, or re-validates the same certificate within the validity window, the CRL shard wins on amortized cost.

### The privacy trade-off is real

OCSP reveals which certificates a relying party is validating. In a mutual TLS environment where an API gateway checks client certificates, the OCSP responder can build a log of which clients are connecting and when. CRL sharding reveals only which shard the relying party downloaded --- with 128 shards, that narrows the certificate to roughly 1/128th of the total population, but does not identify the specific certificate.

For environments subject to regulatory scrutiny --- financial services, healthcare, government --- this difference matters.

### Full CRLs still have a place

The full CRL at 16,598 bytes is 17x larger than a single shard, but it is a single download that covers all 300 revocations. For a relying party that validates many certificates across many shards, downloading the full CRL may be more efficient than fetching dozens of individual shards. The breakeven point depends on how many distinct shards you would need:

| | Cost |
|---|---|
| Full CRL (one-time) | 16,598 bytes |
| Per shard | ~900 bytes |
| **Breakeven** | **~18 shards** (16,598 / 900) |

If a relying party validates certificates spanning more than 18 distinct shards within the CRL's validity period, the full CRL is more bandwidth-efficient. Below that threshold, shards win.

## When to Use Which

**Use OCSP when:**
- You need real-time revocation status (seconds, not hours)
- You validate certificates infrequently or from diverse issuers
- You can tolerate the privacy exposure
- Your OCSP infrastructure supports pre-signing and caching

**Use CRL sharding when:**
- You validate certificates from a single CA at moderate volume
- Privacy matters --- you do not want the CA tracking validation patterns
- Clients can cache shards for the validity period
- Your CRL would otherwise be too large for clients to download efficiently

**Use full CRLs when:**
- Your revocation list is small (under a few thousand entries)
- Relying parties validate certificates across many shards
- Simplicity matters more than optimal bandwidth
- You are operating in an air-gapped or offline environment

## Where the Industry Is Heading

The measurements above capture the current state of the art, but the revocation landscape is shifting fast. Several developments in the past year are pushing the industry decisively toward CRL-based approaches.

**Let's Encrypt shut down its OCSP responders.** In August 2025, Let's Encrypt — the world's largest public CA — [stopped serving OCSP responses entirely](https://letsencrypt.org/2025/01/30/ocsp-service-is-being-turned-off/). At peak, their OCSP infrastructure handled 340 billion requests per month. They moved to CRL-only revocation, citing privacy concerns (OCSP lets the CA see which sites users visit), operational complexity, and the fact that most browsers had already stopped relying on OCSP for real-time checks. When the CA responsible for over half of all public TLS certificates abandons OCSP, it is a strong signal.

This was not sudden. The CA/Browser Forum made OCSP optional for public CAs in 2023, removing the previous requirement. HARICA has announced it will deprecate OCSP by March 2026. The trend is clear: OCSP is being phased out of the WebPKI.

**Browsers have moved to local revocation checking.** Firefox deployed [CRLite](https://blog.mozilla.org/security/2020/01/09/crlite-part-1-all-web-pki-revocations-compressed/) as the default revocation mechanism starting with Firefox 137 (April 2025). CRLite compresses the entire set of revoked Web PKI certificates — roughly 4 million entries — into a ~300 KB daily download using Clubcard cascade filters. The browser checks revocation locally against this compressed dataset with zero network requests and zero privacy leakage. No OCSP query, no CRL download at validation time.

Chrome takes a different approach with CRLSets, but coverage is limited. CRLSets contain only about 35,000 entries out of roughly 4 million total revocations — less than 1% coverage. Google selects which revocations to include based on perceived risk, which means most revoked certificates are not covered.

For enterprise and private PKI, the browser approaches are not directly applicable, but they validate the architectural direction: push revocation data to relying parties in bulk rather than querying per-certificate. CRL sharding follows the same philosophy.

**Certificate lifetimes are shrinking dramatically.** The CA/Browser Forum passed [Ballot SC-081v3](https://cabforum.org/2025/04/11/ballot-sc-081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/) in April 2025, establishing a mandatory reduction schedule for public certificate validity:

| Effective Date | Maximum Validity |
|---|---|
| March 15, 2026 | 200 days |
| March 15, 2027 | 100 days |
| March 15, 2029 | 47 days |

At 47-day certificate lifetimes, the window during which a revoked certificate remains dangerous shrinks substantially. Short-lived certificates reduce the need for real-time revocation checking — if a certificate will expire in a few weeks anyway, the urgency of propagating revocation status diminishes. This further weakens the case for OCSP's real-time model and strengthens periodic CRL distribution.

**Post-quantum signatures will amplify the size advantage of CRL sharding.** NIST finalized its first post-quantum cryptography standards in August 2024, including [ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) (formerly CRYSTALS-Dilithium) for digital signatures. ML-DSA-65 signatures are approximately 3,300 bytes — over 6x larger than the 512-byte RSA-4096 signatures in the measurements above.

When CAs transition to post-quantum algorithms, every signed response gets more expensive. An OCSP response with an ML-DSA signature would be roughly 5,400 bytes per certificate lookup. A CRL shard with the same signature amortizes that 3,300-byte cost across all entries in the shard. The sharding advantage measured at 2.4x with RSA-4096 would widen significantly with post-quantum signatures.

## What I Would Measure Next

These tests run on localhost, which eliminates network latency and jitter. In a production deployment, the TLS handshake cost would increase with network round-trips (1-RTT for TLS 1.3 resumption, 2-RTT for a fresh handshake), and the relative impact of payload size would increase on constrained links. Measuring over a realistic WAN path --- especially from IoT devices on cellular connections --- would produce different absolute numbers while likely preserving the same relative ordering.

I would also like to test with larger populations. At 10,000 or 100,000 revocations, the shard-to-OCSP size ratio should become even more favorable for sharding, since each shard would contain more entries amortized against the same fixed signature overhead.

---

*The measurements in this post come from [PKI.Next](https://github.com/czinda/PKI.Next), an open-source PKI platform built in Rust with native support for OCSP pre-signing, CRL sharding, and mutual TLS. The previous post in this series covers [event-driven certificate lifecycle management with Ansible](/posts/event-driven-certificate-revocation-lab/).*
