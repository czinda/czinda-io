---
title: "Replacing Six ASN.1 Crates with One: Migrating to Synta"
date: 2026-05-19
draft: false
tags: ["rust", "asn1", "x509", "synta", "pki", "cryptography", "migration", "zero-copy"]
description: "How PKI.Next replaced six competing ASN.1/X.509 Rust crates with synta — a schema-generated, zero-copy library — in a single migration that touched 34 files, deleted 1,726 lines, and made certificate parsing 3x faster."
---

Every X.509 certificate, every CRL, every OCSP response, every CSR is encoded in ASN.1 DER. If you are building PKI software in Rust, ASN.1 encoding and decoding is the foundation everything else rests on. Get it wrong, and certificates parse incorrectly. Get it slow, and your CA cannot keep up with issuance. Get it fragmented across multiple libraries, and you spend more time managing dependencies than building features.

PKI.Next was using six ASN.1 crates simultaneously. We replaced all of them with [synta](https://crates.io/crates/synta) in a single commit. This post explains why, how, and what we gained.

## The Fragmentation Problem

Rust's ASN.1 ecosystem evolved in pieces. Different projects built different libraries for different use cases, and none of them covered everything a CA needs:

| Crate | Purpose | Pain Point |
|---|---|---|
| `der` (0.7) | DER encoding/decoding primitives | Low-level; no X.509 awareness |
| `x509-cert` (0.2) | X.509 certificate structures | Slow parsing; allocates intermediate structs |
| `spki` (0.7) | SubjectPublicKeyInfo handling | Tightly coupled to `der` version |
| `rasn` (0.22) | General ASN.1 BER/DER codec | Not X.509-optimized |
| `rasn-ocsp` (0.22) | OCSP message structures | Separate codec from main rasn |
| `rasn-pkix` (0.22) | PKIX (X.509/PKCS) structures | Version-locked to rasn |

PKI.Next was using all six. Parsing a CSR required `der` for the outer DER decoding, `x509-cert` for the certificate request structure, `spki` for extracting the public key, and `rasn` for any PKCS attribute decoding. Building an OCSP response required `rasn-ocsp` for the response types and `der` again for encoding.

The practical consequences:

- **Version conflicts.** `x509-cert` 0.2 requires `der` 0.7 exactly. Bumping `der` to 0.8 for a bug fix breaks `x509-cert`. `rasn` has its own DER implementation that is not interoperable with `der`.
- **Boundary-crossing allocations.** Decoding a CSR with `der`, then converting the result to `x509-cert` types, then extracting the SPKI with `spki` means the same bytes are parsed, allocated, and copied multiple times as data crosses library boundaries.
- **Inconsistent error handling.** Each crate has its own error types. Composing errors from three libraries in a single function requires `map_err` gymnastics or a catch-all error variant.
- **No post-quantum OIDs.** None of the legacy crates include ML-DSA (FIPS 204) or ML-KEM (FIPS 203) object identifiers. Adding PQC support meant hard-coding OID constants ourselves.

## What Synta Does Differently

[Synta](https://crates.io/crates/synta) is a schema-generated, zero-copy ASN.1 library. Those two adjectives do most of the work:

**Schema-generated** means the X.509 structures in `synta-certificate` are compiled from the actual ASN.1 module definitions in RFC 5280, not hand-coded Rust structs. When an RFC updates a structure, the code is regenerated from the schema. Hand-coded structs drift from the specification over time; generated code does not.

**Zero-copy** means the `Decoder` borrows from the input buffer instead of allocating new memory for each parsed field. The key type is `RawDer<'a>`, which holds a reference to a slice of the original DER bytes:

```rust
// RawDer borrows from the input buffer — no allocation
let subject_raw: RawDer = decoder.decode()?;
let subject_bytes: &[u8] = subject_raw.as_bytes(); // points into original input
```

The architecture is three tiers:

{{< mermaid >}}
graph LR
    subgraph "synta ecosystem"
        codegen["synta-codegen<br/><i>ASN.1 → Rust compiler</i>"]
        cert["synta-certificate<br/><i>X.509 types, NameBuilder,<br/>format_dn(), OID constants</i>"]
        core["synta<br/><i>Decoder, Encoder, RawDer,<br/>zero-copy DER codec</i>"]
    end

    codegen -->|generates| cert
    cert -->|depends on| core

    style core fill:#d4edda
    style cert fill:#e6f3ff
    style codegen fill:#f0f0f0
{{< /mermaid >}}

The performance difference is measurable. From [synta's published benchmarks](https://crates.io/crates/synta), parsing a single X.509 certificate:

| Library | Parse Time | Factor |
|---|---|---|
| **synta** | **0.48 μs** | **1.0x** |
| cryptography-x509 (Python/Rust) | 1.51 μs | 3.1x slower |
| x509-parser | 2.13 μs | 4.4x slower |
| x509-cert | 3.33 μs | 6.9x slower |
| NSS (C) | 8.46 μs | 17.6x slower |

For a CA processing thousands of certificates per second --- parsing CSRs, building certs, generating CRLs, responding to OCSP queries --- 0.48 μs versus 3.33 μs per certificate is the difference between comfortable headroom and a bottleneck.

## Before and After: CSR Parsing

The best way to show the difference is code. Here is how PKI.Next parses a PKCS#10 Certificate Signing Request after the migration:

```rust
use synta::{tag, Decoder, Encoding, ObjectIdentifier, RawDer, Tag};
use synta_certificate::format_dn;

pub fn parse_csr_der(der: &[u8]) -> Result<ParsedCsr, PkiError> {
    let mut outer = Decoder::new(der, Encoding::Der);
    let mut csr_seq = outer
        .enter_constructed(Tag::universal_constructed(tag::TAG_SEQUENCE))?;

    // CertificationRequestInfo SEQUENCE
    let mut cri_seq = csr_seq
        .enter_constructed(Tag::universal_constructed(tag::TAG_SEQUENCE))?;

    // version INTEGER — skip
    let _version: RawDer = cri_seq.decode()?;

    // subject Name — raw DER for format_dn
    let subject_raw: RawDer = cri_seq.decode()?;
    let subject_dn = format_dn(subject_raw.as_bytes());

    // subjectPKInfo — zero-copy reference
    let spki_raw: RawDer = cri_seq.decode()?;
    let spki_bytes = spki_raw.as_bytes();
    let public_key_info_der = spki_bytes.to_vec();

    let (key_algorithm_oid, pk_bytes) = parse_spki_internals(spki_bytes)?;

    // ...
}
```

Notice what is absent:

- No `CertReq::from_der()` → `CertReqInfo` → `SubjectPublicKeyInfo` type conversion chain
- No intermediate allocations between parsing and the final `ParsedCsr` struct
- No `use der::Decode;` + `use x509_cert::request::CertReq;` + `use spki::SubjectPublicKeyInfoRef;` — a single `Decoder` handles everything

The `RawDer` type is the key. When we decode the subject field, we get a `RawDer<'_>` that borrows from the input buffer. We pass those bytes directly to `format_dn()` — which is a synta-certificate helper that converts DER-encoded distinguished names to [RFC 4514](https://www.rfc-editor.org/rfc/rfc4514) string format — without ever allocating an intermediate `Name` struct.

{{< mermaid >}}
graph TB
    subgraph "Old: Three Libraries"
        input1["CSR DER bytes"]
        der1["der::Decode<br/><i>parse outer SEQUENCE</i>"]
        x509["x509_cert::CertReq<br/><i>allocate CertReqInfo</i>"]
        spki_lib["spki::SubjectPublicKeyInfo<br/><i>re-parse SPKI</i>"]
        output1["ParsedCsr"]

        input1 --> der1 -->|"copy"| x509 -->|"copy"| spki_lib -->|"copy"| output1
    end

    subgraph "New: Single Decoder"
        input2["CSR DER bytes"]
        dec2["synta::Decoder<br/><i>zero-copy walk</i>"]
        raw2["RawDer<br/><i>borrow fields</i>"]
        output2["ParsedCsr"]

        input2 --> dec2 -->|"borrow"| raw2 -->|"one copy"| output2
    end

    style der1 fill:#fff3cd
    style x509 fill:#fff3cd
    style spki_lib fill:#fff3cd
    style dec2 fill:#d4edda
    style raw2 fill:#d4edda
{{< /mermaid >}}

### OID-Based Algorithm Detection

The parsed CSR needs to determine the key algorithm. With synta, this is pattern matching on OID components:

```rust
fn extract_key_size_bits(alg_oid: &[u32], pk_bytes: &[u8]) -> Option<usize> {
    match alg_oid {
        // RSA
        [1, 2, 840, 113549, 1, 1, 1] => extract_rsa_key_size_bits(pk_bytes),
        // ECDSA — determine curve from uncompressed point length
        [1, 2, 840, 10045, 2, 1] => match pk_bytes.len() {
            65 => Some(256),   // P-256
            97 => Some(384),   // P-384
            133 => Some(521),  // P-521
            _ => None,
        },
        // Ed25519
        [1, 3, 101, 112] => Some(256),
        // ML-DSA (FIPS 204)
        [2, 16, 840, 1, 101, 3, 4, 3, 17] => Some(128), // ML-DSA-44
        [2, 16, 840, 1, 101, 3, 4, 3, 18] => Some(192), // ML-DSA-65
        [2, 16, 840, 1, 101, 3, 4, 3, 19] => Some(256), // ML-DSA-87
        // ML-KEM (FIPS 203)
        [2, 16, 840, 1, 101, 3, 4, 4, 1] => Some(128), // ML-KEM-512
        [2, 16, 840, 1, 101, 3, 4, 4, 2] => Some(192), // ML-KEM-768
        [2, 16, 840, 1, 101, 3, 4, 4, 3] => Some(256), // ML-KEM-1024
        _ => None,
    }
}
```

Synta's `ObjectIdentifier` stores OID arcs as `&[u32]`, so algorithm identification is a simple slice match. The post-quantum OIDs (ML-DSA, ML-KEM) work identically to classical algorithms — there is no special-casing or feature flag.

## OCSP: Where ASN.1 Gets Hard

OCSP (RFC 6960) is the most challenging ASN.1 encoding in PKI. The response contains IMPLICIT tags — context-specific encodings that replace the default tag of a type without wrapping it in a new structure. Getting the tag bytes wrong produces responses that every relying party rejects.

The certificate status field is the canonical example:

```asn1
CertStatus ::= CHOICE {
    good        [0] IMPLICIT NULL,
    revoked     [1] IMPLICIT RevokedInfo,
    unknown     [2] IMPLICIT NULL
}
```

In synta, this maps directly to Rust's enum and byte-level tag construction:

```rust
fn encode_cert_status(status: &OcspCertStatus) -> Result<Vec<u8>, PkiError> {
    match status {
        OcspCertStatus::Good => {
            // [0] IMPLICIT NULL: context tag 0, primitive, zero length
            Ok(vec![0x80, 0x00])
        }
        OcspCertStatus::Revoked { revocation_time, reason } => {
            // [1] IMPLICIT RevokedInfo: replace SEQUENCE tag with context tag
            let mut content = Vec::new();
            content.extend_from_slice(&encode_generalized_time(*revocation_time)?);
            if let Some(r) = reason {
                content.extend_from_slice(&encode_revocation_reason(*r)?);
            }
            let mut tagged = Vec::new();
            tagged.push(0xA1); // context-specific, constructed, tag 1
            tagged.extend_from_slice(&der_encode_length(content.len()));
            tagged.extend_from_slice(&content);
            Ok(tagged)
        }
        OcspCertStatus::Unknown => {
            // [2] IMPLICIT NULL: context tag 2, primitive, zero length
            Ok(vec![0x82, 0x00])
        }
    }
}
```

The legacy approach with `rasn-ocsp` would have involved deserializing into `rasn-ocsp` types, then re-serializing with `rasn`'s BER/DER encoder. The problem is that OCSP IMPLICIT tag semantics are notoriously hard to get right in generic codecs — the tag replacement rules depend on whether the underlying type is primitive or constructed, and generic frameworks sometimes get this wrong for CHOICE types.

With synta, we encode the tags directly. `0x80` is context-specific tag 0, primitive. `0xA1` is context-specific tag 1, constructed. `0x82` is context-specific tag 2, primitive. The hex values in the code match the hex values in the wire format. There is no abstraction between intent and output.

## The Migration

The actual migration was a single commit (`8e25a8e`):

- **34 files changed** across 13 crates
- **1,862 insertions, 1,726 deletions** (net +136 lines)
- **All 57 test suites pass**, clippy clean

### What Was Mechanical

About 60% of the migration was straightforward substitution:

- `use der::Decode;` → removed; `use synta::Decoder;`
- `CertReq::from_der(bytes)` → `Decoder::new(bytes, Encoding::Der)` + manual field extraction
- `Name::to_string()` → `format_dn(raw_der.as_bytes())`

The mechanical changes were tedious but low-risk — the type system caught most mistakes at compile time.

### What Required Rethinking

The remaining 40% required understanding the DER encoding at the byte level:

1. **OCSP IMPLICIT tags.** The `rasn-ocsp` crate handled tag encoding internally. With synta, we encode the context-specific tags directly (`0x80`, `0xA1`, `0x82`). This is more verbose but eliminates an entire class of bugs where the codec's tag inference logic disagrees with the RFC.

2. **Extension parsing.** The old code relied on `x509-cert`'s typed extension structs (`SubjectAltName`, `KeyUsage`, etc.). With synta, extensions are parsed lazily — the extension value is stored as `RawDer` and only decoded when accessed. This means the parser does not fail on unknown or malformed extensions, which is the correct behavior for a CA that must accept certificates from diverse sources.

3. **RSA key size extraction.** Previously handled by `spki`'s `SubjectPublicKeyInfo::subject_public_key()`. With synta, we manually parse the BIT STRING to extract the RSA modulus and count its bytes. More code, but one fewer dependency.

### What We Kept

Two legacy crates were deliberately retained:

- **`x509-parser`** (0.17) — used only in `pki-lint` for RFC 5280 conformance checking. The `x509_lint` crate registry depends on `x509-parser`'s typed ASN.1 model. Replacing it would require rewriting the linting framework.

- **`pkcs8`** (0.10) — used only in `pki-crypto` for encrypted PKCS#8 private key import. Synta does not include a PKCS#8 encryption/decryption implementation, and building one would be a significant effort for marginal benefit.

Both crates are isolated to a single consumer and do not interact with synta.

## What We Gained

### Performance

Synta's upstream benchmarks show 3–7x faster certificate parsing than the libraries it replaced. PKI.Next's own criterion benchmarks confirm the real-world gains:

| Operation | Time | What It Does |
|---|---|---|
| `parse_csr_der` | **391 ns** | Parse PKCS#10 CSR: extract subject DN, SPKI, algorithm OID, key size |
| `extract_tbs_fields` | **345 ns** | Parse X.509 TBS: serial, issuer, validity, subject, extensions |
| `build_ocsp_response` (1 cert) | **~175 ns** | Build a complete OCSP response with Good status |
| `build_ocsp_response` (10 certs) | **~175 ns** | Batch response (amortized per cert) |

Parsing a full CSR in 391 ns means a single core can parse **2.5 million CSRs per second**. Certificate field extraction at 345 ns is faster than synta's published certificate parsing benchmark (480 ns), because PKI.Next extracts fields lazily via `RawDer` references rather than fully decoding into typed structs.

For a CA that processes certificate requests, validates certificate chains, generates CRLs, and responds to OCSP queries, this compounds. Every request that touches ASN.1 — which is every request — benefits.

### Simplicity

Six ASN.1 dependencies collapsed to two (`synta` + `synta-certificate`). The workspace `Cargo.toml` went from:

```toml
# Before: six crates, version-locked to each other
der = "0.7"
x509-cert = "0.2"
spki = "0.7"
rasn = "0.22"
rasn-ocsp = "0.22"
rasn-pkix = "0.22"
```

to:

```toml
# After: two crates, same version
synta = { version = "0.1", features = ["derive"] }
synta-certificate = { version = "0.1", features = ["std", "derive"] }
```

Fewer dependencies means fewer version conflicts, fewer security advisories to track, and a smaller attack surface.

### Post-Quantum Readiness

Synta-certificate includes OID constants for ML-DSA (FIPS 204) and ML-KEM (FIPS 203). When PKI.Next added [post-quantum certificate support](/posts/pki-next-part2-post-quantum-certificates/), the algorithm OIDs were already available — no hard-coded constants needed.

### Consistent Error Handling

Every ASN.1 operation now returns synta's error types. No more `map_err` gymnastics converting between `der::Error`, `rasn::error::DecodeError`, and `x509_cert::Error`. One error model, one match arm.

## Should You Migrate?

If you are building PKI software in Rust, yes. The zero-copy parsing, schema-generated types, and unified API are worth the migration effort.

If you are building general-purpose ASN.1 tooling (LDAP, SNMP, telecom protocols), it depends on whether synta-codegen supports your ASN.1 modules. Synta is X.509-focused; other ASN.1 applications may need `rasn`'s broader schema support.

If you are happy with `x509-cert` and `der` and do not have performance requirements, there is no urgency. Those crates work correctly — they are just slower and more fragmented than synta.

The concrete lesson from this migration is that ASN.1 libraries in Rust are not interchangeable components. Each one makes different trade-offs around allocation, error handling, and schema coverage. Choosing the right one early saves a migration later. And if you are building a CA, zero-copy parsing is not a premature optimization — it is the foundation that every other performance decision rests on.

---

*If you are interested in the CA that uses synta, the [PKI.Next series](/posts/pki-next-part1-building-ca-in-rust/) covers the full architecture — from the [Rust crate structure](/posts/pki-next-part1-building-ca-in-rust/) to [post-quantum certificates](/posts/pki-next-part2-post-quantum-certificates/) to [FIPS 140-3 crypto pluggability](/posts/pki-next-part3-fips-and-hsm/).*
