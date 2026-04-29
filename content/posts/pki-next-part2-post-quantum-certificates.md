---
title: "PKI.Next Part 2: Post-Quantum Certificates Are Here"
date: 2026-05-01
draft: true
tags: ["pki", "post-quantum", "ml-dsa", "fips-204", "certificates", "security", "cryptography", "pki-next"]
description: "How PKI.Next implements ML-DSA (FIPS 204) post-quantum signatures today, the engineering decisions behind dual-mode PQC support, and why your CA needs to be ready before the quantum threat arrives."
series: ["PKI.Next"]
---

In August 2024, NIST published [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), finalizing ML-DSA (Module-Lattice Digital Signature Algorithm, formerly CRYSTALS-Dilithium) as the first post-quantum digital signature standard. Six months later, [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881) defined how to encode ML-DSA keys and signatures in X.509 certificates.

PKI.Next supports all three ML-DSA security levels today. This post explains what that means in practice, how the implementation works, and why the engineering is harder than just swapping an algorithm.

## The Quantum Threat to PKI

Every X.509 certificate ever issued relies on one assumption: that certain mathematical problems are hard enough that an attacker cannot reverse a signature. RSA depends on integer factorization. ECDSA depends on the discrete logarithm problem in elliptic curve groups. Both problems are believed to be computationally infeasible with classical computers.

A sufficiently large quantum computer running Shor's algorithm solves both problems in polynomial time. The security of every RSA and ECDSA certificate collapses.

This is not an imminent threat --- current quantum computers have on the order of 1,000 noisy qubits, while breaking a 2048-bit RSA key requires an estimated 4,000+ error-corrected logical qubits. But the timeline matters for PKI specifically, because of a risk unique to digital signatures:

**Harvest Now, Decrypt Later.** An adversary can record signed data today and verify the signatures later with a quantum computer. For certificates, this means:

- A CA certificate issued today with a 10-year validity period needs its signature to remain unforgeable for 10 years
- An audit log signed with ECDSA today could be retroactively tampered if the CA key is recovered quantumly
- Code signing certificates authenticate software that may be verified decades from now

The transition timeline is not "when will quantum computers break crypto?" It is "when must my certificates be quantum-resistant given their lifetimes?"

{{< mermaid >}}
timeline
    title Post-Quantum Cryptography Timeline
    2024 : NIST publishes FIPS 204 (ML-DSA)
         : NIST publishes FIPS 203 (ML-KEM)
    2025 : RFC 9881 - ML-DSA in X.509
         : RFC 9690 - ML-KEM in CMS
         : CNSA 2.0 mandates PQC for NSS
    2026 : First CAs issue ML-DSA certificates
         : PKI.Next ships PQC support
    2027 : NIST expected to finalize SLH-DSA
    2028 : Estimated hybrid transition period begins
    2030 : CNSA 2.0 deadline for software signing
    2033 : CNSA 2.0 deadline for all PKI signatures
    2035+ : Quantum threat window opens
{{< /mermaid >}}

NSA's CNSA 2.0 guidance is explicit: all National Security Systems must transition to ML-DSA by 2033, with software and firmware signing required by 2030. That is seven years to replace every CA, every certificate profile, every relying party validation stack. The transition has to start now.

## ML-DSA: What Changed

ML-DSA is a lattice-based signature scheme. Instead of relying on factoring or discrete logs, its security reduces to the hardness of the Module Learning With Errors (MLWE) problem --- a problem that no known quantum algorithm can solve efficiently.

NIST defined three security levels:

| Parameter Set | Security Level | Public Key Size | Signature Size | NIST Category |
|---|---|---|---|---|
| **ML-DSA-44** | 128-bit | 1,312 bytes | 2,420 bytes | Category 2 |
| **ML-DSA-65** | 192-bit | 1,952 bytes | 3,309 bytes | Category 3 |
| **ML-DSA-87** | 256-bit | 2,592 bytes | 4,627 bytes | Category 5 |

For comparison:

| Algorithm | Public Key Size | Signature Size |
|---|---|---|
| ECDSA P-256 | 65 bytes | 64 bytes |
| RSA-4096 | 512 bytes | 512 bytes |
| Ed25519 | 32 bytes | 64 bytes |
| **ML-DSA-65** | **1,952 bytes** | **3,309 bytes** |

ML-DSA-65 signatures are **52x larger** than ECDSA P-256 signatures. Public keys are **30x larger**. This has cascading consequences for every system that processes certificates:

- TLS handshakes carry the full certificate chain, including every intermediate CA's public key and signature
- CRL entries include signed structures where the signature overhead is amortized per CRL, not per entry
- OCSP responses carry a signature per response, making individual status checks significantly more expensive on the wire
- Certificate Transparency logs must store and transmit the larger certificates

The size increase is the price of quantum resistance. There is no known way to get post-quantum signatures that are as compact as elliptic curve signatures.

## Implementation in PKI.Next

PKI.Next supports ML-DSA through two backends: a pure-Rust software implementation using the `fips204` crate, and hardware support via PKCS#11 using tokens that implement the CKM_ML_DSA mechanism (PKCS#11 v3.2).

### The SigningAlgorithm Enum

Every signing algorithm in PKI.Next is represented by a single enum:

```rust
pub enum SigningAlgorithm {
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    RsaSha256,
    Ed25519,
    MlDsa44,
    MlDsa65,
    MlDsa87,
}
```

Each variant carries its OID, display name, and public key algorithm OID. For ML-DSA, RFC 9881 specifies that the signature OID and the public key algorithm OID are identical --- a departure from RSA and ECDSA where they differ:

```rust
// ML-DSA: same OID for signature and public key (RFC 9881)
Self::MlDsa44 => &[2, 16, 840, 1, 101, 3, 4, 3, 17],
Self::MlDsa65 => &[2, 16, 840, 1, 101, 3, 4, 3, 18],
Self::MlDsa87 => &[2, 16, 840, 1, 101, 3, 4, 3, 19],
```

This enum is the single source of truth for algorithm metadata. Adding a new algorithm means adding one variant and implementing the match arms. Every part of the system --- CSR parsing, certificate building, OCSP response signing, CRL generation --- uses the same enum.

### Software Signing Path

The default (non-HSM) signing path uses the `fips204` crate, a pure-Rust implementation of FIPS 204:

```rust
enum SoftwareKeyPair {
    // ... classical algorithms ...
    MlDsa44(Box<fips204::ml_dsa_44::PrivateKey>),
    MlDsa65(Box<fips204::ml_dsa_65::PrivateKey>),
    MlDsa87(Box<fips204::ml_dsa_87::PrivateKey>),
}
```

The private keys are boxed because ML-DSA key structures are large (4,032 bytes for ML-DSA-65) and would blow the stack in a non-boxed enum variant.

A subtlety in key loading: OpenSSL 3.x encodes ML-DSA private keys inside the PKCS#8 `privateKey` OCTET STRING with an extra ASN.1 wrapper --- a SEQUENCE containing a seed and an expanded key. PKI.Next includes a custom parser (`unwrap_ml_dsa_private_key`) to extract the expanded key from this wrapper, since the `fips204` crate expects raw key bytes.

### PKCS#11 Signing Path

For production deployments, ML-DSA signing happens on a PKCS#11 token. The `Pkcs11Signer` uses the `CKM_ML_DSA` mechanism introduced in PKCS#11 v3.2:

```rust
SigningAlgorithm::MlDsa44
| SigningAlgorithm::MlDsa65
| SigningAlgorithm::MlDsa87 => {
    Mechanism::MlDsa(
        SignAdditionalContext::new(HedgeType::Preferred, None)
    )
}
```

The `HedgeType::Preferred` parameter enables hedged signing --- the token uses both deterministic and randomized components in signature generation, providing defense against side-channel attacks even if the token's random number generator is weak.

For testing and development, PKI.Next uses [Kryoptic](https://github.com/latchset/kryoptic), a Rust-based PKCS#11 v3.2 soft-token that supports ML-DSA, ML-KEM, and SLH-DSA. Kryoptic is not a hardware HSM, but it implements the same PKCS#11 interface, so the code path is identical.

### Certificate Building

The certificate builder handles ML-DSA's encoding requirements per RFC 9881:

{{< mermaid >}}
graph LR
    subgraph "X.509 Certificate"
        tbs["TBS Certificate<br/><i>to-be-signed payload</i>"]
        subgraph "Subject Public Key Info"
            algo_spki["Algorithm: ML-DSA-65<br/><i>OID 2.16.840.1.101.3.4.3.18</i>"]
            pubkey["Public Key<br/><i>1,952 bytes raw</i>"]
        end
        subgraph "Signature Algorithm"
            algo_sig["Algorithm: ML-DSA-65<br/><i>same OID as SPKI</i>"]
        end
        sig["Signature Value<br/><i>3,309 bytes</i>"]
    end

    tbs --> sig
    algo_spki -.- algo_sig

    style algo_spki fill:#e6f3ff
    style algo_sig fill:#e6f3ff
{{< /mermaid >}}

Two encoding details matter:

1. **No algorithm parameters.** RSA signatures include a NULL parameter in the AlgorithmIdentifier SEQUENCE. ECDSA includes curve parameters. ML-DSA uses a bare OID with no parameters --- the AlgorithmIdentifier is just `SEQUENCE { OID }`. Getting this wrong produces certificates that OpenSSL rejects.

2. **Raw public key encoding.** The SubjectPublicKeyInfo `subjectPublicKey` BIT STRING contains the ML-DSA public key as raw bytes, not wrapped in an additional ASN.1 structure. This differs from ECDSA where the public key is an uncompressed point encoding.

## The FIPS Boundary Problem

Here is where it gets interesting. PKI.Next supports three signing backends, but they do not all support the same algorithms:

{{< mermaid >}}
graph TB
    subgraph "Algorithm Support Matrix"
        direction LR
        subgraph ring["ring (default)"]
            r1["ECDSA P-256 ✓"]
            r2["ECDSA P-384 ✓"]
            r3["RSA-SHA256 ✓"]
            r4["Ed25519 ✓"]
            r5["ML-DSA ✗"]
        end
        subgraph awslc["aws-lc-rs (FIPS)"]
            a1["ECDSA P-256 ✓"]
            a2["ECDSA P-384 ✓"]
            a3["RSA-SHA256 ✓"]
            a4["Ed25519 ✗"]
            a5["ML-DSA ✗"]
        end
        subgraph pkcs11["PKCS#11 (HSM)"]
            p1["ECDSA P-256 ✓"]
            p2["ECDSA P-384 ✓"]
            p3["RSA-SHA256 ✓"]
            p4["Ed25519 ✓"]
            p5["ML-DSA ✓"]
        end
    end

    style ring fill:#f0f0f0
    style awslc fill:#fff3cd
    style pkcs11 fill:#d4edda
{{< /mermaid >}}

The FIPS-validated library (`aws-lc-rs`) does not include ML-DSA --- NIST's FIPS 204 is a separate validation from FIPS 140-3 cryptographic module validation. Ed25519 is also absent from the FIPS boundary, which is an RSA + ECDSA-only perimeter.

This means:

- **Development builds** (`ring` backend): Classical algorithms only; ML-DSA uses the `fips204` crate (software, non-FIPS)
- **FIPS production builds** (`aws-lc-rs` backend): RSA + ECDSA only; Ed25519 and ML-DSA must use PKCS#11
- **HSM production builds** (PKCS#11 backend): Everything, including ML-DSA, through hardware

The `FipsSoftwareSigner` enforces this boundary at construction time:

```rust
if !Self::is_fips_algorithm(algorithm) {
    return Err(PkiError::SigningError {
        reason: format!(
            "Algorithm {algorithm} is not available in FIPS mode. \
             FIPS software signing supports: RSA-SHA256, ECDSA-P256, ECDSA-P384. \
             For Ed25519 or ML-DSA, use PKCS#11/HSM (hsm_enabled = true)."
        ),
    });
}
```

This is not a bug or a limitation. It is the correct behavior: you cannot claim FIPS 140-3 compliance for an algorithm that has not been validated under FIPS 140-3. ML-DSA will eventually be included in FIPS-validated modules (likely by 2027-2028), but today, the only FIPS-compliant way to do ML-DSA is through a PKCS#11 token that has its own PQC validation.

## The TLS Problem

There is a catch with ML-DSA certificates that is not immediately obvious: **most TLS libraries cannot verify them.**

`rustls`, the TLS library used by PKI.Next's internal communications and the `rs-pki` CLI tool, does not support ML-DSA signature verification. Neither does OpenSSL's default TLS stack in most distributions. This means an ML-DSA-signed CA certificate cannot be used for TLS server authentication without custom verification logic.

PKI.Next handles this with the `--insecure` flag on the CLI:

```bash
rs-pki --url https://ca.example.com:8443 \
       --insecure \
       cert list
```

The `--insecure` flag disables rustls certificate verification, allowing the CLI to communicate with a CA whose server certificate is signed by an ML-DSA CA. This is a pragmatic compromise: the CLI is connecting to a CA that the operator has explicitly configured, not an arbitrary internet server. The mTLS client certificate still authenticates the CLI to the CA.

For inter-service communication (protocol servers to CA API), the same approach applies. The RA client can be configured to trust the ML-DSA CA certificate directly, bypassing the TLS library's signature verification for the CA chain while still performing all other TLS checks.

This situation will improve as TLS libraries add PQC support. OpenSSL 3.5 (expected 2026) includes ML-DSA support via the `oqs-provider`, and rustls has an [open RFC](https://github.com/rustls/rustls/issues/1930) for post-quantum signature verification.

## Bootstrapping a PQC CA

The `rs-pki ca init` command can bootstrap a CA directly on a PKCS#11 token with ML-DSA:

```bash
rs-pki ca init \
    --pkcs11-module /usr/lib/libkryoptic.so \
    --pkcs11-slot 0 \
    --hsm-pin 12345678 \
    --key-label "pqc-ca-key" \
    --algorithm ML-DSA-65 \
    --subject "CN=PQC Test CA,O=Example,C=US" \
    --validity-days 3650
```

This generates an ML-DSA-65 key pair on the PKCS#11 token and creates a self-signed CA certificate. The key never leaves the token --- generation and signing both happen through PKCS#11 calls.

For tokens that do not support on-token ML-DSA key generation (the `CKM_ML_DSA_KEY_PAIR_GEN` mechanism), the key must be generated externally and imported. The `setup-kryoptic.sh` script in the repository demonstrates this workflow using OpenSSL 3.5's ML-DSA support.

## Size Impact in Practice

To make the size differences concrete, here is what a real ML-DSA-65 CA certificate looks like compared to an ECDSA P-256 equivalent:

| Component | ECDSA P-256 | ML-DSA-65 | Factor |
|---|---|---|---|
| CA public key | 65 bytes | 1,952 bytes | 30x |
| CA signature (self-signed) | 72 bytes | 3,309 bytes | 46x |
| **Total CA certificate** | **~600 bytes** | **~5,800 bytes** | **~10x** |
| TLS handshake (1 intermediate) | ~1,200 bytes certs | ~11,600 bytes certs | ~10x |
| CRL signature overhead | 72 bytes | 3,309 bytes | 46x |
| OCSP response signature | 72 bytes | 3,309 bytes | 46x |

A 10x increase in certificate size is significant but manageable for most networks. The exception is constrained environments --- IoT devices on NB-IoT or LoRaWAN links where every byte counts. This is one reason PKI.Next includes a CoAP/DTLS protocol server: CoAP's blockwise transfer (RFC 7959) handles large payloads over constrained links by breaking them into individually acknowledged blocks.

The OCSP impact is where CRL sharding pays dividends. As discussed in a [previous post](/posts/ocsp-vs-crl-sharding-performance/), CRL shards amortize the signature cost across all entries in the shard. With ML-DSA signatures at 3,309 bytes, the per-certificate cost of OCSP (one signature per query) becomes dramatically more expensive than downloading a shard (one signature per shard). The 2.4x advantage measured with RSA-4096 would expand to roughly 4-5x with ML-DSA-65.

## What Comes Next

ML-DSA is the beginning, not the end. Several developments are on the horizon:

**Composite certificates** (draft-ietf-lamps-pq-composite-sigs) would embed both a classical and a post-quantum signature in a single certificate. This provides quantum resistance while maintaining backward compatibility with relying parties that do not understand ML-DSA. PKI.Next's `Signer` trait is designed to support this --- a composite signer would wrap two inner signers and concatenate their outputs.

**SLH-DSA** (FIPS 205, formerly SPHINCS+) is a hash-based signature scheme that does not rely on lattice assumptions. It is slower and produces larger signatures than ML-DSA, but its security is based on simpler, better-understood assumptions. SLH-DSA is already compiled into Kryoptic and could be added to PKI.Next with minimal code changes.

**ML-KEM** (FIPS 203) for key encapsulation is relevant for key escrow profiles. PKI.Next's Dogtag-compatible `caStorageCert` profile already references ML-KEM-768 and ML-KEM-1024 for key transport, anticipating the need to protect archived keys against quantum recovery.

The concrete takeaway: if you are building or operating a CA today, the time to add PQC support is now, even if you are not issuing PQC certificates in production yet. The engineering work --- algorithm abstraction, key format handling, size-aware protocol design --- is substantial, and doing it under time pressure when quantum computers arrive is not a plan.

---

*Next in the series: [Part 3: FIPS 140-3 and the Crypto Pluggability Problem](/posts/pki-next-part3-fips-and-hsm/) --- how Rust's feature flags and trait objects let you swap cryptographic backends without touching business logic.*

*Previous: [Part 1: Building a Certificate Authority in Rust](/posts/pki-next-part1-building-ca-in-rust/)*
