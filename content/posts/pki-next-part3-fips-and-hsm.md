---
title: "PKI.Next Part 3: FIPS 140-3 and the Crypto Pluggability Problem"
date: 2026-05-07
draft: false
tags: ["pki", "fips", "hsm", "pkcs11", "rust", "cryptography", "security", "pki-next", "kipuka", "akamu"]
description: "How PKI.Next uses Rust feature flags and trait objects to support three cryptographic backends — ring, aws-lc-rs (FIPS 140-3), and PKCS#11 hardware — without a single if-else in the certificate issuance path."
series: ["PKI.Next"]
---

A Certificate Authority has a unique constraint that most software does not: the cryptographic backend is not just a library choice, it is a compliance decision. Government customers require FIPS 140-3 validated modules. Financial institutions require hardware security modules. Development teams need fast builds without hardware dependencies. These are three different backends with three different dependencies, build processes, and runtime characteristics --- and the CA business logic should not care which one is active.

This post describes how PKI.Next solves the crypto pluggability problem using Rust's feature flag system and trait objects, achieving zero runtime overhead while supporting three mutually exclusive backends from a single codebase.

## The Three Backends

PKI.Next supports three cryptographic backends, selected at compile time:

{{< mermaid >}}
graph TB
    subgraph "Build Configuration"
        default["cargo build<br/><i>Default: ring backend</i>"]
        fips["cargo build --features fips<br/><i>FIPS: aws-lc-rs backend</i>"]
        hsm["cargo build --features pkcs11<br/><i>HSM: PKCS#11 backend</i>"]
    end

    subgraph "Runtime"
        trait["Arc&lt;dyn Signer&gt;<br/><i>Selected once at startup</i>"]
    end

    subgraph "CA Engine"
        issue["Issue Certificate"]
        crl["Sign CRL"]
        ocsp["Sign OCSP Response"]
    end

    default --> trait
    fips --> trait
    hsm --> trait
    trait --> issue
    trait --> crl
    trait --> ocsp

    style default fill:#e8f5e9
    style fips fill:#fff3cd
    style hsm fill:#e3f2fd
{{< /mermaid >}}

| Backend | Library | Validation | Algorithms | Build Time | Use Case |
|---|---|---|---|---|---|
| **Default** | `ring` | None | ECDSA, RSA, Ed25519 | Fast (~30s) | Development |
| **FIPS** | `aws-lc-rs` | FIPS 140-3 | ECDSA, RSA | Slow (~5 min) | Government/regulated |
| **PKCS#11** | `cryptoki` | Depends on token | All + ML-DSA | Medium (~1 min) | HSM production |

The key insight is that these are **compile-time** selections, not runtime configuration. A binary built with `--features fips` physically cannot use `ring` --- the `ring` dependency is not included in the binary. This eliminates an entire class of misconfiguration: you cannot accidentally deploy a non-FIPS binary in a FIPS-required environment.

## How Feature Flags Work

Rust's feature flag system is a compile-time conditional compilation mechanism. In `Cargo.toml`:

```toml
[features]
default = []
fips = ["aws-lc-rs"]
pkcs11 = ["cryptoki"]

[dependencies]
ring = { workspace = true }
aws-lc-rs = { workspace = true, optional = true }
cryptoki = { workspace = true, optional = true }
```

When you build with `cargo build --features fips`, the compiler includes `aws-lc-rs` and compiles code blocks gated behind `#[cfg(feature = "fips")]`. Code gated behind `#[cfg(not(feature = "fips"))]` is excluded entirely --- not dead code, but absent from the binary.

The `FipsSoftwareSigner` module only compiles when the `fips` feature is active:

```rust
#[cfg(feature = "fips")]
pub mod fips_signer;

pub mod hsm_signer;  // always compiled — cryptoki is optional at link time
```

The `hsm_signer` module is always compiled regardless of feature flags. The `cryptoki` dependency itself is optional, but the module's types and trait implementations are available unconditionally. This lets the `Pkcs11Signer` struct appear in function signatures and match arms without feature gates, simplifying the overall architecture.

The `fips` feature gate matters because `aws-lc-rs` depends on `aws-lc-sys`, which builds AWS-LC (a C library) from source using CMake and Go. The build is slow and requires a C toolchain. Development builds that do not need FIPS compliance should not pay that cost.

## The Signer Trait

The `Signer` trait is the interface that all backends implement:

```rust
#[async_trait]
pub trait Signer: Send + Sync {
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, PkiError>;
    fn algorithm(&self) -> SigningAlgorithm;
    fn public_key_der(&self) -> &[u8];
    fn certificate_der(&self) -> &[u8];
    fn certificate_chain_der(&self) -> Vec<Vec<u8>>;
}
```

Five methods. The `sign` method is async because PKCS#11 signing may involve network round-trips to a remote HSM. The `algorithm` method returns the `SigningAlgorithm` enum discussed in Part 2. The remaining methods provide the CA's own certificate and chain for embedding in OCSP responses and for TLS server identity.

The trait is object-safe, meaning it can be used behind `Arc<dyn Signer>` --- a reference-counted dynamic dispatch pointer. The CA engine stores one of these and calls it for every signing operation:

{{< mermaid >}}
sequenceDiagram
    participant Startup as Startup Code
    participant Config as config.toml
    participant Signer as Arc&lt;dyn Signer&gt;
    participant CA as CA Engine

    Startup->>Config: Read [ca] section
    alt hsm_enabled = true
        Startup->>Signer: Pkcs11Signer::new(module, slot, label)
    else fips feature active
        Startup->>Signer: FipsSoftwareSigner::from_pem(key, cert)
    else default
        Startup->>Signer: SoftwareSigner::from_pem(key, cert)
    end
    Startup->>CA: CaEngine::new(signer)
    
    Note over CA,Signer: All subsequent operations use<br/>the same Arc&lt;dyn Signer&gt;
    
    CA->>Signer: signer.sign(tbs_certificate)
    Signer-->>CA: signature bytes
{{< /mermaid >}}

The startup code is the only place in the entire codebase that knows which backend is active. The configuration determines the signer type:

```toml
[ca]
# Software key (default or FIPS mode)
signing_key = "/etc/pki/keys/ca-key.pem"
certificate = "/etc/pki/keys/ca-cert.pem"
signing_algorithm = "ECDSA-P256-SHA256"
hsm_enabled = false

# HSM key (PKCS#11 mode)
# hsm_enabled = true
# pkcs11_module = "/usr/lib/libkryoptic.so"
# pkcs11_slot = 0
# key_label = "ca-signing-key"
```

Once the signer is constructed, the CA engine receives `Arc<dyn Signer>` and never checks which implementation it holds. There is no `if hsm { ... } else { ... }` in the certificate issuance path, the CRL signing path, or the OCSP response path.

## The FIPS Backend: aws-lc-rs

[aws-lc-rs](https://github.com/aws/aws-lc-rs) is a Rust wrapper around [AWS-LC](https://github.com/aws/aws-lc), Amazon's fork of BoringSSL. AWS-LC has a FIPS 140-3 validation (certificate #4631), making `aws-lc-rs` the most practical path to FIPS compliance for Rust applications.

The `FipsSoftwareSigner` implements the `Signer` trait using `aws-lc-rs` types:

```rust
enum FipsKeyPair {
    Rsa(signature::RsaKeyPair),
    EcdsaP256(signature::EcdsaKeyPair),
    EcdsaP384(signature::EcdsaKeyPair),
}
```

Three algorithms. That is the entire FIPS boundary for software signing. Ed25519 is not included in the FIPS validation. ML-DSA is not included because FIPS 204 is a separate standard from FIPS 140-3. If you need Ed25519 or ML-DSA in a FIPS-compliant deployment, you must use a PKCS#11 token that has its own validation for those algorithms.

The `FipsSoftwareSigner` enforces this boundary at construction time, not at signing time. If you try to create a FIPS signer with an unsupported algorithm, you get a clear error message explaining what to do:

```
Algorithm ML-DSA-65 is not available in FIPS mode. FIPS software signing
supports: RSA-SHA256, ECDSA-P256-SHA256, ECDSA-P384-SHA384.
For Ed25519 or ML-DSA, use PKCS#11/HSM (hsm_enabled = true).
```

### API Differences from ring

`aws-lc-rs` and `ring` have nearly identical APIs --- `aws-lc-rs` was designed as a drop-in replacement. But there are differences that matter:

**RSA signing signatures.** `ring` uses `RsaKeyPair::sign()` which returns a `Signature` type. `aws-lc-rs` uses the same method name but requires a pre-allocated output buffer:

```rust
// aws-lc-rs RSA signing
let mut sig = vec![0u8; kp.public_key().modulus_len()];
kp.sign(&signature::RSA_PKCS1_SHA256, &self.rng, data, &mut sig)?;
```

**Random number generation.** Both libraries provide `SystemRandom`, but `aws-lc-rs` sources entropy from the FIPS-validated DRBG (Deterministic Random Bit Generator), which is a compliance requirement for FIPS mode.

**Build requirements.** `aws-lc-rs` requires CMake, Go (for `boringssl`'s build system), and a C compiler. The Containerfile includes a separate `fips-builder` stage with these dependencies:

```dockerfile
FROM builder AS fips-builder
RUN dnf install -y cmake golang && dnf clean all
RUN cargo build --release --package pki-server --features fips,pkcs11
```

The FIPS binary is built separately and produces distinct container images (`pki-ca-api-fips`, `pki-monolith-fips`) so that the image tag makes the compliance boundary visible.

## The PKCS#11 Backend: Hardware Security Modules

PKCS#11 (Public Key Cryptography Standards #11) is the standard API for hardware security modules. It defines a C interface for cryptographic operations where the private key never leaves the hardware device. PKI.Next implements PKCS#11 support through the `cryptoki` crate.

The `Pkcs11Signer` wraps a PKCS#11 session and key handle:

{{< mermaid >}}
graph LR
    subgraph "PKI.Next Process"
        signer["Pkcs11Signer"]
        session["PKCS#11 Session"]
    end

    subgraph "PKCS#11 Module"
        module["libkryoptic.so<br/><i>or vendor HSM library</i>"]
    end

    subgraph "Token"
        key["Private Key<br/><i>never exported</i>"]
        rng["Hardware RNG"]
    end

    signer --> session
    session --> module
    module --> key
    module --> rng

    style key fill:#ffcdd2
    style rng fill:#ffcdd2
{{< /mermaid >}}

The signing operation sends raw bytes to the token and receives a signature back. The private key exists only inside the token --- the PKCS#11 API provides no mechanism to export it (assuming the token is properly configured with `CKA_EXTRACTABLE = false`).

PKCS#11 v3.2 added support for post-quantum algorithms through new mechanisms:

| Mechanism | Algorithm | Purpose |
|---|---|---|
| `CKM_ML_DSA` | ML-DSA-44/65/87 | Post-quantum signatures |
| `CKM_ML_DSA_KEY_PAIR_GEN` | ML-DSA | Key generation |
| `CKM_ML_KEM` | ML-KEM-768/1024 | Key encapsulation |
| `CKM_SLH_DSA` | SLH-DSA | Hash-based signatures |

PKI.Next's `Pkcs11Signer` maps each `SigningAlgorithm` variant to the corresponding PKCS#11 mechanism:

```rust
match algorithm {
    SigningAlgorithm::EcdsaP256Sha256
    | SigningAlgorithm::EcdsaP384Sha384 =>
        Mechanism::Ecdsa,
    SigningAlgorithm::RsaSha256 =>
        Mechanism::Sha256RsaPkcs,
    SigningAlgorithm::Ed25519 =>
        Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed25519)),
    SigningAlgorithm::MlDsa44
    | SigningAlgorithm::MlDsa65
    | SigningAlgorithm::MlDsa87 =>
        Mechanism::MlDsa(
            SignAdditionalContext::new(HedgeType::Preferred, None)
        ),
}
```

### Kryoptic: The Rust Soft-Token

For development and testing, PKI.Next uses [Kryoptic](https://github.com/latchset/kryoptic), a PKCS#11 v3.2 soft-token written in Rust. Kryoptic stores keys in an SQLite database and implements the full PKCS#11 interface, including post-quantum mechanisms.

Kryoptic is not an HSM. It does not provide hardware key protection. But it exercises the exact same code path as a hardware HSM, which means PKCS#11-related bugs are caught in development and CI, not in production when connected to a $50,000 hardware device.

The setup script generates a Kryoptic configuration and token:

```bash
# Generate Kryoptic configuration
export KRYOPTIC_CONF=/tmp/kryoptic.conf
cat > "$KRYOPTIC_CONF" <<EOF
[token]
label = "PKI-Test"
pin = "12345678"

[storage]
type = "sqlite"
path = "/tmp/kryoptic.db"
EOF

# Build Kryoptic with PQC support
cargo build --manifest-path kryoptic/Cargo.toml \
    --features standard,pqc --release
```

CI runs the full test suite against Kryoptic:

```bash
cargo test --workspace --features pkcs11
```

This tests every algorithm, including ML-DSA, through PKCS#11 without requiring hardware.

## Delegated Signing Keys

PKI.Next supports delegated signing keys for CRL generation. A CRL does not need to be signed by the CA's primary signing key --- RFC 5280 allows a separate key with the `cRLSign` key usage bit. This is useful for two reasons:

1. **Performance.** CRL generation is periodic and can use a less expensive key (e.g., ECDSA instead of RSA-4096) if the CA's primary key is slow
2. **Security.** The CRL signing key can be stored on a different HSM or with different access controls than the CA issuance key

The configuration is straightforward:

```toml
[crl]
signing_key = "/etc/pki/keys/crl-signing-key.pem"
signing_certificate = "/etc/pki/keys/crl-signing-cert.pem"
```

If these fields are absent, the CRL worker uses the CA's primary signing key. If present, it loads a separate signer for CRL operations. The same `Signer` trait abstraction makes this transparent --- the CRL generator does not know whether it is using the primary key or a delegated key.

## Container Build Matrix

The feature flag system produces a matrix of container images:

{{< mermaid >}}
graph TB
    subgraph "Containerfile Multi-Stage Build"
        base["UBI 10 Base<br/><i>Rust 1.88 toolchain</i>"]
        
        subgraph "Builder Stages"
            builder["Default Builder<br/><i>cargo build --release</i>"]
            fips_builder["FIPS Builder<br/><i>cargo build --features fips</i>"]
        end

        subgraph "Runtime Images"
            ca["pki-ca-api"]
            ocsp["pki-ocsp-responder"]
            crl["pki-crl-worker"]
            presigner["pki-ocsp-presigner"]
            monolith["pki-monolith"]
            ca_fips["pki-ca-api-fips"]
            monolith_fips["pki-monolith-fips"]
        end
    end

    base --> builder
    base --> fips_builder
    builder --> ca
    builder --> ocsp
    builder --> crl
    builder --> presigner
    builder --> monolith
    fips_builder --> ca_fips
    fips_builder --> monolith_fips

    style ca_fips fill:#fff3cd
    style monolith_fips fill:#fff3cd
{{< /mermaid >}}

The FIPS images carry the `-fips` suffix, making the compliance boundary visible in container registries and deployment manifests. An operator deploying to a FIPS-required environment uses `pki-ca-api-fips:latest`; one deploying to a development cluster uses `pki-ca-api:latest`. There is no runtime flag to toggle.

## Why This Matters

The crypto pluggability pattern in PKI.Next solves a problem that most CA implementations handle badly:

**Dogtag PKI** uses JSS (Java Security Services) wrapping Mozilla NSS. The FIPS mode is a runtime flag (`pki_fips_mode_enabled`), and misconfiguring it produces cryptic NSS errors at signing time rather than a clear startup failure. The NSS PKCS#11 layer adds a second level of indirection that complicates debugging.

**EJBCA** uses the JCA/JCE provider system, where the crypto backend is selected by provider ordering in `java.security`. A missing or mis-ordered provider produces `NoSuchAlgorithmException` at runtime, potentially after the CA has been serving traffic for hours.

PKI.Next's approach --- compile-time backend selection, trait-based abstraction, startup-time validation --- means:

1. The binary either includes FIPS crypto or it does not. There is no misconfiguration.
2. Algorithm support is checked when the signer is constructed, before the CA accepts any requests.
3. The CA engine's signing code is identical regardless of backend, reducing the surface area for backend-specific bugs.

The trade-off is build complexity: CI runs three build configurations (`default`, `--features fips`, `--features pkcs11`) and three corresponding test suites. But that complexity lives in CI, where it belongs, not in production deployment where it would be dangerous.

---

**Update (June 2026):** The crypto pluggability pattern and PKCS#11 integration described here are implemented in:

- **kipuka** (EST/CMP enrollment with HSM key protection) — [kipuka.dev](https://kipuka.dev) · [source](https://codeberg.org/czinda/kipuka)
- **Akamu** (ACME CA with HSM CA keys) — [source](https://codeberg.org/czinda/akamu)
- **Synta** (ASN.1/X.509 foundation) — [source](https://codeberg.org/abbra/synta) · [crates.io](https://crates.io/crates/synta)

*Next in the series: [Part 4: Tamper-Evident Audit Logs](/posts/pki-next-part4-tamper-evident-audit/) --- HMAC hash chaining for Common Criteria compliance, and the timestamp precision bug that almost broke it.*

*Previous: [Part 2: Post-Quantum Certificates Are Here](/posts/pki-next-part2-post-quantum-certificates/)*
