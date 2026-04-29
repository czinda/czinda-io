---
title: "PKI.Next Part 1: Building a Certificate Authority in Rust"
date: 2026-04-29
draft: false
tags: ["pki", "rust", "certificates", "security", "architecture", "ca", "pki-next"]
description: "Why we chose Rust to build a modern Certificate Authority from scratch, the modular crate architecture that makes it work, and what 49,000 lines of Rust buys you that Java and C never could."
series: ["PKI.Next"]
---

This is the first post in a series about PKI.Next, a Certificate Authority built from scratch in Rust. The series covers the architecture, the cryptographic decisions, and the operational features that make a CA trustworthy enough to replace systems that have been running for two decades.

## Why Build a New CA?

I have spent years working with [Dogtag PKI](https://www.dogtagpki.org/), Red Hat's Java-based Certificate Authority that has been in production since the mid-2000s. Dogtag works. It issues certificates, it generates CRLs, it handles OCSP, and it has passed Common Criteria evaluations. But it carries twenty years of accumulated decisions that are increasingly difficult to change:

- **Java serialization** in the request pipeline, tightly coupling internal message formats to JDK versions
- **JSS (Java Security Services)** wrapping Mozilla NSS, creating a two-layer abstraction over PKCS#11 that makes debugging HSM issues genuinely painful
- **Tomcat deployment**, requiring a full Java application server for what is fundamentally a signing service
- **XML-heavy configuration** spread across dozens of profile definitions and CS.cfg entries
- **No native container story** --- Dogtag assumes systemd, NFS-shared `pki-tomcat` directories, and persistent local state

None of these are bugs. They are the natural consequences of building a CA in 2004 and maintaining it through fifteen years of changing requirements. But they make it hard to answer the questions that matter today: How do you run a CA in Kubernetes? How do you add post-quantum algorithms without rewriting the crypto layer? How do you get from zero to issuing certificates in under a minute?

PKI.Next is an attempt to answer those questions with a clean sheet.

## Why Rust

The language choice was not about performance benchmarks. A CA is not a high-throughput system --- even large deployments issue thousands of certificates per day, not millions per second. The choice was about three properties that matter specifically for PKI infrastructure:

**Memory safety without garbage collection.** A CA holds signing keys in memory. A use-after-free or buffer overflow in a CA is not a crash --- it is a key compromise. Rust's ownership model eliminates these classes of bugs at compile time, without the unpredictable pause times of a garbage collector that would complicate HSM token sessions.

**Zero-cost abstractions over unsafe operations.** Cryptographic operations are inherently `unsafe` at the FFI boundary --- you are calling into C libraries (OpenSSL, aws-lc, PKCS#11 modules) that use raw pointers and manual memory management. Rust lets you wrap these in safe abstractions with no runtime overhead. The `Signer` trait in PKI.Next looks the same whether the backing implementation is a software key, a FIPS-validated library, or a hardware security module.

**Compile-time feature selection.** Rust's feature flag system lets you build the same codebase with different cryptographic backends. `cargo build --features fips` links against `aws-lc-rs` for FIPS 140-3 validated crypto. `cargo build --features pkcs11` enables hardware security module support. The default build uses `ring` for fast development. These are not runtime configuration options that could be misconfigured in production --- the binary physically cannot use the wrong backend.

## The Crate Architecture

PKI.Next is a Cargo workspace of 23 crates. The dependency graph is intentionally layered to enforce separation of concerns:

{{< mermaid >}}
graph TD
    subgraph "Foundation"
        types["pki-types<br/><i>shared data structures</i>"]
        crypto["pki-crypto<br/><i>signing, cert building</i>"]
        store["pki-store<br/><i>persistence traits + PG</i>"]
        lint["pki-lint<br/><i>certificate validation</i>"]
    end

    subgraph "CA Engine"
        ca["pki-ca<br/><i>issuance, revocation, CRL</i>"]
        ocsp["pki-ocsp<br/><i>OCSP response building</i>"]
    end

    subgraph "Server Infrastructure"
        common["pki-server-common<br/><i>middleware, HA, audit</i>"]
        server["pki-server<br/><i>CA API + workers</i>"]
        ra["pki-ra-client<br/><i>RA &#8594; CA communication</i>"]
    end

    subgraph "Protocol Servers"
        est["pki-est-server<br/><i>RFC 7030</i>"]
        acme["pki-acme-server<br/><i>RFC 8555</i>"]
        coap["pki-coap-server<br/><i>RFC 9148</i>"]
        spire["pki-spire-server<br/><i>SPIFFE/SPIRE</i>"]
        vault["pki-vault-server<br/><i>key escrow</i>"]
        dogtag["pki-dogtag-compat<br/><i>Dogtag API proxy</i>"]
    end

    subgraph "CLI"
        cli["pki-cli<br/><i>rs-pki binary</i>"]
    end

    types --> crypto
    types --> store
    crypto --> ca
    store --> ca
    lint --> ca
    crypto --> ocsp
    ca --> server
    ocsp --> server
    common --> server
    store --> common
    ra --> est
    ra --> acme
    ra --> coap
    ra --> spire
    ra --> vault
    ra --> dogtag
    ra --> cli
{{< /mermaid >}}

The key design constraint is that **protocol servers never touch the CA's signing key**. They communicate with the CA through `pki-ra-client`, which makes mTLS-authenticated API calls. This is the Registration Authority (RA) pattern from RFC 4210, applied to every enrollment protocol:

{{< mermaid >}}
sequenceDiagram
    participant Client as Client Device
    participant PS as Protocol Server<br/>(EST/ACME/CoAP)
    participant CA as CA API Server
    participant HSM as Signing Key<br/>(Software/PKCS#11)

    Client->>PS: Protocol-specific request<br/>(EST SimpleEnroll, ACME Order, etc.)
    PS->>PS: Parse & validate protocol
    PS->>CA: POST /v1/ca/requests<br/>(CSR + profile + metadata)
    CA->>CA: Policy check & profile enforcement
    CA->>HSM: Sign certificate
    HSM-->>CA: Signed certificate
    CA-->>PS: Certificate response
    PS-->>Client: Protocol-specific response<br/>(PKCS#7, PEM, CBOR, etc.)
{{< /mermaid >}}

This means you can deploy the EST server in a DMZ, the ACME server on a public endpoint, and the CoAP server on an IoT gateway --- all issuing certificates from the same CA --- without exposing the CA's signing key to any of them. If a protocol server is compromised, the attacker can submit requests but cannot sign certificates.

## Seven Binaries from One Crate

The `pki-server` crate compiles into seven distinct binaries, each running a single responsibility:

| Binary | Port | Purpose |
|---|---|---|
| `pki-ca-api` | 8443 | REST API for certificate operations |
| `pki-ocsp-responder` | 8444 | OCSP status queries |
| `pki-crl-worker` | 9090 (health) | Periodic CRL generation |
| `pki-ocsp-presigner` | 9090 (health) | Pre-signs OCSP responses to Redis |
| `pki-expiration-monitor` | 9090 (health) | Certificate expiry notifications |
| `pki-migrate` | --- | Database schema migrations |
| `pki-server` | 8443 | Monolith mode (all of the above) |

The monolith binary is the same code with all workers running as Tokio tasks in a single process. It exists for development and small deployments where running six containers is overkill. The microservice binaries exist for production deployments where you want to scale, restart, and monitor each component independently.

This is not a matter of opinion or architecture astronautics. In practice:

- The **CRL worker** needs to run exactly once (leader-elected) while the CA API scales horizontally
- The **OCSP presigner** is CPU-bound (signing responses) while the OCSP responder is I/O-bound (serving from Redis)
- The **expiration monitor** runs on a slow timer and should not compete for resources with request-serving components

## The Signing Abstraction

The central abstraction in `pki-crypto` is the `Signer` trait:

```rust
pub trait Signer: Send + Sync {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn algorithm(&self) -> &SigningAlgorithm;
    fn public_key_der(&self) -> &[u8];
}
```

Three methods. Every signing operation in the system --- certificate issuance, CRL signing, OCSP response signing --- goes through this trait. The implementations are:

| Implementation | Backend | Algorithms | Use Case |
|---|---|---|---|
| `SoftwareSigner` | `ring` | ECDSA, RSA, Ed25519 | Development, non-FIPS |
| `FipsSoftwareSigner` | `aws-lc-rs` | ECDSA, RSA | FIPS 140-3 production |
| `Pkcs11Signer` | `cryptoki` | ECDSA, RSA, Ed25519, ML-DSA | HSM-backed production |

The CA engine does not know which implementation it is using. The startup code selects the signer based on configuration:

```toml
[ca]
signing_key = "/etc/pki/keys/ca-key.pem"    # Software signer
hsm_enabled = false

# OR

[ca]
hsm_enabled = true
pkcs11_module = "/usr/lib/libkryoptic.so"    # PKCS#11 signer
pkcs11_slot = 0
key_label = "ca-signing-key"
```

This is where Rust's type system pays dividends. The `Signer` trait is object-safe, so the CA engine stores `Arc<dyn Signer>` --- a reference-counted pointer to whatever implementation was selected at startup. There is no `if hsm { ... } else { ... }` sprinkled through the certificate issuance code. The signing backend is decided once, at process startup, and the rest of the system is oblivious.

## What 49,000 Lines Gets You

The complete feature set, as of this writing:

**Certificate Lifecycle**
- CSR submission, agent approval/rejection, bulk operations
- 26 built-in certificate profiles (TLS server, client auth, subordinate CA, OCSP signing, S/MIME, PKINIT, router, VPN, Wi-Fi, code signing, and more)
- Certificate hold and unrevoke (RFC 5280 `certificateHold` reason)
- Re-enrollment with new key pairs

**Revocation**
- Full CRL, delta CRL, and sharded CRL generation
- OCSP responder with Redis-backed pre-signed response cache
- Bulk revocation API

**Cryptography**
- ECDSA P-256/P-384, RSA-4096, Ed25519
- ML-DSA-44/65/87 (FIPS 204 post-quantum signatures)
- FIPS 140-3 mode via `aws-lc-rs`
- PKCS#11 HSM support (Kryoptic soft-token for testing, hardware HSMs for production)

**Enrollment Protocols**
- EST (RFC 7030) --- enterprise device enrollment
- ACME (RFC 8555) --- automated certificate management with MPIC
- CoAP/DTLS (RFC 9148) --- constrained IoT devices
- SPIFFE/SPIRE --- Kubernetes workload identity
- Dogtag compatibility proxy --- drop-in replacement for FreeIPA

**Operations**
- HMAC-chained audit logs (Common Criteria FAU_STG.2 tamper evidence)
- Leader election for HA worker deployments (Redis or PostgreSQL advisory locks)
- React/PatternFly 6 dashboard with 47 pages
- CLI tool (`rs-pki`) with 16 command groups
- Container-native: 12 container image targets from a single Containerfile
- Health checks on every binary

**Security**
- Role-based access control with exclusive role constraints
- mTLS everywhere (inter-service, CLI, protocol servers)
- Access banners, session management, system recovery
- Certificate linting against CA/Browser Forum Baseline Requirements

## The Dashboard

PKI is traditionally a CLI-and-config-file domain. Dogtag has a web UI, but it is a Struts-era JSP application that requires significant expertise to navigate. PKI.Next ships a modern React dashboard built on Red Hat's PatternFly 6 design system:

{{< mermaid >}}
graph LR
    subgraph "Dashboard Pages"
        overview["Overview<br/><i>stats, charts, activity</i>"]
        certs["Certificates<br/><i>list, detail, download</i>"]
        requests["Requests<br/><i>queue, approve, reject</i>"]
        profiles["Profiles<br/><i>create, edit, manage</i>"]
        crl["CRL Management<br/><i>generate, shards, delta</i>"]
        audit["Audit Log<br/><i>search, filter, verify chain</i>"]
        users["User Management<br/><i>RBAC, roles, sessions</i>"]
        servers["Protocol Servers<br/><i>register, configure, deploy</i>"]
        trust["Trust Hierarchy<br/><i>CA chain visualization</i>"]
    end

    subgraph "Backend"
        api["CA REST API<br/>Axum / Rust"]
    end

    overview --> api
    certs --> api
    requests --> api
    profiles --> api
    crl --> api
    audit --> api
    users --> api
    servers --> api
    trust --> api
{{< /mermaid >}}

The dashboard is not a separate application --- it is served by the CA API binary as static assets, so there is no additional deployment step. The protocol server management pages deserve special mention: you can register an EST or ACME server, configure its enrollment profile, validate the configuration, trigger a health check, and generate deployment artifacts (Docker Compose, Quadlet systemd units, or Ansible playbooks) directly from the browser.

## What Comes Next

The rest of this series digs into specific features:

- **[Part 2: Post-Quantum Certificates Are Here](/posts/pki-next-part2-post-quantum-certificates/)** --- ML-DSA signing, what FIPS 204 means for PKI, and why your CA needs to be ready now
- **[Part 3: FIPS 140-3 and the Crypto Pluggability Problem](/posts/pki-next-part3-fips-and-hsm/)** --- How feature flags and trait objects let you swap crypto backends without touching business logic
- **[Part 4: Tamper-Evident Audit Logs](/posts/pki-next-part4-tamper-evident-audit/)** --- HMAC hash chaining for Common Criteria compliance, and the timestamp precision bug that almost broke it
- **[Part 5: One CA, Six Protocols](/posts/pki-next-part5-protocol-servers/)** --- EST, ACME, CoAP, SPIFFE, Vault, and Dogtag --- how the RA pattern makes it all work
- **[Part 6: Replacing Dogtag PKI](/posts/pki-next-part6-replacing-dogtag/)** --- The compatibility proxy, migration path, and what twenty years of PKI teaches you about building the next twenty

Each post includes architecture diagrams, configuration examples, and the specific implementation decisions that make a Certificate Authority trustworthy.

---

*The previous posts on this blog cover [OCSP vs CRL sharding performance](/posts/ocsp-vs-crl-sharding-performance/) and [event-driven certificate lifecycle management](/posts/event-driven-certificate-revocation-lab/).*
