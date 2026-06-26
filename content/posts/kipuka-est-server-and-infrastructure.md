---
title: "kipuka: An EST Enrollment Server Built for Enterprise PKI"
date: 2026-06-25
draft: false
tags: ["pki", "est", "rust", "certificates", "security", "hsm", "enterprise", "kipuka", "rfc-7030", "coap", "post-quantum", "cmp"]
description: "Enterprise certificate enrollment shouldn't require a monolithic CA. kipuka is a Rust-based EST server with multi-CA failover, HSM key protection, NIAP compliance, CoAP/DTLS for constrained devices, CMP enrollment, and post-quantum readiness — designed to fit into the PKI you already have."
series: ["PKI.Next"]
---

Enterprise certificate enrollment has a tooling problem.

Most organizations run a certificate authority — often Red Hat Certificate
System (Dogtag), Microsoft AD CS, or EJBCA — but getting certificates onto
devices, servers, and workloads still involves brittle SCEP integrations,
custom scripts, or manual CSR submission. The enrollment layer is the weak
link.

[EST (Enrollment over Secure Transport)](https://www.rfc-editor.org/rfc/rfc7030)
was designed to fix this. Published as RFC 7030 in 2013, it replaces SCEP
with a modern HTTPS-based protocol that supports mutual TLS, one-time
passwords, and integration with existing CAs. But production-ready EST
implementations remain scarce — especially ones that meet government and
enterprise compliance requirements.

[kipuka](https://kipuka.dev) is an EST enrollment server built specifically
for this gap.

## The problem kipuka solves

If you're running enterprise PKI today, you probably recognize these pain
points:

**Enrollment is fragmented.** Your CA issues certificates, but the enrollment
path varies by device type. Network equipment uses SCEP. Mobile devices use
profiles. Servers use custom scripts or Certmonger. Each path has its own
authentication story, its own failure modes, and its own monitoring gaps.

**SCEP is showing its age.** It was designed for a world of pre-shared
secrets and HTTP polling. It has no native mTLS support, no standard renewal
mechanism, and
[known security weaknesses](https://www.rfc-editor.org/rfc/rfc7030#section-1)
that RFC 7030 was explicitly designed to address.

**Compliance requirements are tightening.** NIAP's CA Protection Profile
demands specific audit trail requirements (FAU_GEN.1), cryptographic module
standards (FCS_CKM.1), and authentication failure handling (FIA_AFL.1). The
CA/B Forum's Baseline Requirements are shortening certificate validity from
398 days to 47 days by 2029. Meeting these with ad-hoc enrollment scripts
isn't sustainable.

**CA coupling creates fragility.** When your enrollment logic is embedded in
your CA, a CA outage means no enrollment. When your enrollment server can
only talk to one CA vendor, you're locked in.

kipuka addresses these by providing a dedicated EST enrollment layer that
sits in front of your existing CA infrastructure.

## What kipuka enrolls

kipuka is protocol-native for the device types that enterprise and
government environments actually need to manage:

| Device / Workload | Transport | Auth Method | Example |
|-------------------|-----------|-------------|---------|
| **Servers and VMs** | EST/HTTPS | OTP or mTLS | Apache, Nginx, RHEL hosts |
| **Containers and pods** | EST/HTTPS | mTLS auto-renewal | Kubernetes workloads, OpenShift routes |
| **Network equipment** | EST/HTTPS | OTP (replacing SCEP) | Cisco IOS-XE, Juniper, Aruba |
| **Workstations and laptops** | EST/HTTPS | GSSAPI/Kerberos | Domain-joined Windows, RHEL, macOS |
| **Mobile devices** | EST/HTTPS | OTP | iOS, Android MDM enrollment |
| **IoT sensors and gateways** | EST/CoAP/DTLS | mTLS or OTP | Constrained ARM/RISC-V devices |
| **Industrial controllers** | CMP (RFC 4210) | MAC or signature | SCADA, PLC, DCS systems |
| **Telecom equipment** | CMP (RFC 4210) | MAC or signature | 5G RAN, core network functions |
| **Load balancers and proxies** | EST/HTTPS | mTLS renewal | F5, HAProxy, Envoy sidecars |
| **HSM-backed services** | EST/HTTPS | mTLS | Payment processing, key management |

The three transport options — HTTPS, CoAP/DTLS, and CMP — cover
everything from a Kubernetes sidecar requesting a 47-day TLS cert to
an embedded sensor on a constrained network enrolling over UDP. EST labels
route each device type to the right certificate profile, CA backend, and
key constraints without per-device configuration on the enrollment server.

{{< mermaid >}}
graph TD
    subgraph HTTPS["HTTPS Clients"]
        A1["Servers / VMs"]
        A2["Containers / Pods"]
        A3["Network Equipment"]
        A4["Workstations"]
        A5["Mobile Devices"]
        A6["Load Balancers"]
    end
    subgraph COAP["Constrained Devices"]
        B1["IoT Sensors"]
        B2["Gateways"]
        B3["Embedded Controllers"]
    end
    HTTPS -->|"TLS + OTP / mTLS / Kerberos"| EST["kipuka-est<br/>EST + CMP routes"]
    COAP -->|"DTLS 1.2 over UDP"| CoAP["kipuka-coap<br/>Block1/2, EST bridge"]
    EST --> Core["Shared Enrollment Core"]
    CoAP --> Core
    Core --> Local["Local CAs<br/>(file or HSM)"]
    Core --> Remote["Remote CAs<br/>(Dogtag, EST)"]
{{< /mermaid >}}

## What kipuka is

kipuka is a Rust-based EST server that implements the full
[RFC 7030](https://www.rfc-editor.org/rfc/rfc7030) enrollment operations:

| Operation | Path | Purpose |
|-----------|------|---------|
| CA Certs | `GET /cacerts` | Retrieve the CA certificate chain (no auth) |
| Simple Enroll | `POST /simpleenroll` | Initial certificate enrollment |
| Simple Re-enroll | `POST /simplereenroll` | Certificate renewal with mTLS |
| Full CMC | `POST /fullcmc` | Complex enrollment via RFC 5272 CMC |
| Server Keygen | `POST /serverkeygen` | Server-side key generation with KRA escrow |
| CSR Attributes | `GET /csrattrs` | Advertise required CSR fields to clients |

The name comes from Hawaiian geology. A *kipuka* is an area of older,
established land surrounded by younger lava flows — an island of stability
in a changing landscape. It seemed right for a service whose job is to be
the most reliable thing in the certificate lifecycle.

## Designed for enterprise PKI

kipuka isn't a standalone CA. It's an enrollment frontend that integrates
with the CA infrastructure you already run.

### Multi-CA with automatic failover

Most enterprises don't run a single CA. They have an RSA issuing CA, an
ECDSA issuing CA, maybe a separate CA for device certificates. Some run
geographically distributed CAs for latency or regulatory reasons.

kipuka supports multiple CA backends with four failover strategies:

```toml
[ha]
enabled = true
strategy = "active-passive"   # or round-robin, weighted, latency-based
check_interval = "30s"
failure_threshold = 3

[[ha.group]]
name = "rsa-issuers"
ca_ids = ["rsa-ca-east", "rsa-ca-west"]
strategy = "latency-based"
```

A circuit breaker tracks CA health through five states — Healthy, Degraded,
Unhealthy, CircuitOpen, and Recovering — with configurable thresholds and
cooldown periods. When a CA goes down, enrollment continues through the next
healthy backend. No manual intervention required.

### EST labels for certificate profiles

Different use cases need different certificate profiles. A TLS server cert
needs `serverAuth` EKU and SAN enforcement. A client auth cert needs
`clientAuth` and stricter key type constraints. A device cert might have a
longer validity and a Subject DN pattern requirement.

EST labels let you expose these as separate enrollment paths:

```toml
[[est.label]]
name = "server-tls"
ca_id = "rsa-ca"
allowed_key_types = ["rsa:2048", "rsa:4096", "ec:p256", "ec:p384"]
required_ext_key_usage = ["serverAuth"]
max_validity_days = 398
require_san = true

[[est.label]]
name = "client-auth"
ca_id = "ecdsa-ca"
allowed_key_types = ["ec:p256", "ec:p384"]
required_ext_key_usage = ["clientAuth"]

[[est.label]]
name = "device"
ca_id = "rsa-ca"
subject_pattern = "CN=device-.*,O=Example Corp"
max_validity_days = 825
```

Clients enroll against `/.well-known/est/server-tls/simpleenroll` or
`/.well-known/est/device/simpleenroll`. Each label enforces its profile
constraints independently.

### HSM key protection via PKCS#11

CA private keys belong in a hardware security module. kipuka integrates with
HSMs via the PKCS#11 standard, with tested support for enterprise-grade
hardware:

| Vendor | Model | FIPS Level |
|--------|-------|------------|
| Entrust | nShield Connect/Solo | 140-3 Level 3 |
| Utimaco | CryptoServer Se/CP5 | 140-3 Level 3 |
| Thales | Luna 7 (CSP11/TCT) | 140-3 Level 3 |
| Kryoptic | SoftHSM-compatible | Development/test |

Key material never leaves the HSM boundary. kipuka handles session
management, connection pooling, and health checking against the PKCS#11
interface. PIN management supports environment variables (preferred for
containers) and secured files — never plaintext in configuration.

### Red Hat Certificate System (Dogtag) integration

For organizations running Red Hat Certificate System, kipuka includes a
native REST API client that delegates enrollment to Dogtag. This gives you
EST protocol support in front of your existing Dogtag infrastructure without
modifying the CA:

- **Profile-based enrollment** — map EST labels to Dogtag certificate profiles
- **Full CMC passthrough** — RFC 5272 requests forwarded directly to Dogtag's CMC endpoint
- **KRA integration** — server-side key generation with Key Recovery Authority escrow
- **Multi-instance pooling** — connect to multiple Dogtag instances with circuit breaker failover

This is particularly relevant for RHEL and IdM environments where Dogtag is
already the CA of record.

### Authentication

kipuka supports three authentication methods, selectable per deployment:

**OTP (One-Time Passwords)** — for initial enrollment. Tokens are generated
via the admin API, hashed with argon2id before storage, and validated with
timing-safe comparison. Rate limiting protects against brute-force attempts.
Minimum token length is 16 characters for NIAP compliance.

**mTLS (Mutual TLS)** — for certificate renewal. The client presents its
existing certificate during the TLS handshake. kipuka validates the
certificate chain against configured trust anchors and allows re-enrollment
without additional credentials.

**GSSAPI/Kerberos** — for enterprise SSO environments. SPNEGO token parsing
extracts Kerberos principals from AP-REQ tickets for identity mapping. With
the optional `gssapi` feature flag, kipuka links against libgssapi for full
cryptographic ticket verification via `gss_accept_sec_context`. Credential
initialization from a keytab happens at startup, and mutual authentication
tokens are supported. A `require_crypto_verification` config option controls
whether structural parsing (faster, no krb5 dependency) or full
cryptographic verification (production-recommended) is used.

### CMP enrollment (RFC 4210)

Beyond EST, kipuka implements the
[Certificate Management Protocol](https://www.rfc-editor.org/rfc/rfc4210)
for environments that need it. CMP is the protocol of choice for many
telecom and industrial PKI deployments, and it's required by some European
eIDAS trust service providers.

kipuka's CMP implementation includes:

- **Signature-based protection** — verify CMP message signatures over
  `header||body` using signer certificates from `extraCerts`, with chain
  validation against configured CA trust anchors
- **MAC-based protection** — shared secret authentication per RFC 4210
  §5.1.3.1 with PBKDF2 key derivation (iterated OWF with SHA-256/384/512,
  capped at 100k iterations) and HMAC with constant-time comparison
- **RA authorization** — certificates with the `id-kp-cmcRA` extended key
  usage can perform revocation on behalf of any entity
- **Dynamic CA parameters** — CMP responses use the actual CA subject DN
  and signature algorithm rather than hardcoded values

### CoAP/DTLS transport (RFC 7252 / RFC 9483)

Not every enrollment client speaks HTTPS.
[EST-coaps](https://www.rfc-editor.org/rfc/rfc9148) defines certificate
enrollment over CoAP/DTLS for constrained devices — IoT sensors, embedded
controllers, and network equipment that can't afford a full TLS stack.

kipuka includes a complete CoAP/DTLS transport layer:

{{< mermaid >}}
graph TD
    Device["Constrained Device<br/>(sensor, controller, gateway)"]
    Device -->|"DTLS 1.2 over UDP"| CoAP
    subgraph CoAP["kipuka-coap"]
        Block1["Block1 assembly<br/>reassemble multi-block CSR uploads"]
        Block2["Block2 split<br/>fragment large cert responses"]
        Bridge["EST route bridge<br/>/cacerts, /simpleenroll, /simplereenroll"]
    end
    CoAP -->|"same issuance, audit, and<br/>compliance logic as HTTPS"| Core["Shared EST Core"]
{{< /mermaid >}}

The DTLS transport uses OpenSSL for the handshake, with per-peer
`DtlsConnection` state, memory BIO architecture, client certificate
extraction, and session resumption caching. Block1 assembly handles
multi-block CSR uploads with configurable TTL and capacity limits. Block2
disassembly fragments large certificate responses automatically.

The CoAP server shares `AppState` with the HTTPS server — enabling it
requires a single `[coap]` section in the configuration. All EST operations
route through the same issuance, audit, and compliance logic.

### Post-quantum cryptography (FIPS 203 / FIPS 204)

kipuka supports post-quantum certificate enrollment today:

**ML-DSA (FIPS 204)** — CSR validation recognizes ML-DSA algorithm OIDs.
EST labels can constrain enrollment to specific ML-DSA security levels via
`allowed_ml_dsa_levels`. ML-DSA CAs are auto-detected and configured with
`hash_algorithm="none"` because the hash is built into the algorithm per
the FIPS 204 specification — there is no separate SHA parameter.

**ML-KEM (FIPS 203)** — key encapsulation mechanism support for hybrid
key exchange scenarios. Profile enforcement validates CSR algorithms against
`allowed_ml_kem_levels`.

**Composite signatures** — `allow_composite_ml_dsa` enables profiles that
combine ML-DSA with a classical algorithm for defense-in-depth during the
transition period.

**HSM support** — the cryptoki upgrade to v0.12 (PKCS#11 v3.2) enables
ML-DSA key generation (`MlDsaKeyPairGen`), ML-DSA signing
(`Mechanism::MlDsa` with `HedgeType::Preferred`), ML-KEM key pair
generation (`MlKemKeyPairGen`), and ML-KEM encapsulate/decapsulate — all
through standard PKCS#11 v3.2 mechanism IDs rather than vendor-specific
values.

Software key generation via synta-certificate works without an HSM.
Runtime requires OpenSSL 3.5+ with the PQC provider.

### STAR short-lived certificates (RFC 8739)

[STAR](https://www.rfc-editor.org/rfc/rfc8739) (Short-Term Automatic
Renewal) certificates solve the revocation latency problem. Instead of
issuing long-lived certificates and relying on CRL/OCSP for revocation, STAR
issues certificates with very short validity periods and automatically
renews them. If the STAR order is cancelled, the certificate simply expires
without needing a revocation check.

kipuka's STAR implementation issues real certificates via the standard
`issue_certificate()` path with clamped validity, wraps responses in
PKCS#7 certs-only format, and tracks order state through the full lifecycle.

### CMS-EST security hardening (RFC 5652)

The CMS (Cryptographic Message Syntax) layer that wraps Full CMC requests
received significant security hardening:

- **SignedData verification** — signature verification now operates over
  re-tagged `signedAttrs` DER (`SET OF` tag `0x31`) per RFC 5652 §5.4,
  rather than the raw payload
- **Signer identification** — signer certificate is matched against the
  `SignerIdentifier` (sid) instead of blindly using the first certificate
  in `CertificateSet`
- **Subject identity binding** — simplereenroll via CMS compares the CSR
  subject with the CMS signer identity to prevent enrollment impersonation
- **RA EKU enforcement** — Full CMC requests require the `id-kp-cmcRA`
  extended key usage on the signer certificate
- **Configurable CMC truststore** — a dedicated `cmc_truststore_file`
  option allows RA certificates issued by a different CA or intermediate
  to sign CMC requests, rather than requiring the target CA cert as the
  sole trust anchor

### Compliance mapping

kipuka is designed with specific compliance frameworks in mind:

**NIAP CA Protection Profile v2.0** — security functional requirements are
mapped to implementation:
- FAU_GEN.1/2: structured audit trail with authenticated identity on every event
- FCS_CKM.1: key generation via PKCS#11 or CSPRNG with 64+ bit serial numbers
- FIA_AFL.1: rate limiting with lockout and audit on authentication failure
- FTP_TRP.1: EST over TLS 1.2+ with mTLS, admin API on separate TLS endpoint

**CA/B Forum Baseline Requirements** — certificate profiles enforce:
- Serial numbers: 160 bits from CSPRNG (exceeds the 64-bit minimum)
- Key constraints: RSA ≥2048, ECDSA P-256/P-384
- Validity tracking: 398 days today, with configuration for the
  [upcoming reductions](https://cabforum.org/2025/03/ballot-sc-081/)
  (200 days in 2026, 100 in 2027, 47 in 2029)

The full compliance mapping is in the
[documentation](https://kipuka.dev/doc/compliance/niap.html).

## How it's built

kipuka is written in Rust, chosen for memory safety in a security-critical
service that handles private keys and cryptographic operations.

The architecture is a Cargo workspace with seven crates, organized in
layers:

{{< mermaid >}}
graph TD
    Clients["Clients"]
    Clients -->|"HTTPS (TLS)"| EST["kipuka-est<br/>axum routes, EST + CMP"]
    Clients -->|"CoAP (DTLS)"| CoAP["kipuka-coap<br/>DTLS transport, Block1/Block2"]
    EST --> Core["Shared Enrollment Core"]
    CoAP --> Core
    Core --> OTP["kipuka-otp<br/>OTP store, rate limit"]
    Core --> HSM["kipuka-hsm<br/>PKCS#11, HSM crypto"]
    Core --> Dogtag["kipuka-dogtag<br/>Dogtag CA REST client"]
    Core --> Util["kipuka-util<br/>shared types & config"]
    OTP --> DB["sqlx<br/>SQLite · PostgreSQL · MariaDB"]
{{< /mermaid >}}

Each crate has a clear responsibility boundary. `kipuka-est` handles EST
protocol routing and certificate issuance. `kipuka-hsm` abstracts PKCS#11
operations. `kipuka-otp` manages token lifecycle with timing-safe
validation. `kipuka-dogtag` is a standalone Dogtag REST client that could
be reused independently.

The database layer supports three backends — SQLite for single-node
deployments, PostgreSQL for production clusters, and MariaDB for existing
Galera environments — switchable with a single configuration line.

### Audit logging

Every security-relevant event is recorded to an append-only audit trail
compliant with NIAP FAU_GEN.1. Twenty-one event types cover the certificate
lifecycle (issuance, renewal, revocation), authentication (success, failure,
lockout), and administrative operations (OTP provisioning, CA health
changes).

Events are always stored in the database. Optional destinations include
file-based JSON lines (append-only) and syslog over TLS for integration
with enterprise SIEM platforms.

## Getting started

The fastest path is the container image:

```bash
# Pull the image (no login required)
podman pull registry.kipuka.dev/kipuka:latest

# Run with your configuration
podman run --rm \
  -v ./kipuka.toml:/etc/kipuka/kipuka.toml:ro \
  -v ./certs:/etc/kipuka/certs:ro \
  -p 9443:9443 \
  registry.kipuka.dev/kipuka:latest
```

Or build from source:

```bash
git clone https://codeberg.org/czinda/kipuka
cd kipuka
cargo build --release
cp kipuka.toml.example kipuka.toml
cargo run --release -- --config kipuka.toml
```

A minimal configuration needs four things: a listen address, a TLS
certificate, a database, and a CA:

```toml
[server]
listen = "0.0.0.0:9443"

[tls]
cert = "/etc/kipuka/tls/server.pem"
key = "/etc/kipuka/tls/server.key"

[tls.client_auth]
trust_anchors = "/etc/kipuka/tls/client-ca.pem"

[db]
url = "sqlite:///var/lib/kipuka/kipuka.db"

[[ca]]
id = "main"
cert = "/etc/kipuka/ca/ca.pem"
key = "/etc/kipuka/ca/ca.key"
```

The [documentation](https://kipuka.dev/doc/) covers installation,
first-run walkthrough, certificate enrollment, and the full configuration
reference.

## Current status and roadmap

kipuka is under active development. Here's what works today and what's
coming:

**Implemented:**
- Full EST protocol: simpleenroll, simplereenroll, fullcmc, serverkeygen, csrattrs, cacerts
- CMP enrollment with signature and MAC-based protection (RFC 4210)
- CMS SignedData verification with signedAttrs re-tagging (RFC 5652 §5.4)
- STAR short-term auto-renewal with real certificate issuance (RFC 8739)
- CoAP/DTLS transport for constrained devices (RFC 7252 / RFC 9483)
- Post-quantum cryptography: ML-DSA (FIPS 204), ML-KEM (FIPS 203), composite signatures
- GSSAPI/Kerberos authentication with libgssapi FFI and keytab support
- Multi-CA with four HA failover strategies and queue-and-retry
- PKCS#11 v3.2 HSM integration (Entrust, Utimaco, Thales, Kryoptic) with PQC mechanisms
- Dogtag PKI REST client with multi-instance pooling
- OTP authentication with timing-safe validation and rate limiting
- mTLS client certificate authentication with OCSP/CRL revocation checking
- OCSP stapling with response fetch and cache
- Server-side key generation with KRA escrow
- Remote CA enrollment via EST client delegation
- CMS-EST security hardening: signer identity binding, RA EKU enforcement, configurable CMC truststore
- Admin API with mTLS validation, constant-time bearer tokens, and real DB/HSM health probes
- SQLite, PostgreSQL, and MariaDB backends
- NIAP-compliant structured audit logging (21 event types)
- PatternFly web dashboard
- FreeIPA integration test suite (Beaker topology with 10 GSSAPI smoke tests)

**Planned:**
- Full OCSP responder
- Certificate transparency log submission
- CMP polling and delayed enrollment

The container image is available at
`registry.kipuka.dev/kipuka:latest` (x86_64 and arm64) with anonymous
pulls — no registry login required.

---

kipuka is open source under GPL-3.0-or-later.

- [Project site](https://kipuka.dev)
- [Documentation](https://kipuka.dev/doc/)
- [API reference](https://kipuka.dev/api/)
- [Source code](https://codeberg.org/czinda/kipuka)
- [Container image](https://registry.kipuka.dev)
