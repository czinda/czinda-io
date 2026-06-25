---
title: "kipuka: An EST Enrollment Server Built for Enterprise PKI"
date: 2026-06-25
draft: false
tags: ["pki", "est", "rust", "certificates", "security", "hsm", "enterprise", "kipuka", "rfc-7030"]
description: "Enterprise certificate enrollment shouldn't require a monolithic CA. kipuka is a Rust-based EST server with multi-CA failover, HSM key protection, and NIAP compliance — designed to fit into the PKI you already have."
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

## What kipuka is

kipuka is a Rust-based EST server that implements the core
[RFC 7030](https://www.rfc-editor.org/rfc/rfc7030) enrollment operations:

| Operation | Path | Purpose |
|-----------|------|---------|
| CA Certs | `GET /cacerts` | Retrieve the CA certificate chain (no auth) |
| Simple Enroll | `POST /simpleenroll` | Initial certificate enrollment |
| Simple Re-enroll | `POST /simplereenroll` | Certificate renewal with mTLS |
| Full CMC | `POST /fullcmc` | Complex enrollment via RFC 5272 CMC |

Server-side key generation (`/serverkeygen`) and CSR attribute advertisement
(`/csrattrs`) are in active development.

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

**GSSAPI/Kerberos** — for enterprise SSO environments. Protocol structure is
in place (SPNEGO, channel binding, principal mapping); FFI integration with
libgssapi is planned.

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

The architecture is a Cargo workspace with six crates:

```
                      Clients
                        |
                   TLS + mTLS/OTP
                        |
                +-------+-------+
                |   kipuka-est  |     axum routes, EST protocol
                +---+---+---+---+
                    |   |   |
          +---------+   |   +---------+
          |             |             |
     kipuka-otp    kipuka-hsm    kipuka-util
     OTP lifecycle  PKCS#11      shared types
                    HSM ops         & config
          |             |
          |        kipuka-dogtag
          |         Dogtag PKI
          |         REST client
          |
     +----+----+       kipuka-coap
     |   sqlx  |       CoAP transport
     | sqlite  |       (planned)
     | postgres|
     | mariadb |
     +---------+
```

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
- Certificate enrollment and renewal (simpleenroll, simplereenroll)
- Full CMC enrollment (RFC 5272)
- STAR short-term auto-renewal state machine (RFC 8739)
- Multi-CA with four HA failover strategies
- PKCS#11 HSM integration (Entrust, Utimaco, Thales, Kryoptic)
- Dogtag PKI REST client with multi-instance pooling
- OTP authentication with timing-safe validation and rate limiting
- mTLS client certificate authentication
- SQLite, PostgreSQL, and MariaDB backends
- NIAP-compliant structured audit logging
- Admin API for OTP provisioning and CA management
- PatternFly web dashboard

**In progress:**
- Server-side key generation (`/serverkeygen`) with KRA integration
- PKCS#7 SignedData encoding for `/cacerts` responses
- CSR self-signature verification and proof-of-possession linking
- GSSAPI/Kerberos authentication via libgssapi FFI

**Planned:**
- OCSP responder
- CoAP transport for constrained devices (RFC 7252)
- Post-quantum signing (ML-DSA via FIPS 204)
- Certificate transparency log submission

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
