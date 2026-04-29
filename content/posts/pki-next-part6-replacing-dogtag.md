---
title: "PKI.Next Part 6: Replacing Dogtag PKI"
date: 2026-05-09
draft: true
tags: ["pki", "dogtag", "freeipa", "migration", "rust", "java", "security", "pki-next"]
description: "What twenty years of operating Dogtag PKI taught us about building its replacement, the compatibility proxy that makes migration possible, and the architectural bets that will define the next twenty years of certificate management."
mermaid: true
series: ["PKI.Next"]
---

[Dogtag PKI](https://www.dogtagpki.org/) has been Red Hat's Certificate Authority since 2005. It started as Netscape Certificate Management System, became Red Hat Certificate System, was open-sourced as Dogtag, and is now the CA backend for [FreeIPA](https://www.freeipa.org/) --- Red Hat's identity management platform that manages certificates, Kerberos, DNS, and SUDO for enterprise Linux environments.

Dogtag works. It has passed Common Criteria evaluations. It runs in government agencies, financial institutions, and large enterprises. It has issued millions of certificates in production.

But Dogtag is also twenty years old. And twenty years of accumulated decisions are becoming increasingly difficult to evolve. This final post in the series explains why we built PKI.Next as a replacement, how the compatibility proxy enables migration without disruption, and what the transition reveals about building infrastructure software for the long term.

## What Dogtag Got Right

Before discussing what needs to change, it is worth acknowledging what Dogtag does well:

**Comprehensive profile system.** Dogtag's certificate profiles are fully declarative XML configurations that control every aspect of certificate issuance: key usage, extensions, validity, naming constraints, and approval workflows. The profile system is powerful enough to encode complex CA policies without code changes.

**Robust PKCS#11 integration.** Dogtag uses Mozilla NSS for all cryptographic operations, accessed through JSS (Java Security Services). NSS has deep PKCS#11 support, including FIPS 140-2 validation (via the `nss-softokn` FIPS module). This is battle-tested infrastructure.

**Enterprise authentication.** Dogtag supports certificate-based authentication, LDAP integration, and SPNEGO/Kerberos out of the box. It integrates with Red Hat Directory Server for user and group management.

**FreeIPA integration.** Dogtag is the CA half of FreeIPA's IPA-CA subsystem. certmonger, the certificate renewal daemon, speaks Dogtag's API natively. IPA's `ipa cert-request` and `ipa cert-show` commands translate to Dogtag REST calls.

These are genuine strengths, and PKI.Next had to match or exceed them to be a credible replacement.

## What Needs to Change

The challenges are not bugs --- they are architectural decisions from 2004 that create friction in 2026:

### Java Serialization in the Request Pipeline

Dogtag uses Java object serialization for internal message passing between subsystems. This was a reasonable choice in 2004 when Java serialization was the standard approach for Java IPC. Today, it is a security liability (Java deserialization vulnerabilities are a [well-documented attack class](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)) and a maintenance burden (serialized formats are tightly coupled to class hierarchies, making refactoring risky).

PKI.Next uses JSON for all API communication and protobuf-style serialization for internal state, with no language-specific serialization.

### NSS/JSS/PKCS#11 Layering

Dogtag's crypto stack has three layers:

{{< mermaid >}}
graph TB
    subgraph "Dogtag Crypto Stack"
        dogtag_app["Dogtag Application Code<br/><i>Java</i>"]
        jss["JSS (Java Security Services)<br/><i>Java → C JNI bridge</i>"]
        nss["Mozilla NSS<br/><i>C library</i>"]
        pkcs11["PKCS#11 Module<br/><i>SoftHSM / Hardware HSM</i>"]
    end

    dogtag_app --> jss
    jss --> nss
    nss --> pkcs11

    style jss fill:#fff3cd
    style nss fill:#fff3cd
{{< /mermaid >}}

When an HSM operation fails, the error propagates through PKCS#11 → NSS (C error code) → JNI bridge (mapped to Java exception) → JSS (wrapped in JSS-specific exception) → Dogtag (caught and logged). By the time the operator sees the error, the original PKCS#11 return code has been translated three times, and the diagnostic information needed to fix the problem is often lost.

PKI.Next has one layer:

{{< mermaid >}}
graph TB
    subgraph "PKI.Next Crypto Stack"
        pki_app["CA Application Code<br/><i>Rust</i>"]
        cryptoki["cryptoki<br/><i>Rust PKCS#11 bindings</i>"]
        pkcs11_2["PKCS#11 Module<br/><i>Kryoptic / Hardware HSM</i>"]
    end

    pki_app --> cryptoki
    cryptoki --> pkcs11_2
{{< /mermaid >}}

`cryptoki` is a direct Rust FFI binding to the PKCS#11 C interface. Errors are PKCS#11 return codes, mapped to Rust `Result` types with the original CKR code preserved. One translation, one error type, one log line that tells you what happened.

### Container Hostility

Dogtag is deployed as a Tomcat web application. It expects:
- A writable `/var/lib/pki/pki-tomcat/` directory with specific subdirectory structure
- An NSS database (certdb) at a fixed path
- systemd for lifecycle management
- Shared filesystem access between replicas for certain HA configurations

Running Dogtag in a container requires emulating all of this: creating the directory structure, initializing the NSS database, generating a server certificate within NSS, and managing Tomcat lifecycle --- all before the CA can start. The `pki-server` CLI tool automates some of this, but it is fundamentally wrapping a design that assumed bare-metal deployment.

PKI.Next is a statically-linked binary that reads a TOML configuration file and connects to PostgreSQL. Container deployment is:

```bash
podman run -d \
    -v /etc/pki/config.toml:/etc/pki-rust/config.toml:ro \
    -v /etc/pki/keys:/etc/pki-rust/keys:ro \
    -e DATABASE_URL=postgresql://pki:pki@db:5432/pki \
    pki-ca-api:latest
```

No directory scaffolding. No database initialization (the `pki-migrate` container handles that). No intermediate certificate generation. The CA reads its config and starts serving.

### Algorithm Agility

Adding a new signing algorithm to Dogtag requires changes across the NSS, JSS, and Dogtag layers. When FIPS 204 (ML-DSA) was standardized, supporting it in Dogtag would require:

1. NSS adding ML-DSA support (or an NSS module that delegates to a PKCS#11 provider with ML-DSA)
2. JSS exposing the NSS ML-DSA APIs to Java
3. Dogtag adding ML-DSA to its algorithm configuration and profile system

Each layer is maintained by a different team with different release cycles. The practical timeline for ML-DSA support in Dogtag is measured in years.

PKI.Next added ML-DSA support in one crate (`pki-crypto`) by implementing the `Signer` trait with the `fips204` Rust crate. The PR touched 4 files. The CA engine, protocol servers, and CLI did not change at all.

## The Compatibility Proxy

Replacing Dogtag in a FreeIPA deployment is not a matter of swapping a binary. FreeIPA's `certmonger`, `ipa-ca-install`, and `ipa cert-*` commands speak Dogtag's specific REST API. Thousands of deployed FreeIPA servers depend on this API continuing to work.

The `pki-dogtag-compat` proxy provides backward compatibility by translating Dogtag API calls to PKI.Next's native API:

{{< mermaid >}}
sequenceDiagram
    participant CM as certmonger<br/>(FreeIPA)
    participant DC as Dogtag Compat<br/>Proxy
    participant CA as PKI.Next<br/>CA API

    CM->>DC: POST /ca/rest/certrequests<br/>(Dogtag XML format)
    DC->>DC: Parse Dogtag request<br/>Map profile: caIPAserviceCert → serverCert<br/>Extract CSR, subject, extensions
    DC->>CA: POST /v1/ca/requests<br/>(PKI.Next JSON format)
    CA-->>DC: { id: "uuid", status: "pending" }
    DC->>CA: POST /v1/ca/agent/requests/{id}/approve
    CA-->>DC: { certificate_serial: "ABC123" }
    DC-->>CM: Dogtag-format XML response<br/>with certificate PEM

    Note over CM: certmonger installs cert<br/>and schedules renewal
{{< /mermaid >}}

The proxy handles:

**Profile translation.** Dogtag profile names are mapped to PKI.Next profile IDs. The Dogtag-compatible profiles are seeded by a database migration, ensuring they have the correct key usage, EKU, and validity settings.

**Request format translation.** Dogtag uses an XML-heavy request format with Dogtag-specific fields (`requestType`, `requestor_name`, `profileId`). The proxy extracts the PEM-encoded CSR and relevant metadata, constructs a PKI.Next JSON request, and forwards it.

**Response format translation.** PKI.Next returns JSON with certificate PEM. The proxy wraps this in Dogtag's expected XML response format, including the fields that certmonger checks (certificate serial, status, requestId).

**Certificate retrieval.** Dogtag's `GET /ca/rest/certs/{serial}` returns a specific XML structure. The proxy translates from PKI.Next's `GET /v1/ca/certs/{serial}` JSON response.

### What the Proxy Does Not Do

The proxy is a translation layer, not an emulation layer. It does not implement:

- Dogtag's admin console (CLI/web UI for managing the Dogtag instance itself)
- Dogtag's internal subsystem architecture (CA, KRA, OCSP, TKS, TPS as separate Tomcat webapps)
- Dogtag's LDAP-based configuration storage
- Dogtag's clone/replica provisioning

These are operational aspects of Dogtag that do not affect certificate issuance. FreeIPA's certificate operations --- request, approve, retrieve, revoke, renew --- go through the REST API that the proxy implements.

## Migration Path

A FreeIPA deployment can migrate from Dogtag to PKI.Next in phases:

{{< mermaid >}}
graph TB
    subgraph "Phase 1: Parallel Operation"
        ipa1["FreeIPA Server"]
        dogtag1["Dogtag CA<br/><i>(existing, primary)</i>"]
        pkinext1["PKI.Next + Compat Proxy<br/><i>(shadow, monitoring)</i>"]
    end

    subgraph "Phase 2: Switchover"
        ipa2["FreeIPA Server"]
        pkinext2["PKI.Next + Compat Proxy<br/><i>(primary)</i>"]
        dogtag2["Dogtag CA<br/><i>(standby)</i>"]
    end

    subgraph "Phase 3: Native Integration"
        ipa3["FreeIPA Server<br/><i>(native PKI.Next client)</i>"]
        pkinext3["PKI.Next CA<br/><i>(no compat proxy)</i>"]
    end

    ipa1 --> dogtag1
    ipa1 -.->|"mirror requests"| pkinext1
    
    ipa2 --> pkinext2
    ipa2 -.->|"fallback"| dogtag2

    ipa3 --> pkinext3

    style dogtag1 fill:#e3f2fd
    style pkinext1 fill:#e8f5e9
    style pkinext2 fill:#e8f5e9
    style dogtag2 fill:#f5f5f5
    style pkinext3 fill:#e8f5e9
{{< /mermaid >}}

**Phase 1: Parallel operation.** Deploy PKI.Next alongside Dogtag. Mirror certificate requests to both CAs. Compare issuance results. This validates that the compatibility proxy produces identical certificates to Dogtag for the same CSRs and profiles.

**Phase 2: Switchover.** Point FreeIPA's CA URL at the Dogtag compat proxy. certmonger and ipa-cert commands now go through PKI.Next. Dogtag remains available as a fallback. Monitor for any API compatibility gaps.

**Phase 3: Native integration.** Once PKI.Next is stable as the primary CA, FreeIPA can be updated to speak PKI.Next's native API directly, removing the compatibility proxy. This phase is optional --- the proxy adds minimal overhead and can remain indefinitely.

The key advantage of this approach is that **no FreeIPA code changes are required for Phase 1 and Phase 2**. The proxy is transparent to certmonger and the IPA CLI. Phase 3 requires FreeIPA code changes, but those changes can be developed and tested at leisure, without the pressure of a production migration timeline.

## What Twenty Years Teaches You

Building a replacement for Dogtag is not primarily a technical challenge. The code is the easy part. The hard part is internalizing the lessons that twenty years of production operation have taught:

### Audit Trails Are Non-Negotiable

Dogtag logs every operation to a signed audit log. This is not optional, not configurable, and not something operators can turn off. When a security incident occurs, the audit log is the authoritative record of what happened.

PKI.Next adopted this philosophy from day one. The HMAC-chained audit log (Part 4) is not a feature --- it is a structural constraint. Every code path that modifies state must produce an audit event, and every audit event must be chained.

### Profiles Are Policy, Not Configuration

Dogtag's certificate profiles encode organizational policy: what key types are acceptable, what extensions are required, what validity periods are permitted, what approval workflow applies. Changing a profile is a policy decision, not a configuration change.

PKI.Next's 26 built-in profiles encode the same level of policy detail. The profile API requires RBAC authorization. Profile changes are audit-logged. Profiles can be disabled but not silently modified.

### HSM Support Is Not Optional

Every production CA of any consequence uses an HSM. Dogtag's NSS integration, despite its complexity, exists because HSM support is a hard requirement for any CA that handles real certificates.

PKI.Next's PKCS#11 support is not a "nice to have" feature behind a flag. It is a core integration tested in CI with Kryoptic, exercised by every test that touches signing operations when the `pkcs11` feature is enabled.

### Backward Compatibility Is a Feature

Dogtag maintains backward compatibility with client APIs across major versions. FreeIPA code that was written a decade ago still works against current Dogtag. This is not an accident --- it is a deliberate design decision that reflects the reality of enterprise infrastructure: you cannot force all consumers to upgrade simultaneously.

The Dogtag compatibility proxy embodies the same principle for the transition to PKI.Next. Existing FreeIPA deployments do not need to change. New deployments can choose between the compatibility API and the native API. The proxy is not a hack --- it is a respect for the installed base.

## The Architecture Bets

Every long-lived system is built on a set of architectural bets --- decisions that are easy to make today but expensive to change later. PKI.Next's bets are:

**Rust will outlast Java in infrastructure software.** Java is not going away, but the trend in infrastructure (systemd, containerd, Kubernetes components, curl, PostgreSQL) is toward memory-safe systems languages. Rust offers the safety guarantees of Java without the runtime overhead.

**PKCS#11 will remain the HSM interface.** Despite its age and quirks, PKCS#11 is the universal HSM API. Every hardware HSM vendor supports it. PKCS#11 v3.2 added post-quantum algorithms. There is no credible replacement on the horizon.

**Containers are the deployment model.** Bare-metal PKI deployments will continue to exist, but the dominant deployment model for new infrastructure is containers orchestrated by Kubernetes, Podman Compose, or similar systems. Building for containers from day one avoids the retrofit problem that Dogtag faces.

**Protocol diversity will increase.** Ten years ago, the CA needed to support one protocol. Today, it needs six. In ten years, there will be more. The RA pattern (protocol servers as independent binaries communicating with the CA through a typed API) scales to any number of protocols without architectural changes.

**Post-quantum cryptography is not optional.** CAs issue certificates with multi-year validity periods. A CA deployed today must support algorithms that will remain secure for the lifetime of the certificates it issues. ML-DSA support is an investment in future-proofing, not a checkbox feature.

## The Series So Far

This series covered the major features and design decisions in PKI.Next:

| Part | Topic | Key Insight |
|---|---|---|
| [Part 1](/posts/pki-next-part1-building-ca-in-rust/) | Architecture | 23 crates, 7 binaries, RA pattern for protocol isolation |
| [Part 2](/posts/pki-next-part2-post-quantum-certificates/) | Post-Quantum | ML-DSA-44/65/87 via software and PKCS#11, with TLS compatibility workarounds |
| [Part 3](/posts/pki-next-part3-fips-and-hsm/) | FIPS & HSM | Compile-time backend selection via feature flags and trait objects |
| [Part 4](/posts/pki-next-part4-tamper-evident-audit/) | Audit | HMAC hash-chained logs for tamper detection, timestamp precision lesson |
| [Part 5](/posts/pki-next-part5-protocol-servers/) | Protocols | EST, ACME, CoAP, SPIFFE, Vault, Dogtag from one CA |
| [Part 6](/posts/pki-next-part6-replacing-dogtag/) | Migration | Compatibility proxy for zero-disruption Dogtag replacement |

Together, they describe a CA built to handle the requirements of the next decade: post-quantum algorithms, container-native deployment, protocol diversity, and compliance-grade audit trails --- while maintaining backward compatibility with the infrastructure of the last decade.

---

*If you are interested in the project or have questions about the architecture, feel free to reach out.*

*The earlier posts in this blog cover [OCSP vs CRL sharding performance](/posts/ocsp-vs-crl-sharding-performance/), [event-driven certificate lifecycle management](/posts/event-driven-certificate-revocation-lab/), and [Dogtag PKI IoT profiles with Ansible](/posts/dogtag-pki-iot-profiles-ansible/).*
