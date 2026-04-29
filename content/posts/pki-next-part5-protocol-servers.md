---
title: "PKI.Next Part 5: One CA, Six Protocols"
date: 2026-05-07
draft: true
tags: ["pki", "est", "acme", "coap", "spiffe", "certificates", "security", "protocols", "pki-next"]
description: "How PKI.Next serves EST, ACME, CoAP, SPIFFE/SPIRE, HashiCorp Vault, and Dogtag compatibility from a single CA using the Registration Authority pattern — and why protocol diversity is the future of PKI."
series: ["PKI.Next"]
---

A Certificate Authority that only speaks one protocol is a CA that only serves one audience. Enterprise networks need EST for managed devices. DevOps teams expect ACME for automated renewal. IoT deployments require CoAP for constrained devices. Kubernetes clusters want SPIFFE for workload identity. HashiCorp shops need Vault integration. And existing Red Hat infrastructure needs Dogtag compatibility.

PKI.Next serves all six from a single CA, using independent protocol server binaries that communicate with the CA through mTLS-authenticated API calls. This post explains the architecture, the protocol implementations, and why the Registration Authority pattern makes this possible without compromising security.

## The Registration Authority Pattern

The architectural foundation is the Registration Authority (RA) pattern from RFC 4210. In traditional PKI, a Registration Authority is a delegate that accepts certificate requests, performs validation, and forwards approved requests to the CA for signing. The RA never touches the CA's private key.

PKI.Next extends this pattern to every enrollment protocol:

{{< mermaid >}}
graph TB
    subgraph "Client Devices"
        browser["Browser / CLI<br/><i>ACME client</i>"]
        router["Router / Switch<br/><i>EST client</i>"]
        sensor["IoT Sensor<br/><i>CoAP/DTLS client</i>"]
        pod["Kubernetes Pod<br/><i>SPIFFE workload</i>"]
        vault_client["Vault Consumer<br/><i>vault read pki/issue</i>"]
        ipa["FreeIPA Server<br/><i>certmonger</i>"]
    end

    subgraph "Protocol Servers (DMZ / Edge)"
        acme["ACME Server<br/><i>RFC 8555</i><br/>Port 8448"]
        est["EST Server<br/><i>RFC 7030</i><br/>Port 8445"]
        coap["CoAP Server<br/><i>RFC 9148</i><br/>Port 5684"]
        spire["SPIRE Server<br/><i>SPIFFE</i><br/>Unix Socket"]
        vault_srv["Vault Server<br/><i>Key Escrow</i><br/>Port 8200"]
        dogtag["Dogtag Compat<br/><i>API Proxy</i><br/>Port 8080"]
    end

    subgraph "CA Core (Secure Zone)"
        ca["CA API Server<br/><i>Port 8443</i>"]
        hsm["Signing Key<br/><i>PKCS#11 / Software</i>"]
        db["PostgreSQL"]
    end

    browser --> acme
    router --> est
    sensor --> coap
    pod --> spire
    vault_client --> vault_srv
    ipa --> dogtag

    acme -->|"mTLS"| ca
    est -->|"mTLS"| ca
    coap -->|"mTLS"| ca
    spire -->|"mTLS"| ca
    vault_srv -->|"mTLS"| ca
    dogtag -->|"mTLS"| ca

    ca --> hsm
    ca --> db

    style ca fill:#e8f5e9
    style hsm fill:#ffcdd2
{{< /mermaid >}}

Each protocol server is a standalone binary with its own process, port, and failure domain. They share nothing except the `pki-ra-client` library, which provides a typed Rust client for the CA's REST API. The CA API is the only component that holds the signing key and accesses the certificate database.

This separation has concrete security benefits:

1. **Blast radius containment.** A vulnerability in the ACME server (which is internet-facing) cannot access the signing key. The attacker can submit certificate requests, but they are subject to the same validation and approval policies as any legitimate request.

2. **Independent scaling.** The ACME server handles bursty traffic from Let's Encrypt-style automated renewals. The EST server handles steady-state enterprise enrollment. They scale independently without competing for the CA's resources.

3. **Network segmentation.** Protocol servers can be deployed in a DMZ, on edge nodes, or in different data centers. The only network path to the CA is the mTLS-authenticated API connection.

4. **Protocol isolation.** A bug in CoAP's blockwise transfer implementation cannot affect ACME's order processing. Each protocol server has its own codebase, dependencies, and attack surface.

## The RA Client

Every protocol server uses `pki-ra-client` to communicate with the CA. The client authenticates using mTLS --- each protocol server has its own client certificate signed by the CA:

```toml
# Protocol server configuration
[ra]
ca_url = "https://ca-api.internal:8443"
client_cert = "/etc/pki/ra/ra-cert.pem"
client_key = "/etc/pki/ra/ra-key.pem"
ca_cert = "/etc/pki/ra/ca-cert.pem"
```

The RA client provides typed methods for CA operations:

```rust
// Submit a certificate request
let response = ra_client.submit_request(
    &csr_pem,
    "serverCert",     // profile ID
    metadata,          // device info, requestor
).await?;

// Auto-approve (for auto-enrollment profiles)
let cert = ra_client.approve_request(&request_id).await?;
```

For profiles configured with `auth_method = "auto"`, the protocol server can submit and approve in one step. For agent-approved profiles, the protocol server submits the request and the certificate is issued only after an agent approves it through the dashboard or CLI.

## EST: Enterprise Device Enrollment

[EST (Enrollment over Secure Transport, RFC 7030)](https://www.rfc-editor.org/rfc/rfc7030) is the standard protocol for managed device enrollment in enterprise networks. It runs over HTTPS and provides:

{{< mermaid >}}
sequenceDiagram
    participant Device as Network Device
    participant EST as EST Server
    participant CA as CA API

    Note over Device,EST: TLS with optional client cert

    Device->>EST: GET /cacerts
    EST->>CA: GET /v1/ca/chain
    CA-->>EST: CA certificate chain
    EST-->>Device: PKCS#7 CA certs

    Device->>EST: GET /csrattrs
    EST-->>Device: Required CSR attributes

    Device->>EST: POST /simpleenroll
    Note over EST: Parse PKCS#10 CSR from PKCS#7 wrapper
    EST->>CA: POST /v1/ca/requests (CSR + profile)
    CA->>CA: Policy check, sign certificate
    CA-->>EST: Signed certificate
    EST-->>Device: PKCS#7-wrapped certificate

    Note over Device: Certificate installed

    Device->>EST: POST /simplereenroll
    Note over Device,EST: Re-enrollment uses existing cert for auth
    EST->>CA: POST /v1/ca/requests (new CSR)
    CA-->>EST: New certificate
    EST-->>Device: PKCS#7-wrapped new certificate
{{< /mermaid >}}

EST is the protocol of choice for network equipment (Cisco, Juniper, Arista), MDM-managed devices, and enterprise workstations. It is simpler than CMC (RFC 5272) and better supported than SCEP in modern devices.

PKI.Next's EST server implements:
- `/cacerts` --- CA certificate distribution (PKCS#7)
- `/csrattrs` --- CSR attribute requirements
- `/simpleenroll` --- Initial enrollment
- `/simplereenroll` --- Certificate renewal with existing credential

Rate limiting is applied at 10 requests per second sustained, 30 burst --- sufficient for enterprise enrollment but protective against abuse.

## ACME: Automated Certificate Management

[ACME (RFC 8555)](https://www.rfc-editor.org/rfc/rfc8555) is the protocol that powers Let's Encrypt. It automates the entire certificate lifecycle: account creation, domain validation, certificate issuance, and renewal.

PKI.Next's ACME server goes beyond basic RFC 8555 with Multi-Perspective Issuance Corroboration (MPIC):

{{< mermaid >}}
graph TB
    subgraph "ACME Order Flow"
        order["1. Client creates order<br/><code>POST /acme/new-order</code>"]
        authz["2. Server returns authorizations<br/><i>DNS-01 or HTTP-01 challenge</i>"]
        challenge["3. Client provisions challenge<br/><i>DNS TXT record or HTTP token</i>"]
        validate["4. Server validates from multiple vantage points"]
        finalize["5. Client submits CSR<br/><code>POST /acme/finalize</code>"]
        cert["6. Server returns certificate<br/><code>GET /acme/cert</code>"]
    end

    subgraph "MPIC Validation"
        na["North America<br/>ARIN"]
        eu["Europe<br/>RIPE NCC"]
        ap["Asia-Pacific<br/>APNIC"]
        la["Latin America<br/>LACNIC"]
        af["Africa<br/>AFRINIC"]
    end

    order --> authz --> challenge --> validate --> finalize --> cert
    validate --> na
    validate --> eu
    validate --> ap
    validate --> la
    validate --> af

    style validate fill:#fff3cd
{{< /mermaid >}}

MPIC validates domain control from multiple geographic vantage points across all five Regional Internet Registries (RIRs). This defends against BGP hijacking attacks where an adversary reroutes traffic for a specific IP prefix to intercept domain validation challenges. If an attacker controls only one network path, at least some MPIC vantage points will see the legitimate server, causing validation to fail.

The MPIC client supports configurable quorum policies --- you can require validation from all 5 regions, or from any 3 of 5, depending on your risk tolerance and availability requirements.

The ACME server stores order state in PostgreSQL, supporting the full ACME state machine (pending, ready, processing, valid, invalid, expired) with proper transitions and cleanup of expired orders.

## CoAP: Constrained IoT Devices

[EST over CoAP (RFC 9148)](https://www.rfc-editor.org/rfc/rfc9148) adapts EST for constrained devices that cannot afford the overhead of HTTP/TLS. CoAP (Constrained Application Protocol) runs over UDP with DTLS 1.2 for security, and uses blockwise transfer (RFC 7959) to handle large payloads over constrained links.

{{< mermaid >}}
sequenceDiagram
    participant Sensor as IoT Sensor<br/>(Class 2 device)
    participant CoAP as CoAP/DTLS Server
    participant CA as CA API

    Note over Sensor,CoAP: DTLS 1.2 handshake<br/>(UDP, not TCP)

    Sensor->>CoAP: GET /est/crts (Block2)
    Note over Sensor,CoAP: Large CA cert transferred<br/>in 256-byte blocks
    CoAP->>CA: GET /v1/ca/chain
    CA-->>CoAP: CA chain (PEM)
    CoAP-->>Sensor: CBOR-encoded CA certs<br/>(Block2 transfer)

    Sensor->>CoAP: POST /est/sen (Block1)
    Note over Sensor,CoAP: CSR uploaded in blocks
    CoAP->>CA: POST /v1/ca/requests
    CA-->>CoAP: Signed certificate
    CoAP-->>Sensor: CBOR-encoded cert<br/>(Block2 transfer)
{{< /mermaid >}}

The CoAP server is purpose-built for environments where:

- **Bandwidth is scarce.** NB-IoT and LoRaWAN links have per-message costs. CoAP's binary format and compact headers use a fraction of HTTP's overhead.
- **TCP is unavailable.** Many IoT radios support only UDP. CoAP runs natively over UDP with reliability handled at the application layer.
- **Memory is limited.** Class 2 constrained devices (RFC 7228) have ~50 KB RAM. Blockwise transfer lets them process certificates in small chunks without buffering the entire payload.

The blockwise transfer handler manages reassembly of multi-block requests and responses, with stale buffer cleanup to prevent memory exhaustion from abandoned transfers.

A separate HTTP health check endpoint runs on a sideband port, allowing container orchestrators (Kubernetes, Podman) to monitor the CoAP server's health without speaking CoAP/DTLS.

## SPIFFE/SPIRE: Workload Identity

[SPIFFE (Secure Production Identity Framework for Everyone)](https://spiffe.io/) defines a standard for workload identity in dynamic environments like Kubernetes. Instead of static certificates tied to hostnames, SPIFFE assigns cryptographic identities based on workload attributes:

```
spiffe://example.com/ns/production/sa/payment-service
```

PKI.Next's SPIRE server implements two types of identity documents:

{{< mermaid >}}
graph TB
    subgraph "SPIRE Server"
        reg["Registration Entries<br/><i>SPIFFE ID ↔ selector mapping</i>"]
        x509["X.509-SVID Issuer<br/><i>Via CA API (mTLS)</i>"]
        jwt["JWT-SVID Issuer<br/><i>Local Ed25519 key</i>"]
        mgmt["Management API<br/><i>Entry CRUD</i>"]
    end

    subgraph "Workload API (Unix Socket)"
        fetch_x509["FetchX509SVID<br/><i>Returns cert + key</i>"]
        fetch_jwt["FetchJWTSVID<br/><i>Returns signed JWT</i>"]
        fetch_bundle["FetchJWTBundles<br/><i>Trust bundle</i>"]
        validate["ValidateJWTSVID<br/><i>Verify JWT</i>"]
    end

    subgraph "Kubernetes"
        pod1["Pod A<br/><i>payment-service</i>"]
        pod2["Pod B<br/><i>order-service</i>"]
    end

    pod1 -->|"Unix socket"| fetch_x509
    pod2 -->|"Unix socket"| fetch_jwt
    reg --> x509
    reg --> jwt
    x509 -->|"mTLS"| CA["CA API"]
    mgmt --> reg

    style CA fill:#e8f5e9
{{< /mermaid >}}

**X.509-SVIDs** are short-lived certificates (typically 1 hour) that embed the SPIFFE ID as a URI SAN. The SPIRE server issues these through the CA API, using the full certificate profile and policy engine. This means workload certificates go through the same issuance pipeline as any other certificate --- same audit trail, same profile constraints, same RBAC.

**JWT-SVIDs** are signed JWTs for service-to-service authentication where X.509 is impractical. The SPIRE server signs these locally with an Ed25519 key, not through the CA API, because JWT issuance needs to be fast (sub-millisecond) and does not require the same audit chain as X.509 certificates.

Registration entries map SPIFFE IDs to workload selectors:

```bash
rs-pki spiffe register \
    --spiffe-id spiffe://example.com/ns/prod/sa/api \
    --selector k8s:pod-label:app=api-server \
    --dns-name api.prod.svc.cluster.local
```

Rate limiting (20 req/s sustained, 50 burst) prevents a compromised workload from overwhelming the SPIRE server with identity requests.

## Vault: Key Escrow and Certificate Issuance

The Vault protocol server provides a HashiCorp Vault-compatible API for organizations that use Vault as their secrets management layer. Rather than replacing Vault, it integrates PKI.Next as a backend:

{{< mermaid >}}
sequenceDiagram
    participant App as Application
    participant Vault as Vault Server<br/>(PKI.Next)
    participant CA as CA API

    App->>Vault: vault write pki/issue/web-server<br/>common_name=app.example.com
    Vault->>CA: POST /v1/ca/requests (CSR)
    CA-->>Vault: Signed certificate
    Vault-->>App: Certificate + Private Key

    App->>Vault: vault write transit/keys/app-key<br/>type=ecdsa-p256
    Vault->>Vault: Generate key, encrypt with AES-GCM
    Vault-->>App: Key metadata

    App->>Vault: vault write transit/sign/app-key<br/>input=base64data
    Vault->>Vault: Decrypt key, sign data
    Vault-->>App: Signature
{{< /mermaid >}}

The Vault server also provides key escrow: generating, encrypting (AES-GCM), and archiving private keys for recovery. This supports compliance scenarios where key recovery is mandated (e.g., S/MIME encryption certificates where a departing employee's email must remain readable).

## Dogtag Compatibility: The Migration Bridge

The most unusual protocol server is `pki-dogtag-compat` --- a translation proxy that accepts Dogtag PKI's REST API format and forwards requests to PKI.Next's native API. This exists for exactly one reason: FreeIPA.

{{< mermaid >}}
graph LR
    subgraph "FreeIPA Server"
        certmonger["certmonger<br/><i>cert renewal daemon</i>"]
        ipa_cert["ipa-cert CLI<br/><i>cert management</i>"]
    end

    subgraph "Dogtag Compat Proxy"
        translate["API Translation<br/><i>Dogtag REST → PKI.Next</i>"]
        profile_map["Profile Mapping<br/><i>caIPAserviceCert → serverCert</i>"]
    end

    subgraph "PKI.Next CA"
        api["CA API"]
    end

    certmonger -->|"Dogtag REST API"| translate
    ipa_cert -->|"Dogtag REST API"| translate
    translate --> profile_map
    profile_map -->|"Native API"| api

    style translate fill:#fff3cd
{{< /mermaid >}}

FreeIPA uses Dogtag PKI as its CA backend and speaks Dogtag's specific REST API dialect. Replacing Dogtag in a FreeIPA deployment means either modifying FreeIPA (a multi-year effort across a large codebase) or providing a compatibility layer that speaks Dogtag's protocol while using PKI.Next's engine.

The compatibility proxy translates:
- Dogtag profile names (e.g., `caIPAserviceCert`) to PKI.Next profile IDs
- Dogtag request format (XML-heavy, with Dogtag-specific fields) to PKI.Next JSON
- Dogtag response format back to what FreeIPA expects

The Dogtag-compatible profiles are seeded by database migration:

| Dogtag Profile | PKI.Next Profile | Purpose |
|---|---|---|
| `caCACert` | CA certificate | Intermediate CA issuance |
| `caOCSPCert` | OCSP signing | OCSP responder identity |
| `caCRLSigningCert` | CRL signing | CRL signing delegation |
| `caStorageCert` | Key escrow | Key recovery (ML-KEM hybrid) |
| `caAgentCert` | Agent authentication | RA/agent operations |
| `caRouterCert` | Router/gateway | Network device identity |

This is not a permanent solution --- it is a migration bridge. The goal is for FreeIPA to eventually speak PKI.Next's native API. But the bridge lets existing FreeIPA deployments switch to PKI.Next without any FreeIPA-side changes, which removes the chicken-and-egg problem of migrating infrastructure that is tightly coupled.

## Protocol Server Management

All protocol servers are managed through the CA dashboard and CLI:

```bash
# Register a new EST server
rs-pki server register \
    --name "est-dmz-01" \
    --type est \
    --base-url https://est.dmz.example.com:8445 \
    --health-endpoint /healthz

# Configure enrollment profile
rs-pki server config set est-dmz-01 \
    --enrollment-profile serverCert \
    --require-client-cert true \
    --listen-port 8445

# Health check
rs-pki server health-check est-dmz-01

# Generate deployment artifacts
rs-pki server deploy est-dmz-01 --format compose    # Docker Compose
rs-pki server deploy est-dmz-01 --format quadlet    # Systemd Quadlet
rs-pki server deploy est-dmz-01 --format ansible    # Ansible playbook
```

The deployment artifact generation is particularly useful: the CA knows the server's configuration, certificates, and network requirements, so it can generate a complete deployment manifest without the operator having to assemble it manually.

## Why Protocol Diversity Matters

The trend in PKI is clear: certificate consumers are fragmenting. Ten years ago, certificates were primarily for web servers, and one protocol (manual CSR submission) was sufficient. Today:

- Web servers use ACME for automated renewal
- Enterprise devices use EST or SCEP for managed enrollment
- IoT devices need constrained-network protocols like CoAP/DTLS
- Kubernetes workloads expect SPIFFE identities, not hostname-based certificates
- DevOps pipelines integrate through Vault
- Legacy infrastructure speaks Dogtag, EJBCA, or vendor-specific APIs

A CA that only supports one protocol forces every consumer to adapt to that protocol. A CA that supports many protocols lets each consumer use the protocol that fits its operational model. The RA pattern makes this tractable: each protocol server is a translation layer between a wire protocol and the CA's API, and the CA does not need to know which protocol originated the request.

---

*Next in the series: [Part 6: Replacing Dogtag PKI](/posts/pki-next-part6-replacing-dogtag/) --- the migration path from twenty years of Java-based PKI to a Rust-based replacement, and what Dogtag teaches us about building for the next twenty years.*

*Previous: [Part 4: Tamper-Evident Audit Logs](/posts/pki-next-part4-tamper-evident-audit/)*
