---
title: "Event-Driven Certificate Lifecycle Management with Ansible"
date: 2026-02-12
draft: false
tags: ["pki", "zero-trust", "ansible", "certificates", "security", "iot", "identity", "hummingbird", "ubi", "containers", "post-quantum"]
description: "Automating the full certificate lifecycle — from issuance to revocation — using Event-Driven Ansible, Dogtag PKI, FreeIPA, UBI minimal containers, and post-quantum ML-DSA-87 certificates in an industry moving toward CRL-based revocation and 47-day cert lifetimes."
---

Every certificate has a lifecycle: issuance, renewal, and eventually revocation. In most organizations, that lifecycle is managed through tickets, spreadsheets, and manual intervention. When a device is compromised or an employee leaves, revoking their certificate takes hours or days. Meanwhile, the identity tied to that certificate remains trusted across the network.

The industry is making this worse, not better. The CA/Browser Forum passed [Ballot SC-081v3](https://cabforum.org/2025/04/11/ballot-sc-081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/) in April 2025, mandating a reduction in public certificate validity to 200 days (March 2026), 100 days (March 2027), and 47 days (March 2029). At the same time, OCSP — the protocol most organizations rely on for real-time revocation checking — is being deprecated across the industry. Let's Encrypt [shut down its OCSP responders](https://letsencrypt.org/2025/01/30/ocsp-service-is-being-turned-off/) in August 2025 after handling 340 billion requests per month at peak. Firefox replaced OCSP with CRLite as of Firefox 137. HARICA is deprecating OCSP by March 2026. The safety nets are disappearing and the timelines are compressing. Manual certificate management is no longer just slow — it is structurally incompatible with where the industry is heading.

This post walks through an open-source lab I built that ties certificate lifecycle directly to identity events. When an identity changes state — a device is flagged, a user is offboarded, an IoT sensor behaves anomalously — the certificate follows automatically.

## Certificates Are Identity

This is the foundational point that gets lost in most PKI discussions. A certificate is not just an encryption artifact. It is a **machine-readable identity assertion**. When a device presents a certificate to authenticate, it is saying "I am this identity, and a trusted authority vouches for me."

That means certificate lifecycle management *is* identity lifecycle management:

- **Provisioning a device** = issuing a certificate
- **Rotating credentials** = renewing a certificate
- **Decommissioning a device** = revoking a certificate
- **Offboarding a user** = revoking their client certificate

When these two lifecycles are decoupled — when identity changes happen in one system and certificate changes happen in another — gaps appear. Those gaps are where attackers live.

## The Problem: Disconnected Lifecycles

Consider a typical enterprise scenario:

1. An IoT temperature sensor is deployed on the factory floor and issued a client certificate
2. Six months later, the sensor starts exhibiting anomalous behavior — firmware may be compromised
3. The security team flags the device in their EDR platform
4. Someone opens a ticket for the PKI team to revoke the certificate
5. The PKI admin logs into the CA, searches for the certificate, and revokes it
6. Hours have passed. The compromised device has been authenticating to backend services the entire time.

Now multiply this by thousands of IoT devices, hundreds of users, and multiple certificate authorities. The manual approach does not scale. With SC-081v3 driving certificate lifetimes down to 47 days by 2029, steps 4 and 5 become even more absurd — teams that cannot keep up with annual renewals today will be managing renewal cycles that recur every six weeks, while simultaneously handling revocation requests through the same manual queue.

## The Solution: Event-Driven Certificate Lifecycle

The [Certificate Revocation Lab](https://github.com/czinda/cert-revocation-lab) demonstrates a different model: identity events drive certificate actions automatically through Ansible.

```
┌─────────────┐     ┌─────────┐     ┌─────────────┐     ┌─────────────┐
│  Identity   │────▶│  Kafka  │────▶│  Event-     │────▶│  Dogtag     │
│  Event      │     │  Event  │     │  Driven     │     │  PKI        │
│             │     │  Bus    │     │  Ansible    │     │             │
└─────────────┘     └─────────┘     └─────────────┘     └─────────────┘
       │                                   │
       │                                   ▼
┌──────┴──────┐                    ┌─────────────┐
│  Sources:   │                    │  Ansible     │
│  • EDR/XDR  │                    │  Playbooks   │
│  • SIEM     │                    │  • Revoke    │
│  • FreeIPA  │                    │  • Renew     │
│  • HR System│                    │  • Re-issue  │
└─────────────┘                    └─────────────┘
```

The key insight: **Ansible already manages infrastructure.** Most organizations use it for configuration management, patching, and deployment. Extending it to certificate lifecycle means PKI operations use the same language, tooling, and workflows that teams already know.

## Architecture

### Identity-Aware PKI Hierarchy

The lab implements three independent PKI hierarchies, each on its own container network with dedicated 389DS instances and Dogtag CAs:

| Algorithm      | Use Case                          | Key Strength                               |
|----------------|-----------------------------------|--------------------------------------------|
| **RSA-4096**   | Users, servers, legacy devices    | Universal support, well-understood         |
| **ECC P-384**  | IoT devices, mobile, edge compute | Smaller keys, faster operations, low power |
| **ML-DSA-87**  | Post-quantum readiness            | Quantum-resistant (NIST FIPS 204 Level 5)  |

Each hierarchy follows a three-tier structure:

```
Root CA (Offline Trust Anchor)
    │
    └── Intermediate CA (Online Issuing CA)
            │
            ├── IoT Sub-CA (Device Certificates)
            │
            └── EST Sub-CA (Enrollment over Secure Transport)
```

This separation is deliberate:

- **Root CA** stays offline — it is the trust anchor and signs only subordinate CA certificates
- **Intermediate CA** handles day-to-day issuance for users and servers, and can be rotated without disrupting the trust chain
- **IoT Sub-CA** issues constrained, short-lived certificates for devices with tightly scoped key usage and name constraints
- **EST Sub-CA** handles automated device enrollment via the EST protocol (RFC 7030), running on a custom Dogtag build with ML-DSA support in the post-quantum hierarchy

The algorithm choice maps to the identity type. User workstations and servers get RSA certificates for maximum compatibility. IoT devices — sensors, controllers, edge gateways — get ECC certificates because the smaller key size and faster cryptographic operations matter on constrained hardware. The ML-DSA-87 hierarchy provides a concrete post-quantum migration path. NIST finalized [ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) (FIPS 204) and [ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) (FIPS 203) in August 2024 as the first post-quantum cryptographic standards, and the lab includes a full ML-DSA-87 PKI hierarchy — Root CA, Intermediate CA, IoT Sub-CA, and EST Sub-CA — running on a custom Dogtag build. This is not a placeholder; you can issue, revoke, and verify post-quantum certificates through the same event-driven pipeline as RSA and ECC. The EDA rulebook has explicit ML-DSA rules for all 26 event types, routing to PQ-specific revocation playbooks. Organizations can use this to test their post-quantum migration strategy end-to-end before touching production infrastructure.

### FreeIPA: The Identity Source of Truth

FreeIPA serves as the central identity store, tying together:

- **Users**: Employees, contractors, service accounts
- **Hosts**: Servers, workstations, IoT devices
- **Services**: Applications that need machine identity
- **Certificate Profiles**: Rules governing what kind of certificate each identity type receives

When a device is enrolled in FreeIPA, it gets an identity. That identity can be bound to a certificate. When the identity state changes — disabled, deleted, moved to a quarantine group — that change becomes an event that Ansible can act on.

### Event-Driven Ansible: The Automation Engine

Event-Driven Ansible (EDA) is the bridge between "something happened" and "do something about it." It watches event sources — Kafka topics, webhooks, log files — and triggers Ansible playbooks based on rules. AAP 2.6 (released November 2025) expanded EDA's Kafka capabilities with multi-topic subscriptions and wildcard topic matching, so a rulebook can subscribe to `security-events.*` to capture events from multiple sub-topics without modification. EDA job labels allow tagging and filtering automation jobs by event source, making it easier to audit which security events triggered which certificate actions.

Here is the core of the EDA rulebook:

```yaml
# ansible/rulebooks/certificate-lifecycle.yml
- name: Certificate Lifecycle Processor
  hosts: all
  sources:
    - eda.builtin.kafka:
        host: kafka.cert-lab.local
        port: 9092
        topic: security-events

  rules:
    - name: Credential Theft - Revoke RSA Certificate
      condition: >
        event.event_type == "credential_theft" and
        event.severity in ["high", "critical"] and
        (event.pki_type is not defined or event.pki_type == "rsa")
      action:
        run_playbook:
          name: playbooks/dogtag-rsa-revoke-certificate.yml
          extra_vars:
            event: "{{ event }}"
            priority: "high"
            ca_level: "intermediate"

    - name: IoT Device Anomaly - Revoke ECC Certificate
      condition: >
        event.event_type == "device_anomaly" and
        event.pki_type == "ecc"
      action:
        run_playbook:
          name: playbooks/dogtag-ecc-revoke-certificate.yml
          extra_vars:
            event: "{{ event }}"
            ca_level: "iot"

    - name: User Offboarding - Revoke All User Certificates
      condition: >
        event.event_type == "user_offboarded"
      action:
        run_playbook:
          name: playbooks/revoke-user-certificates.yml
          extra_vars:
            event: "{{ event }}"
            revoke_reason: "cessationOfOperation"
```

This is where Ansible shines. The rulebook is readable. A security engineer can look at it and understand the logic without being a developer. The playbooks it calls are standard Ansible — the same tool the team uses for everything else.

### What the Playbooks Do

Each revocation playbook follows the same pattern:

1. **Authenticate** to the correct Dogtag CA instance (RSA or ECC)
2. **Look up the certificate** by the identity's common name or serial number
3. **Revoke** with the appropriate reason code (keyCompromise, cessationOfOperation, affiliationChanged)
4. **Log the action** back to Kafka for audit
5. **Notify** downstream systems (SIEM, ticketing, monitoring)

Because it is Ansible, each step is idempotent. If the playbook runs twice for the same event, nothing breaks. If a step fails, the playbook reports exactly which task failed and why.

## Applying This to IoT Devices

IoT is where event-driven certificate lifecycle management has the most impact. Consider the scale and constraints:

- **Thousands of devices**: A manufacturing plant might have 10,000 sensors, each with a client certificate
- **Constrained hardware**: Many IoT devices cannot perform complex cryptographic operations — ECC's smaller keys and faster signatures are essential
- **Remote locations**: Devices may be deployed in locations where physical access for manual remediation is impractical
- **Autonomous operation**: Devices operate without human supervision, making automated lifecycle management a requirement

### IoT Lifecycle Scenarios

**Device Provisioning via EST**: IoT and OT devices don't enroll through the same workflows as users. They use the Enrollment over Secure Transport (EST) protocol (RFC 7030), which allows devices to automatically request, renew, and re-key certificates over HTTPS. A device boots up, authenticates with a manufacturer-installed credential or bootstrap certificate, and enrolls for a production ECC certificate from the IoT Sub-CA — no human in the loop.

Dogtag PKI and Red Hat Certificate System (RHCS) fully support EST as a native enrollment protocol. This is an important distinction: FreeIPA and IdM are identity management platforms, not enterprise PKI platforms. They handle user and host identity well, but for protocol-level enrollment like EST and ACME, you need the full Dogtag/RHCS stack. RHCS provides the certificate profiles, enrollment policies, and protocol endpoints that IoT and OT environments require.

**Firmware Anomaly**: An EDR agent or network monitor detects the device behaving unexpectedly. An event is published. EDA revokes the device's certificate within seconds, immediately cutting off its access to backend APIs. The device can re-enroll via EST once remediated.

**Fleet Rotation**: A scheduled Ansible playbook triggers certificate renewal across an entire device fleet before expiration. For EST-capable devices, this can also be handled by the devices themselves — EST supports re-enrollment natively, so devices can renew their own certificates without Ansible needing to push to each endpoint.

**Device Decommissioning**: When a device is removed from inventory, its certificate is revoked and added to the CRL automatically.

## Automated Enrollment for Web and Application Servers

IoT devices are not the only systems that benefit from automated enrollment. Web servers and application servers have the same problem — certificates expire, and someone has to renew them. The ACME protocol (RFC 8555), originally developed by Let's Encrypt, solves this for public-facing services. But enterprises need the same automation for internal services.

Dogtag PKI and RHCS support ACME as a built-in enrollment protocol. This means internal web servers, API gateways, load balancers, and application servers can automatically request and renew certificates from your enterprise CA using the same ACME clients (certbot, acme.sh, cert-manager) that teams already use for public certificates.

The combination looks like this:

| Protocol | Target Systems               | Enrollment Model          |
|----------|------------------------------|---------------------------|
| **EST**  | IoT sensors, OT controllers, embedded devices | Device-initiated, mutual TLS bootstrap |
| **ACME** | Web servers, API gateways, application servers | Server-initiated, HTTP/DNS challenge   |
| **CMP**  | Network infrastructure, legacy systems         | Router/switch initiated                |

Each protocol serves a different class of identity, but all feed into the same Dogtag/RHCS CA hierarchy. And all of them produce certificates that are subject to the same event-driven revocation workflow — when a security event fires, EDA revokes the certificate regardless of how it was enrolled.

## Applying This to Users

The same event-driven model works for user certificate lifecycle, though the enrollment path is different. Users typically get certificates through FreeIPA/IdM or direct Dogtag enrollment rather than automated protocols:

**Employee Onboarding**: HR system triggers provisioning. FreeIPA creates the identity. Ansible requests an RSA client certificate and configures the user's workstation for certificate-based authentication.

**Role Change**: An employee moves departments. Their old certificates, scoped to the previous role's access, are revoked. New certificates with updated attributes are issued.

**Offboarding**: The HR system fires an event. EDA revokes all certificates associated with the user's identity — workstation, VPN, email signing — in a single automated action. No waiting for the PKI team to process a ticket.

**Credential Compromise**: A SIEM detects credential theft indicators on a user's workstation. The certificate is revoked immediately. The user re-authenticates through a remediation workflow and receives a new certificate.

## Container Strategy: Project Hummingbird and UBI Minimal

A security-focused lab that manages PKI infrastructure should not be running unnecessarily large base images full of packages it never uses. The lab's container strategy is built on [Project Hummingbird](https://projecthummingbird.io/) images and Red Hat's [Universal Base Image](https://catalog.redhat.com/software/base-images) (UBI) minimal variants, hosted on quay.io.

Project Hummingbird provides community container images built on Fedora and UBI bases, giving the container ecosystem an alternative to Docker Hub's Debian-based official images. The images are minimal by design — they include only what the application needs to run, not a general-purpose Linux distribution.

**Why UBI Minimal matters.** Red Hat's Universal Base Image comes in several variants. The one that matters most for production containers is **UBI Minimal** (`ubi9/ubi-minimal`). It uses `microdnf` instead of `dnf`, ships without a package cache, excludes documentation, and omits utilities like `curl`, `wget`, and even a shell in the micro variant. A standard `ubi9` image is roughly 215 MB. UBI Minimal is around 90 MB. UBI Micro drops below 40 MB.

For a PKI lab, this is not just a size optimization — it is a security posture decision:

- **Fewer packages = fewer CVEs.** Every binary in a container image is a potential vulnerability. A Debian-based `python:3.11-slim` image carries `apt`, `dpkg`, `perl`, `openssl` CLI tools, and dozens of shared libraries that the Python application never calls. Each one shows up in vulnerability scans and requires patching. UBI Minimal eliminates most of this.
- **No shell in production images.** If an attacker gains code execution inside a container, the first thing they look for is a shell. UBI Micro images have no `/bin/sh`. The attacker has code execution in a process that can talk to its own application, and nothing else. For containers that handle CA credentials and certificate signing operations, this matters.
- **Deterministic supply chain.** UBI images are built and signed by Red Hat, scanned continuously, and published to `registry.access.redhat.com` and `quay.io`. The provenance is traceable. Docker Hub official images are maintained by Docker, Inc. and community volunteers with varying levels of security rigor.
- **Air-gapped and disconnected environments.** Many organizations that run enterprise PKI do so in air-gapped networks. Docker Hub rate limits (100 pulls per 6 hours for anonymous users) make it impractical to rebuild containers in disconnected CI/CD pipelines without a paid subscription or a registry mirror. Quay.io has no anonymous rate limits. UBI images can also be redistributed freely under Red Hat's EULA, which matters for government and defense environments.

**Image mapping.** The lab uses Hummingbird or quay.io equivalents wherever available:

| Before (Docker Hub, Debian-based) | After (quay.io, Fedora/UBI-based) | Why |
|---|---|---|
| `postgres:15` | `quay.io/hummingbird/postgresql:latest` | Fedora-based, no Debian apt chain |
| `redis:7` | `quay.io/hummingbird/valkey:latest` | Valkey fork, Redis-compatible, Fedora-based |
| `python:3.11-slim` (4 Containerfiles) | `quay.io/hummingbird/python:3.12-builder` | Fedora 44 base, Python 3.14, non-root default |
| `prom/prometheus:latest` | `quay.io/prometheus/prometheus:latest` | Already on quay.io, just pinning the registry |
| `jupyter/minimal-notebook:latest` | `quay.io/jupyter/minimal-notebook:latest` | Already on quay.io, just pinning the registry |

Images with no Hummingbird or quay.io alternative — 389DS, Dogtag PKI, FreeIPA, AWX, EDA, Grafana, and Confluent Kafka/Zookeeper — stay on their current registries. Every image reference uses a fully-qualified registry prefix (`docker.io/`, `quay.io/`, `registry.access.redhat.com/`) to prevent Podman's interactive registry selection prompt, which breaks unattended lab startup.

**Practical lessons from the Hummingbird migration:**

- **Hummingbird images only publish `latest` tags.** There is no `postgresql:15` or `valkey:7`. If you have version-pinned variables in your `.env`, they must be set to `latest` or the pull will fail with `manifest unknown`. This is a trade-off: you lose version pinning but gain a rolling-release model where images track the latest stable Fedora package. For a lab environment this is acceptable; for production, you would want to build your own images from UBI base and pin your application versions explicitly.

- **The Hummingbird Python image is Fedora 44 with Python 3.14**, not 3.12 despite the tag. Python 3.14 is new enough that many packages lack pre-built wheels. The lab's Containerfiles install `gcc` and `python3-devel` via `dnf` for C extensions like `aiokafka` and `pydantic-core`, and use minimum version pins (`>=`) instead of exact pins (`==`) so pip can resolve to versions with Python 3.14 wheels. This is the most disruptive change in the migration — if your application depends on a package that has not published Python 3.14 wheels yet, you need the build toolchain in the image.

- **The Hummingbird Python image runs as UID 65532 by default** and does not include `curl`. This is the UBI minimal philosophy in action: the image ships only what Python needs to run. Containerfiles use `USER 0` for build steps (installing system packages, pip install), then switch to `USER 65532` for runtime. Healthchecks use `python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"` instead of `curl`. This is more verbose but eliminates a binary from the attack surface.

- **Valkey is a drop-in Redis replacement.** The [Valkey](https://valkey.io/) project forked from Redis when Redis changed its license in March 2024. The Hummingbird Valkey image is wire-compatible with Redis. The only change in the lab is the healthcheck command: `valkey-cli ping` instead of `redis-cli ping`. The container name stays `redis` for backward compatibility with `REDIS_HOST` references in AWX and other services. For new deployments, there is no reason to use Redis over Valkey.

**What is left to migrate.** Kafka and Zookeeper remain on Confluent images (`confluentinc/cp-kafka`, `confluentinc/cp-zookeeper`). The natural next step is [Strimzi](https://strimzi.io/) (`quay.io/strimzi/kafka`), which provides a **UBI-based Kafka image with KRaft mode** — eliminating the Zookeeper dependency entirely. KRaft replaces Zookeeper's role in Kafka metadata management with a built-in Raft consensus protocol, reducing the lab from 10 containers to 9 and removing an entire category of operational complexity (Zookeeper quorum management, session timeouts, data directory corruption). That migration involves different environment variable configuration and KRaft storage initialization, so it is tracked separately. The 389DS, Dogtag PKI, and FreeIPA images are already UBI-based — they come from Red Hat and Fedora package builds that target UBI natively.

## Running the Lab

The entire environment runs in containers using Podman:

```bash
# Clone the repository
git clone https://github.com/czinda/cert-revocation-lab.git
cd cert-revocation-lab

# Install prerequisites (RHEL or Ubuntu)
./setup-prerequisites.sh

# Start with RSA PKI (default)
./start-lab.sh

# Start with specific PKI types
./start-lab.sh --ecc          # ECC P-384 only
./start-lab.sh --pqc          # ML-DSA-87 only
./start-lab.sh --all          # All three PKI types

# Run the end-to-end test
./lab test --pki-type rsa --scenario "Certificate Private Key Compromise"

# Check service health
./lab status

# Run comprehensive validation
./lab validate
```

The lab starts in phases:

1. Base infrastructure (PostgreSQL, Valkey, Zookeeper)
2. Kafka event bus
3. PKI containers (389DS + Dogtag CAs — one network per algorithm)
4. FreeIPA for identity management
5. AWX/Ansible infrastructure
6. Event-Driven Ansible server
7. Mock EDR and SIEM tools
8. IoT client simulator (EST enrollment)
9. Monitoring stack (Prometheus, Grafana, PKI exporter)
10. Jupyter for analysis

All images use fully-qualified registry prefixes (`docker.io/`, `quay.io/`, `registry.access.redhat.com/`) for Podman compatibility.

### Testing Security Scenarios

The lab includes mock EDR and SIEM systems that generate realistic events:

```bash
# Simulate a compromised IoT device
curl -X POST http://localhost:8082/trigger \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": "sensor-floor-3-042",
    "scenario": "IoT Device Firmware Tampering",
    "severity": "critical",
    "pki_type": "ecc"
  }'

# Simulate a user credential theft
curl -X POST http://localhost:8082/trigger \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": "workstation-42",
    "scenario": "Mimikatz Credential Dumping",
    "severity": "critical",
    "pki_type": "rsa"
  }'
```

Watch the EDA logs and you will see the event consumed, the playbook triggered, and the certificate revoked — all within seconds.

## Why Ansible Is the Right Tool for This

There are many ways to automate PKI operations. Custom scripts, purpose-built microservices, vendor-specific APIs. Here is why Ansible stands out:

**Teams already know it.** Ansible is the most widely adopted automation tool in enterprise IT. Using it for certificate lifecycle means no new language to learn, no new platform to maintain.

**Playbooks are auditable.** Every action is declared in YAML. Security and compliance teams can review exactly what happens when a certificate is revoked. Try doing that with a shell script.

**Idempotency is built in.** Run a playbook twice, get the same result. This matters when events might be delivered more than once or when you need to retry after a failure.

**EDA extends the model.** Event-Driven Ansible adds the reactive layer without replacing anything. Existing playbooks, roles, and inventories all work. You are adding event triggers to automation you likely already have.

**It scales.** AWX (or Ansible Automation Platform) provides the execution environment, RBAC, credential management, and job scheduling. AAP 2.6 adds native integration with external secret managers — HashiCorp Vault, CyberArk, Azure Key Vault — so CA credentials can be pulled from a dedicated secrets manager rather than stored in AWX credential stores. EDA job labels allow tagging automation jobs by event source for audit filtering. The lab includes AWX to demonstrate this.

## The Bigger Picture

This lab is a proof of concept, but the pattern applies broadly. Any system where identity state drives access decisions can benefit from event-driven certificate lifecycle management:

- **Industrial IoT**: Thousands of sensors and controllers in manufacturing, energy, and utilities
- **Connected Vehicles**: Fleet vehicles with certificates for V2X communication
- **Medical Devices**: Regulated devices requiring auditable credential management
- **Remote Workforce**: User certificates for VPN, email signing, and workstation authentication
- **Service Mesh**: Machine-to-machine identity in microservices architectures

The common thread: **when identity changes, certificates must follow, and automation is the only way to do it at scale.**

The industry trajectory reinforces this. With OCSP being deprecated — Let's Encrypt shut it down, Firefox replaced it with CRLite, HARICA is following — revocation is moving to a CRL-centric model. Revocation events update the CRL, and relying parties consume it on their own schedule without per-certificate queries to an OCSP responder. This is exactly how the lab works. And with SC-081v3 driving certificate lifetimes to 47 days by 2029, event-driven renewal is no longer a best practice — it is a requirement. Organizations that cannot automate certificate renewal at six-week intervals will face outages, not just risk.

## Conclusion

Certificate lifecycle management is identity lifecycle management. Treating them as separate problems creates gaps that put organizations at risk. By using Event-Driven Ansible to connect identity events to PKI actions — across RSA, ECC, and post-quantum ML-DSA-87 hierarchies, running on minimal container images with a CRL-centric revocation model — you get automated, auditable, and consistent certificate operations for both IoT devices and users, built for an industry moving to shorter lifetimes and CRL-based revocation.

The code is open source and contributions are welcome: [github.com/czinda/cert-revocation-lab](https://github.com/czinda/cert-revocation-lab)

---

*This post is part of a series on PKI modernization and identity-driven security automation. Next up: [configuring Dogtag PKI certificate profiles for IoT device enrollment with Ansible](/posts/dogtag-pki-iot-profiles-ansible/).*
