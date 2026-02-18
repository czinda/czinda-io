---
title: "Event-Driven Certificate Lifecycle Management with Ansible"
date: 2025-02-12
draft: false
tags: ["pki", "zero-trust", "ansible", "certificates", "security", "iot", "identity"]
description: "Automating the full certificate lifecycle — from issuance to revocation — using Event-Driven Ansible, Dogtag PKI, and FreeIPA identity management for IoT devices and users alike."
---

Every certificate has a lifecycle: issuance, renewal, and eventually revocation. In most organizations, that lifecycle is managed through tickets, spreadsheets, and manual intervention. When a device is compromised or an employee leaves, revoking their certificate takes hours or days. Meanwhile, the identity tied to that certificate remains trusted across the network.

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

Now multiply this by thousands of IoT devices, hundreds of users, and multiple certificate authorities. The manual approach does not scale.

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

The lab implements two PKI hierarchies using proven, widely-supported algorithms:

| Algorithm     | Use Case                          | Key Strength                               |
|---------------|-----------------------------------|--------------------------------------------|
| **RSA-4096**  | Users, servers, legacy devices    | Universal support, well-understood         |
| **ECC P-384** | IoT devices, mobile, edge compute | Smaller keys, faster operations, low power |

Each hierarchy follows a three-tier structure:

```
Root CA (Offline Trust Anchor)
    │
    └── Intermediate CA (Online Issuing CA)
            │
            └── IoT Sub-CA (Device Certificates)
```

This separation is deliberate:

- **Root CA** stays offline — it is the trust anchor and signs only subordinate CA certificates
- **Intermediate CA** handles day-to-day issuance for users and servers, and can be rotated without disrupting the trust chain
- **IoT Sub-CA** issues constrained, short-lived certificates for devices with tightly scoped key usage and name constraints

The algorithm choice maps to the identity type. User workstations and servers get RSA certificates for maximum compatibility. IoT devices — sensors, controllers, edge gateways — get ECC certificates because the smaller key size and faster cryptographic operations matter on constrained hardware.

### FreeIPA: The Identity Source of Truth

FreeIPA serves as the central identity store, tying together:

- **Users**: Employees, contractors, service accounts
- **Hosts**: Servers, workstations, IoT devices
- **Services**: Applications that need machine identity
- **Certificate Profiles**: Rules governing what kind of certificate each identity type receives

When a device is enrolled in FreeIPA, it gets an identity. That identity can be bound to a certificate. When the identity state changes — disabled, deleted, moved to a quarantine group — that change becomes an event that Ansible can act on.

### Event-Driven Ansible: The Automation Engine

Event-Driven Ansible (EDA) is the bridge between "something happened" and "do something about it." It watches event sources — Kafka topics, webhooks, log files — and triggers Ansible playbooks based on rules.

Here is the core of the EDA rulebook:

```yaml
# ansible/rulebooks/certificate-lifecycle.yml
- name: Certificate Lifecycle Processor
  hosts: all
  sources:
    - ansible.eda.kafka:
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

## Running the Lab

The entire environment runs in containers using Podman:

```bash
# Clone the repository
git clone https://github.com/czinda/cert-revocation-lab.git
cd cert-revocation-lab

# Install prerequisites (RHEL or Ubuntu)
./setup-prerequisites.sh

# Start with RSA PKI (default)
sudo ./start-lab.sh

# Or start with both RSA and ECC
sudo ./start-lab.sh --all

# Run the end-to-end test
./test-revocation.sh
```

The lab starts in phases:

1. Base infrastructure (PostgreSQL, Redis, Zookeeper)
2. Kafka event bus
3. PKI containers (389DS + Dogtag CAs for RSA and ECC)
4. FreeIPA for identity management
5. AWX/Ansible infrastructure
6. Event-Driven Ansible server
7. Mock EDR and SIEM tools
8. Jupyter for analysis

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

**It scales.** AWX (or Ansible Automation Platform) provides the execution environment, RBAC, credential management, and job scheduling. The lab includes AWX to demonstrate this.

## The Bigger Picture

This lab is a proof of concept, but the pattern applies broadly. Any system where identity state drives access decisions can benefit from event-driven certificate lifecycle management:

- **Industrial IoT**: Thousands of sensors and controllers in manufacturing, energy, and utilities
- **Connected Vehicles**: Fleet vehicles with certificates for V2X communication
- **Medical Devices**: Regulated devices requiring auditable credential management
- **Remote Workforce**: User certificates for VPN, email signing, and workstation authentication
- **Service Mesh**: Machine-to-machine identity in microservices architectures

The common thread: **when identity changes, certificates must follow, and automation is the only way to do it at scale.**

## Conclusion

Certificate lifecycle management is identity lifecycle management. Treating them as separate problems creates gaps that put organizations at risk. By using Event-Driven Ansible to connect identity events to PKI actions, you get automated, auditable, and consistent certificate operations — for both IoT devices and users.

The code is open source and contributions are welcome: [github.com/czinda/cert-revocation-lab](https://github.com/czinda/cert-revocation-lab)

---

## Update: February 2026

Several industry developments since this post was published validate the event-driven approach and expand the tooling available.

**OCSP deprecation validates CRL-based revocation.** Let's Encrypt [shut down its OCSP responders](https://letsencrypt.org/2025/01/30/ocsp-service-is-being-turned-off/) in August 2025 after handling 340 billion requests per month at peak. The CA/Browser Forum made OCSP optional for public CAs in 2023, and HARICA is deprecating OCSP by March 2026. Firefox replaced OCSP with CRLite (compressed local CRL checking) as of Firefox 137. The industry is moving to CRL-based revocation, which aligns well with the model in this lab — revocation events update the CRL, and relying parties consume it on their own schedule without per-certificate queries to an OCSP responder.

**Ansible Automation Platform 2.6.** Red Hat released [AAP 2.6](https://docs.redhat.com/en/documentation/red_hat_ansible_automation_platform/2.6/html/red_hat_ansible_automation_platform_release_notes/index) in November 2025 with several features relevant to this architecture:

- **External secret management** — native integration with HashiCorp Vault, CyberArk, and Azure Key Vault for CA credentials. The lab stores PKI admin credentials in AWX credential stores; AAP 2.6 allows pulling them from a dedicated secrets manager instead, improving the security posture.
- **Enhanced Kafka support in EDA** — multi-topic subscriptions and wildcard topic matching. The lab's EDA rulebook listens on a single `security-events` topic; with AAP 2.6, you can subscribe to `security-events.*` to capture events from multiple sub-topics without modifying the rulebook.
- **EDA job labels** — tag and filter automation jobs by event source, making it easier to audit which security events triggered which certificate actions.

**EDA plugin namespace migration.** The Event-Driven Ansible plugin ecosystem is migrating source plugins from the `ansible.eda` namespace to `eda.builtin`. The Kafka source plugin used in this lab's rulebook (`ansible.eda.kafka`) should be updated to `eda.builtin.kafka` for forward compatibility with newer EDA controller versions.

**Certificate lifetimes are shrinking.** The CA/Browser Forum passed [Ballot SC-081v3](https://cabforum.org/2025/04/11/ballot-sc-081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/) in April 2025, mandating a reduction in public certificate validity to 200 days (March 2026), 100 days (March 2027), and 47 days (March 2029). At 47-day lifetimes, manual certificate renewal becomes impossible at any scale. The event-driven renewal model demonstrated in this lab — where Ansible monitors certificate expiration and triggers re-enrollment via EST or ACME — becomes not just a best practice but a necessity.

**Post-quantum cryptography and algorithm migration.** NIST finalized [ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) (FIPS 204) and [ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) (FIPS 203) in August 2024 as the first post-quantum cryptographic standards. The RSA-4096 and ECC P-384 algorithms used in this lab's PKI hierarchies are not quantum-resistant. When organizations begin migrating to post-quantum algorithms, the event-driven model becomes especially valuable — an algorithm migration across thousands of certificates is essentially a fleet-wide re-issuance event. The same EDA + Ansible pattern that handles revocation can drive algorithm migration: publish a migration event, trigger playbooks that re-enroll devices with new key types, and revoke the old certificates. The architecture does not need to change; only the playbook parameters do.

---

*This post is part of a series on PKI modernization and identity-driven security automation. Next up: [configuring Dogtag PKI certificate profiles for IoT device enrollment with Ansible](/posts/dogtag-pki-iot-profiles-ansible/).*
