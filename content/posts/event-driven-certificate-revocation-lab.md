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

| Algorithm    | Use Case                          | Key Strength                              |
|--------------|-----------------------------------|-------------------------------------------|
| **RSA-4096** | Users, servers, legacy devices    | Universal support, well-understood        |
| **ECC P-384**| IoT devices, mobile, edge compute | Smaller keys, faster operations, low power|

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

**Device Provisioning**: When a new sensor is registered in FreeIPA, an Ansible playbook requests an ECC certificate from the IoT Sub-CA, pushes it to the device, and configures mutual TLS.

**Firmware Anomaly**: An EDR agent or network monitor detects the device behaving unexpectedly. An event is published. EDA revokes the device's certificate within seconds, immediately cutting off its access to backend APIs.

**Fleet Rotation**: A scheduled Ansible playbook renews certificates across an entire device fleet before expiration. No manual tracking of expiry dates. No spreadsheets.

**Device Decommissioning**: When a device is removed from the FreeIPA inventory, its certificate is revoked and added to the CRL automatically.

## Applying This to Users

The same model works for user certificate lifecycle:

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

*This post is part of a series on PKI modernization and identity-driven security automation. Next up: deep dives into Dogtag PKI configuration with Ansible and FreeIPA-integrated certificate profiles for IoT device enrollment.*
