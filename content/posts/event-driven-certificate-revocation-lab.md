---
title: "Building an Event-Driven Certificate Revocation Lab"
date: 2025-02-12
draft: false
tags: ["pki", "zero-trust", "ansible", "certificates", "security", "post-quantum"]
description: "A deep dive into automating certificate lifecycle management with Event-Driven Ansible, Dogtag PKI, and multi-algorithm cryptography including post-quantum ML-DSA-87."
---

When a security incident occurs, how quickly can your organization revoke compromised certificates? In most enterprises, the answer is "hours to days" - a window that attackers actively exploit. This post explores an open-source lab environment I built to demonstrate real-time, event-driven certificate revocation using modern PKI infrastructure.

## The Problem: Certificate Revocation is Broken

Traditional certificate revocation relies on manual processes: a security analyst detects a compromise, opens a ticket, someone with PKI access eventually revokes the certificate, and then hopes that clients actually check revocation status. This workflow has several failure modes:

1. **Time**: Manual processes take hours or days
2. **Human Error**: Steps get skipped under pressure
3. **Coverage**: Not all certificates are tracked
4. **Verification**: Revocation checking is often soft-fail

In a Zero Trust architecture, certificates are the primary authentication mechanism. A compromised certificate grants an attacker persistent, trusted access until revocation. The gap between compromise detection and revocation is critical.

## The Solution: Event-Driven Automation

The [Certificate Revocation Lab](https://github.com/czinda/cert-revocation-lab) demonstrates a fundamentally different approach: security events automatically trigger certificate revocation without human intervention.

```
┌─────────────┐     ┌─────────┐     ┌─────────────┐     ┌─────────────┐
│  Security   │────▶│  Kafka  │────▶│  Event-     │────▶│  Dogtag     │
│  Event      │     │         │     │  Driven     │     │  PKI        │
│  (EDR/SIEM) │     │         │     │  Ansible    │     │             │
└─────────────┘     └─────────┘     └─────────────┘     └─────────────┘
```

When an EDR system detects malware on a device, it publishes an event to Kafka. Event-Driven Ansible (EDA) consumes these events and executes playbooks that revoke the device's certificate within seconds.

## Architecture Deep Dive

### Multi-Algorithm PKI Hierarchy

The lab implements three complete, independent PKI hierarchies:

| Algorithm | Use Case | Ports |
|-----------|----------|-------|
| **RSA-4096** | Traditional compatibility | 8443-8445 |
| **ECC P-384** | Modern efficiency | 8463-8465 |
| **ML-DSA-87** | Post-quantum readiness | 8453-8455 |

Each hierarchy follows the same three-tier structure:

```
Root CA (Offline Trust Anchor)
    │
    └── Intermediate CA (Online Issuing CA)
            │
            └── IoT Sub-CA (Device Certificates)
```

This separation matters because:

- **Root CA** stays offline and signs only subordinate CA certificates
- **Intermediate CA** handles day-to-day issuance and can be rotated
- **IoT Sub-CA** issues constrained certificates for devices with limited scope

### Why Post-Quantum Now?

The ML-DSA-87 (formerly Dilithium) hierarchy uses NIST FIPS 204 Level 5 signatures. While quantum computers capable of breaking RSA/ECC don't exist yet, certificates issued today may still be valid when they do. This is the "harvest now, decrypt later" threat.

Running a PQ PKI alongside traditional algorithms lets organizations:

1. Gain operational experience with larger key sizes and signatures
2. Test compatibility with existing infrastructure
3. Prepare migration playbooks before they're urgent

### Event-Driven Ansible Workflow

The magic happens in the EDA rulebook. Here's the simplified flow:

```yaml
# ansible/rulebooks/security-events.yml
- name: Certificate Revocation on Security Events
  hosts: all
  sources:
    - ansible.eda.kafka:
        host: kafka
        port: 9092
        topic: security-events

  rules:
    - name: Revoke certificate on malware detection
      condition: event.severity in ["high", "critical"]
      action:
        run_playbook:
          name: playbooks/revoke-certificate.yml
          extra_vars:
            certificate_cn: "{{ event.certificate_cn }}"
            pki_type: "{{ event.pki_type | default('rsa') }}"
            reason: "keyCompromise"
```

When Kafka receives a security event, EDA evaluates the conditions and triggers the appropriate playbook. The revocation playbook:

1. Authenticates to the correct Dogtag CA (RSA, ECC, or PQ)
2. Finds the certificate by common name
3. Revokes it with the appropriate reason code
4. Optionally notifies downstream systems

### Mock Security Tools

The lab includes FastAPI-based mock EDR and SIEM systems that generate realistic security events:

```bash
# Trigger a security event
curl -X POST http://localhost:8082/trigger \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": "workstation-42",
    "scenario": "Mimikatz Credential Dumping",
    "severity": "critical",
    "pki_type": "rsa"
  }'
```

Available scenarios include:

- Mimikatz Credential Dumping
- Ransomware Encryption Detected
- Certificate Private Key Compromise
- IoT Device Firmware Tampering
- Impossible Travel Detected
- Kerberoasting Detected

Each scenario maps to realistic indicators of compromise that would warrant certificate revocation.

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

# Or start with multiple PKI types
sudo ./start-lab.sh --all  # RSA + ECC + PQ

# Run the end-to-end test
./test-revocation.sh
```

The `start-lab.sh` script orchestrates a phased startup:

1. Base infrastructure (PostgreSQL, Redis, Zookeeper)
2. Kafka event bus
3. PKI containers (389DS + Dogtag CAs)
4. FreeIPA for identity management
5. AWX/Ansible infrastructure
6. Event-Driven Ansible server
7. Mock security tools
8. Jupyter for analysis

### Container Architecture

The lab uses both rootless and rootful Podman containers:

- **Rootless**: Kafka, EDA, mock tools (unprivileged)
- **Rootful**: Dogtag PKI, FreeIPA (require systemd)

This reflects real-world constraints where PKI infrastructure typically requires elevated privileges while consuming applications run unprivileged.

## Why This Matters

### Reducing Mean Time to Revocation

In a traditional workflow:
1. EDR detects malware (T+0)
2. Alert reaches SOC (T+15 minutes)
3. Analyst triages (T+2 hours)
4. Ticket created for PKI team (T+3 hours)
5. Certificate revoked (T+8 hours)

With event-driven automation:
1. EDR detects malware (T+0)
2. Event published to Kafka (T+1 second)
3. EDA triggers playbook (T+2 seconds)
4. Certificate revoked (T+5 seconds)

That's a reduction from hours to seconds.

### Consistency and Auditability

Every revocation follows the same playbook with the same parameters. The Kafka event log provides a complete audit trail of what triggered each revocation. No more "who revoked this and why?" investigations.

### Algorithm Agility

By supporting RSA, ECC, and post-quantum algorithms in parallel, the lab demonstrates how organizations can maintain cryptographic agility. When NIST finalizes PQ standards or a new algorithm weakness is discovered, the infrastructure already supports migration.

### Testing Security Responses

The mock EDR/SIEM tools let security teams test their incident response procedures without real malware. Fire drills for certificate revocation help identify gaps before they matter.

## Future Directions

The lab is actively evolving. Planned enhancements include:

- **CRL and OCSP Distribution**: Automated publishing of revocation information
- **Certificate Transparency**: Integration with CT logs
- **Hardware Security Modules**: PKCS#11 integration for key protection
- **Cross-Signing**: Trust bridges between algorithm families
- **Kubernetes Integration**: Cert-manager with custom issuers

## Conclusion

Certificate revocation doesn't have to be a manual, error-prone process. By combining event-driven architecture with modern PKI infrastructure, organizations can achieve near-real-time response to security incidents. The cert-revocation-lab provides a complete, working reference implementation for exploring these concepts.

The code is open source and contributions are welcome: [github.com/czinda/cert-revocation-lab](https://github.com/czinda/cert-revocation-lab)

---

*This post is part of a series on PKI modernization. Follow along for deep dives into specific components including Dogtag PKI configuration, Event-Driven Ansible rulebooks, and post-quantum cryptography deployment.*
