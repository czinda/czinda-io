---
title: "Securing Critical Infrastructure: Certificate-Based Identity for Water and Utility Systems"
date: 2026-08-18
draft: false
tags: ["pki", "certificates", "critical-infrastructure", "ot-security", "scada", "water-systems", "mTLS", "rhcs", "identity", "ansible", "image-mode"]
description: "How the largest coordinated cyberattack on U.S. water systems exploited the absence of cryptographic identity — and how certificate-based infrastructure already deployed in defense and federal environments could have prevented it."
---

In July and August 2026, a coordinated cyberattack struck water systems across more than twelve U.S. states. Over a single weekend, more than thirty Minnesota water utilities lost control of their programmable logic controllers. Operators were locked out of their own equipment. Safety alarms were silently disabled while displays continued to show normal operation. Boil-water advisories went out across multiple states, and facilities fell back to manual operations --- dispatching personnel to physically operate pumps and valves.

The attackers did not use a zero-day exploit. They did not deploy custom malware. They used the vendor's own engineering software over standard industrial protocols to connect to controllers that were sitting on the public internet, protected by nothing more than default passwords.

This post examines what happened, why it happened, and how certificate-based identity --- the same infrastructure that protects Department of Defense and federal civilian networks --- addresses every link in the attack chain.

## The Attack Surface

The primary targets were Allen-Bradley MicroLogix and CompactLogix programmable logic controllers (PLCs) manufactured by Rockwell Automation. These devices control pumps, valves, lift stations, water towers, and chemical treatment equipment at water utilities across the country.

[CISA Advisory AA26-097A](https://www.cisa.gov/news-events/cybersecurity-advisories) documents the campaign, attributing it to CyberAv3ngers, an IRGC-linked threat group that previously compromised U.S. water utilities in late 2023. The group has been targeting PLCs across critical infrastructure since at least March 2026.

The scale of the exposure is staggering:

| Metric | Value |
|--------|-------|
| U.S. states targeted | 12+ |
| Minnesota water systems hit in one weekend | 30+ |
| Rockwell PLCs exposed on the public internet | 4,407 |
| U.S. public drinking water systems at risk | 152,000 |

A Shodan-style survey of the exposed controllers revealed the specific hardware:

- **Allen-Bradley MicroLogix 1100** --- discontinued by Rockwell in April 2022 with a "no future patches" designation. Still deployed in production.
- **Allen-Bradley MicroLogix 1400** --- accounted for approximately 50% of all exposed Rockwell controllers. 19 of 22 controllers in affected cities were running firmware vulnerable to [CVE-2017-16740](https://nvd.nist.gov/vuln/detail/CVE-2017-16740) (CVSS 8.6), a Modbus TCP buffer overflow.
- **CompactLogix 1769** (22%) and **ControlLogix 5590** (8%) rounded out the remainder.

More than 70% of the exposed U.S. PLCs were connected via mobile carrier networks --- cellular modems providing direct internet connectivity with no gateway, firewall, or segmentation between the controller and the public internet. The total number of exposed Rockwell controllers has dropped 47% since 2020, but 4,407 remain.

The most critical vulnerability was [CVE-2021-22681](https://nvd.nist.gov/vuln/detail/CVE-2021-22681) (CVSS 9.8) --- an authentication bypass caused by an insufficiently protected cryptographic key in Rockwell's authentication mechanism. As of the time of the attacks, no complete vendor patch was available. Compounding this, deployed devices routinely had hardcoded SNMP community strings, cleartext credentials, and expired or nonexistent certificates.

## The Kill Chain

The FBI's post-incident analysis was blunt: "The activity did not rely on a novel exploit or custom malware."

The attack chain was six steps, each exploiting the absence of basic identity infrastructure:

1. **Scan.** Identify PLCs exposing port 44818 (EtherNet/IP) on the public internet. This is a well-known industrial protocol port, and tools like Shodan and Censys have indexed exposed controllers for years.

2. **Connect.** Use legitimate engineering tools --- Rockwell's Studio 5000 and Schneider's EcoStruxure --- from leased cloud infrastructure. The tools are freely available, and the protocol is open.

3. **Authenticate.** Default passwords on devices that had never been reconfigured, or the CVE-2021-22681 authentication bypass on devices where passwords had been changed. Either way, the attacker gets in.

4. **Exfiltrate.** Download the PLC project files --- the running control program that governs how the physical process operates. This gives the attacker a complete understanding of the facility's logic.

5. **Lock out.** Change admin passwords and IP addresses on the PLCs. The devices disappear from the SCADA network. Operators cannot reconnect because they no longer know the credentials or the network addresses of their own equipment.

6. **Tamper.** Modify ladder logic, delete Add-On Instructions (reusable logic blocks controlling safe operation), and disable safety alarms --- all while preserving the appearance of normal operation on HMI displays.

What was missing from this entire chain is a short list:

- **No device identity.** PLCs had no certificates. They accepted connections from anyone who could supply a password.
- **No mutual authentication.** No mechanism existed to verify that the engineering tool connecting to a PLC was authorized to do so.
- **No network segmentation.** PLCs were directly on the internet via cellular modems, with no gateway mediating access.
- **No integrity verification.** No mechanism existed to detect when control logic had been modified.
- **No centralized access management.** Every device was managed with its own local credentials, independently.

## After the Breach

The consequences were physical and immediate.

**Operator lockout.** With passwords and IP addresses changed, operators lost all visibility into pressure, tank levels, water chemistry, and equipment status. Facilities reverted to manual operations, dispatching personnel to physically read gauges and operate pumps.

**Ladder logic manipulation.** Attackers modified or deleted Add-On Instructions --- the reusable logic blocks that encode safe operating procedures. Safety alarms and automatic shutdown logic were disabled. The malicious logic was designed to preserve the appearance of normal operation on operator displays, meaning that unsafe conditions could develop without notification.

**Pressure loss.** Drops in water pressure allow untreated groundwater to seep into distribution pipes through cracks and joints --- a direct public health hazard that triggers boil-water advisories.

**Flooding.** Uncontrolled pump operation caused flooding at multiple facilities.

**Poisoned backups.** The FBI issued a specific warning: restored backups can silently reintroduce attacker logic if the backup files are not independently validated before restoration. This means that even the recovery path is compromised without integrity verification.

## The Integrator Multiplier

The reason thirty-plus facilities fell in a single weekend deserves its own section, because it reveals a systemic vulnerability in how operational technology is deployed.

Most water utilities outsource PLC installation and network configuration to third-party system integrators. These integrators develop a standard design --- a specific network topology, credential pattern, cellular modem configuration, and PLC programming template --- and deploy it across their entire customer base.

The FBI's analysis identified the pattern: "Similarities in network setup provided by third parties may provide [attackers] the opportunity to" multiply successful techniques across every customer using that integrator's design.

The math is simple. Compromise one integrator's design --- figure out the default password, the modem configuration, the exposed port --- and the technique works on every customer. Same cellular gateway. Same default password. Same exposed EtherNet/IP port. Copied across thirty or more facilities.

This is the infrastructure-as-code argument, inverted. When the integrator's "standard design" is a vulnerable configuration deployed by hand, it scales vulnerability. When the standard design is an Ansible playbook that enforces certificate-based identity, network segmentation, and hardened configurations by default, it scales security. The playbook *is* the standard design --- and it is auditable, versioned, repeatable, and secure.

## Root Cause: Passwords Cannot Protect Industrial Systems

The fundamental failure is architectural. Passwords are shared secrets. Anyone who knows the password gets access. They can be guessed, brute-forced, left at factory defaults, or bypassed entirely via authentication vulnerabilities like CVE-2021-22681.

Worse, passwords are symmetric in a way that creates an inescapable lockout vulnerability: if an attacker changes the password, the operator is locked out. There is no external authority that can override a locally-managed password. There is no revocation mechanism --- a compromised password means rebuilding the device's credential state from scratch. And password management does not scale: managing unique, rotated credentials across thirty distributed facilities manually is operationally impossible, which is why they end up shared and static.

Certificates solve each of these problems at the architectural level:

| Property | Passwords | Certificates |
|----------|-----------|--------------|
| **Secret type** | Shared secret --- anyone who knows it gets in | Private key never leaves the device |
| **Attack resistance** | Guessable, brute-forceable, defaultable | Cryptographic proof --- cannot be guessed |
| **Lockout risk** | Attacker changes password → operator locked out | No password to change |
| **Authentication model** | One-sided --- device trusts anyone with the password | Mutual --- both sides prove identity (mTLS) |
| **Revocation** | None --- compromised password means rebuild | Instant via OCSP/CRL --- seconds to revoke |
| **Scale** | Manual per-device management | Automated lifecycle --- enrollment, renewal, rotation |

With mutual TLS (mTLS), an attacker who has network access but no valid certificate cannot even establish a connection. The TLS handshake fails before any application-layer protocol is reached. There is no password to guess, no default credential to exploit, and no authentication bypass to trigger --- the cryptographic proof is the only path in.

## The Architecture: Certificate-Based Identity for OT

The solution is not theoretical. It is the same certificate-based identity architecture that has been deployed in defense, federal civilian, and intelligence community environments for over a decade. Applied to operational technology, it has four layers:

### Device Identity

Every PLC, sensor, gateway, and HMI station receives a unique X.509 certificate issued by an enterprise Certificate Authority. The certificate binds a cryptographic key pair to the device's identity. The private key is generated on the device (or in a hardware security module) and never transmitted.

### Mutual TLS

Every connection between components requires both sides to present valid certificates. The engineering workstation proves its identity to the PLC. The PLC proves its identity to the SCADA system. No connection proceeds on implicit trust.

### Instant Revocation

When a device is compromised, its certificate is revoked via OCSP (Online Certificate Status Protocol). Every other device on the network rejects connections from the revoked certificate within seconds. Compare this to the password model, where a compromised credential requires manually touching every device that might share it.

### Automated Lifecycle

Protocols like ACME ([RFC 8555](https://www.rfc-editor.org/rfc/rfc8555)), EST ([RFC 7030](https://www.rfc-editor.org/rfc/rfc7030)), and CMP ([RFC 4210](https://www.rfc-editor.org/rfc/rfc4210)) automate certificate enrollment, renewal, and rotation. No manual credential management, no emergency weekend certificate changes, no expired certificates on forgotten devices.

The deployment architecture uses an OT gateway pattern:

{{< mermaid >}}
graph TD
    subgraph "Trust Root"
        ca["Enterprise CA<br/><i>HSM-backed · FIPS 140-3</i>"]
    end

    subgraph "OT Gateway"
        gw["RHEL Gateway<br/><i>certmonger · mTLS termination<br/>Protocol mediation</i>"]
    end

    subgraph "OT Environment"
        plc["PLCs · SCADA · Sensors<br/><i>Network-isolated<br/>Certificate-authenticated<br/>Audit-logged</i>"]
    end

    ca -->|"Issues certificates"| gw
    gw -->|"Authenticated connections only"| plc
{{< /mermaid >}}

The gateway terminates TLS, mediates protocol translation between IT and OT networks, and enforces certificate-based authentication at the boundary. PLCs behind the gateway are network-isolated --- they are never directly reachable from the internet.

## The Technology Stack

### Red Hat Certificate System: Enterprise PKI

[Red Hat Certificate System](https://www.redhat.com/en/technologies/linux-platforms/enterprise-linux/identity-management) (RHCS) is an enterprise CA with a lineage that goes back to Netscape Certificate Management System in the late 1990s. It provides the trust root for the entire architecture:

- **Root and subordinate CA hierarchy** supporting both air-gapped and connected deployment models
- **HSM-backed key protection** at FIPS 140-3 Level 3
- **Certificate profiles** for every OT device type --- PLCs, gateways, operator workstations, and service accounts each get profiles with appropriate key usage, validity periods, and extension sets
- **ACME, EST, and CMP enrollment** for automated certificate lifecycle across different device classes
- **OCSP responder** for real-time revocation checking, plus CRL distribution for offline and air-gapped OT networks
- **Full audit trail** --- every issuance, renewal, and revocation is logged with who, what, when, and why
- **Post-quantum readiness** --- ML-DSA and SLH-DSA support for the migration to quantum-resistant certificates (see [The State of Post-Quantum Cryptography](/posts/state-of-pqc-may-2026/) for details)

RHCS is proven in DoD, federal civilian, and intelligence community environments. The same CA infrastructure that issues Common Access Cards and authenticates classified networks can issue certificates to water treatment PLCs.

### RHEL IdM: Centralized Access Control

RHEL Identity Management replaces per-device password management with centralized, policy-driven identity:

- **Kerberos authentication** --- no passwords sent over the network
- **Smart card, PIV, and CAC support** for operator authentication
- **Host-Based Access Control (HBAC)** --- control which operators can access which systems
- **Centralized sudo** --- control what operators can do on the systems they can access
- **Multi-master replication** --- no single point of failure in the identity infrastructure
- **Offline authentication** via SSSD caching --- operators can authenticate even when connectivity to the central IdM server is interrupted
- **Active Directory trust** for hybrid environments where the IT side runs Windows

With IdM, an attacker cannot lock out operators by changing a password on a single device. Authentication is centralized and policy-driven. Revoking an operator's access or a device's enrollment is a single action at the directory level, not a device-by-device scramble.

### RHEL: The Hardened Platform

Every OT gateway and management system runs on a platform that needs to be hardened from the start:

| Capability | What It Does |
|------------|--------------|
| **FIPS 140-3** | Validated cryptographic modules --- all crypto operations use certified algorithms |
| **SELinux** | Mandatory access controls confine every process; even a compromised application's damage is contained |
| **CIS/STIG baselines** | Automated security profiles applied at install and verified continuously |
| **System-wide crypto policies** | One command eliminates weak algorithms and enforces TLS 1.2+ with strong ciphers everywhere |

RHEL's security track record matters for infrastructure that runs for years without replacement: 20+ years of CVE response, a 10-year lifecycle with Extended Lifecycle Support, over 3,800 security advisories published per year, and a critical CVE patch turnaround of less than 24 hours.

### Image Mode: Immutable, Tamper-Proof Gateways

RHEL Image Mode (`bootc`) is directly relevant to the water system attack pattern, where attackers modified host configurations and installed backdoors after gaining access.

With Image Mode, the root filesystem is read-only. There is nothing to modify. The operating system is delivered as a signed OCI container image:

- **Immutable root filesystem** --- attackers cannot modify system binaries or install backdoors
- **OCI container-based delivery** --- OS images are built, signed, and distributed via standard container registries
- **Atomic updates** --- roll forward to new image versions; if an update fails, roll back instantly
- **Identity at first boot** --- the image discovers IdM via DNS SRV records, auto-enrolls, receives a host certificate, and joins the appropriate host groups. No hardcoded credentials in the image.
- **CIS/STIG profiles baked in** --- security baselines applied at image build time, not post-install
- **FIPS mode from first boot** --- validated cryptography from the moment the gateway powers on
- **Tamper evidence** --- any deviation from the signed image is detectable; a compromised gateway can be re-imaged from the golden image in minutes, not rebuilt from scratch

Every facility gets exactly the same hardened image, eliminating the configuration drift that plagues manually managed infrastructure.

### Ansible: Compliance at Scale

You cannot secure thirty distributed facilities manually. Most water utilities have fewer than five IT staff. Automation fills the gap between what needs to be done and who is available to do it.

Ansible automates the entire security lifecycle:

- **Certificate enrollment** --- automated RHCS enrollment for every new device and gateway
- **IdM domain join** --- new systems automatically enrolled in the identity domain
- **Security hardening** --- CIS/STIG profiles applied consistently across all facilities
- **Crypto policy enforcement** --- eliminate weak algorithms network-wide in one playbook
- **Certificate rotation** --- automated renewal before expiry, no emergency weekend changes
- **Drift detection** --- immediate notification when a system deviates from the security baseline, including changes to PLC control logic
- **Incident response** --- revoke certificates, isolate systems, and remediate across all facilities in minutes

The integrator multiplier problem becomes an integrator multiplier *solution*. Instead of copying a vulnerable manual configuration across customers, the Ansible playbook encodes the hardened, certificate-based design. Every facility gets the same security posture, and deviations are detected automatically.

## The 47-Day Certificate Mandate

The [CA/Browser Forum's Ballot SC-081v3](https://cabforum.org/2025/04/14/ballot-sc-081v3/) establishes a mandatory timeline for reducing TLS certificate maximum lifetimes:

| Date | Maximum Certificate Lifetime |
|------|------------------------------|
| March 2026 | 200 days |
| March 2027 | 100 days |
| **March 2029** | **47 days** |

While this mandate applies specifically to publicly-trusted server authentication certificates, internal policies at enterprises and government agencies tend to mirror external mandates. The direction is clear: certificate lifetimes are getting shorter, and manual certificate management becomes impossible at 47-day rotation cycles.

For OT environments, shorter lifetimes mean a shorter window of exposure when a certificate is compromised. But they also mean that certificate automation is no longer optional --- it is a prerequisite for keeping systems operational. The organizations that build automated certificate infrastructure now will be ready for the mandate. Those that wait will face an operational crisis when manual processes cannot keep pace.

## Why This Matters Right Now

Three facts define the urgency:

| Metric | Value |
|--------|-------|
| Water utilities that failed federal cyber inspections | 70% |
| CISA workforce reduction in 2025 | ~1/3 |
| Enforceable federal cybersecurity standards for water | 0 |

**The threat is real.** State-sponsored actors are actively targeting U.S. water infrastructure. The CyberAv3ngers campaign documented in CISA Advisory AA26-097A is not an isolated incident --- it is a sustained, multi-state operation by an IRGC-linked group with a track record dating to 2023.

**The defenses are thinner.** EPA cybersecurity enforcement authority over water systems was rescinded following legal challenges. CISA's staffing was significantly reduced in 2025. Water utilities are largely on their own for cybersecurity.

**The technology exists.** Certificate-based identity is not experimental. It is proven technology deployed at scale across the most security-sensitive environments in the U.S. government. The same infrastructure that issues Common Access Cards and authenticates classified networks can protect water treatment systems. The gap is not technological --- it is adoption.

The [Cyberspace Solarium Commission](https://www.solarium.gov/) warned in 2020 that "water utilities remain largely ill-prepared to defend their networks from cyber-enabled disruption." Six years later, that prediction came true.

The water sector does not need to invent new technology. It needs to adopt proven identity infrastructure that the most secure environments already use.

## References

1. CISA, ["Advisory AA26-097A: CyberAv3ngers Targeting PLCs Across Critical Infrastructure,"](https://www.cisa.gov/news-events/cybersecurity-advisories) Cybersecurity and Infrastructure Security Agency, 2026.

2. NIST, ["CVE-2017-16740: Allen-Bradley MicroLogix 1400 Modbus TCP Buffer Overflow,"](https://nvd.nist.gov/vuln/detail/CVE-2017-16740) National Vulnerability Database, CVSS 8.6.

3. NIST, ["CVE-2021-22681: Rockwell Automation Authentication Bypass via Insufficiently Protected Credentials,"](https://nvd.nist.gov/vuln/detail/CVE-2021-22681) National Vulnerability Database, CVSS 9.8.

4. CA/Browser Forum, ["Ballot SC-081v3: Reducing TLS Certificate Lifetimes,"](https://cabforum.org/2025/04/14/ballot-sc-081v3/) April 2025. Establishes 200-day (2026), 100-day (2027), and 47-day (2029) maximum certificate lifetimes.

5. U.S. Cyberspace Solarium Commission, [*Report of the United States of America Cyberspace Solarium Commission*](https://www.solarium.gov/), March 2020.

6. IETF, ["RFC 8555: Automatic Certificate Management Environment (ACME),"](https://www.rfc-editor.org/rfc/rfc8555) March 2019.

7. IETF, ["RFC 7030: Enrollment over Secure Transport (EST),"](https://www.rfc-editor.org/rfc/rfc7030) October 2013.

8. IETF, ["RFC 4210: Internet X.509 Public Key Infrastructure --- Certificate Management Protocol (CMP),"](https://www.rfc-editor.org/rfc/rfc4210) September 2005.

---

*This post is based on a talk I gave in August 2026 on securing critical infrastructure with certificate-based identity. The attack details are drawn from CISA Advisory AA26-097A, FBI incident analysis, and publicly available vulnerability data. If your organization operates critical infrastructure and wants to evaluate certificate-based identity, I am happy to discuss --- reach me at czinda@redhat.com or on Signal at czinda.09.*
