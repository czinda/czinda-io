---
title: "Configuring Dogtag PKI Certificate Profiles for IoT with Ansible"
date: 2026-02-19
draft: false
tags: ["pki", "ansible", "iot", "certificates", "dogtag", "rhcs", "est", "security", "post-quantum", "coap"]
description: "How to build and automate Dogtag PKI certificate profiles for IoT device enrollment using EST, Ansible, and Red Hat Certificate System — covering constrained device enrollment, post-quantum key sizing, and certificate lifetimes aligned with SC-081v3."
---

In the [previous post](/posts/event-driven-certificate-revocation-lab/), I covered event-driven certificate lifecycle management — how Ansible automates revocation when identity events fire. But revocation is only half the story. Before you can revoke a certificate, you have to issue one. And for IoT devices, issuance needs to be automated, constrained, and scalable.

This post digs into the enrollment side: how to configure Dogtag PKI certificate profiles specifically for IoT devices, how to expose those profiles over the EST protocol for automated device enrollment, and how to manage it all with Ansible.

## Why FreeIPA Is Not the Answer for IoT PKI

FreeIPA (and its downstream, Red Hat Identity Management) is an excellent identity platform. It handles user authentication, host enrollment, Kerberos, DNS, and basic certificate issuance well. For user and server identity, it is often the right choice.

But FreeIPA was not designed for IoT certificate management, and trying to force it into that role creates problems:

**Limited certificate profiles.** FreeIPA exposes a simplified certificate interface on top of its embedded Dogtag instance. You get a handful of built-in profiles — caIPAserviceCert, caIPAuserCert — with limited customization. IoT devices need profiles with specific key usage constraints, short validity periods, custom extensions, and name constraints that FreeIPA's interface does not support well.

**No EST support.** FreeIPA's certificate issuance is tightly coupled to its own enrollment workflow. There is no EST endpoint. IoT devices that speak EST — which is most modern industrial and OT devices — cannot enroll directly against FreeIPA.

**No ACME for internal services.** Similarly, FreeIPA does not provide an ACME endpoint for web and application server enrollment.

**Scale and performance.** FreeIPA is an identity management platform that happens to include a CA. It was not designed for high-volume certificate issuance across thousands of headless devices. Under load, the certificate subsystem competes with the identity subsystem for resources.

**Profile management is opaque.** Modifying certificate profiles in FreeIPA means working around its abstractions. The underlying Dogtag profiles are there, but FreeIPA's tooling discourages direct access to them.

The right tool is the CA itself: **Dogtag PKI**, or its enterprise-supported downstream, **Red Hat Certificate System (RHCS)**. These provide the full certificate authority stack — profile engine, enrollment protocols, audit logging, HSM integration — without the identity management layer getting in the way. Dogtag PKI shipped versions [11.6.0](https://github.com/dogtagpki/pki/releases/tag/v11.6.0) and [11.7.0](https://github.com/dogtagpki/pki/releases/tag/v11.7.0) in 2025, with 11.8-beta also available, bringing improvements to EST handling, ACME support, and the profile engine.

FreeIPA and RHCS complement each other. Use FreeIPA for identity (users, hosts, groups, policies). Use RHCS for PKI (certificate profiles, EST/ACME endpoints, CA hierarchy, revocation infrastructure). Connect them with Ansible.

## Dogtag PKI Certificate Profiles

A certificate profile in Dogtag defines everything about how a certificate is issued: what fields it contains, what extensions are set, how long it is valid, what the requester must provide, and what policies constrain issuance.

### Anatomy of an IoT Device Profile

Here is a profile designed for IoT sensor devices:

```properties
# iot-sensor.cfg
desc=IoT Sensor Device Certificate
visible=true
enable=true
auth.instance_id=SessionAuthentication

# Input: what the device must provide
input.list=i1
input.i1.class_id=certReqInputImpl

# Output: what the CA returns
output.list=o1
output.o1.class_id=certOutputImpl

# Policy: constraints on the issued certificate
policyset.list=sensorSet
policyset.sensorSet.list=1,2,3,4,5,6,7

# 1. Subject name from CSR
policyset.sensorSet.1.constraint.class_id=subjectNameConstraintImpl
policyset.sensorSet.1.constraint.name=Subject Name Constraint
policyset.sensorSet.1.constraint.params.pattern=CN=sensor-.*\.iot\.example\.com
policyset.sensorSet.1.default.class_id=userSubjectNameDefaultImpl
policyset.sensorSet.1.default.name=Subject Name Default

# 2. Short validity period - 90 days
policyset.sensorSet.2.constraint.class_id=validityConstraintImpl
policyset.sensorSet.2.constraint.name=Validity Constraint
policyset.sensorSet.2.constraint.params.range=90
policyset.sensorSet.2.constraint.params.notBeforeCheck=false
policyset.sensorSet.2.constraint.params.notAfterCheck=false
policyset.sensorSet.2.default.class_id=validityDefaultImpl
policyset.sensorSet.2.default.name=Validity Default
policyset.sensorSet.2.default.params.range=90

# 3. Key usage - digital signature and key encipherment only
policyset.sensorSet.3.constraint.class_id=keyUsageExtConstraintImpl
policyset.sensorSet.3.constraint.name=Key Usage Constraint
policyset.sensorSet.3.constraint.params.keyUsageCritical=true
policyset.sensorSet.3.constraint.params.keyUsageDigitalSignature=true
policyset.sensorSet.3.constraint.params.keyUsageKeyEncipherment=true
policyset.sensorSet.3.constraint.params.keyUsageDataEncipherment=false
policyset.sensorSet.3.constraint.params.keyUsageKeyAgreement=false
policyset.sensorSet.3.constraint.params.keyUsageCertSign=false
policyset.sensorSet.3.constraint.params.keyUsageCrlSign=false
policyset.sensorSet.3.default.class_id=keyUsageExtDefaultImpl
policyset.sensorSet.3.default.name=Key Usage Default
policyset.sensorSet.3.default.params.keyUsageCritical=true
policyset.sensorSet.3.default.params.keyUsageDigitalSignature=true
policyset.sensorSet.3.default.params.keyUsageKeyEncipherment=true

# 4. Extended key usage - client authentication only
policyset.sensorSet.4.constraint.class_id=noConstraintImpl
policyset.sensorSet.4.constraint.name=No Constraint
policyset.sensorSet.4.default.class_id=extendedKeyUsageExtDefaultImpl
policyset.sensorSet.4.default.name=Extended Key Usage Default
policyset.sensorSet.4.default.params.exKeyUsageCritical=false
policyset.sensorSet.4.default.params.exKeyUsageOIDs=1.3.6.1.5.5.7.3.2

# 5. ECC key constraint - P-384 only
policyset.sensorSet.5.constraint.class_id=keyConstraintImpl
policyset.sensorSet.5.constraint.name=Key Constraint
policyset.sensorSet.5.constraint.params.keyType=EC
policyset.sensorSet.5.constraint.params.keyParameters=nistp384

# 6. Authority Key Identifier
policyset.sensorSet.6.constraint.class_id=noConstraintImpl
policyset.sensorSet.6.default.class_id=authorityKeyIdentifierExtDefaultImpl

# 7. CRL Distribution Point
policyset.sensorSet.7.constraint.class_id=noConstraintImpl
policyset.sensorSet.7.default.class_id=crlDistributionPointsExtDefaultImpl
policyset.sensorSet.7.default.params.crlDistPointsCritical=false
policyset.sensorSet.7.default.params.crlDistPointsNum=1
policyset.sensorSet.7.default.params.crlDistPointsPointName_0=http://crl.example.com/iot-sub-ca.crl
policyset.sensorSet.7.default.params.crlDistPointsPointType_0=URIName
```

Every line in this profile is a deliberate security decision:

- **Subject name pattern** (`CN=sensor-.*\.iot\.example\.com`): Devices can only get certificates matching a specific naming convention. A compromised enrollment cannot mint certificates for arbitrary hostnames.
- **90-day validity**: Short-lived certificates limit the blast radius of a compromise. The device must re-enroll via EST before expiration. This is already aligned with where the industry is heading — the CA/Browser Forum passed [Ballot SC-081v3](https://cabforum.org/2025/04/11/ballot-sc-081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/) in April 2025, reducing maximum public certificate validity to 200 days (March 2026), 100 days (March 2027), and 47 days (March 2029). While SC-081v3 applies to Web PKI, it sets the direction for all certificate ecosystems. At these lifetimes, automated renewal via EST is not optional — it is the only way to keep devices enrolled.
- **Client auth only** (EKU `1.3.6.1.5.5.7.3.2`): The certificate can only be used for TLS client authentication. It cannot be used as a server certificate or for code signing.
- **ECC P-384 only**: The profile rejects RSA keys. IoT devices in this class use ECC exclusively.
- **CRL distribution point**: Relying parties know where to check revocation status. With the industry moving away from OCSP — Let's Encrypt shut down its responders, Firefox replaced OCSP with CRLite — CRL distribution points are more important than ever as the primary revocation mechanism.

### Profile Variants by Device Class

Different device classes need different profiles:

| Profile | Target | Validity | Key Type | Key Usage |
|---------|--------|----------|----------|-----------|
| `iot-sensor` | Temperature, humidity, pressure sensors | 90 days | ECC P-384 | Client auth |
| `iot-controller` | PLCs, RTUs, industrial controllers | 180 days | ECC P-384 | Client auth, key encipherment |
| `iot-gateway` | Edge gateways, protocol translators | 365 days | ECC P-384 | Client auth, server auth |
| `ot-scada` | SCADA HMIs, historian servers | 365 days | RSA-4096 | Client auth, server auth |

The gateway profile allows server auth because gateways accept inbound connections from sensors. The SCADA profile uses RSA because many legacy OT systems do not support ECC. Each profile encodes these requirements as enforceable constraints — not documentation, not convention, but CA-enforced policy.

### Post-Quantum Key Sizing and IoT Profiles

The key type decisions in these profiles will eventually need to account for post-quantum cryptography. NIST finalized [ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) (FIPS 204) for digital signatures and [ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) (FIPS 203) for key encapsulation in August 2024. ECC P-384, used in the sensor and controller profiles, is not quantum-resistant. An eventual migration to ML-DSA will be necessary for long-term security.

The challenge is size. An ML-DSA-44 public key is 1,312 bytes and a signature is approximately 2,420 bytes, compared to ECC P-384's 96-byte public key and ~96-byte signature. For constrained IoT devices, this is a significant increase in certificate size, CSR size, and bandwidth during enrollment. The migration path will likely involve hybrid certificates (ECC + ML-DSA) during a transition period, with profile constraints updated accordingly. The Dogtag profile structure is flexible enough to accommodate this — new key type constraints and signature algorithm policies can be added without restructuring the profile framework.

The [cert-revocation-lab](https://github.com/czinda/cert-revocation-lab) already includes a full ML-DSA-87 PKI hierarchy for testing post-quantum issuance and revocation through the same event-driven pipeline. Organizations can use it to evaluate the impact of PQ certificate sizes on their IoT enrollment workflows before committing to a migration timeline.

## EST: Automated Device Enrollment

The Enrollment over Secure Transport (EST) protocol (RFC 7030) is how IoT devices actually consume these profiles. EST provides a simple HTTPS-based interface for:

- **Initial enrollment** (`/simpleenroll`): Device submits a CSR, receives a signed certificate
- **Re-enrollment** (`/simplereenroll`): Device renews its certificate before expiration
- **CA certificate retrieval** (`/cacerts`): Device fetches the CA chain for trust configuration
- **CSR attributes** (`/csrattrs`): CA tells the device what fields to include in its CSR

### How EST Works with Dogtag

Dogtag PKI exposes EST as a native subsystem. The enrollment flow:

```
┌──────────────┐                    ┌──────────────┐
│  IoT Device  │                    │  Dogtag PKI  │
│              │                    │  (RHCS)      │
│              │                    │              │
│  1. Generate ├───/cacerts────────▶│  Return CA   │
│     keypair  │◀──────────────────┤  chain       │
│              │                    │              │
│  2. Create   ├───/simpleenroll──▶│  Validate    │
│     CSR      │   + CSR + auth    │  against     │
│              │                    │  profile     │
│              │◀──────────────────┤              │
│  3. Install  │   Signed cert     │  Issue cert  │
│     cert     │                    │              │
│              │                    │              │
│              │  ... 89 days ...   │              │
│              │                    │              │
│  4. Re-enroll├───/simplereenroll─▶│  Validate    │
│     (renew)  │   + CSR + cert    │  + re-issue  │
│              │◀──────────────────┤              │
│              │   New cert        │              │
└──────────────┘                    └──────────────┘
```

The device authenticates to the EST endpoint using either a bootstrap certificate (installed at manufacture) or HTTP basic auth over TLS. Dogtag validates the request against the certificate profile — if the CSR does not match the profile constraints, enrollment is rejected.

### Lightweight Enrollment for Constrained Devices

EST over HTTPS works well for devices that can handle a full TLS stack, but many constrained IoT devices — battery-powered sensors, low-bandwidth LPWAN nodes — cannot afford that overhead. Two protocols extend EST to these environments:

- **EST-coaps** ([RFC 9148](https://datatracker.ietf.org/doc/rfc9148/)) brings EST enrollment over CoAP and DTLS, reducing the transport overhead significantly for devices that already use CoAP for application data. The enrollment semantics are the same — `/simpleenroll`, `/simplereenroll`, `/cacerts` — but carried over UDP-based DTLS instead of TCP-based TLS.
- **EST-oscore** (active [IETF draft](https://datatracker.ietf.org/doc/draft-ietf-ace-est-oscore/)) goes further, using OSCORE and EDHOC for object-level security. This eliminates even the DTLS session overhead, making certificate enrollment feasible on Class 1 constrained devices with as little as 10 KB of RAM.

As Dogtag/RHCS adds support for these transport bindings, the profile configurations in this post remain valid — the certificate content does not change, only the enrollment transport.

### EST Configuration in Dogtag

Enabling EST in Dogtag involves configuring the EST subsystem and mapping it to a certificate profile:

```properties
# /var/lib/pki/pki-tomcat/conf/est/backend.conf
est.backend.configFile=/var/lib/pki/pki-tomcat/conf/est/backend.properties

# Profile mapping for EST enrollment
est.profile.default=iot-sensor
est.profile.mapping.sensor=iot-sensor
est.profile.mapping.controller=iot-controller
est.profile.mapping.gateway=iot-gateway
```

The profile mapping allows a single EST endpoint to serve multiple device classes. The device indicates which profile to use through its CSR attributes or the enrollment URL path.

## Managing It All with Ansible

Manually configuring certificate profiles and EST endpoints across multiple CA instances is exactly the kind of work Ansible eliminates. Here is how to automate the full setup.

### Deploying Certificate Profiles

```yaml
# playbooks/deploy-iot-profiles.yml
- name: Deploy IoT Certificate Profiles to Dogtag
  hosts: dogtag_servers
  vars:
    pki_instance: pki-tomcat
    profiles:
      - iot-sensor
      - iot-controller
      - iot-gateway
      - ot-scada

  tasks:
    - name: Copy profile configurations
      ansible.builtin.copy:
        src: "profiles/{{ item }}.cfg"
        dest: "/var/lib/pki/{{ pki_instance }}/ca/profiles/ca/{{ item }}.cfg"
        owner: pkiuser
        group: pkiuser
        mode: '0644'
      loop: "{{ profiles }}"
      notify: restart pki

    - name: Enable profiles in Dogtag
      ansible.builtin.command:
        cmd: >
          pki -d /root/.dogtag/nssdb
          -c {{ pki_admin_password }}
          -n "PKI Administrator"
          ca-profile-enable {{ item }}
      loop: "{{ profiles }}"
      register: profile_result
      changed_when: "'Enabled' in profile_result.stdout"
      failed_when:
        - profile_result.rc != 0
        - "'already enabled' not in profile_result.stderr"

    - name: Verify profiles are active
      ansible.builtin.command:
        cmd: >
          pki -d /root/.dogtag/nssdb
          -c {{ pki_admin_password }}
          -n "PKI Administrator"
          ca-profile-show {{ item }}
      loop: "{{ profiles }}"
      register: verify_result
      changed_when: false
      failed_when: "'enabled: true' not in verify_result.stdout"

  handlers:
    - name: restart pki
      ansible.builtin.systemd:
        name: "pki-tomcatd@{{ pki_instance }}"
        state: restarted
```

Run this playbook once against your CA infrastructure and every IoT profile is deployed, enabled, and verified. Run it again and nothing changes — idempotency.

### Enrolling a Device via EST with Ansible

For devices that cannot run their own EST client, Ansible can handle enrollment on their behalf:

```yaml
# playbooks/enroll-iot-device.yml
- name: Enroll IoT Device via EST
  hosts: iot_devices
  vars:
    est_server: ca.example.com
    est_port: 8443
    device_cn: "sensor-{{ inventory_hostname }}.iot.example.com"

  tasks:
    - name: Generate ECC P-384 private key
      community.crypto.openssl_privatekey:
        path: /etc/pki/tls/private/device.key
        type: ECC
        curve: secp384r1
        mode: '0600'

    - name: Generate CSR
      community.crypto.openssl_csr:
        path: /etc/pki/tls/certs/device.csr
        privatekey_path: /etc/pki/tls/private/device.key
        common_name: "{{ device_cn }}"
        key_usage:
          - digitalSignature
          - keyEncipherment
        key_usage_critical: true
        extended_key_usage:
          - clientAuth

    - name: Enroll via EST
      ansible.builtin.uri:
        url: "https://{{ est_server }}:{{ est_port }}/.well-known/est/simpleenroll"
        method: POST
        body: "{{ lookup('file', '/etc/pki/tls/certs/device.csr') }}"
        body_format: raw
        headers:
          Content-Type: application/pkcs10
        client_cert: /etc/pki/tls/certs/bootstrap.pem
        client_key: /etc/pki/tls/private/bootstrap.key
        validate_certs: true
        status_code: 200
        dest: /etc/pki/tls/certs/device.pem

    - name: Configure mutual TLS for device services
      ansible.builtin.template:
        src: tls-config.j2
        dest: /etc/device-agent/tls.conf
        mode: '0644'
      notify: restart device agent
```

This playbook handles the full enrollment workflow: key generation, CSR creation, EST enrollment, and TLS configuration. For devices that do have an EST client built in, Ansible's role shifts to configuring the EST client parameters and monitoring enrollment status.

### Automating Certificate Renewal

EST re-enrollment can be triggered by Ansible on a schedule or by the device itself. Here is the Ansible approach for fleet-wide renewal:

```yaml
# playbooks/renew-iot-fleet.yml
- name: Renew Certificates for IoT Fleet
  hosts: iot_devices
  vars:
    renewal_threshold_days: 30

  tasks:
    - name: Check certificate expiration
      community.crypto.x509_certificate_info:
        path: /etc/pki/tls/certs/device.pem
      register: cert_info

    - name: Calculate days until expiration
      ansible.builtin.set_fact:
        days_remaining: "{{ ((cert_info.not_after | to_datetime('%Y%m%d%H%M%SZ')) - (ansible_date_time.iso8601 | to_datetime('%Y-%m-%dT%H:%M:%SZ'))).days }}"

    - name: Re-enroll via EST if nearing expiration
      ansible.builtin.uri:
        url: "https://{{ est_server }}:{{ est_port }}/.well-known/est/simplereenroll"
        method: POST
        body: "{{ lookup('file', '/etc/pki/tls/certs/device.csr') }}"
        body_format: raw
        headers:
          Content-Type: application/pkcs10
        client_cert: /etc/pki/tls/certs/device.pem
        client_key: /etc/pki/tls/private/device.key
        validate_certs: true
        status_code: 200
        dest: /etc/pki/tls/certs/device.pem
      when: days_remaining | int < renewal_threshold_days
      notify: restart device agent
```

Schedule this playbook in AWX to run weekly. Devices within 30 days of expiration get renewed automatically. Devices with time remaining are skipped. As certificate lifetimes shrink toward the 47-day floor set by SC-081v3, this renewal automation shifts from convenience to necessity — at 90-day validity with a 30-day threshold, devices have a 60-day window, but at 47-day validity, the margin for missed renewals disappears.

## Tying It Together: Profile to Enrollment to Revocation

The full lifecycle, managed entirely through Ansible and Dogtag/RHCS:

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Ansible Automation                            │
│                                                                      │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────────┐   │
│  │  Deploy     │    │  Enroll     │    │  Revoke (Event-Driven)  │   │
│  │  Profiles   │    │  via EST    │    │  via EDA + Kafka        │   │
│  │             │    │             │    │                         │   │
│  │  Playbook   │    │  Playbook   │    │  Rulebook + Playbook    │   │
│  └──────┬──────┘    └──────┬──────┘    └────────────┬────────────┘   │
│         │                  │                        │                │
└─────────┼──────────────────┼────────────────────────┼────────────────┘
          │                  │                        │
          ▼                  ▼                        ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     Dogtag PKI / RHCS                                │
│                                                                      │
│  Certificate Profiles ──▶ EST Endpoint ──▶ Issued Certificates       │
│                                               │                      │
│                                               ▼                      │
│                                             CRL                      │
└──────────────────────────────────────────────────────────────────────┘
```

1. **Ansible deploys profiles** to Dogtag, defining what certificates look like for each device class
2. **Devices enroll via EST** (or Ansible enrolls on their behalf), getting certificates that conform to the profile
3. **Security events trigger EDA**, which runs Ansible playbooks to revoke certificates in the same Dogtag CA
4. **Dogtag publishes revocation** via CRL, so relying parties stop trusting the revoked certificate
5. **Remediated devices re-enroll via EST**, getting a fresh certificate under the same profile constraints

Every step is automated. Every step is auditable. Every step uses the same tooling.

## Conclusion

FreeIPA is the right tool for managing user and host identity. It is not the right tool for IoT certificate management. For that, you need the full Dogtag PKI or Red Hat Certificate System stack — certificate profiles with enforceable constraints, EST endpoints for automated device enrollment, and the flexibility to define different certificate policies for different device classes.

Ansible ties it all together. The same automation platform that deploys your infrastructure can deploy your certificate profiles, enroll your devices, renew your fleet, and revoke compromised certificates — all in readable, auditable, idempotent playbooks.

The code is open source: [github.com/czinda/cert-revocation-lab](https://github.com/czinda/cert-revocation-lab)

---

*This post is part of a series on PKI modernization and identity-driven security automation. Previous: [Event-Driven Certificate Lifecycle Management with Ansible](/posts/event-driven-certificate-revocation-lab/).*
