---
title: "The State of Post-Quantum Cryptography: May 2026"
date: 2026-05-26
draft: false
tags: ["post-quantum", "pqc", "ml-kem", "ml-dsa", "tls", "ssh", "pki", "fips", "cryptography", "kipuka", "akamu", "synta"]
description: "A practitioner's scorecard for post-quantum cryptography adoption across TLS, SSH, and PKI — what works today, what's close, and what's still blocked."
---

Post-quantum cryptography is no longer a standards exercise. ML-KEM key exchange is the default in every major browser and in OpenSSH. RHEL 10 ships with post-quantum TLS and SSH enabled out of the box. DigiCert is issuing ML-DSA certificates today.

But "available" and "deployed" are not the same thing. Key exchange is largely solved. Authentication --- the part where certificates, signatures, and trust chains live --- is not. The gap between what the standards define and what production systems can actually verify is where most of the engineering work remains.

This post is a practitioner's scorecard. It covers what works today, what is close, and what is still blocked across TLS, SSH, and PKI. It is the first installment of a periodic series; I will update it as the landscape evolves.

If you want the implementation details --- how a CA actually signs ML-DSA certificates, handles FIPS constraints, and manages the size explosion --- the [PKI.Next series](/posts/pki-next-part1-building-ca-in-rust/) covers that in depth. This post is the view from 10,000 feet.

## The Standards Foundation

NIST published the first three post-quantum cryptographic standards in August 2024:

| Standard | Algorithm | Purpose | Based On |
|----------|-----------|---------|----------|
| [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) | ML-KEM | Key encapsulation | CRYSTALS-Kyber |
| [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) | ML-DSA | Digital signatures | CRYSTALS-Dilithium |
| [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) | SLH-DSA | Digital signatures (backup) | SPHINCS+ |

Two more standards are in progress:

- **FIPS 206 (FN-DSA)**, based on FALCON, is expected later in 2026. It produces smaller signatures than ML-DSA and is designed for bandwidth-constrained environments.
- **HQC**, a code-based key encapsulation mechanism, was selected in March 2025 as a backup to ML-KEM. The draft standard is expected in early 2026 with finalization in 2027.

The compliance deadlines are real and approaching:

| Deadline | Requirement |
|----------|-------------|
| **September 2026** | FIPS 140-2 sunset |
| **January 2027** | CNSA 2.0 procurement requirements for National Security Systems |
| **2030** | CNSA 2.0 deadline for software and firmware signing |
| **2033** | CNSA 2.0 deadline for all PKI signatures |
| **2035** | NIST IR 8547: quantum-vulnerable algorithms removed from all NIST standards |

CNSA 2.0 is prescriptive: it requires ML-DSA-87 and ML-KEM-1024 exclusively (Category 5 security) for National Security Systems. The broader FIPS standards offer additional parameter sets, but the highest-security variants are the only ones acceptable for government use.

## TLS: Key Exchange Is Solved, Authentication Is Not

### Key Exchange: Done

Post-quantum key exchange in TLS 1.3 is a solved problem at scale. The hybrid approach --- combining ML-KEM-768 with X25519 in a single key exchange --- is deployed across all major browsers and CDNs:

- **Chrome 131** (November 2024) made `X25519MLKEM768` the default TLS 1.3 key exchange offer. By Chrome 138, users could no longer disable it.
- **Firefox 132** enabled `X25519MLKEM768` by default on desktop. Firefox 135 added support over QUIC/HTTP3.
- **Edge 131** mirrors Chrome's timeline, being Chromium-based.
- **Cloudflare** reports that over 60% of human-initiated TLS traffic now uses hybrid ML-KEM key exchange.
- **Akamai** made post-quantum key exchange the default for all client connections in January 2026, completing full network rollout by March 2026.

On the server side, [rustls](https://github.com/rustls/rustls) has supported ML-KEM key exchange by default since version 0.23.27. The upcoming 0.24 release will require explicit crypto provider selection, with `rustls-aws-lc-rs` providing the post-quantum algorithms and `rustls-ring` limited to classical-only.

The IETF specifications for hybrid TLS key exchange ([draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)) are still in draft, but the deployed implementations are stable and interoperable.

**Bottom line:** if you are running a modern browser or a server with rustls/OpenSSL 3.5+, your TLS key exchange is already quantum-resistant. This is the "harvest now, decrypt later" defense, and it is operational.

### Authentication: The Hard Part

TLS authentication --- where the server proves its identity via a certificate chain --- is a different story. The pieces exist but do not connect yet:

- **[RFC 9881](https://www.rfc-editor.org/rfc/rfc9881)** (October 2025) defines ML-DSA algorithm identifiers for X.509 certificates.
- **[DigiCert](https://docs.digicert.com/en/trust-lifecycle-manager/enroll-and-manage-certificates/post-quantum-cryptography-pqc/issue-pqc-mldsa-dilithium-certificates.html)** is issuing ML-DSA certificates today through Trust Lifecycle Manager.
- **OpenSSL 3.5** (April 2025) includes ML-DSA support in the default provider.

But here is the gap: **most TLS libraries cannot verify ML-DSA signatures in a handshake.** Rustls does not support ML-DSA certificate verification in its stable API. The `aws-lc-rs` crate provides ML-DSA through an [unstable feature flag](https://crates.io/crates/aws-lc-rs), not the production path. Cloudflare has stated they will add ML-DSA certificate support [when CAs broadly support them](https://developers.cloudflare.com/ssl/post-quantum-cryptography/pqc-support/) --- their estimate is 2026.

The size problem compounds this. An ML-DSA-65 signature is 3,309 bytes and a public key is 1,952 bytes. A typical two-certificate TLS chain (end-entity + intermediate) adds roughly **14.7 KB** of signature and key data to the handshake --- compared to ~256 bytes with ECDSA P-256. This is not just a bandwidth concern; it impacts connection latency, particularly on mobile networks and constrained devices.

**Bottom line:** you can *issue* ML-DSA certificates today. You cannot *use* them for TLS authentication in most production stacks. Key exchange protects the session; authentication protects the identity. One of these two is solved.

## SSH: Post-Quantum by Default

SSH is further along than TLS for a simple reason: key exchange was the only urgent problem, and OpenSSH solved it.

[OpenSSH](https://www.openssh.org/pq.html) has offered post-quantum key agreement since release 9.0 (April 2022), initially via the `sntrup761x25519-sha512` algorithm. OpenSSH 10.0 (April 2025) made `mlkem768x25519-sha256` --- the NIST ML-KEM standard combined with X25519 --- the **default** key exchange algorithm.

OpenSSH 10.1 and later [warn you](https://supportportal.juniper.net/s/article/2026-03-Reference-Advisory-OpenSSH-client-new-warning-in-versions-10-1-and-higher-connection-is-not-using-a-post-quantum-key-exchange-algorithm) when a connection is not using a post-quantum key exchange:

```
WARNING: connection is not using a post-quantum key exchange algorithm.
This session may be vulnerable to "store now, decrypt later" attacks.
The server may need to be upgraded.
```

The IETF is standardizing the hybrid SSH key exchange algorithms in [draft-ietf-sshm-mlkem-hybrid-kex](https://datatracker.ietf.org/doc/draft-ietf-sshm-mlkem-hybrid-kex/) (revision 10, February 2026), defining `mlkem768x25519-sha256`, `mlkem768nistp256-sha256`, and `mlkem1024nistp384-sha384`.

Adoption is accelerating. Between October 2024 and March 2025, SSH key exchange with ML-KEM grew **554%**. All the hybrids combine a post-quantum algorithm with a classical one, so if ML-KEM were to have a flaw, X25519 still protects the session --- and vice versa.

### Distribution Support

[Red Hat Enterprise Linux 10](https://www.redhat.com/en/blog/post-quantum-cryptography-red-hat-enterprise-linux-10) tells the story of how quickly this moved:

| Release | Date | PQ SSH Status |
|---------|------|---------------|
| RHEL 10.0 | 2025 | Technology Preview |
| [RHEL 10.1](https://www.redhat.com/en/blog/whats-new-post-quantum-cryptography-rhel-101) | 2025 | GA, PQ enabled by default |
| [RHEL 10.2](https://linuxiac.com/rhel-10-2-released-with-post-quantum-ssh-and-kernel-livepatching/) | May 2026 | Full PQ SSH, FUTURE policy requires hybrid-only |

RHEL 10.1 was the first major Linux distribution to sign its packages with hybrid post-quantum keys. In RHEL 10.2, the `FUTURE` system-wide cryptographic policy permits *only* hybrid ML-KEM key exchange algorithms, discontinuing traditional non-post-quantum methods entirely.

### What SSH Is Missing

Post-quantum *user authentication* does not exist yet. SSH user keys are still RSA or Ed25519. There is no standard for ML-DSA SSH host or user keys. Key exchange protects the session confidentiality; if an attacker steals your SSH key, the quantum-resistant key exchange does not help. This is an acceptable trade-off today --- "store now, decrypt later" attacks target session data, not authentication keys --- but it is a gap that will need to close.

**Bottom line:** if you are running OpenSSH 10.0+ or RHEL 10.1+, your SSH sessions are already quantum-resistant for key exchange. Check with `ssh -vv` and look for `mlkem768x25519-sha256` in the negotiated KEX.

## PKI: The Certificate Size Problem

Post-quantum PKI is where the engineering gets hard. The signature sizes that are merely awkward in a TLS handshake become structural problems when multiplied across certificate revocation, OCSP responses, and certificate transparency logs.

### What Works Today

- **[DigiCert](https://docs.digicert.com/en/trust-lifecycle-manager/enroll-and-manage-certificates/post-quantum-cryptography-pqc/issue-pqc-mldsa-dilithium-certificates.html)** issues ML-DSA certificates through Trust Lifecycle Manager. You need OpenSSL 3.5+ to generate CSRs with ML-DSA keys.
- **[RFC 9881](https://www.rfc-editor.org/rfc/rfc9881)** defines how ML-DSA keys and signatures are encoded in X.509 certificates. The encoding is straightforward: a bare OID with no parameters, raw public key bytes in the SubjectPublicKeyInfo, and identical OIDs for signature and public key algorithms.
- **Composite certificates** ([draft-ietf-lamps-pq-composite-sigs](https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html)) embed both a classical and a post-quantum signature in a single certificate, providing quantum resistance while maintaining backward compatibility.

### Merkle Tree Certificates: The Structural Answer

The most significant response to the size problem is [Merkle Tree Certificates](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/) (MTCs), being standardized by the IETF's [PLANTS working group](https://datatracker.ietf.org/wg/plants/about/) (PKI, Logs, And Tree Signatures). The current draft (revision 03, April 2026) is 83 pages and defines a fundamentally different certificate architecture.

Instead of each certificate carrying its own signature, certificates are batched into a Merkle tree. The CA signs the tree root once, and each certificate carries a short inclusion proof --- a path of hashes from its leaf to the signed root.

The size savings are dramatic:

| Approach | TLS Auth Data | Factor |
|----------|---------------|--------|
| ML-DSA-65 traditional chain (2 certs) | ~14,700 bytes | 1.0x |
| MTC inclusion proof (~4.4M cert tree) | ~736 bytes | **20x smaller** |

[Google's February 2026 announcement](https://groups.google.com/g/certificate-transparency/c/w0sUcZ7FO0g) described three deployment phases:

1. **Phase 1** (underway): Live feasibility study with Cloudflare, ~1,000 certificates enrolled
2. **Phase 2** (target Q1 2027): Public infrastructure bootstrap
3. **Phase 3** (target Q3 2027): Chrome Quantum-resistant Root Store

Chrome has designated MTC as its [preferred path for post-quantum TLS authentication](https://postquantum.com/security-pqc/googles-merkle-tree-mtc-https/). DigiCert has [open-sourced an MTC playground](https://www.digicert.com/blog/digicert-mtc-playground) implementation.

There is a significant caveat: MTCs require clients to regularly fetch tree head updates through an out-of-band channel. This is trivial for auto-updating browsers, but difficult for command-line tools, embedded systems, or IoT devices. Servers will need to serve both MTC inclusion proofs and traditional X.509 certificates for the foreseeable future.

### The 47-Day Certificate Timeline

In parallel, the CA/Browser Forum's [Ballot SC-081v3](https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/) (passed unanimously, April 2025) is driving certificate lifetimes shorter:

| Date | Maximum Lifetime |
|------|-----------------|
| **March 2026** (now in effect) | 200 days |
| March 2027 | 100 days |
| **March 2029** | **47 days** |

The 47-day target is not arbitrary: 31 days (one maximal month) + 15 days (half a 30-day month) + 1 day buffer. At 47 days, certificates expire before most revocation systems would have propagated a revocation anyway, reducing the dependency on OCSP and CRLs.

This creates a natural synergy with Merkle Tree Certificates. MTCs' batch issuance model --- where a CA signs a tree of thousands of certificates at once --- fits naturally with short-lived certificates that are reissued frequently. The overhead of managing frequent issuance is offset by the dramatic reduction in per-certificate signature size.

## FIPS 140-3: The Validation Gap

FIPS validation moves at its own pace, and that pace does not match deployment reality.

### What Has Been Validated

[AWS-LC FIPS 3.0](https://aws.amazon.com/blogs/security/aws-lc-fips-3-0-first-cryptographic-library-to-include-ml-kem-in-fips-140-3-validation/) is the first open-source cryptographic module to include ML-KEM in a FIPS 140-3 validation (certificates #4631, #4759, #4816). All three ML-KEM parameter sets (512, 768, 1024) are covered.

AWS KMS now supports ML-DSA key creation and signing through its FIPS 140-3 Level 3 validated HSMs. This means you can use ML-DSA as a root of trust for code and document signing today --- but only through KMS, not through the `aws-lc-rs` Rust crate's stable API.

### What Has Not

- **ML-DSA** is not yet in any FIPS-validated software library's stable interface. In `aws-lc-rs`, it is behind the `aws_lc_rs_unstable` feature flag.
- **OpenSSL 3.5's FIPS provider** includes ML-KEM for hybrid key exchange only (`SecP256r1MLKEM768` and `SecP384r1MLKEM1024`). ML-DSA and SLH-DSA are in the default provider but not the FIPS provider.
- **Ed25519** remains outside the FIPS boundary in most validated modules.

The average FIPS 140-3 processing time is **542 days**. This is the real bottleneck: even if a library submits ML-DSA for validation today, the certificate may not arrive until late 2027 or 2028.

NIST's April 2026 update to the [FIPS 140-3 Implementation Guidance](https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-ig-announcements) relaxed self-test requirements for ML-KEM, ML-DSA, and SLH-DSA --- modules can now test internal algorithms rather than external ones, and check against the private key only (since it contains the public key). This should speed up future validations, but the queue is deep.

**FIPS 140-2 sunsets in September 2026.** Any system still relying on a FIPS 140-2-only module needs to migrate to a FIPS 140-3-validated module within four months.

**Bottom line for FIPS-constrained deployments:** ML-KEM key exchange is available in FIPS mode via AWS-LC. For ML-DSA signing, your options are AWS KMS or a PKCS#11 hardware token with its own PQC validation. Do not wait for software FIPS ML-DSA --- use HSMs.

## The Practitioner's Scorecard

| Capability | Status | Standard | What To Do Now |
|------------|--------|----------|----------------|
| **TLS key exchange** | Deployed | FIPS 203 / ML-KEM | Likely already on. Verify with browser DevTools or `openssl s_client`. |
| **TLS authentication** | Available (limited) | FIPS 204 / RFC 9881 | Test ML-DSA cert issuance with DigiCert. Not deployable for public TLS yet. |
| **SSH key exchange** | Deployed | FIPS 203 / ML-KEM | Update to OpenSSH 10.0+. Check with `ssh -vv`. |
| **SSH user auth** | Missing | --- | No standard exists. Continue with Ed25519 keys. |
| **X.509 issuance** | Available | RFC 9881 | Generate ML-DSA CSRs with OpenSSL 3.5. Test in non-production. |
| **Composite certs** | Draft | LAMPS WG | Track the [composite signatures draft](https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html). |
| **Merkle Tree Certs** | Draft / Phase 1 | PLANTS WG | Watch [draft-ietf-plants-merkle-tree-certs](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/). |
| **FIPS ML-KEM** | Validated | FIPS 203 | Use AWS-LC FIPS 3.0 or OpenSSL 3.5 FIPS provider (hybrid only). |
| **FIPS ML-DSA** | Not validated (software) | FIPS 204 | Use PKCS#11 HSM or AWS KMS. Do not wait for software validation. |
| **Code signing** | Available (limited) | FIPS 204 | ML-DSA keys in AWS KMS for roots of trust. |

## What to Do Today

**If you manage TLS servers:**
1. Verify your servers negotiate `X25519MLKEM768`. Most modern TLS libraries do this by default. If you are running rustls 0.23.27+, OpenSSL 3.5+, or behind Cloudflare/Akamai, you are already covered.
2. Plan for 200-day certificate lifetimes --- the first SC-081v3 milestone took effect in March 2026. Automate your certificate renewal now if you have not already.

**If you manage SSH infrastructure:**
1. Update to OpenSSH 10.0 or later. On RHEL 10.1+, post-quantum SSH key exchange is on by default.
2. Look for the `mlkem768x25519-sha256` KEX algorithm in your `ssh -vv` output. If you see `sntrup761x25519-sha512` instead, that is also post-quantum --- just the older algorithm.

**If you operate a PKI or CA:**
1. Test ML-DSA certificate issuance with OpenSSL 3.5 in a lab environment. The encoding rules ([RFC 9881](https://www.rfc-editor.org/rfc/rfc9881)) have subtleties --- no algorithm parameters, raw public key encoding --- that differ from RSA and ECDSA.
2. If you need FIPS-compliant ML-DSA signing today, use a PKCS#11 token. Software FIPS validation for ML-DSA is at least 18 months away.

**If you are planning a PQC migration:**
1. Prioritize key exchange. This is the "harvest now, decrypt later" defense, and it is the most mature.
2. Do not block on ML-DSA for authentication. The size problem is real, and Merkle Tree Certificates may change the architecture before ML-DSA TLS authentication is broadly deployable.
3. Watch the PLANTS working group. MTCs are the most likely path to practical post-quantum TLS authentication at scale.

---

**Update (June 2026):** The PQC capabilities discussed in this scorecard — ML-DSA certificate issuance, PKCS#11 HSM support, and Merkle Tree Certificates — are implemented in [kipuka](https://kipuka.dev) (EST/CMP enrollment, [source](https://codeberg.org/czinda/kipuka)), [Akamu](https://codeberg.org/czinda/akamu) (ACME CA), and [Synta](https://codeberg.org/abbra/synta) (ASN.1/X.509 foundation, [crates.io](https://crates.io/crates/synta)).

*This is the first installment of a periodic series tracking post-quantum cryptography adoption. For implementation details --- signing ML-DSA certificates, handling FIPS constraints, managing ASN.1 encoding --- see the [PKI.Next series](/posts/pki-next-part1-building-ca-in-rust/).*
