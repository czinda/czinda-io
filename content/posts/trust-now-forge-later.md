---
title: "Trust Now, Forge Later: The PQC Threat Nobody Is Talking About"
date: 2026-09-01
draft: false
tags: ["post-quantum", "pqc", "ml-dsa", "certificates", "pki", "trust", "tnfl", "pa-techcon"]
description: "Everyone is worried about quantum computers decrypting recorded traffic — but the ability to forge certificates from published public keys is worse, and the remediation window closes before the attack becomes possible."
---

Every conversation about post-quantum risk starts with the same story: adversaries are recording encrypted traffic today and will decrypt it when quantum computers arrive. That threat --- Harvest Now, Decrypt Later (HNDL) --- is real, and I covered it in detail in [Encryption on Borrowed Time](/posts/encryption-on-borrowed-time/). But HNDL has a twin that gets far less attention, and it is the one that should set your migration calendar.

Trust Now, Forge Later (TNFL) uses the same mathematics to attack a different target. Instead of breaking the key exchange that protects a recorded session, it breaks the signature that anchors trust. The result is not exposed data --- it is forged identity. And unlike HNDL, there is no cleaning it up after the fact.

## Why TNFL Is Worse

The asymmetry between the two threats comes down to three properties:

| Property | HNDL | TNFL |
|----------|------|------|
| **Damage scope** | Bounded by what you already sent | Unbounded going forward |
| **Direction** | Retrospective --- past traffic exposed | Prospective --- enables future attacks |
| **Remediation window** | Respond after breach is discovered | Must finish *before* capability exists |

HNDL is bad. You lose the confidentiality of everything you transmitted before you upgraded. But the damage is capped --- once you switch to post-quantum key exchange, new traffic is protected. The adversary's harvest pile stops growing.

TNFL damage has no cap. A forged certificate authority key lets the attacker mint new certificates indefinitely --- certificates that validate perfectly against every trust store that pins the compromised root. Rogue devices join networks. Signed software updates install silently. Federation tokens are accepted. Mutual TLS stops meaning anything. And every one of those forged artifacts is indistinguishable from a real one.

The remediation asymmetry is the part that should keep you up at night. With HNDL, you can respond after you learn the attack is feasible. You upgrade your key exchange, and new sessions are protected. The response is reactive and it works. With TNFL, you must replace every trust root on every device that pins it --- and that work has to be complete *before* a cryptographically relevant quantum computer (CRQC) exists. There is no post-incident version of this. If you are still running classical signature roots when the capability arrives, the trust infrastructure is already compromised. You will not get a notification.

## The Attack Requires No Intrusion

This is the part that surprises security teams who are used to thinking about perimeter defense and intrusion detection.

A certificate authority's public key is distributed to every device that has to trust it. That distribution is the entire point of a public key infrastructure --- the root's public key goes into trust stores in browsers, phones, servers, embedded controllers, roadside cabinets, smart meters, and medical devices. Publishing it is the feature.

It is also the attack surface.

Shor's algorithm derives the private key from the published public key. The attacker does not need to breach your network, compromise an insider, steal an HSM, or exploit a vulnerability. The input to the attack is a value you handed out on purpose, to as many devices as possible, and you cannot take it back.

Your CA can be air-gapped, HSM-backed, stored in a vault under two-person control, and audited quarterly. None of it helps against TNFL. The attacker works from the public half of the key --- the half that is, by design, not secret.

## The Kill Chain Has No Intrusion Step

The four-step attack chain looks nothing like a traditional compromise:

**1. Map.** Catalog the PKI hierarchy --- root CAs, intermediates, cross-certifications, trust chains. All of this information is published deliberately. Certificate Transparency logs, trust store manifests, and the certificates themselves are public documents. The reconnaissance phase requires nothing more than reading what you made available.

**2. Break.** Run Shor's algorithm on the root CA's public key to derive its private key. This is pure computation on a published value. No network access required, no vulnerability exploited, no log entry generated.

**3. Forge.** Use the derived private key to issue new certificates. These certificates are mathematically correct --- the signatures verify, the chains build cleanly, the validity periods are plausible. They are not "fake" in any detectable sense. They are certificates signed by the real private key.

**4. Impersonate.** Deploy the forged certificates. Rogue devices present valid credentials and join trusted networks. Signed code passes integrity checks. Federation assertions are accepted by relying parties. Every system that trusts the compromised root now trusts the attacker.

Notice what is missing from that chain: there is no intrusion, no lateral movement, no privilege escalation, no command and control, no exfiltration. The entire attack happens outside your network, and the first observable effect is a perfectly valid certificate appearing where it should not --- except you cannot tell that it should not, because there is no forensic difference between a forged certificate and a real one.

## No Forensic Tell

This deserves its own section because it breaks a fundamental assumption in incident response.

When an attacker compromises a system, they leave traces. Log entries, modified files, network connections, anomalous behavior. Forensic teams reconstruct the timeline from artifacts. With TNFL, there are no artifacts. A certificate signed by a derived private key is byte-for-byte identical in structure to a certificate signed by the legitimate holder of that key. The signature is mathematically valid. The chain verifies. The OCSP response comes back good, because the certificate was never revoked --- it was never issued by the real CA in the first place, so the real CA has no record of it.

The only detection mechanism is an inventory check: does this certificate appear in your issuance logs? If your CA did not issue it, someone else did --- using your key. But that check requires a complete, real-time certificate inventory, which almost no organization has today. And the check only works if you are looking for it, which means you have to already suspect the compromise.

Certificate Transparency (CT) helps for the public web --- a forged public TLS certificate would eventually surface in CT logs as an issuance the legitimate CA did not make. But CT does not cover internal PKI, private CAs, code signing, device identity, or federation. Those are exactly the targets that matter most for TNFL.

## The Remediation Problem: Fifteen-Year Devices

Even once you accept that TNFL is the binding threat, the remediation is harder than it first appears. Replacing a trust root is not a software update --- it is a trust anchor replacement on every device that pins the current root.

For servers, workstations, and managed endpoints, this is tractable. You issue new certificates from a PQC-capable CA, distribute the new root, and phase out the classical one. It is a significant project, but it follows known patterns.

For long-lived field devices, it is a different problem entirely.

A traffic signal cabinet installed by PennDOT in 2027 with a pinned classical trust root and no remote update path is a device you will still be operating in 2042. If a CRQC arrives in 2035 and that cabinet still trusts a classical root, the trust is already broken. You cannot remediate it remotely, because there is no remote update mechanism --- that was the trade-off made at procurement time for cost, simplicity, or bandwidth constraints.

The same pattern applies to:

- SCADA controllers at water and wastewater facilities
- Interoperable radio key material in emergency communications equipment
- Smart meters with ten-to-twenty-year deployment cycles
- Medical devices with FDA-cleared firmware that cannot be field-updated
- Building automation systems in schools and government facilities

For all of these, the remediation window is not "when quantum arrives" --- it is "before the next procurement cycle for devices that will still be in service when quantum arrives." That window is open right now, and it closes with every purchase order that does not include PQC requirements.

This is why [procurement language](/posts/fix-procurement-first/) is the highest-leverage move in the entire migration plan.

## What TNFL Means for Your Calendar

If HNDL were the only threat, you could argue for a phased, deliberate migration. Start when you are ready, finish when it is convenient, and accept that some historical traffic is exposed. The damage is retrospective and bounded.

TNFL removes that flexibility. The work has a hard deadline --- not a compliance deadline set by a regulation, but a physical deadline set by the capability of an adversary's hardware. And unlike most deadlines, this one does not come with advance notice. The first indication that a CRQC can break your signatures is the existence of a CRQC that can break your signatures.

[Mosca's Theorem](https://globalriskinstitute.org/publication/quantum-threat-timeline-report-2022/) frames this precisely. For TNFL, the relevant X is not "how long the data must stay confidential" --- it is "how long the trust anchor must remain valid." For a root CA with a twenty-year certificate and devices that pin it for fifteen years, X is effectively the remaining life of those devices. Y is the time to replace the root across all of them. If X + Y exceeds Z, you are already too late.

The federal timeline reflects this understanding. [EO 14412](https://www.whitehouse.gov/briefing-room/presidential-actions/) sets December 2030 for PQC key establishment (the HNDL fix) and December 2031 for PQC digital signatures (the TNFL fix). The extra year for signatures is not because signatures are less important --- it is because they are harder to replace. But both deadlines assume that preparation starts now, not when the threat materializes.

For state and local government, the mechanism is indirect but no less binding. Federal data exchange agreements, grant conditions, procurement rules, and browser enforcement all carry PQC requirements downstream. I covered the four vectors in detail in [Encryption on Borrowed Time](/posts/encryption-on-borrowed-time/#the-mandates-reach-you-anyway).

## What to Do About It

The good news is that the TNFL fix is the same infrastructure you need for everything else. A PQC-capable CA that supports [ML-DSA (FIPS 204)](https://csrc.nist.gov/pubs/fips/204/final) can issue certificates with post-quantum signatures. Certificate automation via [ACME (RFC 8555)](https://www.rfc-editor.org/rfc/rfc8555) and [EST (RFC 7030)](https://www.rfc-editor.org/rfc/rfc7030) handles the lifecycle. Hybrid certificates --- classical and post-quantum signatures together --- provide a migration path that does not require a flag day.

The order matters:

1. **Key exchange first** --- stop the HNDL bleeding. This is largely a configuration change on modern stacks and protects new traffic immediately.
2. **Signatures second** --- re-anchor trust on PQC. Harder, because it requires CA migration, new root distribution, and device-by-device trust anchor replacement.
3. **Classical deprecation third** --- leaving both algorithm families enabled lets an attacker downgrade to the weaker one. Plan the removal explicitly.

For the implementation details --- how a CA actually signs ML-DSA certificates, handles the FIPS constraints, and manages the signature size explosion --- see the [PKI.Next series](/posts/pki-next-part1-building-ca-in-rust/) and [The State of Post-Quantum Cryptography](/posts/state-of-pqc-may-2026/).

The strategic details --- inventory, risk-ranking, procurement language, and the 90-day plan --- are in [Encryption on Borrowed Time](/posts/encryption-on-borrowed-time/).

The next post in this series, [Fix Procurement First](/posts/fix-procurement-first/), covers the single highest-leverage action: the contract clauses that cost a paragraph and protect you for a decade.

## References

1. NIST, ["FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA),"](https://csrc.nist.gov/pubs/fips/204/final) August 2024.

2. NIST, ["IR 8547: Transition to Post-Quantum Cryptography Standards,"](https://csrc.nist.gov/pubs/ir/8547/ipd) Initial Public Draft, November 2024.

3. Michele Mosca, ["Quantum Threat Timeline Report,"](https://globalriskinstitute.org/publication/quantum-threat-timeline-report-2022/) Global Risk Institute, 2022.

4. IETF, ["RFC 8555: Automatic Certificate Management Environment (ACME),"](https://www.rfc-editor.org/rfc/rfc8555) March 2019.

5. IETF, ["RFC 7030: Enrollment over Secure Transport (EST),"](https://www.rfc-editor.org/rfc/rfc7030) October 2013.

6. IETF, ["RFC 6962: Certificate Transparency,"](https://www.rfc-editor.org/rfc/rfc6962) June 2013.

---

*This is the second post in a series adapted from my talk at [PA TechCon 2026](https://www.patechcon.com/). The previous post, [Encryption on Borrowed Time](/posts/encryption-on-borrowed-time/), covers the full migration plan. Next: [Fix Procurement First](/posts/fix-procurement-first/) --- the cheapest thing on the entire list.*
