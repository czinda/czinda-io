---
title: "Two Metrics That Matter: Measuring PQC Readiness"
date: 2026-09-22
draft: false
tags: ["post-quantum", "pqc", "metrics", "governance", "certificates", "automation", "pa-techcon"]
description: "You can measure post-quantum readiness with two numbers. Everything else is commentary."
---

This is the fifth and final post in a series based on my [PA TechCon 2026 talk](/posts/encryption-on-borrowed-time/). The previous posts covered [the threat model](/posts/trust-now-forge-later/), [procurement](/posts/fix-procurement-first/), and [the local government gap](/posts/the-part-with-no-ciso/). This one is about how you know whether any of it is working.

## The Dashboard Problem

Every PQC migration plan I have reviewed includes a reporting section. Most of them propose a dashboard with fifteen to thirty metrics: certificate inventory completion percentage, vendor compliance attestation counts, HSM firmware versions, policy document status, training completion rates, risk assessment coverage, and a constellation of RAG indicators that someone updates monthly in a spreadsheet they email to a distribution list nobody reads.

These dashboards do not survive. They do not survive the person who built them leaving. They do not survive an administration change. They do not survive the first quarter where nobody asks about them, because nobody asks about them once the initial urgency fades. They are project artifacts, and projects end.

What survives is a number simple enough that a cabinet secretary can hold it in their head during a budget meeting. You get two of those. Pick carefully.

## Metric 1: Share of Traffic on Post-Quantum Key Exchange

This is your HNDL score. It answers a single question: **what percentage of the Commonwealth's encrypted traffic is protected against harvest-now-decrypt-later collection?**

Every day that hybrid ML-KEM key exchange is enabled on a VPN tunnel, a TLS endpoint, or an IPsec link carrying long-retention data is a day of traffic that never enters anyone's harvest pile. Every day it is not is a day of traffic that is permanently exposed --- the decryption is simply [scheduled for later](/posts/encryption-on-borrowed-time/#harvest-now-decrypt-later-hndl).

The metric has natural properties that make it useful:

- **It starts at zero.** Today, without intervention, zero percent of Commonwealth traffic uses post-quantum key exchange. The number can only go up, and every increase is meaningful.
- **It has a ceiling of 100%.** You know what done looks like.
- **It is measurable at the network layer.** TLS and IPsec handshakes advertise the key exchange algorithm they negotiated. You do not need to survey application owners --- you can observe it directly.
- **Progress is monotonic.** Once a service is configured for hybrid key exchange, it stays that way. You do not lose ground unless someone actively removes the configuration.

The first ten percentage points are cheap. Modern web servers, load balancers, and VPN concentrators on current operating systems already support hybrid ML-KEM key exchange. Enabling it is largely a configuration change --- no code deployment, no application modification. The hard part is the long tail: legacy systems, embedded devices, and third-party services you do not control.

If this number is not moving, nothing else matters. You are adding to the harvest pile every day.

## Metric 2: Share of Certificates Issued and Renewed Without a Human

This is your automation score. It answers a different question: **can you rotate your cryptographic estate when you need to?**

This metric looks like it belongs to a different conversation --- certificate lifecycle management, not quantum computing. It belongs here because automation is the prerequisite for everything that follows. Without it, PQC migration at Commonwealth scale is not difficult. It is [arithmetically impossible](/posts/encryption-on-borrowed-time/#phase-2-certificate-automation).

Here is why:

**The 47-day test.** [CA/Browser Forum ballot SC-081v3](https://cabforum.org/2025/04/14/ballot-sc-081v3/) mandates 47-day maximum TLS certificate lifetimes by March 2029. That is eight renewals per year, per certificate, across every public-facing service. If your automation score is zero --- if every certificate renewal requires a human to file a ticket, generate a CSR, submit it, download the certificate, install it, and verify it --- you will not survive 47-day lifetimes. You will have outages. Resident-facing outages, on services that issue benefits and collect taxes.

**The algorithm rotation test.** When you are ready to change the cryptographic algorithm --- from RSA to ML-DSA, or from one post-quantum algorithm to the next one after it --- the mechanism is a certificate profile change on the CA. The new algorithm takes effect at the next renewal. If renewal is automated, the entire estate rotates within one certificate lifetime. If renewal is manual, the rotation takes however long it takes to file and close every ticket, which at Commonwealth scale is measured in years.

**The crypto agility test.** [FIPS 206](https://csrc.nist.gov/pubs/fips/206/ipd) (FN-DSA) and HQC are already queued behind ML-KEM and ML-DSA. This is not the last cryptographic transition. It is the first one you do deliberately. Your automation score measures whether the next transition is a policy change or another emergency program.

If this number is high, PQC migration is a configuration change. If it is low, PQC migration is a multi-year project that competes for budget with everything else. The difference between those two outcomes is decided by the automation you build now, not by the algorithm you choose later.

## Why These Two and Not Others

There are many things worth measuring during a PQC migration. Inventory completion matters. Vendor compliance matters. Training matters. Risk assessments matter. None of them should be your executive metric, because they measure preparation, not protection.

Metric 1 measures actual protection. Traffic is either on post-quantum key exchange or it is not. There is no partial credit.

Metric 2 measures operational capability. You can either rotate your certificates without human intervention or you cannot. The capability is binary; the metric tracks how much of your estate has it.

Together, they cover the two problems:

| Metric | Threat | Question |
|--------|--------|----------|
| PQC key exchange share | HNDL | Are you stopping the bleeding? |
| Automated certificate share | TNFL (and operational readiness) | Can you rotate when you need to? |

Everything else is a leading indicator for one of these two. Inventory completion is a leading indicator for key exchange deployment. Vendor compliance is a leading indicator for automation coverage. Track those in your project plan. Report these two to leadership.

## The Governance Argument

These metrics survive turnover because they are simple enough to explain in one sentence each:

- "What share of our traffic is protected against quantum decryption?"
- "What share of our certificates renew themselves?"

A new CIO, a new CISO, a new administration can understand what the numbers mean and whether they are going in the right direction without reading a briefing document. That is not a minor property. Programs that require institutional knowledge to interpret their own metrics die when the people with that knowledge leave.

Report them quarterly. Resist the urge to add more. The moment you add a third metric, you have started building the dashboard nobody reads. Two numbers, every quarter, until both are close to 100%. Then you are done --- not with security, but with the PQC transition specifically. And the automation you built to get the second number to 100% is the standing capability that handles whatever comes next.

---

*This is the final post in a series based on my [PA TechCon 2026](/posts/encryption-on-borrowed-time/) talk. The series covered [the TNFL threat](/posts/trust-now-forge-later/), [procurement as the cheapest lever](/posts/fix-procurement-first/), and [the local government gap](/posts/the-part-with-no-ciso/). If your organization is working on PQC migration planning, I am happy to discuss --- reach me at czinda@redhat.com.*

## References

1. CA/Browser Forum, ["Ballot SC-081v3: Reducing TLS Certificate Lifetimes,"](https://cabforum.org/2025/04/14/ballot-sc-081v3/) April 2025.

2. NIST, ["FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM),"](https://csrc.nist.gov/pubs/fips/203/final) August 2024.

3. NIST, ["FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA),"](https://csrc.nist.gov/pubs/fips/204/final) August 2024.

4. NIST, ["FIPS 206 (Initial Public Draft): Federal Information Processing Standard for FN-DSA,"](https://csrc.nist.gov/pubs/fips/206/ipd) 2024.
