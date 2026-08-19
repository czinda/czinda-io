---
title: "Encryption on Borrowed Time: A PQC Migration Plan for State Government"
date: 2026-08-25
draft: false
tags: ["post-quantum", "pqc", "ml-kem", "ml-dsa", "certificates", "pki", "government", "procurement", "mosca", "47-day", "pa-techcon"]
description: "Pennsylvania's data has a shelf life measured in decades. The encryption protecting it has a shelf life measured in years. A migration plan for state and local government, from a talk at PA TechCon 2026."
---

I gave this talk at [PA TechCon 2026](https://www.patechcon.com/) in Harrisburg on August 13. The audience was Pennsylvania state and local government IT leaders --- CIOs, CISOs, procurement officers, and the county IT directors who keep the lights on with two-person teams. The premise fits in one sentence: Pennsylvania's data has a shelf life measured in decades, and the encryption protecting it has a shelf life measured in years. Nobody has done the subtraction.

This post is the long version of that talk. I should be upfront: I build certificate infrastructure for a living, so discount me accordingly. But the plan holds regardless of whose product you buy.

## The Two Threats

Most coverage of post-quantum risk focuses on one threat. There are two, and they require different fixes on different timelines.

### Harvest Now, Decrypt Later (HNDL)

HNDL is a confidentiality attack, and it has already started. The adversary passively records encrypted traffic off the wire --- VPN tunnels, TLS sessions, site-to-site IPsec. No breach, no alarm, no log entry, no SIEM alert, no notification obligation triggered. The ciphertext goes into storage, where it sits until a cryptographically relevant quantum computer (CRQC) can run [Shor's algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm) against the recorded key exchange and recover the session keys.

The mechanics are worth understanding:

1. **Every session begins with a public handshake.** Before any data moves, the two ends negotiate a shared secret using RSA or Elliptic-Curve Diffie-Hellman. That negotiation travels in the clear --- it is designed to. Anyone on the path can record it verbatim.

2. **The bulk data is protected by AES, and AES holds up.** Symmetric encryption survives the quantum transition. Grover's algorithm roughly halves the effective key strength, so AES-256 remains sound. The cipher is not the problem.

3. **The handshake is the weak link.** Shor's algorithm factors the RSA modulus or solves the elliptic-curve discrete logarithm in polynomial time. That yields the private key, which unwraps the session key from the recording.

4. **So the recording decrypts itself the day the machine exists.** The adversary never had to break anything in real time --- only be patient and buy disks.

"We will upgrade when quantum arrives" is not a strategy. By then the data is already gone.

### Trust Now, Forge Later (TNFL)

TNFL is the one that should worry you more, and it gets far less attention. HNDL steals your secrets. TNFL steals your identity.

The same mathematics that breaks a key exchange also breaks a digital signature. A certificate authority's public key is distributed to every device that has to trust it --- that publication is the feature, and it is also the attack surface. Shor's algorithm derives the private key from the published public key. No malware, no insider, no stolen HSM --- just arithmetic performed on a value you handed out on purpose.

The attack chain has no intrusion step:

1. **Map.** Catalog the PKI hierarchy --- root CAs, intermediates, trust chains. All of it is published deliberately.
2. **Break.** Derive the CA's private key from its public key. The public key was distributed by design.
3. **Forge.** Mint certificates that validate perfectly. The signatures are mathematically correct and the chains build cleanly.
4. **Impersonate.** Rogue devices join networks. Signed updates install silently. Federation tokens are accepted. mTLS stops meaning anything.

There is no forensic tell. A forged certificate and a real one are the same object. You cannot distinguish them after the fact.

The asymmetry between the two threats matters for planning. HNDL damage is bounded by what you have already sent --- it is retrospective. TNFL damage is unbounded going forward --- it is prospective. And the remediation window for TNFL closes *before* the attack becomes possible, not after. You must replace trust roots on every device that pins them, including field equipment with a fifteen-year life and no remote update path. That work has to finish before the capability exists.

### Side by Side

| | HNDL | TNFL |
|---|---|---|
| **Target** | Confidentiality | Trust and authentication |
| **Posture** | Passive --- intercept and store | Active --- forge and impersonate |
| **What breaks** | Key exchange (RSA / ECDH) | Signatures (RSA / ECDSA) |
| **Damage** | Retroactive: past traffic exposed | Prospective: enables future attacks |
| **Fix** | ML-KEM ([FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)) | ML-DSA ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)) |

Both fixes ride the same automation. One inventory, one certificate platform, one set of procurement clauses covers both.

## Mosca's Theorem: The Arithmetic That Ends the Argument

[Michele Mosca](https://uwaterloo.ca/institute-for-quantum-computing/profiles/michele-mosca) at the University of Waterloo gave us the only formula this topic needs. It has three variables:

- **X** --- Data shelf life. How long the information must stay confidential, set by statute, retention schedule, or the harm caused if it surfaces.
- **Y** --- Migration time. How long to inventory, plan, procure, test, and re-key everything you own. Measured in years, not sprints.
- **Z** --- Time to a cryptographically relevant quantum computer. Nobody knows this precisely, and every revision has moved it closer.

The theorem: **if X + Y > Z, the data you are encrypting today is already compromised.** The decryption is simply scheduled for later.

Every room I present this in gets stuck debating Z --- is it ten years, twenty, never? Mosca's move is that you do not need to win that argument. X and Y are things you already know and control. If X + Y exceeds any plausible estimate of Z, the answer is the same regardless of which estimate you believe.

Two implications:

1. **The deadline is not when quantum arrives. It is quantum arrival minus Y.** You have to be finished migrating by then, so your real due date is years earlier than the one in the headlines.

2. **Y is the only variable you control.** X is fixed by statute and by harm. Z is fixed by physics and someone else's research budget. Y is a function of inventory and automation --- which is the entire back half of this post.

### Applied to Pennsylvania

How long must Commonwealth data stay confidential?

| Retention | Examples |
|-----------|----------|
| **Lifetime and beyond** | Criminal history, child welfare and sealed juvenile files, vital records, adoption records |
| **50--75 years** | Medicaid and benefit case files, SERS and PSERS pension records, driver histories, voter registration |
| **7--25 years** | Tax filings and federal tax information, unemployment compensation wage records, procurement files |

Run the numbers on one Medicaid record. X is roughly fifty years --- that record must stay confidential for the beneficiary's life and beyond. Y is three to five years for an agency that size, and that assumes it starts now. Z, on current estimates, is somewhere in the early-to-mid 2030s. Fifty plus five lands decades past any plausible Z.

The protection on a record created this week has already failed. We simply have not observed it yet.

## The Ground Moved in 2026

Most migration plans in government are written against 2035, the year NIST IR 8547 disallows classical algorithms from all NIST standards. That date stopped being the binding constraint this year.

| Timeline | Deadline | Source |
|----------|----------|--------|
| **Jan 2027** | No new National Security System acquisitions without PQC support | [CNSA 2.0](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF) |
| **Mar 2029** | 47-day maximum public TLS certificate lifetimes | [CA/B Forum SC-081v3](https://cabforum.org/2025/04/14/ballot-sc-081v3/) |
| **Dec 2030** | PQC key establishment for federal high-value systems | [EO 14412](https://www.whitehouse.gov/briefing-room/presidential-actions/) |
| **Dec 2031** | PQC digital signatures | EO 14412 |
| **2029** | Complete PQC migration across Google | [Google Security Blog, March 25, 2026](https://security.googleblog.com/) |
| **2035** | Classical algorithms disallowed from all NIST standards | [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd) |

Google's date carries particular weight. They build the quantum hardware *and* the browser. When that company pulls its own migration target in by six years and publishes the reasoning, that is a statement about the physics, not a market position. They had nothing to sell by saying it.

And 2029 appears twice: Google's completion target and the year 47-day certificates take full effect. The automation you build for one is the automation you need for the other.

## The Commonwealth Blast Radius

### The Shared Layer

Before individual agencies, four things OA/OIT own on everyone's behalf:

- **Commonwealth network.** Site-to-site IPsec between Harrisburg and every regional office, VPN concentrators, remote access for a hybrid workforce. All HNDL collection targets today.
- **Identity and federation.** Enterprise directory, single sign-on, federation tokens, MFA, employee credentials. Signature-based, and therefore squarely a TNFL target.
- **Enterprise PKI.** Whatever issues certificates for internal services today. This is simultaneously the largest TNFL exposure and the lever that fixes it.
- **Code and config signing.** Software distribution, patch pipelines, device management. A forged signing key installs whatever the attacker likes, statewide, silently.

One enterprise decision here is worth forty agency projects. Fix the CA and the automation once and every agency inherits it. Skip it and forty agencies each build a worse version of the same thing.

### The Largest Data Custodians

**Human Services** --- Medicaid claims, benefit case files, child welfare, long-term care. HIPAA plus CMS data flows to federal partners already on the 2030 clock.

**Health** --- Vital records with century-long retention, disease surveillance, the immunization registry, hospital reporting. HNDL exposure with no expiry.

**Revenue** --- Personal and business tax filings, e-file channels to the IRS, and Federal Tax Information governed by [IRS Publication 1075](https://www.irs.gov/privacy-disclosure/safeguards-program).

**PennDOT** --- Driver and vehicle records, REAL ID source documents, and tens of thousands of field devices --- signals, ITS cabinets, roadside units --- on fifteen-to-twenty-year service lives. A signal cabinet installed in 2027 with a pinned trust root and no remote update path is a 2042 problem you are creating today, with this year's budget, under a contract somebody is signing this quarter.

**State Police** --- CLEAN, the Commonwealth's gateway to NCIC and CJIS. Criminal history is lifetime-sensitive, and CJIS encryption rules will move with federal policy.

**Department of State** --- Voter registration, election night reporting, notary and professional licensure, campaign finance. Integrity-critical and highly visible.

**Treasury** --- Payment files, banking and ACH channels, unclaimed property. Signature integrity is the entire control --- a forged signing key is a forged payment.

**PEMA** --- Emergency communications, statewide interoperable radio key material, public alerting. Long-lived keys inside equipment that is physically hard to reach.

**DEP** --- Air and water monitoring telemetry, plus oversight of drinking-water and wastewater operators running SCADA on decade-old control hardware.

If your agency is not on this list, that is a slide-space problem, not a risk assessment.

### The Part with No CISO

Sixty-seven counties. Five hundred school districts. Twenty-five hundred municipalities. Between them, approximately zero cryptographers.

They connect to Commonwealth systems as trusted peers. Their weakest trust anchor becomes yours. A borough water authority is never going to staff a PQC migration. That is not a criticism --- it is arithmetic.

If the Commonwealth does not publish the template, the standard, and the contract language, this does not happen at the local level. Full stop.

### The Mandates Reach You Anyway

The objection I get every time: "None of these federal mandates apply to Pennsylvania directly." True. Also irrelevant.

**Through the data you receive.** CJIS for CLEAN and every police department behind it. IRS Publication 1075 for Federal Tax Information at Revenue. CMS and HIPAA for Human Services and Health. SSA exchange agreements for Labor & Industry. When the federal side moves its encryption requirements, your interface moves too, or it stops working.

**Through the money you accept.** Federal grant conditions and cooperative agreements carry security terms. As agencies rewrite those against EO 14412, PQC language lands in the grant --- and the grant lands on you.

**Through the vendors you buy from.** The FAR Council was directed to propose a rule requiring covered contractors to meet PQC FIPS by the end of 2030. Your vendors are rebuilding for that clock right now. You can inherit it for free by asking, or pay for it later as a change order.

**Through the browsers your residents use.** [CA/Browser Forum ballot SC-081v3](https://cabforum.org/2025/04/14/ballot-sc-081v3/) cuts public TLS certificate lifetimes to 47 days by March 2029, enforced by Chrome, Safari, and Firefox. Every public-facing pa.gov service is in scope, and there is no waiver.

Pennsylvania does not need its own quantum mandate. It has already inherited about six of them.

## How to Prepare

### Phase 0: The Next 90 Days

Three things. Two of them are free.

**Name a PQC migration lead.** One person per agency, reporting to the agency CIO, with a matching enterprise role at OA/OIT. Mirroring the federal model makes every later conversation with a federal partner easier. This costs a title, not a budget line.

**Inventory the cryptography.** Every certificate, key store, TLS endpoint, VPN tunnel, signing key, and HSM. Algorithm, key size, expiry, owner, and what breaks when it changes. Nobody has this today, and everything downstream depends on it. Assume twelve to eighteen months to reach an inventory you actually trust --- discovery is the long pole, not the algorithm swap.

**Start requiring a CBOM.** A cryptographic bill of materials, from vendors and for internal builds. Federal guidance on minimum CBOM elements is in flight. Ask for it now rather than retrofitting it into contracts in 2029.

You cannot migrate what you cannot see.

### Phase 1: Risk-Rank by Shelf Life

Score every system on two axes: how long the data must remain confidential, and how long the system stays in service before natural replacement. High on both is your first wave.

Separate the confidentiality problem from the integrity problem. Anything transmitting long-retention data is an HNDL priority and gets ML-KEM key exchange. Anything anchoring trust --- CAs, signing keys, device identity, federation --- is a TNFL priority and gets ML-DSA. The lists are different, and so are their deadlines.

Flag everything you cannot reach twice. Field devices, embedded controllers, anything with a pinned trust root and no remote update path. These must be solved at procurement, because you will not be visiting them again before 2035.

Be honest about what you will simply retire. Some systems will not survive the migration, and should not. Naming them now converts a cryptography problem into a modernization business case you can actually fund.

### Phase 2: Certificate Automation

If certificate renewal is a ticket and a human, PQC migration at Commonwealth scale is not difficult. It is arithmetically impossible.

- **ACME** ([RFC 8555](https://www.rfc-editor.org/rfc/rfc8555)) for servers and services, **EST** ([RFC 7030](https://www.rfc-editor.org/rfc/rfc7030)) for devices and constrained hardware. Issue, renew, and revoke with no human in the loop.
- **Policy, not code.** Algorithm choice lives in a certificate profile on the CA. Changing the crypto suite becomes a policy edit that propagates on the next renewal cycle --- no code deployment, no device visit, no project.
- **A PQC-capable CA.** Whatever issues your internal certificates must support ML-KEM and ML-DSA, and whatever comes after them. Open standards keep the exit door open.
- **Hybrid by default.** Classical and post-quantum together through the transition. You gain PQC protection without betting everything on a young implementation.

### The 47-Day Forcing Function

[CA/Browser Forum ballot SC-081v3](https://cabforum.org/2025/04/14/ballot-sc-081v3/) has nothing to do with quantum, and it is going to hit you first:

| Date | Maximum Certificate Lifetime |
|------|------------------------------|
| March 2026 | 200 days |
| March 2027 | 100 days |
| **March 2029** | **47 days** |

That is eight renewals per year, per certificate, across every public-facing Commonwealth service. A missed renewal is an outage on a resident-facing site.

Here is the reframe that justifies the budget: you are being forced to build certificate automation regardless of anything I have said about quantum. Spend that money once and take crypto agility as a side effect. Short lifetimes turn every renewal into an upgrade opportunity. Change the algorithm in one profile and the estate rotates within 47 days, instead of waiting years for long certificates to age out.

### Fix Procurement First

If you do nothing else from this post, do this. It costs a paragraph.

1. Require NIST PQC algorithms --- ML-KEM ([FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)) and ML-DSA ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)) --- or a dated, contractual roadmap to them
2. Require FIPS 140-3 validated cryptographic modules, and ask where the product sits in the validation queue
3. Require a cryptographic bill of materials at delivery and at every major release
4. Require crypto agility as a design requirement: changing algorithms without a re-architecture or a change order
5. Require remote update capability for anything deployed in the field with a trust anchor inside it
6. Add a right-to-test clause --- you should be able to verify the claim, not merely receive it

Anything you are buying right now --- an elections platform, a benefits system, a fleet of roadside devices --- is a system you will still be running in 2035. The contract you sign this year is a cryptographic decision, whether or not anyone in the room calls it one.

## After Preparation

### Key Exchange First, Signatures Second

The order matters, and the right order is not the obvious one.

1. **Stop the bleeding (HNDL).** Turn on hybrid post-quantum key exchange everywhere traffic carries long-retention data. Every day it is switched on is a day of traffic that never enters the harvest pile. On modern stacks, this is largely a configuration change --- it is the fastest win available.

2. **Re-anchor trust (TNFL).** Migrate signing: CAs, code signing, device identity, federation. Harder --- larger keys and signatures, HSM firmware dependencies, embedded devices that need bigger certificates than they were designed to hold. Start at the roots and work outward.

3. **Retire the old algorithms.** Migration is not finished when PQC is enabled. It is finished when RSA and ECC are switched off. Leaving both running lets an attacker negotiate the weaker option. Plan the deprecation explicitly and test what breaks.

The federal deadlines encode this order: key establishment in 2030, signatures in 2031. That is not arbitrary --- it reflects the fact that signatures are the harder lift.

### Crypto Agility as a Standing Capability

What "done" actually looks like is not a date. It is an operating capability:

- The inventory is live, not a document. Continuously discovered, not surveyed once. If it is a spreadsheet somebody refreshes quarterly, it is already wrong.
- Algorithm changes are a policy edit. A certificate profile change that propagates on the next renewal cycle, not a project.
- You can answer "how fast could we rotate?" with an actual number. That number is the real measure of readiness.
- Procurement enforces it without anyone thinking about it. Standard clauses, standard CBOM expectations, standard test criteria.

[FIPS 206](https://csrc.nist.gov/pubs/fips/206/ipd) (FN-DSA) and HQC are already queued behind ML-KEM and ML-DSA. This transition is not the last one. It is the first one you do deliberately.

### An Operating Model That Survives Turnover

This has to survive an administration change, so it cannot depend on any one person continuing to care.

| Role | Responsibility |
|------|---------------|
| **OA / OIT** | Enterprise policy, the cryptographic inventory standard, the shared PKI and automation platform, model contract language |
| **Agency CIOs and ISOs** | A named PQC migration lead, inventory accuracy for their estate, system risk-ranking, a migration plan measured against the enterprise standard |
| **Procurement and Legal** | Standard clauses in every solicitation and renewal, CBOM as a named deliverable, vendor attestation held to a real test |
| **Counties and Locals** | Consume a published template and a shared service --- do not ask a borough water authority to run a cryptographic migration program on its own |

Report two numbers quarterly: **share of traffic on post-quantum key exchange**, and **share of certificates issued and renewed without a human**. Everything else is commentary. Two numbers a cabinet secretary can hold in their head will outlast any thirty-KPI dashboard nobody reads.

## 90 Days / 12 Months / 36 Months

| Next 90 Days | Within 12 Months | Within 36 Months |
|--------------|-------------------|-------------------|
| Name a PQC migration lead | An inventory you actually trust | PQC key exchange the statewide default |
| Open the cryptographic inventory | Systems risk-ranked by data shelf life | Trust roots re-anchored on PQC signatures |
| Add PQC and CBOM language to every solicitation in flight | Certificate automation in production on a real workload | Classical algorithm deprecation under way, with a date |
| Get your three largest vendors' roadmaps in writing | Hybrid key exchange piloted on your highest-retention flows | Template published for counties, districts, and authorities |

Two of the four items in the first column are free. Naming a lead costs a title. Adding contract language costs a paragraph.

---

Pennsylvania's data outlives Pennsylvania's encryption. That gap is the whole problem, and everything in this post is about closing it before somebody else measures it for you.

## References

1. NIST, ["FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM),"](https://csrc.nist.gov/pubs/fips/203/final) August 2024.

2. NIST, ["FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA),"](https://csrc.nist.gov/pubs/fips/204/final) August 2024.

3. NIST, ["FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA),"](https://csrc.nist.gov/pubs/fips/205/final) August 2024.

4. NIST, ["IR 8547: Transition to Post-Quantum Cryptography Standards,"](https://csrc.nist.gov/pubs/ir/8547/ipd) Initial Public Draft, November 2024.

5. NSA, ["CNSA 2.0: Commercial National Security Algorithm Suite,"](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF) September 2022.

6. CA/Browser Forum, ["Ballot SC-081v3: Reducing TLS Certificate Lifetimes,"](https://cabforum.org/2025/04/14/ballot-sc-081v3/) April 2025.

7. Michele Mosca, ["Quantum Computing: A New Threat to Cybersecurity,"](https://globalriskinstitute.org/publication/quantum-threat-timeline-report-2022/) Global Risk Institute, 2022.

8. IETF, ["RFC 8555: Automatic Certificate Management Environment (ACME),"](https://www.rfc-editor.org/rfc/rfc8555) March 2019.

9. IETF, ["RFC 7030: Enrollment over Secure Transport (EST),"](https://www.rfc-editor.org/rfc/rfc7030) October 2013.

---

*This post is adapted from a talk I gave at [PA TechCon 2026](https://www.patechcon.com/) in Harrisburg on August 13, 2026. The next post in this series --- [Trust Now, Forge Later: The PQC Threat Nobody Is Talking About](/posts/trust-now-forge-later/) --- goes deeper on why TNFL should set your migration calendar. If your organization wants to discuss PQC migration planning, I am happy to help --- reach me at czinda@redhat.com.*
