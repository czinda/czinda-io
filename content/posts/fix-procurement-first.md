---
title: "Fix Procurement First: The Cheapest PQC Migration Move You Can Make"
date: 2026-09-08
draft: false
tags: ["post-quantum", "pqc", "procurement", "government", "cbom", "crypto-agility", "pa-techcon"]
description: "Six contract clauses that cost a paragraph, protect you for a decade, and do more for post-quantum readiness than any product you could buy this fiscal year."
---

This is the third post in a series on post-quantum migration for state and local government, based on a talk I gave at [PA TechCon 2026](/posts/encryption-on-borrowed-time/). The [first post](/posts/encryption-on-borrowed-time/) covers the full migration plan. The [second](/posts/trust-now-forge-later/) explains why the trust integrity threat (TNFL) should set your calendar. This one is about the cheapest thing on the entire list.

Every migration conversation I have with a government agency eventually arrives at the same obstacle: "There is no budget this fiscal year." The answer is always the same. The highest-leverage move you can make for post-quantum readiness does not require budget. It requires a paragraph in your solicitation templates.

## Why Procurement Is the Lever

Anything you are buying right now --- an elections platform, a benefits system, a fleet of roadside devices, a managed security service --- is a system you will still be running in 2035. That is not speculation. Government IT procurement cycles are long, deployments are slow, and replacement timelines stretch to a decade or more. A PennDOT signal cabinet installed next year has a twenty-year service life. A benefits platform under a seven-year contract will still be processing Medicaid claims when [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd) disallows classical algorithms entirely.

The contract you sign this year is a cryptographic decision, whether or not anyone in the room calls it one.

And procurement has a structural advantage that no technical project can match: it operates at the point of maximum leverage. You have bargaining power before you sign. After you sign, the same requirement becomes a change order --- and change orders cost real money.

## The Six Clauses

Here are six requirements you can add to every solicitation in flight. None of them require you to understand the cryptography. All of them protect you for the life of the contract.

### 1. Require NIST PQC Algorithms --- or a Dated Roadmap

Require support for ML-KEM ([FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)) and ML-DSA ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)), the two post-quantum algorithms NIST finalized in August 2024. If the vendor cannot deliver today, require a contractual commitment with a specific date --- not "when available" or "on our roadmap," but a quarter and a year, with a remedy if they miss it.

The distinction matters. "We support post-quantum cryptography" is a press release. "ML-KEM-768 and ML-DSA-65 are available in release 4.2, shipping Q1 2027" is a commitment you can hold someone to.

### 2. Require FIPS 140-3 Validated Cryptographic Modules

FIPS 140-2 sunsets in [September 2026](https://csrc.nist.gov/projects/cryptographic-module-validation-program). After that date, new validations are FIPS 140-3 only. Ask the vendor two questions:

1. What is the CMVP certificate number for the cryptographic module your product uses?
2. Where does the product currently sit in the validation queue?

The first question separates vendors who have done the work from vendors who are using the word "FIPS" as an adjective. The second catches vendors who have submitted but are waiting --- CMVP validation timelines run twelve to eighteen months, and knowing where they are in the queue tells you whether their timeline is real.

### 3. Require a Cryptographic Bill of Materials

A CBOM lists every cryptographic algorithm, key size, protocol version, and certificate in the product. Require it at delivery and at every major release.

The concept mirrors the software bill of materials (SBOM) that federal guidance has normalized over the past several years, but applied specifically to cryptography. A CBOM answers the questions that matter for migration planning:

- What algorithms does this product use, and where?
- What key sizes and protocol versions are configured?
- Are there hardcoded cryptographic parameters that cannot be changed without a code release?
- What certificates does it ship with, and who issued them?

Federal guidance on minimum CBOM elements is in flight. You do not need to wait for it. Ask for a CBOM now, accept whatever format the vendor provides, and refine the requirement as standards mature. The act of asking forces the vendor to inventory their own cryptographic dependencies --- which most have not done.

### 4. Require Crypto Agility as a Design Requirement

Crypto agility means the product can change cryptographic algorithms without a re-architecture or a change order. This is a design property, not a feature flag. It means:

- Algorithm selection is configuration, not compiled-in
- Certificate profiles can be updated without a software release
- Key exchange and signature algorithms can be changed independently
- The product does not hardcode assumptions about key sizes, signature lengths, or certificate chain depths

Why this matters beyond PQC: [FIPS 206](https://csrc.nist.gov/pubs/fips/206/ipd) (FN-DSA, based on FALCON) and HQC are already queued behind ML-KEM and ML-DSA. The post-quantum transition is not the last cryptographic change you will make --- it is the first one you are doing deliberately. A product that requires a re-architecture to change algorithms will require another re-architecture for the next transition, and the one after that.

Crypto agility also makes the [47-day certificate mandate](https://cabforum.org/2025/04/14/ballot-sc-081v3/) manageable. When algorithm changes are a policy edit that propagates on the next renewal cycle, rotating the entire certificate estate becomes routine rather than emergency.

### 5. Require Remote Update Capability for Field-Deployed Equipment

Anything deployed in the field with a trust anchor inside it --- a traffic signal cabinet, a water treatment controller, an emergency radio, a smart meter --- must be remotely updatable. If it cannot receive a firmware update, a certificate rotation, or a trust root replacement without a physical site visit, you are creating a problem that will outlast the person who signed the contract.

This is the requirement that prevents the PennDOT scenario: a signal cabinet installed in 2027 with a pinned classical trust root and no remote update path is a 2042 problem. By then, the trust root may be forgeable, and the only remediation is to dispatch a truck to every intersection in the Commonwealth. That cost dwarfs whatever the remote update capability would have added to the unit price.

For constrained devices that genuinely cannot support remote update --- and some exist --- the contract should explicitly acknowledge the limitation and specify the replacement timeline.

### 6. Add a Right-to-Test Clause

You should be able to verify a vendor's cryptographic claims, not merely receive them. A right-to-test clause gives you the ability to:

- Run your own validation against the vendor's FIPS claims
- Test algorithm negotiation and fallback behavior
- Verify that the CBOM matches what is actually deployed
- Confirm that crypto agility works in practice, not just in documentation

Vendor attestation without a test is a press release. The right-to-test clause is what turns a checkbox into evidence. It also changes the vendor's incentive: claims that will be tested tend to be more accurate than claims that will only be reviewed.

## The FAR Council Tailwind

The FAR Council was directed under [EO 14412](https://www.whitehouse.gov/briefing-room/presidential-actions/) to propose a rule requiring covered contractors to meet PQC FIPS standards by the end of 2030. That means every vendor selling to the federal government is rebuilding their cryptographic stack right now, on their own dime, to meet a deadline that is already binding.

State and local government can inherit this work for free. The vendors are doing the engineering regardless. Adding PQC requirements to your solicitations does not force them to do something new --- it forces them to deliver to you what they are already building for their federal customers. The alternative is waiting until your current contract expires, issuing a new solicitation, and paying for the capability as a line item that the vendor has been shipping to other customers for years.

Ask now, while you have leverage. The same requirement issued as a change order in 2029 will cost real money and come with a timeline you do not control.

## Making It Survive Turnover

The single biggest risk to a procurement-based strategy is that it depends on someone remembering to include the clauses. People change jobs. Administrations turn over. The person who understood why these clauses matter will not be there in four years.

The fix is institutional, not personal:

**Standard templates.** Add the six clauses to the master solicitation template at the enterprise level (OA/OIT for Pennsylvania, or the equivalent central IT authority in your state). Every agency inherits them by default. Opting out requires a justification, not opting in.

**Named deliverable.** Make the CBOM a named deliverable in the contract, not a nice-to-have in the technical requirements. Named deliverables get tracked. Nice-to-haves get forgotten.

**Periodic review.** As NIST finalizes additional algorithms (FN-DSA, HQC) and federal CBOM guidance matures, the template needs to be updated. Assign that to a role, not a person.

The goal is a procurement process that enforces cryptographic readiness without anyone having to think about it. The clauses become boilerplate --- and boilerplate outlasts everyone.

## What This Looks Like in Practice

A vendor responds to your solicitation. You open their proposal and check:

| Requirement | What You See | What It Tells You |
|---|---|---|
| PQC algorithms | "ML-KEM-768 in TLS 1.3, ML-DSA-65 for code signing, GA in release 5.0 Q2 2027" | Real commitment with a verifiable date |
| FIPS 140-3 | "CMVP certificate #4812, aws-lc v2.1" | Validated, not just claimed |
| CBOM | A structured document listing every algorithm, key size, protocol, and certificate | They have inventoried their own crypto --- most have not |
| Crypto agility | "Algorithm selection via configuration file; no recompile required" | You can rotate without a change order |
| Remote update | "OTA firmware, certificate rotation via EST, trust root update via secure boot chain" | You will not be dispatching trucks in 2035 |
| Right-to-test | "Customer may conduct independent cryptographic validation annually" | Their claims will be tested, so they tend to be true |

Now compare that to a vendor who responds with: "We take security seriously and are committed to supporting post-quantum cryptography as standards evolve." That sentence means nothing. It is not a commitment, it is not testable, and it will not protect you.

The six clauses are how you tell the difference.

## The County and Municipal Problem

These clauses solve the state-level procurement problem. But Pennsylvania has sixty-seven counties, five hundred school districts, and twenty-five hundred municipalities. They are not going to draft their own PQC procurement language --- and they should not have to.

The Commonwealth's responsibility is to publish model contract language that locals can adopt verbatim. A borough water authority should be able to copy six clauses into their next SCADA vendor solicitation without understanding the cryptography behind them. That is the template obligation described in [The Part With No CISO](/posts/pqc-the-part-with-no-ciso/), and procurement language is the most concrete form it takes.

## Start This Week

If you are in state or local government procurement, here is what you can do before Friday:

1. **Pull your master solicitation template.** Find the section on security or technical requirements.
2. **Add the six clauses.** Copy them, adapt the language to your format, and get them into the template.
3. **Review solicitations currently in flight.** If any are still in draft or pre-release, add the clauses now. If they have already been issued, note them for the next renewal.
4. **Ask your three largest incumbent vendors** for their PQC roadmap in writing. Not a slide deck --- a document with dates, algorithm names, and FIPS references. The response (or lack of one) will tell you everything you need to know.

None of this requires a budget line. None of it requires cryptographic expertise. It requires the willingness to add a paragraph to a document you are already writing.

## References

1. NIST, ["FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM),"](https://csrc.nist.gov/pubs/fips/203/final) August 2024.

2. NIST, ["FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA),"](https://csrc.nist.gov/pubs/fips/204/final) August 2024.

3. NIST, ["IR 8547: Transition to Post-Quantum Cryptography Standards,"](https://csrc.nist.gov/pubs/ir/8547/ipd) Initial Public Draft, November 2024.

4. NIST, ["FIPS 206: Fast-Fourier Lattice-Based Compact Signatures over NTRU (FN-DSA),"](https://csrc.nist.gov/pubs/fips/206/ipd) Initial Public Draft, 2025.

5. CA/Browser Forum, ["Ballot SC-081v3: Reducing TLS Certificate Lifetimes,"](https://cabforum.org/2025/04/14/ballot-sc-081v3/) April 2025.

6. NIST, ["Cryptographic Module Validation Program (CMVP),"](https://csrc.nist.gov/projects/cryptographic-module-validation-program) --- FIPS 140-2 sunset and 140-3 transition timeline.

---

*This is the third post in a series on post-quantum migration for state and local government. Previous: [Encryption on Borrowed Time](/posts/encryption-on-borrowed-time/) and [Trust Now, Forge Later](/posts/trust-now-forge-later/). Next: [The Part With No CISO](/posts/pqc-the-part-with-no-ciso/). Reach me at czinda@redhat.com.*
