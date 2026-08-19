---
title: "The Part With No CISO: PQC Migration for Counties, School Districts, and Small Utilities"
date: 2026-09-15
draft: false
tags: ["post-quantum", "pqc", "government", "counties", "school-districts", "critical-infrastructure", "scada", "certificates", "procurement", "pa-techcon"]
description: "Post-quantum cryptographic migration fails at the local level unless the state publishes the template, the standard, and the contract language — because a borough water authority is never going to staff a cryptographer."
---

This is the fourth post in a series drawn from a talk I gave at [PA TechCon 2026](/posts/encryption-on-borrowed-time/). The first post covered the full migration plan. This one focuses on the part of the problem that keeps me up at night: the thousands of local entities that connect to state systems as trusted peers and have no realistic path to running their own post-quantum migration.

The numbers for Pennsylvania are specific, but the shape of the problem is universal. Every state has it.

## The Numbers

Pennsylvania has 67 counties, roughly 500 school districts, over 2,500 municipalities, and a constellation of authorities, transit agencies, and special-purpose entities. Between them, they employ approximately zero cryptographers.

These are not organizations that have a CISO who deprioritized PQC. They are organizations that do not have a CISO. Many do not have a dedicated security function at all. The county IT director is also the help desk, the network administrator, and the person who drives to the remote office when the router dies. The school district's technology coordinator is managing a one-to-one device fleet, a student information system, and a building automation controller that was installed before they were hired.

Telling these organizations to "migrate to post-quantum cryptography" is not a useful instruction. It is the equivalent of telling them to build their own power plant because the grid is changing its frequency.

## They Are Already Connected to You

The reason this matters to the Commonwealth --- and to any state --- is that local entities are not isolated. They connect to state systems as trusted peers.

**County election systems** exchange data with the Department of State. Voter registration, election night reporting, ballot tracking --- all of it flows over connections that the state's security posture assumes are trustworthy.

**County 911 and dispatch** connect to statewide interoperable communications networks. Radio key material, CAD systems, and dispatch protocols all depend on cryptographic trust anchors that the county did not choose and cannot replace on its own.

**Police departments** connect to CLEAN --- the Commonwealth's gateway to NCIC and CJIS. Every municipal police department that runs a criminal history check is exercising a trust relationship that terminates at the state level.

**School districts** hold student records under [FERPA](https://www2.ed.gov/policy/gen/guid/fpco/ferpa/index.html) and connect to state reporting systems. A district's one-to-one Chromebook fleet, its student information system, and its cafeteria payment platform all carry data with statutory retention and privacy requirements.

**Municipal water and sewer authorities** run SCADA systems on decade-old control hardware. I wrote about [what happens when these systems lack cryptographic identity](/posts/securing-critical-infrastructure-certificate-identity/) in the context of the 2026 water system cyberattacks --- thirty-plus facilities compromised in a single weekend because PLCs were sitting on the public internet protected by default passwords. The attackers did not need a zero-day. They needed a shared password and a cellular modem.

The borough water authority that serves four thousand residents has the same class of exposure as the utility that serves four hundred thousand. It has none of the same resources.

## The Dual Argument

This is simultaneously an equity argument and a risk argument. They point in the same direction.

### The Equity Case

Local entities deliver the same public services that state agencies do --- often the same services, under delegation. A county human services office processes the same Medicaid applications that the state Department of Human Services oversees. A municipal police department enforces the same criminal code under the same CJIS requirements. A borough water authority is subject to the same Safe Drinking Water Act as a metropolitan utility.

These entities did not choose their cryptographic exposure. They inherited it from the protocols, platforms, and trust relationships that were designed at the state and federal level. Expecting them to independently navigate a cryptographic transition that the federal government is spending billions on is not a reasonable expectation. It is a policy gap.

### The Risk Case

Their weakest trust anchor becomes yours. In a federated system, the security of the whole is bounded by the security of the least-capable participant. A county that continues to authenticate against a state system with a classical certificate after the state has migrated to post-quantum is not just a county problem --- it is a state problem. The trust relationship is bidirectional, and a forged credential from a compromised county system is indistinguishable from a legitimate one.

This is the Trust Now, Forge Later (TNFL) threat at the local level. An attacker who can derive a signing key from a county CA's public key can forge certificates that the state's systems will accept. The county does not need to be the target --- it just needs to be the weakest link in a chain that terminates at something valuable.

## What They Actually Need

Local entities do not need a PQC migration program. They need a template they can consume.

### A Published Standard

The state publishes a cryptographic standard that local entities adopt. Not a suggestion, not a best-practice document --- a standard that is referenced in grant conditions, data-sharing agreements, and the contracts that govern access to state systems. The standard specifies:

- Which algorithms are acceptable and which are deprecated, with dates
- Minimum certificate and key management requirements
- CBOM (cryptographic bill of materials) expectations for vendor procurements
- A timeline that aligns with the state's own migration phases

### A Shared Service

The most effective model is a shared PKI and certificate automation service that local entities consume. The state operates a certificate authority and an enrollment infrastructure --- [ACME](https://www.rfc-editor.org/rfc/rfc8555) for servers and services, [EST](https://www.rfc-editor.org/rfc/rfc7030) for devices --- and local entities enroll their systems into it. The local IT director does not need to understand ML-DSA or certificate profiles. They need to run an enrollment command and confirm that their system joined the domain.

This is the same model that works for identity management today. A county does not run its own Kerberos realm. It joins the state's identity domain, inherits the policies, and gets on with its actual job. PQC migration should work the same way.

### Model Contract Language

Every solicitation a county or school district issues should include PQC-ready language. But a county solicitor is not going to draft cryptographic procurement clauses from scratch. The state publishes [model contract language](/posts/fix-procurement-first/) --- the six clauses I outlined in the procurement post --- and local entities copy them into their RFPs.

This is the cheapest intervention on the entire list. A paragraph in a template that gets reused across thousands of procurements costs the state one afternoon of legal review and saves the local entities from buying systems in 2026 that will be cryptographically obsolete by 2030.

### Vendor Coordination

Local entities buy from a surprisingly small number of vendors. The same three or four companies supply election management systems, student information systems, CAD and dispatch platforms, and SCADA controllers to counties, school districts, and municipalities across the state. The state has leverage that individual local entities do not.

A coordinated conversation with those vendors --- requiring PQC roadmaps, FIPS 140-3 validation timelines, and CBOM commitments --- has a multiplier effect. One conversation with a major election system vendor covers all 67 counties. One conversation with a major SIS vendor covers most of the 500 school districts. The alternative is 567 individual conversations that never happen.

## The SCADA Problem Is Already Here

The [water system cyberattacks of July--August 2026](/posts/securing-critical-infrastructure-certificate-identity/) demonstrated what happens when small utilities operate critical infrastructure without cryptographic identity. PLCs exposed on the public internet, authenticated by default passwords, with no certificates, no mutual authentication, no network segmentation, and no integrity verification.

The PQC dimension makes this worse. Even if those utilities had deployed certificate-based identity --- which they should --- those certificates are anchored on classical algorithms that will eventually be broken by a quantum computer. The borough water authority that just completed a painful upgrade to mTLS on its SCADA network will need to rotate those trust anchors to post-quantum algorithms within a decade.

The shared service model solves both problems at once. A state-operated certificate authority that supports both classical and hybrid post-quantum certificates gives local utilities a single enrollment point that handles the algorithm transition as a policy change. The utility enrolls once. The algorithm upgrade happens on the CA side, and the utility's certificates rotate automatically on the next renewal cycle.

## The Operating Model

The [operating model](/posts/encryption-on-borrowed-time/#an-operating-model-that-survives-turnover) from the main PA TechCon post assigns local entities one role: **consume a published template and a shared service**. That is deliberate.

Do not ask a borough water authority to run a cryptographic migration program on its own. Do not ask a school district with three IT staff to evaluate ML-KEM versus ML-DSA. Do not ask a county 911 center to stand up a PQC-capable certificate authority. These are not things those organizations can do, and pretending otherwise is a plan that fails on contact with reality.

The [two metrics that matter](/posts/two-metrics-that-matter/) --- percent of traffic on post-quantum key exchange, and percent of certificates issued without a human --- apply to local entities as much as they apply to state agencies. But the local entities can only hit those numbers if the state has given them the infrastructure to do so.

## What States Owe Their Locals

Every state has this problem. The numbers vary --- Pennsylvania's 67 counties and 2,500 municipalities might be another state's 100 counties and 400 cities --- but the structure is the same. Local entities connect to state systems, hold sensitive data, operate critical infrastructure, and lack the expertise to navigate a cryptographic transition.

The state's obligation is fourfold:

1. **Publish the standard.** Algorithms, timelines, deprecation dates. Reference it in every data-sharing agreement.
2. **Operate the shared service.** A certificate authority and enrollment infrastructure that local entities join, not build.
3. **Provide model contract language.** Six clauses that local procurement offices copy into their RFPs.
4. **Coordinate with shared vendors.** Use the state's purchasing leverage to get PQC commitments from the vendors that serve hundreds of local entities.

If the state does these four things, local PQC migration becomes a configuration change. If the state does not, it does not happen --- and the state inherits the risk of every unprotected local trust anchor.

That is not a criticism of local government. It is arithmetic.

## References

1. NIST, ["FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM),"](https://csrc.nist.gov/pubs/fips/203/final) August 2024.

2. NIST, ["FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA),"](https://csrc.nist.gov/pubs/fips/204/final) August 2024.

3. IETF, ["RFC 8555: Automatic Certificate Management Environment (ACME),"](https://www.rfc-editor.org/rfc/rfc8555) March 2019.

4. IETF, ["RFC 7030: Enrollment over Secure Transport (EST),"](https://www.rfc-editor.org/rfc/rfc7030) October 2013.

5. U.S. Department of Education, ["Family Educational Rights and Privacy Act (FERPA),"](https://www2.ed.gov/policy/gen/guid/fpco/ferpa/index.html) 20 U.S.C. § 1232g.

6. CISA, ["Advisory AA26-097A: CyberAv3ngers Targeting PLCs Across Critical Infrastructure,"](https://www.cisa.gov/news-events/cybersecurity-advisories) 2026.

---

*This is the fourth in a series drawn from a talk at [PA TechCon 2026](https://www.patechcon.com/). Previous: [Fix Procurement First](/posts/fix-procurement-first/). Next: [Two Metrics That Matter](/posts/two-metrics-that-matter/). For the full migration plan, start with [Encryption on Borrowed Time](/posts/encryption-on-borrowed-time/).*
