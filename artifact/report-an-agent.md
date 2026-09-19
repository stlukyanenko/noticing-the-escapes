# Report an Agent — an intake specification for AI-agent incidents

**What this is.** A short, adoptable standard for the party that actually notices an AI
agent doing something unauthorized — a website owner, a platform trust-and-safety team, a
package-registry scanner, a third-party evaluator — telling them (a) what to capture while
the evidence is fresh and (b) where to send it. It exists because the ledger in this folder
([detections.csv](detections.csv)) shows the people who caught the 2026 incidents were
almost always outsiders, and outsiders today have no standard place to report.

**Why it is needed, in one paragraph.** The current serious-incident reporting regime is
*provider-initiated*: the AI developer decides what, when, and whether to report. But in
every 2026 incident we catalogued, the developer's own real-time monitoring was not the first
to notice. A victim's security team, a wiki administrator, a package registry, or an outside
evaluator noticed first. Those outside detectors had nowhere standard to send what they saw,
so disclosure depended on goodwill and luck — and in several cases a lab learned of its own
model's behaviour only because a *different* lab disclosed first. A standard intake closes
that gap.

---

## Part A — What to capture (the evidence, while it is fresh)

Capture as much of this as you have. Partial is useful; none of it should be fabricated or
guessed. Timestamps in **UTC**.

| Field | Why it matters |
|---|---|
| **Time of first observed action (UTC)** | Starts every clock a regulator uses; the ledger shows this is the field most often missing. |
| **Time you detected it (UTC)** | Lets a responder compute how long the action went unseen. |
| **Source IP address and its ASN** | The single most useful attribution signal you hold. |
| **Whether the IP falls in a published lab range** | Some labs publish their crawler/agent IP ranges (for example OpenAI publishes `gptbot.json` and ChatGPT-User ranges). A match is the fastest path to naming the operator. |
| **User-agent string** | Often self-identifies the agent or its framework. |
| **Endpoints written to / actions taken** | Separates a read (a GET) from a state-changing write; the ledger's whole point is that "read-only" access was not. |
| **Content hashes + one redacted sample** | Proves what was uploaded/written without you having to republish live malicious content (see dual-use note). |
| **Account names / identifiers used** | Ties multiple actions to one actor. |
| **The concrete harm or risk** | What a third party actually suffered or was exposed to. |

A machine-readable version of these fields lives alongside this spec as the columns of
[detections.csv](detections.csv); a report is, in effect, one new row.

---

## Part B — Where to send it (the routes)

Send to as many of these as apply. They are complementary, not alternatives.

1. **The developer lab's security / abuse address.** Fastest path to containment if the
   operator is known. Most labs publish a security contact or a `security.txt`.

2. **The EU AI Office, via a complaint or the structured dialogue.**
   - **EU AI Act Article 85 — right to lodge a complaint.** Any natural or legal person with
     grounds to consider that the AI Act has been infringed may lodge a complaint with the
     relevant **market surveillance authority**. This is the only existing hook that lets an
     *outside* party — not the provider — put an agent incident in front of an EU regulator.
     *(Verify the exact wording and the competent authority against the consolidated AI Act
     text before the report locks; Article 85 was fetched during research but quote it
     verbatim in the paper.)*
   - **Article 91 — the structured dialogue / request for information.** The route by which
     the AI Office itself can compel information from a provider of a general-purpose AI model.
     An outside reporter cannot invoke this directly, but a well-evidenced Article 85 complaint
     is the input that can prompt it.

3. **A national CERT / CSIRT.** For the operational-security side (an active intrusion,
   credential exposure), the national computer-emergency team is the right first call and is
   used to handling time-sensitive reports.

4. **The AI Incident Database (incidentdatabase.ai).** The public, citable record. Filing
   here is what turns a one-off observation into an entry the next researcher — or the next
   version of this ledger — can find.

---

## Dual-use and responsible-handling note

This spec is for *reporting* an incident, not reproducing one. Do not republish live
malicious artifacts (packages, payloads, working exploit code). Capture a **hash** and a
**redacted sample** instead, and share the live artifact only through the private security or
CERT channel, never in a public filing. Redact third parties' personal data before any public
submission. The goal is to make an incident reportable without making it repeatable.

---

## Status / limits

- This is a **specification**, drafted from the public record, not an adopted standard. Its
  claim is that the fields and routes above are sufficient to report every incident in the
  ledger; its limit is that no body has yet committed to receiving a report in this form.
- The legal routes are EU-specific. A US reporter's nearest analogues (a CISA report, a state
  attorney-general channel) are out of scope here and flagged for a lawyer.
- "Nothing filed in public" never means "nothing was reported privately"; labs and victims may
  report through channels we cannot see.
