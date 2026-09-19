# Pre-registered predictions — Caught From Outside

Pre-registered **2026-09-13** (Munich, CEST), before any outcome is known. The point of
writing these down now is the rubric's cheapest point: a dated prediction earns "the
experiment says exactly what it claims to test," and reporting the ones that fail is scored
as a feature, not a confession.

Each prediction states: the claim, our probability, the one-line reason, the date we will
check it, and the rule that decides whether it resolved YES or NO. Probabilities are the
author's, not a model's.

---

## P1 — The next disclosed evaluation-agent incident will not be first caught by the developer's own real-time monitoring

- **Probability: 0.8**
- **Why:** across the eight incidents in the ledger, the developer's own real-time monitor
  was the first detector in zero of them. We expect the pattern to hold for the next one.
- **Resolution date:** 2026-12-31 (or the first such public disclosure before then).
- **Resolves YES if:** the next publicly disclosed incident in which an AI agent takes an
  unauthorized action against a third party during training, evaluation, or internal use was
  first detected by a victim, a platform or registry, a third-party evaluator, or a
  retrospective review — i.e. anything other than the developer's own real-time monitoring.
- **Resolves NO if:** the developer's own real-time monitoring is the stated first detector.
- **Void if:** no qualifying incident is disclosed by the resolution date, or the disclosure
  does not state who detected it first.

## P2 — At least one more previously-undetected Anthropic or OpenAI evaluation-agent incident surfaces from the ongoing rescan

- **Probability: 0.5**
- **Why:** Anthropic widened its review to 481 million transcripts (9.2 million flagged) after
  OpenAI's July disclosure; a scan that large over a short window is unlikely to be complete.
- **Resolution date:** 2026-12-31.
- **Resolves YES if:** Anthropic or OpenAI publicly discloses, by the resolution date, at
  least one further evaluation- or internal-use incident attributed to a rescan of existing
  transcripts (not a newly occurring incident).
- **Resolves NO if:** no such rescan-surfaced incident is disclosed by then.

## P3 — OpenAI's promised misalignment-reporting framework will not name a third-party (non-provider) intake channel

- **Probability: 0.7** *(i.e. we give ~0.3 to the framework actually naming one)*
- **Why:** the existing serious-incident regime is provider-initiated; nothing in the record
  commits any lab to an intake a victim or platform could use directly, and the ledger shows
  that gap is exactly what the outside detectors ran into.
- **Resolution date:** on publication of OpenAI's framework, or 2027-03-31, whichever is first.
- **Resolves YES (prediction holds) if:** the published framework describes only
  provider-initiated reporting and does not name a channel by which an external party (a
  victim, a platform, a registry, a CERT) can report an agent incident to the lab or a
  regulator.
- **Resolves NO (we were wrong) if:** it names such a third-party intake channel.
- **Void if:** no such framework is published by the resolution date.

## P4 — The next disclosed evaluation-agent incident's agent-specific signals will again have no firing public rule

- **Probability: 0.75**
- **Why:** in the eight 2026 incidents, a public detection rule that would fire on the agent's
  actual pattern existed for about 20 of 80 observable signals, and coverage followed where the
  agent acted (10 of 20 for the container intrusion; 1 of 18 for the wiki swarm; 1 of 12 for
  the evaluator's sandbox). We expect the public corpora to still lack rules for the
  agent-specific signals of the next incident.
- **Resolution date:** 2027-03-31 (or the next qualifying disclosure before then).
- **Resolves YES if:** re-running the coverage audit (same method: enumerate the incident's
  observable signals, pin SigmaHQ / Elastic / Falco to the disclosure date, judge match and
  fires-on-agent-pattern) finds that fewer than half of the incident's agent-specific signals
  have a public rule that would fire.
- **Resolves NO if:** half or more do.
- **Void if:** no qualifying incident with enough public action detail to enumerate signals
  is disclosed by the resolution date.
- *Added 2026-09-14 after the judging round; the report's P4.*

---

### How these tie to the artifact

P1 and P2 are the ledger's findings projected forward; if either fails, the "caught from
outside" pattern is weaker than we claim, and we will say so. P3 is the gap that
[report-an-agent.md](report-an-agent.md) proposes to close: if a lab voluntarily opens a
third-party intake channel, the artifact's core recommendation has been partly adopted, which
is a win we would happily lose the bet for.
