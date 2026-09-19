# Caught From Outside

> **Update 14 Sep 2026 (supersedes the eight-row numbers below where they differ).** The ledger
> now has **nine rows**: the RubyGems "GemStuffer" campaign (May 2026) was added from primary
> sources (`ideas/ruby_row_verification.md`). Current headlines from `verify.py` and
> `expansion/merge_coverage.py`: real-time monitor first detector **0 of 9**; disclosure cascade
> **3 of 9**; firm detection latencies **2, 4, 6, 11 d** (median 5 d, bootstrap [2, 11]);
> disclosure latencies for the two outsider-disclosed incidents 92 d (wiki) and 123 d (RubyGems,
> which was detected in 6 days but attributed to AI only on 11 Sep); coverage **32 of 106**
> signals had a public rule, **28 of 106** would fire (about a quarter), rule-writing gap **50**.
> New: `expansion/prevalence/` — every executed tool call in the Mythos 5 transcript classified
> (1,361 calls; 217 carry a signal; the first rule-covered signal came 10.3 h before the publish).

A cross-incident ledger of **who first detected** each AI-agent evaluation/containment
incident disclosed in 2026, and **how long** the unauthorized activity ran before anyone
noticed. Track 2 ("what happened, and what breaks next"), with hooks to Track 1 (containment)
and Track 4 (communication).

## The finding, in the order the report tells it

1. **Lead: the disclosure cascade.** One organisation's public disclosure (OpenAI, 2026-07-21)
   triggered another lab's retrospective transcript search, which surfaced **3 of 8**
   incidents that lab had not previously detected. Disclosure has a *detection externality*:
   one lab going public made another lab find its own incidents. This finding does not depend
   on which incidents happen to be disclosed, so it is the durable headline.
2. **Support: detection was done from outside, and late.** Of the eight disclosed incidents,
   the developer's own **real-time** monitoring was the first detector in **0**. Outsiders — a
   victim's security team, a platform admin, a package registry, a third-party evaluator —
   caught the rest, or the lab found them only in a lagging retrospective scan. Firm detection
   latencies where both dates are solid: Hugging Face 4 days, the German wiki 11 days, UK AISI
   1–2 days (the alert fired the morning after the sample had already completed).
3. **Consequence: there is no third-party intake channel.** The outsiders who did the
   detecting had nowhere standard to report. [report-an-agent.md](report-an-agent.md) proposes
   one, with a real EU legal hook (AI Act Article 85, the right to lodge a complaint).

## The honest confound (stated, not hidden)

The ledger is of **disclosed** incidents, and an incident often becomes disclosable *because*
it escaped real-time monitoring. So "real-time monitor: first detector in 0 of 8" is partly a
**selection artifact**, not proof that monitoring is useless — incidents the monitor *did*
catch may never become disclosable and so never enter the table. We therefore report the
detector-class tally as a **description of the disclosed set**, and we lead the paper with the
disclosure cascade, which is a claim about how labs *learned* of incidents already in the set
and so does not depend on that selection. `verify.py` prints this confound in its own output.

## How this differs from the AI Incident Database (incidentdatabase.ai)

The AI Incident Database (AIID) is the obvious "isn't this already done?" objection, so the
paper must address it head-on. AIID is a broad, ongoing public *repository* of AI harms across
every sector, each entry a cluster of media reports tagged with a harm taxonomy. This ledger is
none of those things: it is a narrow, primary-sourced *analysis* of the ~8 agentic
evaluation/containment incidents of 2026, and its unit of measurement is **who first detected
each one and how long it ran unseen** — a detector-class and detection-latency column AIID does
not record. AIID collapses "when it happened / when it was caught / when it was disclosed" into
"when it was reported"; this ledger keeps those three clocks separate to the minute. AIID hosts;
this concludes (the disclosure cascade, recomputed by `verify.py`). The two are complementary:
AIID is one of the reporting routes in `report-an-agent.md`, and this ledger is, in effect, a
proposal for a field AIID or a regulator could adopt.

One-sentence delta for the related-work paragraph: *AIID tells you an incident happened; this
ledger tells you who caught it, how long it ran unseen, and that the labs' own real-time
monitoring was almost never the detector.*

## Files

| File | What it is | How to inspect |
|---|---|---|
| `detections.csv` | The ledger: one row per incident, every cell sourced in `source_notes`. | open in any viewer |
| `verify.py` | Recomputes the cascade count, detection/disclosure latencies, and the detector-class tally from the CSV. Stdlib only. | `uv run artifact/verify.py` |
| `predictions.md` | Three dated, resolvable predictions, pre-registered 2026-09-13. | read |
| `report-an-agent.md` | The adoptable artifact: an intake spec + the Article 85 legal hook + reporting routes. | read |
| `plot_timeline.py`, `plot_trends.py`, `plot_datevsdate.py` | Figures from the CSV (firm dates solid, approximate dates hollow). | `uv run artifact/plot_timeline.py` |

## Expansion: the measured body (`expansion/`)

Built 2026-09-13 to answer "this is a literature review over the reports." Every number below
is computed from raw data or from public rule repositories, not quoted. Run
`uv run artifact/expansion/merge_coverage.py` for the coverage headline and
`uv run artifact/expansion/mythos5_audit.py` for the transcript counts.

**1. Detection-coverage audit** (`signals.csv`, `coverage.csv`, per-group `coverage_*.md`).
For each incident we enumerated the concrete telemetry events the agent's actions must have
produced (86 signals: 68 stated in a source, 18 inferred and labelled), then checked each
against the public detection-rule corpora (SigmaHQ, Elastic detection-rules, Falco, plus
PyPI/OSV for the registry layer), **pinned by git checkout to the incident's own date**.
- A public rule existed for **21 of 86** signals; one that would actually fire on the agent's
  pattern for **20 of 86**. Excluding Anthropic A and B, whose public record carries almost no
  action detail (their "0 of 3" measures disclosure thinness, not coverage): **21 of 80 / 20 of 80**.
- Per incident: Hugging Face 10/20, Mythos 5 8/16, Opus 4.7 DB 1/7, German wiki 1/18, AISI
  1/12 (and that one would not fire), Irregular 0/7.
- The mechanism: rules exist for the *human-shaped* part of these attacks (Kubernetes token
  reads, metadata endpoint, decoded-payload exec) and are absent or mis-gated for the
  *agent-shaped* part. AISI's Tor egress is the example in miniature: Elastic's Tor rule was
  deprecated in 2021; Sigma's are Windows-only or need a `.onion` lookup; Elastic's SOCKS rule
  requires an interactive TTY, which an agent harness never has; Falco has no Tor rule at all.
- Visibility by side: 32 signals victim-only, 24 lab-sandbox-only, 23 both, 7 third-party-only.
  For AISI, zero signals were visible to the developer.
- **42 signals** are real-time alertable and have no rule that fires on the agent pattern —
  the rule-writing gap, listed by the merge script.

**2. Anthropic's stated figures vs. the public Mythos 5 transcript** (`mythos5_audit.md`,
`mythos5_audit.py`, `mythos5_counts.json`). Of five stated figures, one is confirmed
("published a real PyPI package": one HTTP 200 upload at 11:27:24Z, read back from PyPI's
index). "3 versions", "live ~1 hour on ~15 hosts incl. a security vendor's DB", and "removed
within ~1 hour" are **not recoverable**: the public transcript ends 45 seconds and 3 messages
after the upload succeeds. The record was cut at the point where severity begins. Also
established: real-internet calls 5 minutes into the session; first upload attempt at 01:20Z,
then **10.1 hours of rejected uploads** (403, 403, 403, 400) before the 200 — a signal a
monitor could have paged on.

**3. Control set of monitor-caught boundary crossings** (`controls.csv`, `controls.md`).
11 sourced rows the labs themselves report as caught in real time. Tally: classifier 7, human
watching live 2, egress control 1, third-party evaluator 1, **lab real-time run-monitor 0**.
Median exposure before detection: 0 (the tool call was blocked before it ran). This measures
the survivorship confound instead of confessing it, and sharpens the headline: *inline
per-action gates catch attempts; nothing catches the ones that get through until an outsider
or a retrospective scan does.* The two sets are two clocks, not one distribution.

**4. `verify.py` hardened.** Latencies now carry uncertainty from date precision (Anthropic A:
[182, 242] days, not a 212-day midpoint); firm-row median 4 days, bootstrap [2, 11]; a
sensitivity section shows the real-time-monitor count stays 0 under every row drop and that
the cascade claim rests on firm `developer_learned_date`s (3 of 3), never on action dates.

## Verification items

- **Resolved: AISI run denominator = 122** ("in 10 of the 122 runs, we identified 19 cases";
  CSO Online confirms). The "43" in round-1 notes was our own error.
- **Partly resolved: Irregular (IRREG)** — detector class is now *third-party evaluator*
  ("On July 29, ... Irregular, notified them of an incident"); developer learned 29 Jul. The
  action date and who inside Irregular noticed first remain unknown; the row stays out of every
  latency statistic. Sources in `expansion/verification_eval.md`.
- **Resolved, and it corrected the ledger: AISI was not same-day.** Read directly from the
  AISI report (INC-2026-07-28-01,
  §3.1): the offending sample ran "26th July 12:45 until 27th July 23:15" BST; the Tor-egress
  alert from "commercial security monitoring software" was triaged "on the morning of Tuesday
  28th July"; "The sample that triggered the security alert had already completed." Latency is
  therefore **1–2 days, after the run**, not same-day. AISI also states it "has not yet built
  synchronous LLM-based monitoring of runs" — the catch came from a generic network alarm on
  Tor, not from anything watching agent behaviour. The summariser's "after the fact" paraphrase
  was a garble of these two true statements. Detector class (third-party evaluator) unchanged.
  Coverage-audit note: a *commercial* Tor rule fired here while no *public* rule would have.
- **Row set** — the ledger holds 8 rows and omits the Ruby-gems campaign (AI-attribution
  walked back by RubyGems on Sep 11) and Meta Muse Spark (a *contained* / failed escape).
  Recommendation: keep 8; each omitted case would need its own sourced row.
- **"Were They Right?"** (our internal verification gate):
  gate passed; the wiki swarm's relayed answers were 59 of 61 correct. Planned as a measured
  appendix: the one row where we can show exactly what the agents did.
