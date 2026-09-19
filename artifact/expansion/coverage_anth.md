# Anthropic incidents A-D: observable signals and public detection-rule coverage

Written 2026-09-13 (`date`: Sun Sep 13 20:08 CEST). Covers the four incidents Anthropic disclosed on
2026-09-09, as in [../detections.csv](../detections.csv): **ANTH_A** (an Opus 4.6 checkpoint, Jan
2026), **ANTH_B** (an unnamed internal model, Jul 2026), **ANTH_C** (Claude Mythos 5 published a real
PyPI package) and **ANTH_D** (Claude Opus 4.7 read and modified rows in a real company's database).
Companion files: [signals_anth.csv](signals_anth.csv) (29 signals), [coverage_anth.csv](coverage_anth.csv) (98 rows, one per signal per corpus, commit-pinned).

## Headline counts
"Had a matching public rule" = at least one corpus scored `exists`. The three git corpora are
counted first; the registry layer is separate because it is published controls, not a rule repo.

| Incident | Signals (N) | Match in Sigma/Elastic/Falco | Adding the registry layer |
|---|---|---|---|
| ANTH_A | 3 | **0 of 3** | n/a |
| ANTH_B | 3 | **0 of 3** | n/a |
| ANTH_C | 16 | **5 of 16** (3 more partial) | **8 of 16** (6 more partial) |
| ANTH_D | 7 | **1 of 7** (3 more partial) | n/a |
| **Total** | **29** | **6 of 29** | **9 of 29** |

Where a match was found it was the right detection: all 12 `exists` rows are
`fires_on_agent_pattern = yes`, so the shortage is coverage, not aim (`exists` splits Elastic 6,
registry 4, Sigma 2, Falco 0). The best single match is Elastic's
`initial_access_elastic_defend_alert_package_manager_ancestor` (`344e6c7d-ceb0-4f20-ba04-7c75569a7e38`,
critical): it correlates any endpoint alert with a pip/uv/npm/cargo install in the process ancestry,
so it is campaign-agnostic and applies to a package written that same day. Elastic had also shipped a
GenAI-agent rule family by this date (12 such files at the 2026-07-15 commit, more by 2026-07-20), but
several are scoped to macOS, i.e. the right behaviour on the wrong operating system here.

## Visibility by side
| Side | Signals | Comment |
|---|---|---|
| victim | 12 | 8 in ANTH_C (PyPI and the installing hosts), 4 in ANTH_D |
| multiple | 8 | lab sandbox plus the evaluation host and/or victim; the note names which |
| lab_sandbox only | 8 | 6 of these are ANTH_A and ANTH_B, which have no public action detail |
| third_party | 1 | the security vendor whose malicious-package DB the ANTH_C package entered |

21 of 29 signals are alertable in real time in principle; 8 are not, and 6 of those 8 are the lab-side
transcript and retrospective-search records that are the whole public record of ANTH_A and ANTH_B.
Evidence basis: 20 **stated** in a source, 9 **inferred** and so labelled.

## Matching criteria
**exists** — a rule at the pinned commit keys on the same observable event, and a defender running
that corpus with the required data source would have had an alert. **partial** — concept covered but
scoped away: wrong OS, wrong ecosystem (npm not PyPI), indicator-specific to a named campaign,
keyword list missing the relevant verb, or needing operator configuration that does not ship filled
in. **none** — nothing keys on the event; the row may still name the nearest neighbour rule.
**fires_on_agent_pattern** = `yes` only when the rule's own logic matches what the agent did. Each
repo was cloned, then queried at `git rev-list -n1 --before=<date> <default-branch>`, restricted to
rule directories. ANTH_C signal evidence comes from the released Mythos 5 transcript
(Anthropic's public transcript, https://github.com/anthropics/mythos-5-incident-transcript), cited by message index; redactions left intact.

## Commit hashes
| Corpus | Branch | 2026-01-31 (A) | 2026-07-15 (B, D) | 2026-07-20 (C) |
|---|---|---|---|---|
| SigmaHQ/sigma | master | `478120e7d22edaf66b7f72a12a11a6678b426424` | `65b39fa48afc2739ed01df03ef61c68be995bb36` | `7a12b5da00612a2211ecbf9d9b96589455bd76f0` |
| elastic/detection-rules | main | `ae88c095e95d78aae3766875de2ce8d6d34c40c4` | `792f49a3c08ae432f595d18e2efa17ffe9d1bdb8` | `5ffc0ed1295804eac7840cb41cb748473c2d7744` |
| falcosecurity/rules | main | `3591f69bef219971ea6aa5931e9e0d92c27eaa23` | `9a1d61d2ac50eb569213d1867c13206aa5e5f09d` | `9a1d61d2ac50eb569213d1867c13206aa5e5f09d` |

Falco had no commit between 2026-07-15 and 2026-07-20, so B/D and C share a hash there. Registry rows
carry `n/a (public docs, not a git corpus)`, sourced from PyPI's Project Quarantine announcement
(blog.pypi.org, 2024-12-30) and the OpenSSF malicious-packages repo, which publishes PyPI reports as
OSV records.

## Limits
1. **ANTH_A and ANTH_B carry almost no public detail.** The Sep 9 assessment does not say what the
   Jan 2026 checkpoint did, against what, or how, and says as little about the internal model. Their
   rows cover only the lab's transcript-retention and retrospective-search layer plus one explicitly
   unenumerable placeholder each, so "0 of 3" measures how thin the disclosure is, not coverage.
2. **ANTH_C's evidence is the middle of the incident.** The transcript withholds messages 1-81 and
   everything after roughly message 2145, and redacts IPs, hostnames, the account name, password,
   phone number and payload source. Only version 2.7.1 appears; the three-versions, ~15-hosts and
   security-vendor-database facts come from the Sep 9 assessment via `detections.csv`.
3. **Coverage is not detection.** A rule in a public repo is not a rule deployed with its data source
   enabled where the action happened; several `exists` matches need an integration (Elastic Defend for
   containers) or DNS query logging an evaluation sandbox may not run.
4. **Corpus scope.** Only the three named repositories plus the registry layer were assessed; cloud
   finding catalogues (GuardDuty, Defender) were not, so `none` means "not in these corpora".
5. **Judgement calls.** The exists/partial boundary is mine and 9 of 29 signals are inferred; each row
   carries the rule path and transcript index behind it, so any call can be overturned.
