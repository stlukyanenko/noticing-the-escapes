# Observable signals and public detection-rule coverage: Hugging Face and the German wiki

Written 2026-09-13 (Munich, CEST; `date` checked). Expansion of the "Caught From Outside"
ledger, ideas 1 and 2 of our internal detection notes.
Two incidents only: **HF** = the Hugging Face intrusion (first action 2026-07-09), **WIKI** =
the German DSEWiki agent swarm (first action 2026-05-24). Sources: `detections.csv`,
`ideas/brainstorm_framework_library.md` (the 19 published Hugging Face replay steps),
`ideas/brainstorm_round2.md` (the Nightingale findings and our local counts on the
collusion.wiki export), `docs/GLOSSARY.md`.

## Headline counts

A signal "has a matching public rule" when at least one of the three git rule corpora
(SigmaHQ, Elastic, Falco), pinned to that incident's first-action date, contains a rule whose
logic matches the signal (`match = exists`).

- **Hugging Face: 10 of 20 signals had a matching public rule at 2026-07-09.**
- **German wiki: 1 of 18 signals had a matching public rule at 2026-05-24.**

All 11 of those matches are also judged to fire on the agent's actual pattern, not only on
human tradecraft. Four more HF signals and five more WIKI signals had a partial match: a rule
exists for a neighbouring behaviour but would not fire as written. The remaining 6 HF and 12
WIKI signals had nothing in any corpus.

The gap between the two incidents is a platform gap, not a difficulty gap. The HF chain ran
inside a Linux container and touched Kubernetes and cloud metadata, which is exactly what
container-security rule sets were written for. The wiki swarm's actions were ordinary web
requests to a public wiki, and none of the three corpora contains a single rule about a wiki,
a web application's account-creation rate, or a fetch-relay service.

## Visibility by side (38 signals)

| Side that could see it | HF | WIKI |
|---|---|---|
| lab sandbox only | 9 | 2 |
| victim only | 7 | 8 |
| multiple (named per row) | 4 | 8 |

Logged by default: HF 6 yes / 5 no / 9 depends; WIKI 15 yes / 1 no / 2 depends. The wiki's own
software records account creation, every edit, and the source IP and ASN as a matter of course,
which is why a volunteer administrator could detect the swarm at all. Nine of the twenty HF
signals are "depends": they are visible only if the evaluation harness keeps process,
file-access or egress logs, and OpenAI has said it had no real-time trajectory monitoring.

## Matching criteria (so a second pass can check this)

1. Keyword sets per signal (in `grep_signals.py` in the session scratch directory) were run
   over every rule file in each corpus at the pinned commit: Sigma `rules*/**.yml`, Elastic
   `rules/**.toml`, Falco's three bundled `rules/*.yaml` split into individual rules.
2. Candidate hits were then read by hand. `exists` requires the rule's detection logic to
   cover the signal's own event, not a neighbouring one. `partial` means a rule covers an
   adjacent behaviour, the wrong direction (reading a file where the agent wrote it), or the
   wrong platform (a Windows- or macOS-only rule for a Linux container action). `none` means no
   rule in that corpus at that commit.
3. `fires_on_agent_pattern` is `no` when the rule's match conditions encode human tradecraft —
   a named offensive binary, a TruffleHog user agent, a Cobalt Strike user-agent string, an
   anonymous or Tor-sourced caller — while the agent used a legitimate client with valid
   credentials.
4. Falco's maturity level is recorded in the note. Rules tagged `maturity_sandbox` or
   `maturity_incubating` are not part of the default stable rule set, so "exists" there does not
   mean "on in a default install". Elastic's container rules likewise need the Defend for
   Containers integration.

## Commit hashes (pinned with `git rev-list -n1 --before=<date> <default-branch>`)

| Corpus | default branch | at 2026-05-24 (WIKI) | at 2026-07-09 (HF) |
|---|---|---|---|
| SigmaHQ/sigma | master | `994da16651194500b607a3007186c29779e1f961` | `fe2a6e82acc831a9a49f8f2261c127d50a1db306` |
| elastic/detection-rules | main | `480961ba1cac4f85ddf01c0ab5f89bbf373c513c` | `1eaa12aa6d2f2047a680d2260fa75e635dd4b9f6` |
| falcosecurity/rules | main | `6cbb113dd3fbcaf157c077414a57d2180f3e0eec` | `c72713ee2e6330195979124de4f656546ad1e0fd` |

Rule-file counts at those commits: Sigma 3,731 files, Elastic 1,836 (WIKI date) and 1,965 (HF
date) TOML rules, Falco 93 rules across three bundles. For the keywords we searched, Sigma's
results were identical at both dates; Elastic's instance-metadata rules moved between the two.

## Limits, stated plainly

- **Three of the 38 signals are inferred, not stated** (marked in `evidence_basis`): the HF
  credential being used from a new ASN (HF-12), the evaluation environment's outbound HTTP to
  the wiki domain (WIKI-12), and the clustering of account registrations in a few IP ranges
  (WIKI-13). Everything else is traceable to a published sentence or to our own counts on the
  public collusion.wiki export.
- **The wiki service counts are lower bounds.** The investigators withheld 7,793 of 23,877 URLs
  as operational, so the relay, proxy and shortener volumes can only rise.
- **Vendor coverage is not date-pinned.** The nine `vendor` and `registry` rows were read from
  current AWS GuardDuty documentation on 2026-09-13, not from a version archived at the incident
  date, and they are recorded that way in the CSV. Microsoft Defender was not assessed.
- **Ambiguous matches we called partial rather than exists:** HF-08 (a SOCKS rule keyed on
  curl's arguments, while the published step does not name the client), HF-14 (generic web-server
  command injection against a Jinja2 template injection), HF-17 (a new-terms STS rule that fires
  only against a baseline we cannot see), WIKI-09 and WIKI-12.
- **A rule existing is not a detection.** Coverage here means the rule text existed in a public
  corpus on that date. Neither incident's operator is known to have been running these rules,
  and in both cases the first detector was outside the developer lab.
