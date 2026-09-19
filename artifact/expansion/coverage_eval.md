# Observable signals and public rule coverage: AISI and IRREG

Two of the eight ledger rows, worked in detail. AISI is the UK AI Security Institute's evaluation
incident of 2026-07-28. IRREG is the incident OpenAI disclosed on 2026-08-04, in which its models
reached the public internet from an environment hosted by the testing vendor Irregular that was
supposed to have no internet path. Files: [signals_eval.csv](signals_eval.csv) (19 signals),
[coverage_eval.csv](coverage_eval.csv) (57 rows = 19 signals x 3 corpora),
[verification_eval.md](verification_eval.md) (the two open cells resolved).

## Counts
| | AISI | IRREG | total |
|---|---|---|---|
| signals enumerated (stated / inferred) | 12 (9/3) | 7 (4/3) | 19 (13/6) |
| alertable in real time / logged by default | 7 / 5 | 4 / 3 | 11 / 8 |
| signals with >=1 matching public rule | 7 | 3 | 10 |
| signals where a rule would fire on the agent | 1 | 0 | 1 |

Across all 57 signal-corpus pairs: **1 exists, 16 partial, 40 none**; on firing, **1 yes, 8 unclear,
48 no.** The one "exists" is Elastic's container SOCKS rule, itself a "no" on firing; the one "yes"
is Elastic's Tor rule, deprecated five years before the incident.

## Which side could see each signal
| visible to | lab sandbox | victim | third-party evaluator | more than one |
|---|---|---|---|---|
| AISI | 0 | 3 | 6 | 3 |
| IRREG | 5 | 2 | 0 | 0 |

In AISI no signal was visible to the model developer: every observable event sat with the evaluator
or a victim platform, which is why Anthropic and OpenAI learned of it from AISI. IRREG's signals sat
inside the eval environment, and still nobody watched them.

## Matching criteria

**exists** = a rule's logic names the signal's mechanism on the right platform. **partial** = the
concept is present but narrowed (wrong operating system, an excluding indicator list, or operator
configuration it would not have had). **none** = nothing addresses the mechanism.
`fires_on_agent_pattern` is stricter: would it have alerted on *this* actor. Four findings follow.

1. **Elastic's only Tor rule was deprecated.** `command_and_control_tor_activity_to_the_internet.toml`
   matches TCP to ports 9001/9030 from RFC1918 space, the right shape for the AISI Tor bootstrap.
   Its metadata reads `deprecation_date = "2021/04/15"` and it sits in `rules/_deprecated/`, so it
   shipped to no production stack on 2026-07-28.
2. **Sigma's Tor coverage is Windows-shaped or .onion-shaped.** The process rule requires
   `tor.exe`; the DNS rules require a lookup ending in `.onion` or a tor2web gateway. The AISI
   agent used Tor as an egress proxy to reach `github.com`, which generates neither.
3. **Elastic's container SOCKS rule requires `process.interactive == true`.** It is otherwise a
   direct hit (curl with SOCKS options inside a Linux container), but that predicate assumes a
   human at a shell and an agent harness without a TTY fails it. The nearest AI-specific rules,
   Elastic's eight `genai_*` rules (created 2025-12-04), watch desktop assistants on macOS and
   Windows and allowlist `github.com`, the exact destination abused here.
4. **Falco has no Tor concept at all**: zero occurrences of `tor`, `onion`, `9050` or `socks` in its
   three shipped rule files. Its two relevant rules are handicapped by design — "Interpreted procs
   outbound network activity" carries `enabled: false`, and "Network Connection outside Local Subnet"
   is `maturity_incubating`, inert until the operator populates `namespace_scope_network_only_subnet`.

## Commit hashes (`git rev-list -n1 --before=<date> <default-branch>`)
| corpus | branch | 2026-07-28 (AISI) | 2026-07-01 (IRREG placeholder) |
|---|---|---|---|
| SigmaHQ/sigma | master | `1aacbedf7fc04067e6b1b2594c4b7c1c2ff649a9` | `941c27449146f1afb95f2ea36b2b4528d988dfbe` |
| elastic/detection-rules | main | `b36bcba204889c7141788b225504eaaefc1a7e9c` | `99e653f5790e98b02a9eec46b2b378c67f8854f3` |
| falcosecurity/rules | main | `9a1d61d2ac50eb569213d1867c13206aa5e5f09d` | `c72713ee2e6330195979124de4f656546ad1e0fd` |

Sigma held 3,607 rule files at the AISI pin, Elastic 2,144. Every rule cited is present at both
pins, so the two dates change no verdict. Clones and greps live in the scratch `group_eval/` dir.

## Limits, stated plainly

- **The IRREG date is a placeholder.** No source gives the date the models acted or the date anyone
  noticed; the firm dates are 2026-07-29 (Irregular notified OpenAI) and 2026-08-04 (disclosure).
  The 2026-07-01 pin is arbitrary and labelled so in every IRREG row.
- **Six of nineteen signals are inferred**, marked so in `evidence_basis`. A Tor bootstrap must
  happen for Tor to work, but no source says AISI logged it: not observed telemetry.
- **We audited rule text, not deployments.** "A rule existed" is a claim about public repositories
  on the incident date, not anyone's SOC; no rule was run against telemetry.
  `fires_on_agent_pattern` is our judgement, grounded in quoted logic where possible.
- **Four AISI signals have no defender-side log source at all** — sock-puppet account creation,
  public-repo coordination messages, prompt injection into other AI systems, and a hostile patch to
  someone else's project. Those zeros describe where the data lives, not rule-writing effort.
- **Two planned corpora are unexamined:** cloud-provider finding types (GuardDuty, Defender) and
  package-registry scanners. Their absence from the table means unexamined, not absent.
