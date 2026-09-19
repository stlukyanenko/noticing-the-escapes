# Blind second pass #2 — detection-rule coverage audit

## Protocol as executed
Pass #1 sampled all of `coverage.csv`, so most of its 20 rows were sentinel rows — `rule_id_or_path` empty, `none`, or `(no matching rule)` — which a blind re-reader cannot check, there being no rule text to read. Pass #2 fixes the sampling frame.

`sample.py` keeps a row only if `rule_id_or_path` names a real rule: a path-like slash with no surrounding spaces, a `.yml`/`.yaml`/`.toml` extension, a UUID, or a vendor finding-type name shaped `Category:Resource/Type`. Dropped are sentinels (`none`, `(no matching rule)`, `n/a`, `-`, empty) and descriptive prose naming a policy rather than a rule (e.g. "No documented pre-publish name-confusion block on PyPI").

Of 278 rows, **104 name a real rule**; 8 were already in the pass-1 sample and were excluded, leaving a pool of 96. Twenty were drawn with `random.Random(20260914).sample`.

`answer_key_DO_NOT_OPEN.csv` was written by `sample.py` in step 1 and **was not opened until `blind_verdicts.csv` was complete**. Verdicts came from the rule text alone, read at the pinned commit with `git show <commit>:<path>` (byte-identical to a checkout, and it does not disturb the shared clones), plus `signals.csv` descriptions and the matching-criteria section of `coverage_hf_wiki.md`. The three vendor rows were judged from the AWS GuardDuty Runtime Monitoring finding-type docs. All nine pinned commits resolved.

## Sample composition
By corpus: falco 7, elastic 6, sigma 4, vendor 3. By incident: HF 8, WIKI 5, ANTH_C 3, IRREG 2, AISI 1, ANTH_D 1.

## Agreement
| column | raw agreement | Cohen's kappa |
|---|---|---|
| `match` | 0.700 (14/20) | 0.415 |
| `fires_on_agent_pattern` | 0.700 (14/20) | 0.547 |

Kappa is agreement left after subtracting what two coders would hit by chance; 0.41 and 0.55 are "moderate" — the passes are not independent guessing, but they are not interchangeable either.

`match` (rows = original, cols = pass 2), then `fires_on_agent_pattern`:

| | exists | partial | none | | | yes | no | unclear |
|---|---|---|---|---|---|---|---|---|
| exists | 4 | 2 | 0 | | yes | 4 | 2 | 0 |
| partial | 1 | 10 | 0 | | no | 0 | 7 | 0 |
| none | 0 | 3 | 0 | | unclear | 1 | 3 | 3 |

## The nine disagreeing rows
1. **S1** HF-03, Falco "Update Package Repository": `none`→`partial`; a package-repository-write rule does exist, but it watches local repo config files, not a remote Artifactory proxy.
2. **S9** ANTH_C-01, Sigma "Connection Proxy": `exists`/`yes`→`partial`/`no`; it matches only `http_proxy=` in a command line, and the agent used `curl --socks5-hostname`.
3. **S11** AISI-05, Falco "Program run with disallowed http proxy env": `unclear`→`no`; it requires `HTTP_PROXY` in the process environment, and the agent passed SOCKS options as arguments.
4. **S14** ANTH_D-03, Sigma "Suspicious SQL Query": `none`→`partial`; the rule exists but its keywords are drops and dumps, not the row-modifying write.
5. **S15** HF-11, Elastic Kubernetes pod-exec rule: `unclear`→`no`; it explicitly excludes `/etc/resolv.conf`, the exact file the agent overwrote.
6. **S17** ANTH_C-03, Elastic OAST-domain rule: `exists`/`yes`→`partial`/`no`; it needs macOS, a script interpreter, and a `*.oast*` domain, while the agent used curl on Linux to webhook.site.
7. **S18** IRREG-05, Sigma "Suspicious User Agent": `unclear`→`no`; it enumerates malware user-agent strings the agent's traffic would not carry.
8. **S19** HF-07, GuardDuty `Backdoor:Runtime/C&CActivity.B`: `none`→`partial`; the finding type exists and covers C2 channels, but only for threat-listed IPs, and Tailscale's control plane is not one.
9. **S20** ANTH_C-13, Falco "Interpreted procs outbound network activity": `partial`/`unclear`→`exists`/`yes`; install-time egress from a pip-installed package is a Python process making an outbound connection, which is the rule's own condition.

A definitional gap explains three of the six `match` disagreements. On S1, S14 and S19 the original coder wrote `none` on rows that name a real rule, reading `none` as "no adequate rule", whereas the stated criteria reserve it for "no rule in that corpus at that commit". That is a coding convention differing between passes, not a dispute about any rule's text.

Incidental data-quality finding: `coverage.csv` places "Update Package Repository" in `rules/falco-incubating_rules.yaml`, but at commit `c72713ee` that rule lives in `rules/falco-sandbox_rules.yaml`.

## Effect on the headlines
In this sample the original counted 6 `exists` to pass 2's 5, and 6 `yes` to pass 2's 5. Each headline moves by one row in twenty: **"a rule existed for 21 of 86" becomes roughly 20 of 86, and "the rule would fire for 20 of 86" becomes roughly 19 of 86.** Neither changes in substance — both passes put coverage near a quarter of signals and firing below a quarter.

## Direction of the systematic difference
Pass 2 is systematically stricter on `fires_on_agent_pattern`: three of the original's `unclear` and two of its `yes` verdicts became a definite `no`, against one move toward `yes`, taking the `no` count from 7 to 12. Reading the rule text usually resolves an `unclear` into a `no`, because the gate that blocks the match becomes visible — a Windows or macOS host check, an `HTTP_PROXY` environment variable, an explicit `resolv.conf` exclusion, a threat-list lookup.

On `match`, pass 2 collapses toward the middle: 15 `partial` against the original's 11, and zero `none`. Both directions push the same way. The original coding is slightly optimistic about public rules covering agent behaviour, and the corrected sample makes the coverage gap marginally wider, not narrower.
