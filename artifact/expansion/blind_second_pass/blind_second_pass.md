# Blind second-pass audit of the detection-rule coverage table

A second coder re-judged a random 20-row slice of `coverage.csv` blind, to measure how
reproducible the coverage verdicts are.

## Protocol as executed
1. `sample.py` kept the 221 rows of `../coverage.csv` with non-empty `rule_id_or_path`, drew 20
   with `random.Random(20260913).sample` (seed **20260913**), and wrote `blind_sample.csv`
   (no verdict columns) plus `answer_key_DO_NOT_OPEN.csv`.
2. Signal text came from `../signals.csv` (no verdicts); the `exists`/`partial`/`none` and
   `fires_on_agent_pattern` definitions from the "Matching criteria" section of
   `../coverage_hf_wiki.md` (lines 45-63), read on its own.
3. The corpora were cloned to scratch, `git checkout` run at each row's pinned commit, and the
   named rule read there. The two GuardDuty rows and the PyPI row were judged from rule text
   and public docs. All 20 verdicts then went to `blind_verdicts.csv`.
4. **The answer key was not opened before step 5** — no tool call touched it between creation
   and `agreement.py`, and the second coder's verdicts were already on disk by then.

Sample-frame caveat: 11 of 20 rows carry sentinel text ("none", "(no matching rule)") in
`rule_id_or_path`, so that filter does not isolate rows naming a real rule; half the sample
re-checks absences, which are easier to agree on than rule readings. Composition — corpus:
sigma 7, elastic 6, falco 4, GuardDuty 2, PyPI registry 1. Incident: WIKI 6, HF 5, IRREG 4,
AISI 3, ANTH_C 2.

## Agreement (full output in `agreement.txt`)
`match`: raw 17/20 = 0.850, kappa 0.730. `fires_on_agent_pattern`: raw 17/20 = 0.850, kappa
0.516 — the lower kappa is a base-rate effect, since 18 of 20 rows are "no" for coder 1 and
chance agreement is therefore already high.
```
match (rows coder 1, cols coder 2)      fires (rows coder 1, cols coder 2)
          exists  none  partial                    no  unclear   yes
exists         1     0        1            no      15        0     0
none           0    11        1            unclear  2        0     0
partial        1     0        5            yes      1        0     2
```

## The five disagreements
- **Sample 4** (AISI-03, elastic Tor rule): coder 1 `partial`, coder 2 `exists`; the query is
  exactly TCP to ports 9001/9030 leaving a private range, and coder 2 read the rule's
  `maturity = "deprecated"` as a note rather than a demotion.
- **Sample 14** (ANTH_C-08, Elastic package-manager-ancestry rule): coder 1 `none`, coder 2
  `partial`; it matches `setup.py install`, not the `setup.py sdist` in the signal.
- **Sample 16** (HF-02, Sigma external-service-interaction DNS rule): coder 1 `exists`/`yes`,
  coder 2 `partial`/`no`; the domain list has `.dnshook.site` but not `webhook.site`, and the
  signal is an HTTP POST, not the DNS callback the rule watches.
- **Sample 18** (AISI-05, Sigma proxy rule): coder 1 `unclear`, coder 2 `no`; the rule needs a
  literal `http_proxy=`, which `curl --socks5` does not carry.
- **Sample 19** (HF-14, Elastic web command-injection rule): coder 1 `unclear`, coder 2 `no`; it
  reads payload keywords from `url.original`, but the Jinja2 injection arrived in a config body.

## Headlines ("rule existed 21/86", "would fire 20/86") and coder direction
`exists`: sample 4 gains one, sample 16 loses one, so **21/86 is unchanged**. `would fire`:
sample 16 flips yes to no, so **20/86 becomes 19/86**, a one-row move; the two `unclear`-to-`no`
flips change nothing, since `unclear` was never counted as firing.

Coder 2 is stricter about what a rule's conditions literally cover and resolves `unclear`
downward (both such rows became `no`). The single opposite move, sample 4, is about whether a
deprecated rule counts, not about detection logic. If coder 2 were sole judge the "would fire"
count drops by one and "rule existed" holds, so the conclusion does not turn on who coded.
