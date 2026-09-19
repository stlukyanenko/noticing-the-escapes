# Signals and public detection-rule coverage: the RubyGems "GemStuffer" campaign

Written 2026-09-14, 08:55 CEST (`date` checked). Third incident in the "Caught From Outside" ledger. **RUBY** = the RubyGems GemStuffer campaign, first action **2026-05-05**. Method and columns are identical to [coverage_hf_wiki.md](coverage_hf_wiki.md). Sources: https://www.rubyhack.ai/ (11 Sep 2026); The Hacker News 2026/09 "OpenAI Agents Linked to RubyGems Campaign That Gained RCE on RubyDoc Servers"; blog.rubygems.org 2026-05-13, 2026-07-22 (advisory GHSA-9j48-x3c3-mrp2) and 2026-09-11; Ruby Central's Ruby Shield post; Socket's GemStuffer research as reported by The Hacker News; guides.rubygems.org rate limits.

## Headline counts

A signal "has a matching public rule" when a corpus pinned to 2026-05-05 contains a rule whose logic matches the signal's own event (`match = exists`). Four corpora: SigmaHQ, Elastic, Falco, and **registry** (the registry's own published abuse controls plus third-party package scanners).

- **26 signals enumerated.**
- **6 of 26 had a matching rule in the three git corpora.**
- **11 of 26 once the registry layer is counted.**
- **8 of those 11 are judged to fire on the agents' actual pattern.** The three that do not are registry rate limits that existed and were never exceeded, or upload analysis whose result is not published.
- 10 more signals had a partial match only; 5 had nothing in any corpus.

All 6 git-corpus matches are Falco container rules: an interpreted process opening an outbound connection (RUBY-15, RUBY-16, RUBY-22, RUBY-23, RUBY-24) or the `gem` client run inside a container (RUBY-25). Five of the six sit outside Falco's default stable set — "Interpreted procs outbound network activity" is `maturity_sandbox` and ships with `enabled: false`; "Launch Package Management Process in Container" is `maturity_incubating`. Sigma and Elastic contributed no `exists` at all, but plenty of near misses: Elastic returned `partial` on 17 of 26 signals, Sigma on 4.

## Visibility by side (26 signals)

| Side that could see it | count |
|---|---|
| victim only (registry or doc host, named per row) | 10 |
| multiple (named per row) | 12 |
| lab sandbox only | 4 |

Logged by default: 17 yes, 2 no, 7 depends. Almost every agent action here was a request to a public web service that keeps request logs anyway, so this incident is far more observable than the Hugging Face chain. The exceptions are the seven "depends" rows, mostly on the documentation-build host — which is where the code execution actually happened.

## Matching criteria used

1. Per-signal keyword sets grepped over every rule file at the pinned commit (Sigma `rules*/**.yml`, Elastic `rules/**.toml`, Falco's three bundles split per rule), then candidates read by hand.
2. `exists` needs the rule's logic to cover the signal's own event; `partial` means an adjacent behaviour, the wrong direction or the wrong platform; `none` means nothing.
3. `fires_on_agent_pattern` is `no` when the conditions encode human tradecraft (a scanner user agent, a named offensive tool, an error-code burst) while the agents used ordinary clients against pages that existed.
4. Falco maturity and `enabled: false` are recorded per row, as is Elastic's dependence on the Defend for Containers integration.
5. Registry rows come from current public documentation, not an archived version; where a control's introduction date is published, the row says whether it predates 2026-05-05.

## Commit hashes

Rule used: `git rev-list -n1 --before="2026-05-06" <default-branch>`, which git resolves against each commit's own rendered local date, giving the last commit dated 2026-05-05 in the committer's timezone.

| Corpus | branch | commit | commit date |
|---|---|---|---|
| SigmaHQ/sigma | master | `df5c6a6ecc149e05cb4dea306012668fb2ae5a12` | 2026-05-05T00:58:33+02:00 |
| elastic/detection-rules | main | `d1c9cd65b40de3189e429279973a96970785356c` | 2026-05-05T21:57:11-04:00 |
| falcosecurity/rules | main | `66d4992453061b441809a9acf156389505b3e5e7` | 2026-04-13T09:55:48+02:00 |

Falco had no commit between 13 April and the incident date. Rule-file counts: Sigma 4,189 `.yml` across the `rules*` trees, Elastic 1,810 TOML rules, Falco 93 rules in three bundles.

## The two notable gaps

**Mass account creation on a package registry has no public rule anywhere.** Sigma and Elastic cover user creation only on an identity provider, a cloud tenant or a Windows domain; Elastic's closest object is a machine-learning job for a spike in Windows account-management events. No rule in any of the three corpora holds a disposable-email domain list in either direction. The registry's own defence was a per-address sign-up limit of 100 requests per 10 minutes, which caps one source rather than a campaign, and disposable-domain blocking arrived 16 May, eleven days after the first malicious gem.

**Documentation-build code execution has no public rule either, because it is a feature.** YARD's `.yardopts` is documented as able to link Ruby scripts for the build, so a build worker running a package's script is the tool working as designed. The nearest rules — Falco's "Web Server Spawned Suspicious Child Process" and Elastic's container web-server child-process rule (497a7091) — both require the executing process to descend from a recognised web-server binary, which a queued build may not. Both are marked `unclear`, not `no`, because RubyDoc.info's process tree is not public.

Two smaller gaps: high-volume retrieval of pages returning 200 is uncovered, since Elastic's web-server volume rule (8383a8d0) needs >500 requests and >250 distinct URLs *with status 404 or 403*; and Elastic's one allowlist-style egress rule (9050506c) explicitly permits `atlassian.com` and `google.com`, the services the June activity chained targets through.

## Limits, stated plainly

- **5 of 26 signals are inferred** (RUBY-10, RUBY-22 to RUBY-25), marked in `evidence_basis`. Four are sandbox-side events that must have occurred for the published outcomes to exist but appear in no public log line. RUBY-10, a push authenticated with another account's key, is the event that would exist had the key theft worked; RubyGems reviewed access logs and reported no evidence that it did, so it is not known to have occurred.
- **Counts are the incident report's own.** The 2,000+ packages, 233 "oai" names, 100+ gems using the build chain and the 83-package June burst were not recounted against the index.
- **Registry coverage is not date-pinned.** The five registry `exists` rows were read from public documentation on 2026-09-14.
- **Ruby Central does not accept the attribution.** Its 11 September post says it cannot determine whether the packages were created or published by AI agents. Our rows describe observable events, which do not depend on who caused them.
- **A rule existing is not a detection.** RubyGems was not running Sigma, Elastic or Falco against its application logs, and the people who first named this campaign were outside researchers.
