# Two Sigma rules for signals no public corpus covered

Written 2026-09-13, 21:06 CEST (`date` checked). Companion to
[../coverage_hf_wiki.md](../coverage_hf_wiki.md) and [../coverage_hf_wiki.csv](../coverage_hf_wiki.csv).
Both rules are defensive and generic, and use log sources the affected party already has.

## Rule 1 — [web_wiki_agent_account_and_get_write_burst.yml](web_wiki_agent_account_and_get_write_burst.yml)

**What it detects (corrected after review).** A GET request that actually *commits* a change. An
earlier draft matched `action=edit`, which in MediaWiki is the edit-*form view* — a read every
human editor produces; that predicate was wrong and is gone. The rule now matches GET plus one of
three write families: UseModWiki / ProWiki submit handlers (`action=form_edit` saves a page,
`action=editprefs` / `form_editprefs` writes the preferences that register a username on these
engines, `action=delete`); a write call to `api.php` (`action=edit`, `createaccount`, `delete`,
`move`, `upload`, `rollback`, `block`), which the software expects as a POST with a token, so a
GET-delivered one is anomalous by itself; and a MediaWiki form submit arriving as GET
(`action=submit`, `wpSave=`, `wpCreateaccount=`). Two documents: the building block (`cc0c558e-…`)
and an `event_count` correlation (`85469f73-…`) at 30 per client-hour.

**Which paths the swarm actually used.** The wikis were ProWiki, a UseModWiki derivative, not
MediaWiki. The export's request actions are `form_edit` (save handler), `delete` (the 5,217
administrator deletions) and, among the 101 recorded probes, read-only `browse`, `browse-bare`,
`rc`, `random`, `search` plus `editprefs` / `form_editprefs`. These engines have no sign-up page:
a username is registered by writing preferences, which is why the export holds 3,103 account names
(over 3,700 across the farm). The rule treats that preferences write as the account-creation event
and ignores every read action in the list.

**Log source and threshold.** Webserver access logs carrying the full request line with the query
string, method, status code and client address; logs truncated at the path do not work. The export
holds 14,591 saves over 39 days, peaking at 6,543 edits on 2026-06-18, against administrators
deleting about 100 pages a day, so agent activity sits in the tens to hundreds of writes per
client-hour while a human editor saves a handful an hour and does so by POST. Thirty per
client-hour is about an order of magnitude above a busy human.

**Expected false positives.** Approved wiki bots, import and migration jobs, administrator cleanup
sweeps (bursts of `delete` from one address), and shared egress addresses. Exclude bot and
administrator addresses first; under heavy NAT, group by address and user agent together.

**Why no public corpus had it.** From our coverage rows: WIKI-01 (3,700-plus account registrations)
is `partial` in Sigma and `none` in Elastic and Falco, because account-creation rules exist only
for enterprise identity platforms (Okta, Entra ID, FortiGate, ESXi), none of them a rate rule.
WIKI-02 (roughly 15,000 page saves) and WIKI-03 (state-changing writes arriving as GET) are `none`
in all three corpora at the pinned 2026-05-24 commits; no corpus mentions MediaWiki at all.

## Rule 2 — [registry_new_account_rejected_then_accepted_upload.yml](registry_new_account_rejected_then_accepted_upload.yml)

**What it detects.** One publisher account, within a day and in order: the account is created, its
uploads are rejected repeatedly (HTTP 400 or 403) for a project name, then an upload succeeds. The
file holds three building blocks (account created, upload rejected, upload accepted) and a
`temporal_ordered` correlation (id `c2e54b18-…`) grouped on the acting account.

**Whose rule this is.** The registry operator's (PyPI/PSF, npm, an internal registry), not the
model developer's. In the Anthropic "incident C" case the registry's own takedown within about an
hour was the detection, and everything the agent did before the successful publish sat in the
registry's application logs. The rule names no package, typosquat target or hostname.

**Log source a defender needs.** Registry application and publish-API logs with an event name, the
acting account, the account-creation event, the target project name and each upload's HTTP status,
in ECS-style field names an operator would normalise to.

**Expected false positives.** A genuine first-time publisher rejected for a name clash who fixes it
the same day; release pipelines stood up by a brand-new account; registries returning 403 for rate
limiting. Requiring three or more rejections, or grouping by project name too, cuts the first two.

**Why no public corpus had it.** Our `registry` coverage row (HF-03) records that registry-side
scanners model *published malicious packages*, inspecting artifact content after publication, and
none models publisher behaviour before it. SigmaHQ at the pinned commits has no rule with a
`package_registry` log source; its npm rules are endpoint rules about malicious installs on a
developer machine (Shai-Hulud), not operator-side publish telemetry.

## Rule 3 (Tor / SOCKS egress) — deliberately skipped

Public corpora already cover this one (Elastic `command_and_control_curl_socks_proxy_detected`,
AWS `UnauthorizedAccess:Runtime/TorClient`), UK AISI detected its own incident this way within
minutes, and the "without an interactive TTY" variant reads as guidance on what to avoid.

## Crude false-positive check on rule 1 (synthetic data)

[fp_check/fp_check.py](fp_check/fp_check.py) generates a synthetic combined-format access log,
re-implements the rule's predicate in the standard library and counts how often the correlation
would fire. The data is invented: not a deployment test, and it says nothing about any real wiki's
traffic. Artifacts: [fp_check/access_sample.log](fp_check/access_sample.log) (4,086 lines) and
[fp_check/run_output.txt](fp_check/run_output.txt); command (stdlib, seeded, reproducible):
`uv run --no-project python fp_check.py`.

Benign half — eight hours of page reads from 38 addresses, a crawler, API *read* calls, one busy
human editor (12 saves an hour: GET form view then POST save) and an approved bot doing 6 API
edits an hour by POST: **0 base-rule matches and 0 alerts in 3,412 lines**, a benign fire rate of
zero per hour.

Injected half — 120 short-lived clients each registering a username and saving by GET, plus one
high-rate client: **674 base-rule matches and 1 correlation alert** (140 state-changing GET
requests from one address in one hour). The 120 spread-out clients stay under a per-address
threshold, which is the rule's blind spot and is now stated in the rule: the same threshold on the
/16 prefix raises 2 alerts, one of them on 534 requests in an hour.

## Validation

Run in `artifact/expansion/rules/` after the rewrite of rule 1:
`uvx --from sigma-cli sigma check --fail-on-issues .` Output (sigma-cli 3.1.0, pySigma
validators): `Found 0 errors, 0 condition errors and 0 issues. No rule errors found. No condition
errors found. No validation issues found.` Six documents parsed, two for rule 1 and four for rule
2. Passing the checker means the YAML, required fields, identifiers and correlation references are
spec-compliant. Neither rule has been run against real production logs, and that is the limit to
state in the paper; rule 1's predicate was exercised only on the synthetic log above.
