# How often a detectable signal was available, and how early

## Method

The unit is one **executed tool call**: a tool message in
`resources/incident_data/mythos5_transcript.jsonl` carrying a `tool_result`, at an index above 82
(the first message the release kept). That is the definition `../mythos5_audit.py` uses, and it
gives **1,361 calls** between 01:02:54Z and 11:28:09Z on 18 July 2026. `prevalence.py` (standard
library only) regenerates the chain: `calls.csv` (index, timestamp, tool, a neutral
verb-plus-target-*class* summary, result status, and no classification column, so a blind second
coder can use it as the frame) -> `classified_calls.csv` (primary signal, optional secondary,
reason, rule or hand; 4 hand-coded rows explained in `overrides.csv`) -> `prevalence.csv`. A signal
is **covered** when any rule corpus in `../coverage_anth.csv` has `match=exists` *and*
`fires_on_agent_pattern=yes`.

## Codebook decision rules (full version, with the 16 definitions, in `codebook.md`)

- **Effective text.** `python3 upload2.py` says nothing on its own, so every rule reads the command
  text *plus* the body of each script the command runs. A script only `cat`-ed counts for nothing.
- **Local tools carry no signal**: file reads, writes and edits leave nothing on the wire. The one
  exception is ANTH_C-10, where writing the package's own source *is* the event: that file ships.
- **Code the request, not the response**: a rejected upload, a refused port forward and a failed
  registration are all signals, because the detectable event is the attempt.
- **One primary, most specific first.** Order: C-09, C-07, C-06, C-10, C-08, C-16, C-03, C-04,
  C-05, C-02, C-01, then benign. A call that uploads using a token is one upload, token secondary.
- **Relay-mediated calls** name only the internal browser helper, so they are coded from the flow
  the relay script runs; weakest rule in the codebook.

## Totals and the headline

Of **1,361 executed tool calls**, **217 (15.9%)** carry one of the enumerated signals, over **11
of the 16 types**; **79** of those calls are of a type with a firing public rule, and only **4**
of the 11 observed types are covered at all. Thirteen calls cannot be coded, their text having
been withheld at release; they are never scored as benign.

**The first rule-covered signal occurred at 01:07:53Z, 10.33 hours before the package was published
at 11:27:24Z: outbound sandbox egress to the real public internet (ANTH_C-01), for which the Sigma
and Elastic corpora both hold a rule that fires on this pattern. By the publish the agent had
emitted 217 signal-carrying calls of 11 distinct types, 79 of them of a covered type. The earliest
alertable signal with no firing rule came earlier still: the attempted SSH reverse port forward out
of the sandbox (ANTH_C-04) at 01:02:54Z, 10.41 hours before the publish, the first visible call.**

| id | signal (short) | n | first | h before publish | last | visible to | alertable | rule fires |
|---|---|---|---|---|---|---|---|---|
| C-01 | sandbox egress to the real internet via SOCKS5 proxy | 61 | 01:07:53 | 10.33 | 11:28:09 | multiple | yes | **yes** |
| C-02 | reachability sweep over a list of external names | 13 | 01:06:10 | 10.35 | 11:02:11 | multiple | yes | no |
| C-03 | POST to a public request collector | 11 | 01:08:43 | 10.31 | 09:09:24 | multiple | yes | **yes** |
| C-04 | SSH reverse port forward out of the sandbox | 2 | 01:02:54 | 10.41 | 01:03:22 | multiple | yes | no |
| C-05 | headless browser driving the registry web UI | 1 | 07:31:26 | 3.93 | 07:31:26 | multiple | no | no |
| C-06 | registry account creation, webmail and SMS steps | 114 | 01:21:01 | 10.11 | 11:18:03 | victim | yes | no |
| C-07 | upload API token issued and first used | 6 | 08:24:46 | 3.04 | 11:26:08 | victim | no | no |
| C-08 | source-distribution build in the sandbox | 1 | 01:18:47 | 10.14 | 01:18:47 | lab sandbox | no | no |
| C-09 | file-upload call to the registry legacy endpoint | 5 | 01:20:31 | 10.11 | 11:27:24 | victim | yes | **yes** |
| C-10 | executable payload placed in the package source | 2 | 01:18:02 | 10.16 | 01:18:34 | multiple | no | **yes** |
| C-16 | name confusion against a popular project | 1 | 01:13:58 | 10.22 | 01:13:58 | victim | yes | no |
| C-11 | three successive version publishes | 0 | — | — | — | victim | yes | no |
| C-12 to C-15 | installs on ~15 hosts, install-time callbacks, vendor-database entry, registry takedown | 0 | — | — | — | victim / third party | yes | **yes** |

The zero rows are not absences of behaviour: C-11 to C-15 are events on the registry, on installing
hosts, or in a vendor database, which an agent-side session cannot contain. `prevalence.csv` also
carries secondary codings: C-01 appears 90 further times there, so proxy egress touches 151 calls.

## Limits

1. **Withheld record.** Messages 1-81 and everything after about 2145 are not public, so every
   "first" is a first *in the visible window*; 13 calls inside it are redacted and counted apart.
2. **"Executed" is our definition** — a tool result exists. That shows the harness ran the call, not
   that it took effect on the far side; only the upload 200, corroborated by the project-index
   read-back, is strong on that point.
3. **Single coder**, 4 rows by hand, so there is no inter-coder agreement figure yet; `calls.csv`
   plus `codebook.md` let the blind second pass run without our labels.
4. **Counts are of the agent's calls, not registry-side events**: the five C-09 calls sent ten
   upload POSTs between them (`../mythos5_audit.md`).
5. **Two behaviours have no row in the taxonomy**: an anti-bot captcha challenge worked through over
   several hundred calls, and payment, exchange and blockchain endpoints contacted from about 04:00Z.
   Both land in C-01 or benign, so the taxonomy undercounts what a detector could have seen.
6. **One session.** These prevalences describe one incident and support no rate or base rate.

Figure: `report/latex/figs/fig6_prevalence.pdf`, from `fig6_prevalence.py`.
