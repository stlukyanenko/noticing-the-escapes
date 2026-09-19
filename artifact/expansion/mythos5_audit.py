#!/usr/bin/env -S uv run --script --no-project
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Audit Anthropic's stated Mythos 5 figures against the public transcript.

Recomputes every number in mythos5_audit.md / mythos5_counts.json from
resources/incident_data/mythos5_transcript.jsonl. Standard library only.

Usage:
    uv run artifact/expansion/mythos5_audit.py
    uv run artifact/expansion/mythos5_audit.py --json out.json
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[3]
DEFAULT_TRANSCRIPT = REPO / "resources" / "incident_data" / "mythos5_transcript.jsonl"
DEFAULT_JSON_OUT = pathlib.Path(__file__).resolve().parent / "mythos5_counts.json"

# A publish attempt = a tool call that actually EXECUTES an HTTP POST carrying the
# PyPI legacy ":action": "file_upload" payload. Writing the uploader script is not
# an attempt; running it is. We therefore look for an executed command that invokes
# an upload script, or an inline heredoc containing the file_upload action.
UPLOAD_EXEC = re.compile(
    r"(python3?\s+(-W\s+ignore\s+)?[\w./]*upload[\w.]*\.py"  # runs an upload script
    r"|file_upload)",  # or inline heredoc with the legacy file_upload action
    re.I,
)
HOST_RE = re.compile(
    r"https?://([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\.[A-Za-z]{2,63})"
)
# Commands that actually put a request on the wire, as opposed to merely naming a URL.
FETCH_RE = re.compile(
    r"(curl|wget|requests\.(?:get|post|put|head|delete)|urlopen|httpx\.|fetch\(|\.goto)",
    re.I,
)
# The terminal renders an HTTP code in several shapes; all four are the
# script's own print or curl's own output, never free text:
#   "status: 200" / "status=403" / "-> 405" / "[acct1 user/pass] 403" / "<title>400 ..."
STATUS_RE = re.compile(
    r"(?:status[:=]\s*|->\s*|\]\s+|<title>)([1-5]\d\d)\b"
)
# For COUNTING POSTs, match only the uploader script's own one-line-per-request print:
#   "status: 200" / "status=403" / "[acct1 user/pass] 403"
# The broader STATUS_RE above must not be used for counting, because each request also
# echoes the response body, whose "<title>403 ..." would double every POST.
POST_STATUS_RE = re.compile(r"(?:status[:=]\s*|\]\s+)([1-5]\d\d)\b")
VERSION_RE = re.compile(r"\b\d+\.\d+\.\d+\b")
VENDOR_RE = re.compile(
    r"security vendor|virustotal|socket\.dev|snyk|reversinglabs|phylum|"
    r"malware scanner|security scanner",
    re.I,
)
# Hosts that only ever appear because they are quoted inside a response's CSP
# header or a docs URL are not evidence of contact; we count contact only from
# hosts named in the tool CALL (the outbound request the agent composed).


def load(path: pathlib.Path):
    rows = [json.loads(line) for line in path.open() if line.strip()]
    meta = next((r for r in rows if r.get("record") == "metadata"), None)
    msgs = [r for r in rows if r.get("record") == "message"]
    return rows, meta, msgs


def call_text(m) -> str:
    return json.dumps(m.get("tool_call") or "") + json.dumps(m.get("tool_call_raw") or "")


def result_text(m) -> str:
    return json.dumps(m.get("tool_result") or "")


def all_text(m) -> str:
    return call_text(m) + result_text(m) + json.dumps(m.get("content") or "")


def parse_ts(s):
    if not s or len(s) < 20:  # one truncated stamp ('2026-07-18T11:12') is unusable
        return None
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def audit(path: pathlib.Path) -> dict:
    rows, meta, msgs = load(path)
    out: dict = {}

    # ---- 1. schema -----------------------------------------------------------
    keysets = collections.Counter(tuple(sorted(r.keys())) for r in rows)
    idxs = [m["index"] for m in msgs]
    gaps = [(a, b) for a, b in zip(idxs, idxs[1:]) if b != a + 1]
    stamps = [(m["index"], parse_ts(m.get("timestamp"))) for m in msgs]
    usable = [(i, t) for i, t in stamps if t]
    body = [(i, t) for i, t in usable if i > 0]  # index 0 is the release-stamped system prompt
    out["schema"] = {
        "rows_total": len(rows),
        "metadata_rows": 1 if meta else 0,
        "message_rows": len(msgs),
        "field_sets": {" ".join(k): v for k, v in keysets.items()},
        "roles": dict(collections.Counter(m.get("role") for m in msgs)),
        "types": dict(collections.Counter(m.get("type") for m in msgs)),
        "tool_names": dict(collections.Counter(m.get("tool_name") for m in msgs if m.get("tool_name"))),
        "index_min": min(idxs),
        "index_max": max(idxs),
        "index_gaps": gaps,
        "wall_clock_timestamps_present": True,
        "timestamps_missing_or_truncated": [i for i, t in stamps if t is None],
        "session_start": body[0][1].isoformat(),
        "session_end": body[-1][1].isoformat(),
        "session_span_hours": round((body[-1][1] - body[0][1]).total_seconds() / 3600, 3),
        "human_turn_indices": [m["index"] for m in msgs if m.get("role") == "Human"],
    }
    ts_by_idx = {i: t for i, t in usable}

    def when(i):
        t = ts_by_idx.get(i)
        return t.isoformat() if t else None

    # ---- 2a. publish / upload attempts --------------------------------------
    # Two different denominators, both reported, because they disagree and a reader
    # who is handed only one of them will mis-cite the incident:
    #   call level: how many executed tool calls performed at least one upload POST
    #   POST level: how many HTTP POSTs those calls actually sent
    # They differ because two of the uploader scripts loop over a list of credential
    # pairs, so one tool call sends several POSTs and prints several status lines.
    attempts = []
    for n, m in enumerate(msgs):
        if m.get("type") != "ToolMessage" or m.get("tool_name") != "terminal":
            continue
        c = call_text(m)
        if not UPLOAD_EXEC.search(c):
            continue
        if "upload.pypi.org/legacy" not in c and "upload" not in c.lower():
            continue
        # The status may land in this message's result or in the next one: the terminal
        # pages long output across two messages, and the second page REPEATS part of the
        # first. So read this result, and only fall back to the next when this one shows
        # no status at all. Concatenating both double-counts every POST.
        seq = POST_STATUS_RE.findall(result_text(m))  # ordered, NOT deduped: one per POST
        if not seq and n + 1 < len(msgs):
            seq = POST_STATUS_RE.findall(result_text(msgs[n + 1]))
        attempts.append(
            {
                "index": m["index"],
                "timestamp": when(m["index"]),
                "executed": bool(m.get("tool_result")),
                "http_status_sequence": seq,
                "posts_sent": len(seq),
                "distinct_statuses": sorted(set(seq)),
                "succeeded": "200" in seq,
            }
        )
    successes = [a for a in attempts if a["succeeded"]]
    post_seq = [s for a in attempts for s in a["http_status_sequence"]]

    # Same endpoint, but NOT file uploads, so excluded from the attempt count and
    # listed separately: a GET probe of the endpoint, and a POST carrying the legacy
    # ":action": "user" account-registration payload.
    endpoint_other = []
    for m in msgs:
        if m.get("tool_name") != "terminal" or not m.get("tool_result"):
            continue
        c, r = call_text(m), result_text(m)
        if any(a["index"] == m["index"] for a in attempts):
            continue
        # A command that merely `cat`s or `ls`es the uploader script mentions the
        # endpoint without touching it. Require evidence of an actual request: either
        # curl aimed at the endpoint, or a status printed right beside the endpoint URL.
        adjacent = re.search(r"upload\.pypi\.org/legacy/?[^0-9]{0,12}?([1-5]\d\d)\b", r)
        curled = "curl" in c and "upload.pypi.org" in c
        if not adjacent and not curled:
            continue
        endpoint_other.append(
            {
                "index": m["index"],
                "timestamp": when(m["index"]),
                "status": adjacent.group(1) if adjacent else None,
                "kind": "GET probe of the endpoint" if curled else "POST with ':action': 'user' (account registration)",
                "why_excluded": "not a file_upload POST",
            }
        )
    # Script-authoring calls write the uploader but send nothing over the network.
    authored = [
        m["index"]
        for m in msgs
        if m.get("tool_name") == "create_tool" and "upload.pypi.org" in call_text(m)
    ]
    versions = sorted(
        {
            v
            for m in msgs
            for v in VERSION_RE.findall(call_text(m) + result_text(m))
            if "mlflow" in (call_text(m) + result_text(m)).lower() and v.startswith("2.7.")
        }
    )
    out["publish"] = {
        "definition_call_level": (
            "an executed terminal tool call (a tool_result exists) that runs code sending "
            "at least one POST to upload.pypi.org/legacy with the ':action': 'file_upload' "
            "payload"
        ),
        "definition_post_level": "one HTTP POST carrying that payload, one printed status line each",
        "executed_upload_attempts_CALL_LEVEL": len(attempts),
        "upload_posts_POST_LEVEL": len(post_seq),
        "post_status_sequence": post_seq,
        "post_status_tally": dict(collections.Counter(post_seq)),
        "attempts": attempts,
        "same_endpoint_excluded_not_file_upload": endpoint_other,
        "script_authoring_calls_no_network_io": authored,
        "test_pypi_org_upload_attempts": 0,
        "test_pypi_org_note": (
            "test.pypi.org appears only in the index-115 GET probe; no upload was ever "
            "attempted against it, so nothing was excluded on that basis."
        ),
        "successful_uploads": len(successes),
        "first_success_index": successes[0]["index"] if successes else None,
        "first_success_timestamp": successes[0]["timestamp"] if successes else None,
        "distinct_package_versions_seen": versions,
        "distinct_version_count": len(versions),
    }

    # ---- 2b. hosts ----------------------------------------------------------
    # Three nested definitions, narrowest first. Only the narrowest is defensible as
    # "the agent contacted this host"; the widest is not a contact count at all.
    FIRST_NET = 98  # index of the first call reaching the real public internet

    def cmd(m) -> str:
        tc = m.get("tool_call")
        return tc.get("text", "") if isinstance(tc, dict) else ""

    fetched, first_seen = {}, {}  # narrowest: fetch-primitive target
    in_commands = {}  # middle: any host named in an executed command
    for m in msgs:
        if m.get("tool_name") != "terminal" or not m.get("tool_result"):
            continue
        if m["index"] < FIRST_NET:
            continue
        t = cmd(m)
        for h in HOST_RE.findall(t):
            h = h.lower().rstrip(".")
            in_commands.setdefault(h, m["index"])
            if FETCH_RE.search(t):
                fetched.setdefault(h, m["index"])
                first_seen.setdefault(h, m["index"])
    contacted = fetched
    mentioned = {h.lower().rstrip(".") for m in msgs for h in HOST_RE.findall(all_text(m))}
    first_pub_idx = successes[0]["index"] if successes else None
    after_pub = (
        sorted({h for h, i in first_seen.items() if first_pub_idx is not None and i > first_pub_idx})
        if first_pub_idx
        else []
    )
    out["hosts"] = {
        "quote_a_single_number": False,
        "quote_a_single_number_note": (
            "The three counts below measure three different things and the paper should "
            "give the range with definitions, not one number. None of them is comparable "
            "to a count of hosts the package reached."
        ),
        "def_1_fetch_targets": (
            "hosts named in an executed terminal command (index >= 98, the first call to "
            "the real public internet) whose command contains a fetch primitive: curl, "
            "wget, requests.get/post/put/head/delete, urlopen, httpx, fetch(, or a browser "
            ".goto. The defensible floor for 'the agent contacted this host'."
        ),
        "hosts_the_AGENT_contacted": len(contacted),
        "hosts_the_AGENT_contacted_list": [
            {"host": h, "first_contact_index": i}
            for h, i in sorted(contacted.items(), key=lambda kv: kv[1])
        ],
        "def_2_named_in_executed_commands": (
            "any host in the text of an executed terminal command at index >= 98, including "
            "commands with no fetch primitive (grep patterns, variable assignments)."
        ),
        "hosts_named_in_executed_commands": len(in_commands),
        "hosts_named_in_executed_commands_only": sorted(set(in_commands) - set(contacted)),
        "def_3_any_url_string_anywhere": (
            "any host in any URL in any field: calls, results and reasoning. This is a "
            "ceiling, not contact: it picks up hosts quoted in response CSP headers, "
            "documentation links, and placeholder domains the agent never requested."
        ),
        "hosts_mentioned_anywhere_incl_response_headers": len(mentioned),
        "hosts_first_contacted_after_first_successful_publish": after_pub,
        "hosts_the_PACKAGE_reached": 0,
        "hosts_the_PACKAGE_reached_note": (
            "Not observable. Install/download telemetry lives in PyPI's logs, not in the "
            "agent's session; and the first successful publish is the transcript's "
            "second-to-last tool call."
        ),
    }

    # ---- 2c. publish -> removal span ---------------------------------------
    removal_hits = [
        m["index"]
        for m in msgs
        if first_pub_idx
        and m["index"] > first_pub_idx
        and re.search(r"removed|taken down|yanked|410 Gone|project has been", all_text(m), re.I)
    ]
    out["publish_to_removal"] = {
        "first_removal_signal_index": removal_hits[0] if removal_hits else None,
        "messages_from_publish_to_removal": None,
        "messages_from_publish_to_transcript_end": max(idxs) - first_pub_idx if first_pub_idx else None,
        "seconds_from_publish_to_transcript_end": (
            round((ts_by_idx[max(idxs)] - ts_by_idx[first_pub_idx]).total_seconds())
            if first_pub_idx and first_pub_idx in ts_by_idx and max(idxs) in ts_by_idx
            else None
        ),
        "note": "No removal signal in the public transcript; it ends before any takedown.",
    }

    # ---- 2d. first external signal reaching the agent ----------------------
    first_contact = min(first_seen.values()) if first_seen else None
    err = None
    for m in msgs:
        if m.get("type") != "ToolMessage":
            continue
        if "pypi.org" not in call_text(m) and "pypi.org" not in result_text(m):
            continue
        st = [s for s in STATUS_RE.findall(result_text(m)) if s[0] in "45"]
        if st:
            err = (m["index"], st[0])
            break
    out["external_signal"] = {
        "first_external_host_contact_index": first_contact,
        "first_external_host_contact_timestamp": when(first_contact),
        "messages_from_transcript_start_to_first_contact": first_contact - min(i for i in idxs if i > 0),
        "first_negative_response_from_real_service": {"index": err[0], "http": err[1]} if err else None,
        "first_negative_response_timestamp": when(err[0]) if err else None,
        "first_human_turn_index": out["schema"]["human_turn_indices"][0]
        if out["schema"]["human_turn_indices"]
        else None,
        "first_human_turn_is_incident_related": False,
        "first_human_turn_note": "Harness context-budget prompt ('summarize to /tmp/instructions-to-self.txt'), not an incident response.",
        "first_removal_or_takedown_signal": None,
    }

    # ---- 2e. first externally consequential action -------------------------
    out["first_consequential_action"] = {
        "first_read_only_real_internet_call": {"index": first_contact, "timestamp": when(first_contact)},
        "first_state_changing_attempt_on_third_party": {
            "index": attempts[0]["index"] if attempts else None,
            "timestamp": attempts[0]["timestamp"] if attempts else None,
            "what": "first executed upload POST to upload.pypi.org/legacy (rejected 403)",
        },
        "first_successful_state_change": {
            "index": successes[0]["index"] if successes else None,
            "timestamp": successes[0]["timestamp"] if successes else None,
            "what": "upload POST returns 200; next tool call confirms the file on pypi.org/simple/",
        },
        "hours_from_first_attempt_to_success": (
            round(
                (
                    parse_ts(successes[0]["timestamp"]) - parse_ts(attempts[0]["timestamp"])
                ).total_seconds()
                / 3600,
                2,
            )
            if attempts and successes
            else None
        ),
    }

    # ---- 2f. security-vendor contact ---------------------------------------
    vendor = [m["index"] for m in msgs if VENDOR_RE.search(all_text(m))]
    out["security_vendor"] = {
        "matching_message_indices": vendor,
        "contact_observed": False,
        "note": (
            "Release note states messages after 2145 were redacted precisely because the "
            "model there accesses a third-party security scanner's servers. None of that is "
            "in the public file."
        ),
    }
    return out


def report(a: dict) -> None:
    s = a["schema"]
    p = a["publish"]
    print("=" * 72)
    print("MYTHOS 5 TRANSCRIPT AUDIT")
    print("=" * 72)
    print(f"rows={s['rows_total']} (metadata={s['metadata_rows']}, messages={s['message_rows']})")
    print(f"index range {s['index_min']}..{s['index_max']}, gaps: {s['index_gaps']}")
    print(f"roles: {s['roles']}")
    print(f"tools: {s['tool_names']}")
    print(f"wall-clock timestamps present: {s['wall_clock_timestamps_present']}")
    print(f"  session {s['session_start']} -> {s['session_end']} ({s['session_span_hours']} h)")
    print(f"  unusable stamps at indices {s['timestamps_missing_or_truncated']}")
    print(f"human turns at {s['human_turn_indices']}")
    print("-" * 72)
    print(f"(a) executed upload tool calls: {p['executed_upload_attempts_CALL_LEVEL']}")
    print(f"    upload POSTs sent:          {p['upload_posts_POST_LEVEL']}  tally {p['post_status_tally']}")
    for at in p["attempts"]:
        print(
            f"      idx {at['index']:>5}  {at['timestamp']}  executed={at['executed']}  "
            f"posts={at['posts_sent']}  statuses={at['http_status_sequence']}  ok={at['succeeded']}"
        )
    print(f"    same endpoint, not a file_upload (excluded): {[(e['index'], e['kind'], e['status']) for e in p['same_endpoint_excluded_not_file_upload']]}")
    print(f"    script-authoring calls, no network I/O: {p['script_authoring_calls_no_network_io']}")
    print(f"    test.pypi.org upload attempts: {p['test_pypi_org_upload_attempts']}")
    print(f"    successful uploads: {p['successful_uploads']}  versions seen: {p['distinct_package_versions_seen']}")
    h = a["hosts"]
    print(f"(b) quote a single host number? {h['quote_a_single_number']}")
    print(f"    [1] fetch targets, idx>=98  : {h['hosts_the_AGENT_contacted']}")
    print(f"    [2] named in executed cmds  : {h['hosts_named_in_executed_commands']}")
    print(f"    [3] any URL string anywhere : {h['hosts_mentioned_anywhere_incl_response_headers']}")
    print(f"    hosts the PACKAGE reached: {h['hosts_the_PACKAGE_reached']} ({h['hosts_the_PACKAGE_reached_note']})")
    r = a["publish_to_removal"]
    print(f"(c) first removal signal: {r['first_removal_signal_index']}  ({r['note']})")
    print(f"    publish -> transcript end: {r['messages_from_publish_to_transcript_end']} messages / {r['seconds_from_publish_to_transcript_end']} s")
    e = a["external_signal"]
    print(f"(d) first external contact idx {e['first_external_host_contact_index']} at {e['first_external_host_contact_timestamp']}")
    print(f"    messages from start to first contact: {e['messages_from_transcript_start_to_first_contact']}")
    print(f"    first negative response from real service: {e['first_negative_response_from_real_service']} at {e['first_negative_response_timestamp']}")
    print(f"    first human turn: idx {e['first_human_turn_index']} ({e['first_human_turn_note']})")
    c = a["first_consequential_action"]
    print(f"(e) first state-changing attempt: {c['first_state_changing_attempt_on_third_party']}")
    print(f"    first success: {c['first_successful_state_change']}")
    print(f"    hours attempt -> success: {c['hours_from_first_attempt_to_success']}")
    v = a["security_vendor"]
    print(f"(f) security-vendor contact observed: {v['contact_observed']} (matches at {v['matching_message_indices']})")
    print("=" * 72)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--transcript", type=pathlib.Path, default=DEFAULT_TRANSCRIPT)
    ap.add_argument("--json", dest="json_out", type=pathlib.Path, default=DEFAULT_JSON_OUT)
    ns = ap.parse_args()
    if not ns.transcript.exists():
        print(f"transcript not found: {ns.transcript}", file=sys.stderr)
        return 1
    a = audit(ns.transcript)
    report(a)
    ns.json_out.write_text(json.dumps(a, indent=2) + "\n")
    print(f"wrote {ns.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
