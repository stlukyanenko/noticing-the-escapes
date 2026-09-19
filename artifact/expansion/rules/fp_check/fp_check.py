#!/usr/bin/env python3
"""Crude false-positive check for web_wiki_agent_account_and_get_write_burst.yml.

SYNTHETIC DATA. This script generates a small combined-format access log for an imaginary
wiki, applies the rule's predicate with the standard library only, and reports how often the
correlation would fire. It is not a deployment test and it says nothing about any real wiki's
traffic; it only checks that the predicate separates ordinary reads and human editing from the
incident's GET-write pattern.

Usage (from this directory):
    uv run --no-project python fp_check.py            # writes access_sample.log and prints the report
"""
import random
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOG = HERE / "access_sample.log"
START = datetime(2026, 6, 18, 8, 0, 0, tzinfo=timezone.utc)

# ---------------------------------------------------------------- rule predicate
# Mirrors detection: selection_method and 1 of selection_write_*
WRITE_USEMOD = ("action=form_edit", "action=form_editprefs", "action=editprefs&",
                "action=delete", "action=form_delete")
WRITE_API = ("action=edit", "action=createaccount", "action=delete", "action=move",
             "action=upload", "action=rollback", "action=block")
WRITE_SUBMIT = ("action=submit", "wpSave=", "wpCreateaccount=")


def matches(method: str, uri: str) -> bool:
    if method != "GET":
        return False
    stem, _, query = uri.partition("?")
    if any(k in query for k in WRITE_USEMOD):
        return True
    if stem.endswith("/api.php") and any(k in query for k in WRITE_API):
        return True
    if any(k in query for k in WRITE_SUBMIT):
        return True
    return False


# ---------------------------------------------------------------- synthetic log
def line(ts, ip, method, uri, status, ua):
    return (f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
            f'"{method} {uri} HTTP/1.1" {status} 4213 "-" "{ua}"')


def benign(rng):
    """Eight hours of ordinary traffic: readers, crawlers, and one busy human editor."""
    out = []
    UA_H = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36"
    UA_BOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    readers = [f"203.0.113.{i}" for i in range(2, 40)]
    pages = ["StartSeite", "HilfeSeite", "Impressum", "Projekte", "Archiv2024", "Sandkasten"]
    for minute in range(8 * 60):
        ts = START + timedelta(minutes=minute)
        for _ in range(rng.randint(3, 9)):                      # plain page reads
            out.append(line(ts, rng.choice(readers), "GET",
                            f"/wiki.pl?action=browse&id={rng.choice(pages)}", 200, UA_H))
        if minute % 7 == 0:                                     # recent-changes / search reads
            out.append(line(ts, rng.choice(readers), "GET", "/wiki.pl?action=rc", 200, UA_H))
            out.append(line(ts, rng.choice(readers), "GET",
                            f"/wiki.pl?action=search&word={rng.choice(pages)}", 200, UA_H))
        if minute % 11 == 0:                                    # crawler
            out.append(line(ts, "66.249.66.1", "GET",
                            f"/wiki.pl?action=browse-bare&id={rng.choice(pages)}", 200, UA_BOT))
        if minute % 13 == 0:                                    # API reads (allowed by the rule)
            out.append(line(ts, rng.choice(readers), "GET",
                            "/api.php?action=query&prop=revisions&format=json", 200, UA_H))
    # one human editor, 12 saves per hour: form view by GET, save by POST
    editor = "198.51.100.24"
    for minute in range(0, 8 * 60, 5):
        ts = START + timedelta(minutes=minute)
        out.append(line(ts, editor, "GET", f"/wiki.pl?action=edit&id={rng.choice(pages)}", 200, UA_H))
        out.append(line(ts + timedelta(seconds=95), editor, "POST", "/wiki.pl?action=form_edit", 302, UA_H))
        out.append(line(ts + timedelta(seconds=97), editor, "GET",
                        f"/wiki.pl?action=browse&id={rng.choice(pages)}", 200, UA_H))
    # one approved maintenance bot doing 6 API edits per hour, by POST as the software expects
    for minute in range(0, 8 * 60, 10):
        ts = START + timedelta(minutes=minute)
        out.append(line(ts, "192.0.2.77", "POST", "/api.php?action=edit&format=json", 200, "wikibot/1.2"))
    return out


def swarm(rng):
    """The incident pattern: many short-lived clients registering a username and saving by GET."""
    out = []
    UA = "python-requests/2.32.3"
    for n in range(120):
        ip = f"20.165.{n // 24}.{10 + n % 24}"
        ts = START + timedelta(hours=2, seconds=rng.randint(0, 3500))
        out.append(line(ts, ip, "GET", f"/wiki.pl?action=editprefs&username=Agent{n:04d}", 200, UA))
        out.append(line(ts + timedelta(seconds=2), ip, "GET",
                        f"/wiki.pl?action=form_editprefs&username=Agent{n:04d}", 302, UA))
        for k in range(rng.randint(1, 4)):
            out.append(line(ts + timedelta(seconds=5 + 13 * k), ip, "GET",
                            f"/wiki.pl?action=form_edit&id=Runde3Antwort{n}_{k}&text=Answer", 302, UA))
    # and one high-rate client, the shape the correlation is tuned for
    ip = "20.165.9.9"
    for k in range(140):
        ts = START + timedelta(hours=4, seconds=k * 20)
        out.append(line(ts, ip, "GET", f"/api.php?action=edit&title=Seite{k}&text=x&format=json", 200, UA))
    return out


LINE_RE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3})')


def evaluate(lines, label):
    per_hour = defaultdict(int)          # (ip, hour) -> matching requests
    total_events = len(lines)
    total_matches = 0
    for ln in lines:
        m = LINE_RE.match(ln)
        if not m:
            continue
        ip, ts, method, uri, _status = m.groups()
        if matches(method, uri):
            total_matches += 1
            hour = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").strftime("%Y-%m-%dT%H")
            per_hour[(ip, hour)] += 1
    fires = {k: v for k, v in per_hour.items() if v >= 30}
    per_hour16 = defaultdict(int)        # (ip/16, hour) -> matching requests
    for (ip, hour), v in per_hour.items():
        per_hour16[(".".join(ip.split(".")[:2]), hour)] += v
    fires16 = {k: v for k, v in per_hour16.items() if v >= 30}
    print(f"--- {label}")
    print(f"    log lines:                        {total_events}")
    print(f"    base-rule matches (GET + write):  {total_matches}")
    print(f"    client-hours with >=1 match:      {len(per_hour)}")
    print(f"    correlation alerts (>=30/1h/IP):  {len(fires)}")
    for (ip, hour), v in sorted(fires.items(), key=lambda x: -x[1]):
        print(f"      ALERT {ip} at {hour}Z: {v} state-changing GET requests")
    print(f"    same threshold grouped by /16:    {len(fires16)} alert(s)")
    for (pfx, hour), v in sorted(fires16.items(), key=lambda x: -x[1]):
        print(f"      ALERT {pfx}.0.0/16 at {hour}Z: {v} state-changing GET requests")
    return total_matches, len(fires)


def main():
    rng = random.Random(20260913)
    b = benign(rng)
    s = swarm(rng)
    LOG.write_text("\n".join(b + s) + "\n")
    print(f"synthetic log written to {LOG} ({len(b)} benign + {len(s)} injected lines)\n")
    evaluate(b, "benign traffic only (8 hours: readers, crawler, one human editor, one POST bot)")
    print()
    evaluate(b + s, "benign traffic plus the injected swarm pattern")


if __name__ == "__main__":
    sys.exit(main())
