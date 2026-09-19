# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""
Merge the per-group signal and coverage tables into one, and compute the
detection-coverage headline. Stdlib only.

Inputs (written by three independent agents, one per incident group):
  signals_<group>.csv   incident_id,signal_id,signal_description,visible_to,
                        logged_by_default,alertable_realtime,evidence_basis,source_note
  coverage_<group>.csv  incident_id,signal_id,corpus,rule_id_or_path,
                        commit_hash_at_incident_date,match,fires_on_agent_pattern,note

Outputs: signals.csv, coverage.csv (concatenated, deduplicated on key), and a
printed summary. A signal is COVERED if ANY corpus has match == "exists"; it is
COVERED-AND-FIRES if any corpus has match == "exists" AND
fires_on_agent_pattern == "yes". Both are reported, because a rule that exists
but only fires on human tradecraft is the gap this audit is about.

Run:  uv run artifact/expansion/merge_coverage.py
"""

import csv
import glob
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).parent
SIG_COLS = ["incident_id", "signal_id", "signal_description", "visible_to",
            "logged_by_default", "alertable_realtime", "evidence_basis", "source_note"]
COV_COLS = ["incident_id", "signal_id", "corpus", "rule_id_or_path",
            "commit_hash_at_incident_date", "match", "fires_on_agent_pattern", "note"]


def read_group(pattern, cols):
    rows, sources = [], []
    for p in sorted(glob.glob(str(HERE / pattern))):
        with open(p, newline="", encoding="utf-8") as f:
            r = list(csv.DictReader(f))
        missing = [c for c in cols if r and c not in r[0]]
        if missing:
            raise SystemExit(f"{p}: missing columns {missing}")
        rows.extend({c: (x.get(c) or "").strip() for c in cols} for x in r)
        sources.append(Path(p).name)
    return rows, sources


def write(path, cols, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def main():
    sig, sig_src = read_group("signals_*.csv", SIG_COLS)
    cov, cov_src = read_group("coverage_*.csv", COV_COLS)
    # dedupe (a group could list a signal twice by accident)
    sig = list({(r["incident_id"], r["signal_id"]): r for r in sig}.values())
    cov = list({(r["incident_id"], r["signal_id"], r["corpus"], r["rule_id_or_path"]): r
                for r in cov}.values())
    write(HERE / "signals.csv", SIG_COLS, sig)
    write(HERE / "coverage.csv", COV_COLS, cov)

    print("=" * 72)
    print("DETECTION-COVERAGE AUDIT -- merged")
    print("=" * 72)
    print(f"signal groups : {', '.join(sig_src)}")
    print(f"coverage groups: {', '.join(cov_src)}")
    print(f"signals: {len(sig)}   coverage rows: {len(cov)}")

    # per-signal verdicts
    exists = defaultdict(bool)
    fires = defaultdict(bool)
    for r in cov:
        k = (r["incident_id"], r["signal_id"])
        if r["match"].lower() == "exists":
            exists[k] = True
            if r["fires_on_agent_pattern"].lower() == "yes":
                fires[k] = True

    by_inc = defaultdict(list)
    for r in sig:
        by_inc[r["incident_id"]].append(r)

    print("\n1. PUBLIC-RULE COVERAGE PER INCIDENT  (pinned to the incident date)")
    print(f"   {'incident':8s} {'signals':>7s} {'rule exists':>12s} {'exists+fires':>13s}")
    tot_n = tot_e = tot_f = 0
    for inc in sorted(by_inc):
        n = len(by_inc[inc])
        e = sum(exists[(inc, s["signal_id"])] for s in by_inc[inc])
        fz = sum(fires[(inc, s["signal_id"])] for s in by_inc[inc])
        tot_n, tot_e, tot_f = tot_n + n, tot_e + e, tot_f + fz
        print(f"   {inc:8s} {n:>7d} {e:>12d} {fz:>13d}")
    print(f"   {'ALL':8s} {tot_n:>7d} {tot_e:>12d} {tot_f:>13d}")
    print(f"   -> a public rule EXISTED for {tot_e} of {tot_n} observable signals;")
    print(f"      it would also FIRE on the agent's pattern for {tot_f} of {tot_n}.")
    # Incidents whose public record carries almost no action detail: their
    # "0 of n" measures disclosure thinness, not rule coverage. Report the
    # headline a second time without them so the two are never conflated.
    THIN = {"ANTH_A", "ANTH_B"}
    n2 = sum(len(by_inc[i]) for i in by_inc if i not in THIN)
    e2 = sum(exists[(i, s["signal_id"])] for i in by_inc if i not in THIN for s in by_inc[i])
    f2 = sum(fires[(i, s["signal_id"])] for i in by_inc if i not in THIN for s in by_inc[i])
    print(f"   Excluding thin-disclosure rows ({', '.join(sorted(THIN))}), whose")
    print(f"   signals are mostly the lab's own retrospective records:")
    print(f"      rule existed for {e2} of {n2}; would fire for {f2} of {n2}.")

    print("\n2. VISIBILITY BY SIDE  (who could have seen each signal)")
    print("   (free-text qualifiers such as 'multiple (victim; relay operators)'")
    print("    are folded into their head category; the detail stays in signals.csv)")
    vis = defaultdict(int)
    for r in sig:
        head = (r["visible_to"] or "unspecified").split("(")[0].strip().lower()
        vis[head or "unspecified"] += 1
    for k, v in sorted(vis.items(), key=lambda kv: -kv[1]):
        print(f"   {v:3d}  {k}")

    print("\n3. EVIDENCE BASIS  (stated in a source vs inferred from the action)")
    eb = defaultdict(int)
    for r in sig:
        eb[r["evidence_basis"] or "unspecified"] += 1
    for k, v in sorted(eb.items(), key=lambda kv: -kv[1]):
        print(f"   {v:3d}  {k}")

    print("\n4. REAL-TIME ALERTABLE signals with NO rule that fires on the agent pattern")
    gap = [s for s in sig
           if s["alertable_realtime"].lower() == "yes"
           and not fires[(s["incident_id"], s["signal_id"])]]
    print(f"   {len(gap)} signals. These are the rule-writing gap:")
    for s in gap:
        print(f"   - {s['incident_id']:7s} {s['signal_id']:10s} {s['signal_description'][:70]}")

    print("\nLimits: this audits rule TEXT at a pinned commit, never a deployment or")
    print("real telemetry; 'fires_on_agent_pattern' is the auditor's judgement;")
    print("inferred signals are counted alongside stated ones (see section 3).")


if __name__ == "__main__":
    main()
