#!/usr/bin/env python3
"""Blind second pass #2 sampler.

Corrects the pass-1 sampling flaw: pass 1 drew from all coverage.csv rows,
including sentinel rows whose rule_id_or_path names no rule at all
("none", "(no matching rule)", empty). Those rows are unfalsifiable by a
blind re-reader. Here we keep only rows that name a REAL rule, exclude the
20 rows already drawn in pass 1, and draw 20 fresh rows.
"""
import csv
import os
import random
import re
import collections

EXP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.dirname(os.path.abspath(__file__))
SEED = 20260914
N = 20

SENTINELS = {"", "none", "(no matching rule)", "no matching rule", "n/a", "na", "-", "--"}

PATHY = re.compile(r"[\w.*-]+/[\w.*-]+")            # path-like slash (no spaces around it)
EXTY = re.compile(r"\.(yml|yaml|toml)\b", re.I)      # rule file extension
UUIDY = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
VENDORY = re.compile(r"\b[A-Z][A-Za-z]+:[A-Za-z]+/[A-Za-z]+")  # e.g. GuardDuty finding types


def names_a_rule(v):
    s = (v or "").strip()
    if s.lower() in SENTINELS:
        return False
    return bool(PATHY.search(s) or EXTY.search(s) or UUIDY.search(s) or VENDORY.search(s))


def main():
    with open(os.path.join(EXP, "coverage.csv"), newline="") as f:
        rows = list(csv.DictReader(f))
    total = len(rows)

    qualified = [r for r in rows if names_a_rule(r["rule_id_or_path"])]

    # exclude pass-1 rows by the 4-tuple key
    p1 = os.path.join(EXP, "blind_second_pass", "blind_sample.csv")
    excl = set()
    with open(p1, newline="") as f:
        for r in csv.DictReader(f):
            excl.add((r["incident_id"], r["signal_id"], r["corpus"], r["rule_id_or_path"]))

    pool = [r for r in qualified
            if (r["incident_id"], r["signal_id"], r["corpus"], r["rule_id_or_path"]) not in excl]

    print(f"coverage.csv rows: {total}")
    print(f"rows naming a real rule (sentinel filter passed): {len(qualified)}")
    print(f"pass-1 rows excluded from pool: {len(qualified) - len(pool)}")
    print(f"eligible pool: {len(pool)}")

    rnd = random.Random(SEED)
    if len(pool) <= N:
        sample = list(pool)
        print(f"NOTE: only {len(pool)} qualify (<= {N}); taking all of them.")
    else:
        sample = rnd.sample(pool, N)

    sample_cols = ["sample_id", "incident_id", "signal_id", "corpus",
                   "rule_id_or_path", "commit_hash_at_incident_date"]
    with open(os.path.join(OUT, "blind_sample.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=sample_cols)
        w.writeheader()
        for i, r in enumerate(sample, 1):
            w.writerow({"sample_id": i, **{c: r[c] for c in sample_cols[1:]}})

    with open(os.path.join(OUT, "answer_key_DO_NOT_OPEN.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["sample_id", "match", "fires_on_agent_pattern"])
        for i, r in enumerate(sample, 1):
            w.writerow([i, r["match"], r["fires_on_agent_pattern"]])

    print("\n-- sample composition --")
    print("by corpus:")
    for k, v in sorted(collections.Counter(r["corpus"] for r in sample).items()):
        print(f"  {k}: {v}")
    print("by incident:")
    for k, v in sorted(collections.Counter(r["incident_id"] for r in sample).items()):
        print(f"  {k}: {v}")
    print("\nwrote blind_sample.csv and answer_key_DO_NOT_OPEN.csv")


if __name__ == "__main__":
    main()
