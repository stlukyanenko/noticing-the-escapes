#!/usr/bin/env python3
"""Step 1 of the blind second-pass protocol.

Draws a seeded sample of 20 coverage rows that name a concrete rule, writes a
BLINDED copy (no verdict columns) for the second coder, and stashes the original
verdicts in a separate answer-key file that must not be opened until step 5.
"""
import csv
import random
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXPANSION = HERE.parent
SEED = 20260913
N = 20

BLIND_COLS = [
    "sample_id",
    "incident_id",
    "signal_id",
    "corpus",
    "rule_id_or_path",
    "commit_hash_at_incident_date",
]
KEY_COLS = [
    "sample_id",
    "incident_id",
    "signal_id",
    "corpus",
    "rule_id_or_path",
    "match",
    "fires_on_agent_pattern",
]


def main() -> None:
    with (EXPANSION / "coverage.csv").open(newline="") as fh:
        rows = [r for r in csv.DictReader(fh) if (r.get("rule_id_or_path") or "").strip()]

    print(f"coverage.csv rows with a concrete rule named: {len(rows)}")

    rng = random.Random(SEED)
    sample = rng.sample(rows, N)
    for i, row in enumerate(sample, start=1):
        row["sample_id"] = str(i)

    with (HERE / "blind_sample.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=BLIND_COLS, extrasaction="ignore")
        w.writeheader()
        w.writerows(sample)

    with (HERE / "answer_key_DO_NOT_OPEN.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=KEY_COLS, extrasaction="ignore")
        w.writeheader()
        w.writerows(sample)

    print(f"wrote blind_sample.csv ({N} rows, no verdict columns)")
    print("wrote answer_key_DO_NOT_OPEN.csv (verdicts sealed until step 5)")


if __name__ == "__main__":
    main()
