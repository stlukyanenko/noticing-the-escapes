#!/usr/bin/env python3
"""Step 5: compare the blind second coder's verdicts against the sealed answer key.

Reports raw agreement and Cohen's kappa (stdlib only) for both judgement columns,
prints each confusion matrix, and lists every disagreement.
"""
import csv
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
COLS = ["match", "fires_on_agent_pattern"]


def load(name, key="sample_id"):
    with (HERE / name).open(newline="") as fh:
        return {r[key]: r for r in csv.DictReader(fh)}


def kappa(pairs):
    """Cohen's kappa for a list of (coder_a_label, coder_b_label)."""
    n = len(pairs)
    if n == 0:
        return float("nan")
    po = sum(1 for a, b in pairs if a == b) / n
    ca = Counter(a for a, _ in pairs)
    cb = Counter(b for _, b in pairs)
    labels = set(ca) | set(cb)
    pe = sum((ca[l] / n) * (cb[l] / n) for l in labels)
    if pe == 1.0:
        # Both coders used a single identical label everywhere: kappa undefined.
        return float("nan")
    return (po - pe) / (1 - pe)


def confusion(pairs, labels):
    print("    (rows = coder 1 / answer key, cols = coder 2 / blind)")
    head = "    " + "".join(f"{l:>10}" for l in ["", *labels])
    print(head)
    for a in labels:
        cells = "".join(f"{sum(1 for x, y in pairs if x == a and y == b):>10}" for b in labels)
        print(f"    {a:>10}{cells}")


def main() -> None:
    key = load("answer_key_DO_NOT_OPEN.csv")
    mine = load("blind_verdicts.csv")
    ids = sorted(key, key=int)
    print(f"sample size: {len(ids)} rows\n")

    for col in COLS:
        pairs = [(key[i][col].strip(), mine[i][col].strip()) for i in ids]
        n = len(pairs)
        agree = sum(1 for a, b in pairs if a == b)
        labels = sorted(set(a for a, _ in pairs) | set(b for _, b in pairs))
        k = kappa(pairs)
        print(f"=== {col} ===")
        print(f"raw agreement: {agree}/{n} = {agree / n:.3f}")
        print(f"Cohen's kappa: {k:.3f}" if k == k else "Cohen's kappa: undefined (no label variance)")
        confusion(pairs, labels)
        print()

    print("=== disagreements ===")
    any_dis = False
    for i in ids:
        diffs = [c for c in COLS if key[i][c].strip() != mine[i][c].strip()]
        if not diffs:
            continue
        any_dis = True
        k1, m1 = key[i], mine[i]
        print(f"sample {i} | {k1['incident_id']} / {k1['signal_id']} / {k1['corpus']}")
        print(f"  rule: {k1['rule_id_or_path']}")
        for c in diffs:
            print(f"  {c}: coder1={k1[c]}  coder2={m1[c]}")
        print(f"  coder2 reason: {m1['reason']}")
        print()
    if not any_dis:
        print("none")

    # Headline impact: the report claims rule existed 21/86 and would fire 20/86.
    print("=== headline-relevant label flips ===")
    for i in ids:
        was_exist = key[i]["match"].strip() == "exists"
        now_exist = mine[i]["match"].strip() == "exists"
        was_fire = key[i]["fires_on_agent_pattern"].strip() == "yes"
        now_fire = mine[i]["fires_on_agent_pattern"].strip() == "yes"
        if was_exist != now_exist or was_fire != now_fire:
            print(f"  sample {i} ({key[i]['signal_id']}/{key[i]['corpus']}): "
                  f"exists {was_exist}->{now_exist}, fires {was_fire}->{now_fire}")


if __name__ == "__main__":
    main()
