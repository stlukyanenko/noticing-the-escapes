#!/usr/bin/env python3
"""Compare blind pass-2 verdicts against the sealed original coverage.csv values."""
import csv
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name, cols):
    with open(os.path.join(HERE, name), newline="") as f:
        return {r["sample_id"]: {c: r[c].strip() for c in cols} for r in csv.DictReader(f)}


def kappa(pairs, labels):
    n = len(pairs)
    po = sum(1 for a, b in pairs if a == b) / n
    pe = 0.0
    for lab in labels:
        pa = sum(1 for a, _ in pairs if a == lab) / n
        pb = sum(1 for _, b in pairs if b == lab) / n
        pe += pa * pb
    k = (po - pe) / (1 - pe) if pe < 1 else float("nan")
    return po, pe, k


def confusion(pairs, labels, out):
    w = max(9, max(len(l) for l in labels) + 1)
    out.append("rows = original (pass 1 author), cols = blind pass 2")
    out.append(" " * w + "".join(l.rjust(w) for l in labels) + "  total".rjust(8))
    for r in labels:
        row = [sum(1 for a, b in pairs if a == r and b == c) for c in labels]
        out.append(r.ljust(w) + "".join(str(v).rjust(w) for v in row) + str(sum(row)).rjust(8))
    tot = [sum(1 for _, b in pairs if b == c) for c in labels]
    out.append("total".ljust(w) + "".join(str(v).rjust(w) for v in tot) + str(len(pairs)).rjust(8))


def main():
    mine = load("blind_verdicts.csv", ["match", "fires_on_agent_pattern", "reason"])
    key = load("answer_key_DO_NOT_OPEN.csv", ["match", "fires_on_agent_pattern"])
    ids = sorted(mine, key=int)

    out = ["Blind second pass #2 -- agreement with the original coverage.csv verdicts",
           f"n = {len(ids)} sampled rows, all naming a real detection rule", ""]

    for col, labels in [("match", ["exists", "partial", "none"]),
                        ("fires_on_agent_pattern", ["yes", "no", "unclear"])]:
        pairs = [(key[i][col], mine[i][col]) for i in ids]
        po, pe, k = kappa(pairs, labels)
        out.append("=" * 70)
        out.append(f"COLUMN: {col}")
        out.append("=" * 70)
        out.append(f"raw agreement : {po:.3f}  ({sum(1 for a,b in pairs if a==b)}/{len(pairs)})")
        out.append(f"chance agreement (pe): {pe:.3f}")
        out.append(f"Cohen's kappa : {k:.3f}")
        out.append("")
        confusion(pairs, labels, out)
        out.append("")
        dis = [i for i in ids if key[i][col] != mine[i][col]]
        out.append(f"disagreements ({len(dis)}):")
        if not dis:
            out.append("  none")
        for i in dis:
            out.append(f"  sample {i}: original={key[i][col]!r}  blind2={mine[i][col]!r}")
            out.append(f"    blind2 reason: {mine[i]['reason']}")
        out.append("")

    both = [i for i in ids
            if key[i]["match"] != mine[i]["match"]
            or key[i]["fires_on_agent_pattern"] != mine[i]["fires_on_agent_pattern"]]
    out.append("=" * 70)
    out.append(f"rows disagreeing on at least one column: {len(both)} of {len(ids)} -> {both}")
    out.append("")
    out.append("per-row table")
    out.append("id  original_match blind2_match | original_fires blind2_fires")
    for i in ids:
        flag = "  <-- differs" if i in both else ""
        out.append(f"{i:>2}  {key[i]['match']:<14} {mine[i]['match']:<12} | "
                   f"{key[i]['fires_on_agent_pattern']:<14} "
                   f"{mine[i]['fires_on_agent_pattern']:<12}{flag}")

    text = "\n".join(out) + "\n"
    with open(os.path.join(HERE, "agreement.txt"), "w") as f:
        f.write(text)
    sys.stdout.write(text)


if __name__ == "__main__":
    main()
