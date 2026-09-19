#!/usr/bin/env python3
"""Blind second-pass agreement: coder A (classified_calls.csv, full call text)
vs coder B (blind_verdicts.csv, neutral one-line summaries only).

Stdlib only. Writes agreement.txt next to this file.
"""
import csv
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PARENT = os.path.dirname(HERE)
COVERED = {"ANTH_C-01", "ANTH_C-03", "ANTH_C-09", "ANTH_C-10"}


def load_a(indices):
    with open(os.path.join(PARENT, "classified_calls.csv"), newline="") as fh:
        rows = list(csv.DictReader(fh))
    # locate the primary-category column without assuming its name
    fields = rows[0].keys()
    pcol = next(c for c in fields
                if c.lower() in ("primary", "signal", "signal_id",
                                 "primary_signal", "category", "primary_id"))
    scol = next((c for c in fields if c.lower() in
                 ("secondary", "secondary_signal", "secondary_id")), None)
    rcol = next((c for c in fields if c.lower() in
                 ("reason", "why", "rule", "note", "coded_by")), None)
    out = {}
    for r in rows:
        i = int(r["index"])
        if i in indices:
            out[i] = (norm(r[pcol]),
                      norm(r[scol]) if scol else "",
                      (r[rcol] or "") if rcol else "")
    return out, pcol


def norm(v):
    v = (v or "").strip()
    if v in ("", "-", "none", "NONE", "nan"):
        return "BENIGN"
    if v.upper() in ("BENIGN", "BENIGN/TASK", "BENIGN_TASK"):
        return "BENIGN"
    return v


def kappa(pairs):
    n = len(pairs)
    labels = sorted({a for a, _ in pairs} | {b for _, b in pairs})
    po = sum(1 for a, b in pairs if a == b) / n
    ca = {l: sum(1 for a, _ in pairs if a == l) / n for l in labels}
    cb = {l: sum(1 for _, b in pairs if b == l) / n for l in labels}
    pe = sum(ca[l] * cb[l] for l in labels)
    return po, pe, (po - pe) / (1 - pe) if pe != 1 else float("nan")


def main():
    with open(os.path.join(HERE, "blind_verdicts.csv"), newline="") as fh:
        b_rows = list(csv.DictReader(fh))
    b = {int(r["index"]): (norm(r["primary"]), r["secondary"].strip(),
                           r["reason"]) for r in b_rows}
    with open(os.path.join(HERE, "blind_sample.csv"), newline="") as fh:
        summ = {int(r["index"]): r["summary"] for r in csv.DictReader(fh)}

    a, pcol = load_a(set(b))
    missing = sorted(set(b) - set(a))
    idx = sorted(set(b) & set(a))

    L = []
    P = L.append
    P("Blind second-pass agreement, Mythos-5 signal coding")
    P("=" * 70)
    P(f"coder A = classified_calls.csv (full call text); primary column '{pcol}'")
    P("coder B = blind_verdicts.csv (neutral one-line summaries only)")
    P(f"sample n = {len(idx)}" + (f"  (missing from A: {missing})" if missing else ""))
    P("")

    pairs = [(a[i][0], b[i][0]) for i in idx]
    po, pe, k = kappa(pairs)
    n_ag = sum(1 for x, y in pairs if x == y)
    P("1. PRIMARY CATEGORY")
    P(f"   raw agreement      {n_ag}/{len(idx)} = {po:.3f}")
    P(f"   chance agreement   {pe:.3f}")
    P(f"   Cohen's kappa      {k:.3f}")
    P("")

    for name, fn in (("2. ANY SIGNAL vs BENIGN", lambda v: v != "BENIGN"),
                     ("3. COVERED TYPE (C-01/03/09/10) vs NOT",
                      lambda v: v in COVERED)):
        bp = [(fn(x), fn(y)) for x, y in pairs]
        bpo, bpe, bk = kappa(bp)
        nb = sum(1 for x, y in bp if x == y)
        P(name)
        P(f"   raw agreement      {nb}/{len(idx)} = {bpo:.3f}")
        P(f"   Cohen's kappa      {bk:.3f}")
        P("")

    P("4. CONFUSION MATRIX (rows = coder A, cols = coder B)")
    labels = sorted({x for x, _ in pairs} | {y for _, y in pairs})
    w = max(len(l) for l in labels) + 1
    P("   " + " " * w + "".join(l.rjust(w) for l in labels) + "  total")
    for ra in labels:
        row = [sum(1 for x, y in pairs if x == ra and y == cb) for cb in labels]
        P("   " + ra.ljust(w) + "".join(str(v).rjust(w) for v in row)
          + str(sum(row)).rjust(7))
    P("   " + "total".ljust(w)
      + "".join(str(sum(1 for _, y in pairs if y == cb)).rjust(w)
                for cb in labels) + str(len(pairs)).rjust(7))
    P("")

    P("5. DISAGREEMENTS ON PRIMARY")
    dis = [i for i in idx if a[i][0] != b[i][0]]
    if not dis:
        P("   none")
    for i in dis:
        P(f"   index {i}  |  {summ[i]}")
        P(f"     A: {a[i][0]}" + (f" (2nd {a[i][1]})" if a[i][1] and a[i][1] != 'BENIGN' else "")
          + (f"  [{a[i][2]}]" if a[i][2] else ""))
        P(f"     B: {b[i][0]}" + (f" (2nd {b[i][1]})" if b[i][1] else ""))
        P(f"     B reason: {b[i][2]}")
        P("")

    und = [i for i in idx if "UNDECIDABLE" in b[i][1]]
    P(f"6. B marked UNDECIDABLE_FROM_SUMMARY on {len(und)}/{len(idx)} rows: {und}")
    P(f"   of those, A and B still agreed on {sum(1 for i in und if a[i][0]==b[i][0])}")

    txt = "\n".join(L) + "\n"
    with open(os.path.join(HERE, "agreement.txt"), "w") as fh:
        fh.write(txt)
    print(txt)


if __name__ == "__main__":
    main()
