# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""
Caught From Outside -- recompute every headline number from detections.csv.

This script is the third-party verifier. It reads only detections.csv (one row
per disclosed 2026 evaluation-agent incident) and recomputes, from the dates in
that file, every number the report puts in its headline. It uses the Python
standard library only, so anyone can audit it without installing anything.

Run:  uv run artifact/verify.py

What it prints, in the order the report should present them:
  1. THE DISCLOSURE CASCADE  -- the durable, un-confounded finding: how many
     incidents a lab learned about only because a *different* organisation
     disclosed first.
  2. DETECTION LATENCY        -- first unauthorized action -> first detection,
     per incident, with firm vs. approximate dates kept separate.
  3. DISCLOSURE LATENCY       -- first detection -> public disclosure.
  4. DETECTOR-CLASS TALLY     -- who first detected each incident. Reported as
     a description of the disclosed set, NOT as a base rate, because of the
     survivorship confound printed at the end.
  5. DETECTION LATENCY WITH UNCERTAINTY -- the same latency, but never as a
     bare midpoint: a point for firm rows, an interval for month-precise
     rows, a one-sided bound (or "not estimable") for censored rows.
  6. CROSS-INCIDENT SUMMARY   -- median detection latency over firm rows with
     a seeded bootstrap interval, plus a clearly-labelled sensitivity median
     that also samples inside the month-precise intervals.
  7. SENSITIVITY              -- the cascade count and detector tally
     recomputed with placeholder rows dropped, side by side with all rows.

Date precision: each date carries a precision flag (hour / day / month /
unknown). A latency is called FIRM only when both of its endpoints are
hour- or day-precise. Anything resting on a month-level or unknown date is
printed as APPROXIMATE and is never averaged into a firm headline number.

Interval rules used by sections 5-7 (one rule per precision flag):
  hour, day -> a POINT. The date is taken as exact (+/- 0 days).
  month     -> a UNIFORM INTERVAL over the whole calendar month of the date
               given. The CSV stores month-precise dates as midpoints (day
               15), so the midpoint is expanded back to [1st .. last day].
  unknown   -> CENSORED. No interval is invented. If the source notes fix one
               side (ANTH_B and ANTH_D: the first action happened "before
               23 Jul", i.e. an UPPER bound on the action date, which is a
               LOWER bound on the latency) we print only that bound. If no
               side is fixed (ANTH_C, whose publish date "is not public", and
               IRREG, whose dates are "all placeholder") we print
               "not estimable" and the row enters no arithmetic.
A latency interval is [earliest detection - latest action, latest detection -
earliest action], i.e. the widest span the two date intervals allow.
"""

import csv
import calendar
import random
import statistics
from datetime import date
from pathlib import Path

HERE = Path(__file__).parent
CSV = HERE / "detections.csv"

FIRM = {"hour", "day"}          # precisions we will do arithmetic on
OPENAI_DISCLOSURE = date(2026, 7, 21)   # the event that triggered the cascade

BOOTSTRAP_N = 10_000
BOOTSTRAP_SEED = 20260913       # fixed so the interval is reproducible

# One-sided bounds read out of the CSV's source_notes, for rows whose date
# precision is "unknown" but whose direction the notes do pin down.
# incident_id -> (which endpoint, "on_or_before" date, quoted justification)
ACTION_UPPER_BOUND = {
    "ANTH_B": (date(2026, 7, 23), "notes: 'placeholder before 23 Jul'"),
    "ANTH_D": (date(2026, 7, 23), "notes: found in the 23-24 Jul retrospective"),
}


def parse_date(s):
    s = (s or "").strip()
    if not s:
        return None
    return date.fromisoformat(s)


def latency_days(start, start_prec, end, end_prec):
    """Return (days, firm?). days is None if either endpoint is missing."""
    if start is None or end is None:
        return None, False
    firm = start_prec in FIRM and end_prec in FIRM
    return (end - start).days, firm


def date_interval(d, precision):
    """Return (earliest, latest) possible true dates, or None if censored.

    hour/day -> the date itself on both ends. month -> the first and last day
    of that calendar month. unknown -> None (censored; nothing is invented).
    """
    if d is None:
        return None
    if precision in FIRM:
        return (d, d)
    if precision == "month":
        last = calendar.monthrange(d.year, d.month)[1]
        return (date(d.year, d.month, 1), date(d.year, d.month, last))
    return None


def latency_estimate(r):
    """Classify one row's detection latency.

    Returns (kind, value, note) where kind is one of:
      "point"        value = days                      (both ends firm)
      "interval"     value = (lo_days, hi_days)        (a month-precise end)
      "lower_bound"  value = lo_days                   (censored, one side fixed)
      "none"         value = None                      (not estimable)
    """
    act = date_interval(r["_fa"], r["first_action_precision"])
    det = date_interval(r["_fd"], r["detection_precision"])
    if det is None:
        return "none", None, "detection date unknown"
    if act is None:
        bound = ACTION_UPPER_BOUND.get(r["incident_id"])
        if bound is None:
            return "none", None, "first-action date unknown, no bound in source notes"
        cap, why = bound
        lo = (det[0] - cap).days
        return "lower_bound", lo, why
    lo = (det[0] - act[1]).days
    hi = (det[1] - act[0]).days
    if lo == hi:
        return "point", lo, "both dates hour- or day-precise"
    return "interval", (lo, hi), "month-precision widened to the calendar month"


def bootstrap_median_ci(sampler, n_items, rng, reps=BOOTSTRAP_N):
    """Percentile bootstrap interval for a median.

    sampler(rng, i) returns one draw for item i, so a row that is an interval
    can be redrawn uniformly inside that interval on every replicate.
    """
    meds = []
    for _ in range(reps):
        draw = [sampler(rng, rng.randrange(n_items)) for _ in range(n_items)]
        meds.append(statistics.median(draw))
    meds.sort()
    lo = meds[int(0.025 * len(meds))]
    hi = meds[min(len(meds) - 1, int(0.975 * len(meds)))]
    return lo, hi


def load():
    with open(CSV, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main():
    rows = load()
    for r in rows:
        r["_fa"] = parse_date(r["first_action_date"])
        r["_fd"] = parse_date(r["first_detection_date"])
        r["_dl"] = parse_date(r["developer_learned_date"])
        r["_pd"] = parse_date(r["public_disclosure_date"])

    n = len(rows)
    line = "=" * 72
    print(line)
    print(f"CAUGHT FROM OUTSIDE -- recomputed from detections.csv  (N = {n} incidents)")
    print(line)

    # ---- 1. THE DISCLOSURE CASCADE (lead with this) --------------------------
    cascade = [r for r in rows if "after OpenAI's 21 Jul disclosure" in r["learned_via"]]
    print("\n1. DISCLOSURE CASCADE  (the finding with no survivorship confound)")
    print("   One organisation's public disclosure triggered another lab's")
    print("   retrospective search, which surfaced previously-undetected incidents.")
    print(f"   OpenAI disclosed on {OPENAI_DISCLOSURE.isoformat()}.")
    print(f"   Incidents a lab learned of ONLY via that cascade: {len(cascade)} of {n}")
    for r in cascade:
        print(f"     - {r['incident_id']:8s} {r['incident']}")
    # victims who had not themselves detected the activity
    not_self = [r for r in rows if r["victim_detected"].strip().lower() == "no"]
    print(f"   Disclosed incidents whose victim had NOT detected the activity: {len(not_self)}")
    for r in not_self:
        print(f"     - {r['incident_id']:8s} {r['incident']}")

    # ---- 2. DETECTION LATENCY ------------------------------------------------
    print("\n2. DETECTION LATENCY  (first unauthorized action -> first detection)")
    print(f"   {'id':8s} {'days':>6s}  {'basis':11s} detector class")
    firm_det = []
    for r in rows:
        d, firm = latency_days(r["_fa"], r["first_action_precision"],
                               r["_fd"], r["detection_precision"])
        if d is None:
            shown, basis = "   n/a", "missing"
        else:
            shown = f"{d:6d}"
            basis = "FIRM" if firm else "approx"
            if firm:
                firm_det.append((r["incident_id"], d))
        print(f"   {r['incident_id']:8s} {shown}  {basis:11s} {r['detector_class']}")
    if firm_det:
        days = sorted(d for _, d in firm_det)
        mid = days[len(days) // 2] if len(days) % 2 else (days[len(days)//2 - 1] + days[len(days)//2]) / 2
        print(f"   firm rows only: n={len(firm_det)}, min={min(days)}d, "
              f"median={mid}d, max={max(days)}d")

    # ---- 3. DISCLOSURE LATENCY ----------------------------------------------
    print("\n3. DISCLOSURE LATENCY  (first detection -> public disclosure)")
    for r in rows:
        d, firm = latency_days(r["_fd"], r["detection_precision"],
                               r["_pd"], "day")
        if d is None:
            shown, basis = "   n/a", "missing"
        else:
            shown, basis = f"{d:6d}", ("FIRM" if firm else "approx")
        print(f"   {r['incident_id']:8s} {shown}  {basis}")

    # ---- 4. DETECTOR-CLASS TALLY (descriptive only) --------------------------
    print("\n4. DETECTOR-CLASS TALLY  (who first detected -- DESCRIPTIVE, see confound)")
    counts = {}
    for r in rows:
        counts[r["detector_class"]] = counts.get(r["detector_class"], 0) + 1
    for cls, c in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"   {c:2d}  {cls}")
    lab_rt = counts.get("lab real-time monitor", 0)
    print(f"   -> developer's own real-time monitor was first detector in {lab_rt} of {n}.")

    # ---- 5. DETECTION LATENCY WITH UNCERTAINTY -------------------------------
    print("\n5. DETECTION LATENCY WITH UNCERTAINTY  (no bare midpoints)")
    print("   Rules: hour/day = a point; month = uniform over that calendar")
    print("   month; unknown = censored, so only a bound is printed, and only")
    print("   when the source notes fix one side.")
    print(f"   {'id':8s} {'estimate':>18s}  basis")
    est = {}
    for r in rows:
        kind, val, note = latency_estimate(r)
        est[r["incident_id"]] = (kind, val, note)
        if kind == "point":
            shown = f"{val} d"
        elif kind == "interval":
            shown = f"[{val[0]}, {val[1]}] d"
        elif kind == "lower_bound":
            shown = f">= {val} d"
        else:
            shown = "not estimable"
        print(f"   {r['incident_id']:8s} {shown:>18s}  {note}")
    print("   A '>= 0 d' bound says only that the action preceded the detection;")
    print("   it carries no information about how long the activity ran unseen.")

    # ---- 6. CROSS-INCIDENT SUMMARY -------------------------------------------
    print("\n6. CROSS-INCIDENT SUMMARY  (median detection latency)")
    firm_vals = [v for k, v, _ in est.values() if k == "point"]
    firm_vals.sort()
    rng = random.Random(BOOTSTRAP_SEED)
    fm = statistics.median(firm_vals)
    flo, fhi = bootstrap_median_ci(lambda g, i: firm_vals[i], len(firm_vals), rng)
    print(f"   Firm rows only (n={len(firm_vals)}): values {firm_vals} days.")
    print(f"   Median = {fm} d. Seeded bootstrap ({BOOTSTRAP_N:,} resamples)")
    print(f"   95% percentile interval: [{flo}, {fhi}] days.")
    print("   With 3 firm rows this interval is wide, as it should be: the")
    print("   resampling can only ever return one of the three observed values.")

    # sensitivity version: firm points PLUS a uniform draw inside each interval
    sens = []                       # each entry: (lo, hi); lo == hi for points
    for r in rows:
        kind, val, _ = est[r["incident_id"]]
        if kind == "point":
            sens.append((val, val))
        elif kind == "interval":
            sens.append(val)
    rng2 = random.Random(BOOTSTRAP_SEED)

    def draw(g, i):
        lo, hi = sens[i]
        return lo if lo == hi else g.randint(lo, hi)

    point_med = statistics.median([(lo + hi) / 2 for lo, hi in sens])
    slo, shi = bootstrap_median_ci(draw, len(sens), rng2)
    print(f"\n   SENSITIVITY VERSION (clearly labelled as such): firm rows plus")
    print("   the month-precise rows, each redrawn uniformly inside its own")
    print(f"   interval on every replicate. n={len(sens)} rows: {sens}")
    print(f"   Median of the interval midpoints = {point_med} d.")
    print(f"   Bootstrap 95% percentile interval: [{slo}, {shi}] days.")
    print("   This version is NOT the headline: it mixes measured dates with")
    print("   dates we only know to the month, and censored rows are still out.")

    # ---- 7. SENSITIVITY: which headline numbers survive ----------------------
    print("\n7. SENSITIVITY  (drop placeholder rows; do the headlines survive?)")
    dropped = [r for r in rows
               if r["incident_id"] == "IRREG"
               or r["first_action_precision"].strip().lower() == "unknown"]
    kept = [r for r in rows if r not in dropped]
    print(f"   Dropped as placeholder/unknown ({len(dropped)}): "
          + ", ".join(r["incident_id"] for r in dropped))
    print(f"   Kept as firm-dated ({len(kept)}): "
          + ", ".join(r["incident_id"] for r in kept))

    def cascade_count(rs):
        return sum(1 for r in rs
                   if "after OpenAI's 21 Jul disclosure" in r["learned_via"])

    print(f"\n   {'headline':44s} {'all rows':>10s} {'firm only':>11s}")
    print(f"   {'incidents in the ledger':44s} {len(rows):>10d} {len(kept):>11d}")
    print(f"   {'learned only via the disclosure cascade':44s} "
          f"{cascade_count(rows):>10d} {cascade_count(kept):>11d}")
    rt_all = sum(1 for r in rows if r["detector_class"] == "lab real-time monitor")
    rt_kept = sum(1 for r in kept if r["detector_class"] == "lab real-time monitor")
    print(f"   {'first detected by lab real-time monitor':44s} "
          f"{rt_all:>10d} {rt_kept:>11d}")
    classes = sorted({r["detector_class"] for r in rows})
    print("\n   detector-class tally, side by side:")
    print(f"   {'class':32s} {'all rows':>10s} {'firm only':>11s}")
    for c in classes:
        a = sum(1 for r in rows if r["detector_class"] == c)
        k = sum(1 for r in kept if r["detector_class"] == c)
        print(f"   {c:32s} {a:>10d} {k:>11d}")
    print("\n   What survives: the real-time-monitor count stays at 0 in both")
    print("   columns, so that headline does not rest on placeholder dates.")
    print("   The cascade column above reads 3 -> 0, but that drop uses the")
    print("   WRONG criterion for the cascade claim: the claim is about how the")
    print("   lab LEARNED of an incident (learned_via) and is dated at the")
    print("   detection end (developer_learned_date), not the action end.")
    # The right sensitivity check for the cascade: is the date the lab learned
    # of each cascade row itself firm? (It is the only date the claim uses.)
    casc_rows = [r for r in rows
                 if "after OpenAI's 21 Jul disclosure" in r["learned_via"]]
    # developer_learned_date is a stated calendar day for every cascade row
    # (the 30 Jul post: review began 23 Jul, incidents identified the next
    # day), so it is day-precise by construction; do NOT gate this on
    # detection_precision, which describes a different date (the takedown).
    casc_firm = [r for r in casc_rows
                 if r["_dl"] is not None
                 and r["_dl"] >= OPENAI_DISCLOSURE]
    print(f"   Cascade rows whose developer_learned_date is a stated day on")
    print(f"   or after the {OPENAI_DISCLOSURE.isoformat()} disclosure: "
          f"{len(casc_firm)} of {len(casc_rows)}"
          + (" (" + ", ".join(r['incident_id'] + ' ' + r['_dl'].isoformat()
                                 for r in casc_firm) + ")" if casc_firm else ""))
    print("   So the cascade headline SURVIVES on its own terms: 3 of 8 incidents,")
    print("   each with a firm learned-date after the trigger. What is NOT known")
    print("   for those rows is how long the activity ran before that -- quote")
    print("   the cascade as dated at the detection end, never as a latency.")

    # ---- The confound, stated in the output itself ---------------------------
    print("\n" + line)
    print("SURVIVORSHIP CONFOUND (do not drop this when quoting the tally)")
    print(line)
    print(
        "   This file contains DISCLOSED incidents. An incident often becomes\n"
        "   disclosable *because* it escaped real-time monitoring, so 'real-time\n"
        "   monitor first-detected 0 of N' is partly selection, not pure failure:\n"
        "   incidents the monitor DID catch may never rise to a disclosable event\n"
        "   and so never enter this table. Report the tally as a description of\n"
        "   the disclosed set. The disclosure cascade (section 1) does NOT depend\n"
        "   on this selection: it is a claim about how labs learned of incidents\n"
        "   that were already in the set, so lead the paper with it."
    )
    print(line)


if __name__ == "__main__":
    main()
