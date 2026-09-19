# /// script
# requires-python = ">=3.10"
# dependencies = ["matplotlib", "pandas", "numpy"]
# ///
"""Figure 5 — the two kinds of case measure exposure on different clocks.

Left: the control set. These are disclosed cases where a real-time safeguard
(a classifier, an egress restriction, a watching user, an evaluator's own
harness) stopped the model inside the session. Their exposure is counted in
conversational exchanges, and for most of them it is zero: the action never
took effect. The bars are counts of control cases per exposure category, with
the categories read from the exposure_before_detection field.

Right: the ledger incidents that got outside. Their exposure is counted in
days, and only three of the eight have a firm date on both ends.

The two panels answer the same question -- how much unsanctioned activity
happened before anyone noticed -- in units that do not convert into each other.
That is the point of showing them side by side rather than pooled.

Data: artifact/expansion/controls.csv (11 rows)
      artifact/detections.csv (latencies via verify.py rules)
Run:  uv run artifact/figs/fig5_two_clocks.py
Out:  report/latex/figs/fig5_two_clocks.pdf
"""
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import pandas as pd

from _style import (BLUE, CFO, CLASS_COLOR, GREY, INK, MUTED, ROSE, SAND,
                    SHORT, TEAL, WARM, latency_estimate, plaintitle, save)
import matplotlib.pyplot as plt

# ── left panel: the control set ──────────────────────────────────────────
ctl = pd.read_csv(CFO / "expansion" / "controls.csv")


def bucket(row):
    """Read the exposure field into one of four plain categories."""
    e = str(row.exposure_before_detection).strip().lower()
    if e == "0":
        return "no exposure: the action never took effect"
    if e == "unknown":
        return "not stated in the source"
    if e.startswith("0 ") and "unknown" in e:
        return "none at the block, not stated for the follow-up attempt"
    return "about 70 exchanges before a watching user stepped in"


ctl["bucket"] = [bucket(r) for r in ctl.itertuples()]
ORDER = [
    "no exposure: the action never took effect",
    "none at the block, not stated for the follow-up attempt",
    "about 70 exchanges before a watching user stepped in",
    "not stated in the source",
]
BAR_COLOR = {ORDER[0]: TEAL, ORDER[1]: SAND, ORDER[2]: WARM, ORDER[3]: GREY}
counts = Counter(ctl["bucket"])

# Short axis labels; what each category means is stated in the caption.
SHORT_CAT = {
    ORDER[0]: "no exposure",
    ORDER[1]: "blocked; follow-up\nunstated",
    ORDER[2]: "~70 exchanges",
    ORDER[3]: "not stated",
}

fig, (axL, axR) = plt.subplots(1, 2, figsize=(7.0, 2.8),
                               gridspec_kw={"width_ratios": [1.35, 1.0]})

for i, cat in enumerate(ORDER):
    y = len(ORDER) - 1 - i
    v = counts.get(cat, 0)
    hollow = cat in (ORDER[2], ORDER[3])   # approximate or unstated
    axL.barh(y, v, height=0.52,
             color="white" if hollow else BAR_COLOR[cat],
             hatch="////" if hollow else None,
             edgecolor=BAR_COLOR[cat], linewidth=0.9, zorder=3)
    axL.text(v + 0.12, y, str(v), va="center", fontsize=8.5, fontweight="bold",
             color=INK)

axL.set_yticks(range(len(ORDER)))
axL.set_yticklabels([SHORT_CAT[c] for c in ORDER[::-1]], fontsize=8)
axL.set_xlim(0, 7.4)
axL.set_xticks(range(0, 8))
axL.set_xlabel(f"control cases  (n = {len(ctl)})")
axL.set_ylim(-0.7, len(ORDER) - 0.4)
axL.grid(axis="y", visible=False)
axL.grid(axis="x", ls=":", alpha=0.7)
axL.set_title("Stopped inside the session", loc="left", fontsize=9)

# ── right panel: the incidents that got outside ──────────────────────────
det = pd.read_csv(CFO / "detections.csv")
for col in ["first_action_date", "first_detection_date"]:
    det[col] = pd.to_datetime(det[col])
det["kind"], det["val"] = zip(*[latency_estimate(r) for r in det.itertuples()])

points = [(r.incident_id, r.val, CLASS_COLOR.get(r.detector_class, GREY))
          for r in det.itertuples() if r.kind == "point"]
points.sort(key=lambda t: t[1])
intervals = [(r.incident_id, r.val[0], r.val[1], CLASS_COLOR.get(r.detector_class, GREY))
             for r in det.itertuples() if r.kind == "interval"]
n_other = int((det.kind.isin(["lower_bound", "none"])).sum())
n_bound = int((det.kind == "lower_bound").sum())
n_none = int((det.kind == "none").sum())

labels = []
for i, (inc, v, color) in enumerate(reversed(points)):
    y = len(intervals) + i
    axR.plot([1.0, v], [y, y], color=color, lw=0.8, alpha=0.35, zorder=2)
    axR.scatter(v, y, s=40, color=color, zorder=4, edgecolor="white", lw=0.6)
    axR.text(v * 1.45, y, f"{v} d", va="center", fontsize=8,
             fontweight="bold", color=INK)
    labels.append(SHORT[inc])
for i, (inc, lo, hi, color) in enumerate(intervals):
    y = len(intervals) - 1 - i
    axR.barh(y, hi - lo, left=lo, height=0.34, color="white", hatch="////",
             edgecolor=color, linewidth=0.9, zorder=3)
    axR.text(hi * 1.25, y, f"{lo}–{hi} d", va="center", fontsize=8,
             fontweight="bold", color=INK)
    labels.insert(0, SHORT[inc])

n_rows = len(points) + len(intervals)
axR.set_yticks(range(n_rows))
axR.set_yticklabels(labels, fontsize=7.5)
axR.set_ylim(-0.7, n_rows - 0.45)
axR.set_xscale("log")
axR.set_xlim(1.0, 900)
axR.set_xticks([1, 10, 100])
axR.set_xticklabels(["1", "10", "100"])
axR.set_xlabel("days from first action to first detection (log scale)")
axR.grid(axis="y", visible=False)
axR.grid(axis="x", ls=":", alpha=0.7)
axR.set_title("Reached something outside", loc="left", fontsize=9)
# The four incidents that are not on this axis (two bounds, two not estimable)
# are stated in the caption, not inside the figure.

plaintitle(fig, "Exposure before detection", y=1.06)
fig.tight_layout(w_pad=2.4)
save(fig, "fig5_two_clocks")
