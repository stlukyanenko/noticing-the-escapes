# /// script
# requires-python = ">=3.10"
# dependencies = ["matplotlib", "pandas", "numpy"]
# ///
"""Figure 2 — detection latency per incident, with the uncertainty kept visible.

Each row is one incident. The four kinds of estimate come straight from
verify.py's latency_estimate(), shared through _style.py:
  point        both dates known to the hour or day      -> filled circle
  interval     one date known only to the month         -> hollow hatched bar
  lower_bound  action date censored, source fixes order -> hollow ">=" arrow
  none         not estimable                            -> grey words, no mark

A log x-axis is used because the firm values (2-11 days) and the interval
(182-242 days) cannot share a linear scale. The "not estimable" and ">= 0 day"
rows have no position on a log axis at all, so they start at the left edge and
are labelled in words rather than given a fake number.

Data: artifact/detections.csv, via the verify.py rules
Run:  uv run artifact/figs/fig2_latency.py
Out:  report/latex/figs/fig2_latency.pdf
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import pandas as pd
from matplotlib.lines import Line2D
from matplotlib.patches import Patch

from _style import (CFO, CLASS_COLOR, GREY, GRID, INK, LABEL_BOX, MUTED, SHORT,
                    latency_estimate, plaintitle, save)
import matplotlib.pyplot as plt

df = pd.read_csv(CFO / "detections.csv")
for col in ["first_action_date", "first_detection_date"]:
    df[col] = pd.to_datetime(df[col])
df["kind"], df["val"] = zip(*[latency_estimate(r) for r in df.itertuples()])

# order: firm points ascending, then the interval, then bounds, then the rest
order = {"point": 0, "interval": 1, "lower_bound": 2, "none": 3}


def sortkey(r):
    v = r.val[0] if r.kind == "interval" else (r.val if r.val is not None else 0)
    return (order[r.kind], v)


df = df.loc[sorted(df.index, key=lambda i: sortkey(df.loc[i]))].reset_index(drop=True)

XMIN, XMAX = 1.0, 600.0
GUT_LO, GUT_HI = 1.0, 1.9      # left gutter: rows with no numeric position

fig, ax = plt.subplots(figsize=(7.0, 2.9))
n = len(df)

# Median of the firm rows and its bootstrap interval (verify.py section 6).
# The band is drawn only across the firm rows, because the median and
# its interval are computed from those rows alone.
N_FIRM = int((df.kind == "point").sum())
import statistics
MED = statistics.median([float(v) for v in df.loc[df.kind == "point", "val"]])  # computed, never typed
Y_HI, Y_LO = n - 0.45, n - N_FIRM - 0.45
ax.fill_betweenx([Y_LO, Y_HI], 2, 11, color=GRID, alpha=0.95, zorder=0)
ax.plot([MED, MED], [Y_LO, Y_HI], color=INK, lw=0.9, ls="--", alpha=0.6, zorder=1)

for i, r in df.iterrows():
    y = n - 1 - i
    color = CLASS_COLOR.get(r.detector_class, GREY)
    if r.kind == "point":
        ax.plot([GUT_HI, r.val], [y, y], color=color, lw=0.8, alpha=0.35, zorder=2)
        ax.scatter(r.val, y, s=42, color=color, zorder=4, edgecolor="white", lw=0.6)
        ax.text(r.val * 1.22, y, f"{r.val} d", va="center", fontsize=8,
                color=INK, fontweight="bold")
    elif r.kind == "interval":
        lo, hi = r.val
        ax.barh(y, hi - lo, left=lo, height=0.34, color="white", hatch="////",
                edgecolor=color, linewidth=0.9, zorder=3)
        ax.text(hi * 1.1, y, f"{lo}–{hi} d", va="center", fontsize=8,
                color=INK, fontweight="bold")
    elif r.kind == "lower_bound":
        ax.annotate("", xy=(9.0, y), xytext=(GUT_HI, y),
                    arrowprops=dict(arrowstyle="-|>", color=color, lw=1.0,
                                    ls="dashed", shrinkA=0, shrinkB=0))
        ax.text(10.5, y, "≥ 0 d (bound only)",
                va="center", fontsize=8, color=MUTED)
    else:
        ax.text(GUT_LO * 1.05, y, "not estimable",
                va="center", fontsize=8, color=GREY, style="italic")

ax.set_yticks(range(n))
ax.set_yticklabels([SHORT[r.incident_id] for r in df.iloc[::-1].itertuples()], fontsize=8)
ax.set_ylim(-0.7, n - 0.4)
ax.set_xscale("log")
ax.set_xlim(XMIN, XMAX)
ax.set_xticks([1, 2, 5, 10, 30, 100, 300])
ax.set_xticklabels(["1", "2", "5", "10", "30", "100", "300"])
ax.set_xlabel("days from first action to first detection (log scale)")
ax.grid(axis="y", visible=False)
ax.grid(axis="x", ls=":", alpha=0.7)

ax.annotate(f"median {MED:g} d",
            xy=(MED, n - 0.5), xytext=(26, n - 0.85), fontsize=8, color=INK,
            va="center", bbox=LABEL_BOX,
            arrowprops=dict(arrowstyle="->", color=INK, lw=0.7))

ax.legend(handles=[
    Line2D([0], [0], marker="o", color="w", markerfacecolor=MUTED, markersize=5.5,
           label="firm date on both ends"),
    Patch(facecolor="white", edgecolor=MUTED, hatch="////",
          label="month-precise date"),
    Line2D([0], [0], color=MUTED, lw=1.0, ls="--", label="one-sided bound only"),
], loc="upper left", bbox_to_anchor=(0.0, -0.30), ncol=3, fontsize=7.5)

plaintitle(fig, "Detection latency", y=1.04)
fig.tight_layout()
save(fig, "fig2_latency")
