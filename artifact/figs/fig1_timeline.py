# /// script
# requires-python = ">=3.10"
# dependencies = ["matplotlib", "pandas", "numpy"]
# ///
"""Figure 1 — calendar timeline of the eight ledger incidents (Jan-Sep 2026).

One row per incident. A bar from the first unauthorized action to the first
detection is drawn ONLY where that span is actually estimable, which means both
ends are dated at least to the month (verify.py's "point" and "interval"
cases). Where the first-action date is not known, no bar is drawn at all: a bar
would assert a duration the sources do not support, and the paper never quotes
those rows as a latency. Those rows carry their detection date and their public
disclosure date and nothing else.

A marker is filled when its own date is hour- or day-precise and hollow when
that date is known only to the month or not at all.

Data: artifact/detections.csv
Run:  uv run artifact/figs/fig1_timeline.py
Out:  report/latex/figs/fig1_timeline.pdf
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import matplotlib.dates as mdates
import pandas as pd
from matplotlib.lines import Line2D
from matplotlib.patches import Patch

from _style import (CFO, CLASS_COLOR, FUZZY, GREY, INK, LABEL_BOX, MUTED,
                    SHORT, latency_estimate, plaintitle, save)
import matplotlib.pyplot as plt

df = pd.read_csv(CFO / "detections.csv")
for col in ["first_action_date", "first_detection_date", "public_disclosure_date"]:
    df[col] = pd.to_datetime(df[col])
df["kind"], _ = zip(*[latency_estimate(r) for r in df.itertuples()])
df = df.sort_values("first_action_date").reset_index(drop=True)

CASCADE = {"ANTH_B", "ANTH_C", "ANTH_D"}   # learned_via == the 21 Jul cascade
TRIGGER = pd.Timestamp("2026-07-21")

fig, ax = plt.subplots(figsize=(7.0, 3.5))
n = len(df)

for i, row in df.iterrows():
    y = n - 1 - i                          # earliest incident at the top
    color = CLASS_COLOR.get(row.detector_class, GREY)
    a, d, pub = (row.first_action_date, row.first_detection_date,
                 row.public_disclosure_date)
    action_known = row.first_action_precision not in {"unknown"}
    span_drawable = row.kind in ("point", "interval")
    span_fuzzy = (row.first_action_precision == "month") or (row.detection_precision == "month")

    # The action -> detection bar, only where that span is estimable at all.
    if span_drawable:
        if (d - a).days <= 0:              # same-day: a bar would be invisible
            a_draw, d_draw = a - pd.Timedelta(days=2), a + pd.Timedelta(days=2)
        else:
            a_draw, d_draw = a, d
        ax.barh(y, (d_draw - a_draw).days, left=a_draw, height=0.42,
                color="white" if span_fuzzy else color,
                hatch="////" if span_fuzzy else None,
                edgecolor=color, linewidth=0.9, zorder=2)

    # First-action marker: only where the record dates the first action.
    if action_known:
        hollow = row.first_action_precision in FUZZY
        ax.scatter(a, y, marker="o", s=22,
                   color="white" if hollow else color,
                   edgecolor=color if hollow else "white", linewidth=0.8, zorder=4)

    # First-detection marker, hollow when that date is itself not firm.
    det_hollow = row.detection_precision in FUZZY
    ax.scatter(d, y, marker=">", s=38,
               color="white" if det_hollow else color,
               edgecolor=color if det_hollow else "white", linewidth=0.8, zorder=6)

    ax.plot([d, pub], [y, y], color=color, lw=0.7, ls=":", zorder=1)
    ax.scatter(pub, y, marker="*", s=70, color=color, edgecolor=INK,
               linewidth=0.35, zorder=5)

labels = []
for r in df.iloc[::-1].itertuples():
    tag = "  ← cascade" if r.incident_id in CASCADE else ""
    labels.append(SHORT[r.incident_id] + tag)
ax.set_yticks(range(n))
ax.set_yticklabels(labels, fontsize=8)
ax.set_ylim(-0.8, n - 0.2)
ax.set_xlim(pd.Timestamp("2026-01-01"), pd.Timestamp("2026-10-05"))
ax.xaxis.set_major_locator(mdates.MonthLocator())
ax.xaxis.set_major_formatter(mdates.DateFormatter("%b"))
ax.set_xlabel("2026")
ax.grid(axis="x", ls=":", alpha=0.7)
ax.grid(axis="y", visible=False)

# the trigger: OpenAI's 21 Jul disclosure
ax.axvline(TRIGGER, color=INK, lw=0.8, ls="--", alpha=0.55, zorder=0)
ax.annotate("OpenAI discloses, 21 Jul",
            xy=(TRIGGER, n - 0.35), xytext=(pd.Timestamp("2026-03-20"), n - 0.45),
            fontsize=8, color=INK, fontweight="bold", va="center",
            bbox=LABEL_BOX,
            arrowprops=dict(arrowstyle="->", color=INK, lw=0.7))

# The three cascade rows are tagged on their own y labels; what the cascade is
# and when the review ran is stated in the caption, not in the figure.

marker_legend = [
    Line2D([0], [0], marker="o", color="w", markerfacecolor=MUTED, markersize=4.5,
           label="first unauthorized action"),
    Line2D([0], [0], marker=">", color="w", markerfacecolor=MUTED, markersize=6,
           label="first detection"),
    Line2D([0], [0], marker="*", color="w", markerfacecolor=MUTED,
           markeredgecolor=INK, markersize=9, label="public disclosure"),
    Patch(facecolor="white", edgecolor=MUTED, hatch="////",
          label="month-precise span"),
    Line2D([0], [0], marker=">", color="w", markerfacecolor="white",
           markeredgecolor=MUTED, markersize=6,
           label="date not firm"),
]
leg1 = ax.legend(handles=marker_legend, loc="lower left", fontsize=7.5,
                 ncol=1, handletextpad=0.5, labelspacing=0.35,
                 bbox_to_anchor=(0.005, 0.01))
ax.add_artist(leg1)

present = [c for c in CLASS_COLOR if c in set(df.detector_class)]
ax.legend(handles=[Patch(facecolor=CLASS_COLOR[c], label=c) for c in present],
          loc="upper left", bbox_to_anchor=(0.0, -0.22), ncol=3,
          fontsize=7.5, title="who detected it first", title_fontsize=8,
          alignment="left")

plaintitle(fig, "Timeline", y=1.03)
fig.tight_layout()
save(fig, "fig1_timeline")
