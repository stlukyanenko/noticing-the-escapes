# /// script
# requires-python = ">=3.10"
# dependencies = ["matplotlib", "pandas", "numpy"]
# ///
"""Figure 6 — how often a detectable signal was available, and how early.

One bar per 30 minutes of the released Mythos 5 session (01:02 to 11:28 UTC on
18 July 2026). Bar height is the number of executed tool calls in that half
hour whose primary signal is one of the 16 enumerated signal types; the bar is
split into the part whose signal type has a public detection rule that would
fire on this pattern (covered) and the part that has none (uncovered).

Data: classified_calls.csv and prevalence.csv in this directory, written by
      prevalence.py (see prevalence.md for the codebook and the limits).
Run:  uv run artifact/expansion/prevalence/fig6_prevalence.py
Out:  report/latex/figs/fig6_prevalence.pdf
"""
import csv
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "figs"))

import matplotlib.dates as mdates
import pandas as pd
from matplotlib.lines import Line2D
from matplotlib.patches import Patch

from _style import BLUE, GREY, INK, LABEL_BOX, MUTED, ROSE, RULE, SAND, plaintitle, save
import matplotlib.pyplot as plt

FIRST_COVERED = pd.Timestamp("2026-07-18 01:07:53")   # ANTH_C-01, index 98
FIRST_ATTEMPT = pd.Timestamp("2026-07-18 01:20:31")   # first upload POST, 403
PUBLISH = pd.Timestamp("2026-07-18 11:27:24")         # upload accepted, 200
BIN = "30min"

cov = {}
with (HERE / "prevalence.csv").open() as fh:
    for r in csv.DictReader(fh):
        if (r.get("signal_id") or "").startswith("ANTH_C-"):
            cov[r["signal_id"]] = r["rule_fires"] == "yes"

rows = []
with (HERE / "classified_calls.csv").open() as fh:
    for r in csv.DictReader(fh):
        sid = r["primary_signal"]
        if not sid.startswith("ANTH_C-") or not r["timestamp"]:
            continue
        t = pd.Timestamp(r["timestamp"])
        # three stamps in the released file are truncated to minute precision
        # and parse tz-naive; they are already UTC either way
        t = t.tz_convert("UTC").tz_localize(None) if t.tzinfo else t
        rows.append({"t": t, "covered": cov.get(sid, False)})
df = pd.DataFrame(rows)

idx = pd.date_range("2026-07-18 01:00", "2026-07-18 11:30", freq=BIN)
grid = pd.DataFrame(index=idx)
for flag, col in ((True, "covered"), (False, "uncovered")):
    s = df[df.covered == flag].set_index("t").resample(BIN).size()
    grid[col] = s.reindex(idx, fill_value=0).fillna(0)

fig, ax = plt.subplots(figsize=(7.0, 2.7))
w = 0.022  # bar width in days: ~32 minutes, so bars nearly touch
ax.bar(grid.index, grid["covered"], width=w, color=BLUE, label="covered",
       zorder=3, align="edge")
ax.bar(grid.index, grid["uncovered"], bottom=grid["covered"], width=w,
       color=SAND, label="uncovered", zorder=3, align="edge")

for t, col, lab in ((FIRST_COVERED, BLUE, "first covered signal 01:07:53"),
                    (FIRST_ATTEMPT, ROSE, "first upload attempt 01:20:31"),
                    (PUBLISH, INK, "package published 11:27:24")):
    ax.axvline(t, color=col, lw=1.0, ls=(0, (3, 2)), zorder=4)

top = float((grid["covered"] + grid["uncovered"]).max())
ax.annotate("first covered signal\n01:07:53", xy=(FIRST_COVERED, top * 0.97),
            xytext=(pd.Timestamp("2026-07-18 02:25"), top * 1.05),
            fontsize=7.5, color=BLUE, va="top", bbox=LABEL_BOX,
            arrowprops=dict(arrowstyle="->", color=BLUE, lw=0.7))
ax.annotate("first upload attempt\n01:20:31, rejected",
            xy=(FIRST_ATTEMPT, top * 0.55),
            xytext=(pd.Timestamp("2026-07-18 02:25"), top * 0.72),
            fontsize=7.5, color=ROSE, va="top", bbox=LABEL_BOX,
            arrowprops=dict(arrowstyle="->", color=ROSE, lw=0.7))
ax.annotate("package published\n11:27:24, 10.3 h later",
            xy=(PUBLISH, top * 0.80),
            xytext=(pd.Timestamp("2026-07-18 08:05"), top * 0.90),
            fontsize=7.5, color=INK, va="top", ha="right", bbox=LABEL_BOX,
            arrowprops=dict(arrowstyle="->", color=INK, lw=0.7))

ax.set_xlim(pd.Timestamp("2026-07-18 00:55"), pd.Timestamp("2026-07-18 11:50"))
ax.set_ylim(0, top * 1.18)
ax.set_xlabel("wall clock, 18 July 2026 (UTC)")
ax.set_ylabel("signal-carrying tool calls\nper 30 minutes")
ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
ax.xaxis.set_major_locator(mdates.HourLocator(interval=1))
ax.grid(axis="x", visible=False)
ax.grid(axis="y", ls=":", alpha=0.7)
ax.spines["bottom"].set_color(RULE)

ax.legend(handles=[
    Patch(facecolor=BLUE, label="public rule would fire"),
    Patch(facecolor=SAND, label="no public rule"),
    Line2D([0], [0], color=GREY, lw=1.0, ls=(0, (3, 2)), label="key moments"),
], loc="upper center", ncol=3, fontsize=7.5, bbox_to_anchor=(0.5, -0.30))

plaintitle(fig, "Signals per hour", y=1.06)
fig.tight_layout()
save(fig, "fig6_prevalence")
