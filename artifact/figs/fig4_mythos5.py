# /// script
# requires-python = ">=3.10"
# dependencies = ["matplotlib", "pandas", "numpy"]
# ///
"""Figure 4 — the Mythos 5 package-publish session on a wall clock.

Every timestamp is read from the audit of the public transcript. The left panel
covers the whole session (01:02 to 11:28 UTC on 18 July 2026); the right panel
zooms into the last two minutes, because the final rejection, the accepted
upload and the end of the public record fall within 63 seconds of each other
and cannot be told apart on the full-session axis.

Data: artifact/expansion/mythos5_counts.json
      (written by expansion/mythos5_audit.py; see expansion/mythos5_audit.md)
Run:  uv run artifact/figs/fig4_mythos5.py
Out:  report/latex/figs/fig4_mythos5.pdf
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import matplotlib.dates as mdates
import pandas as pd
from matplotlib.lines import Line2D
from matplotlib.patches import Patch

from _style import (BLUE, CFO, GREY, INK, LABEL_BOX, MUTED, ROSE, RULE, TEAL,
                    plaintitle, save)
import matplotlib.pyplot as plt

d = json.loads((CFO / "expansion" / "mythos5_counts.json").read_text())


def ts(s):
    return pd.Timestamp(s).tz_convert("UTC").tz_localize(None)


start = ts(d["schema"]["session_start"])
end = ts(d["schema"]["session_end"])
first_net = ts(d["external_signal"]["first_external_host_contact_timestamp"])
attempts = [(ts(a["timestamp"]), a["http_status_sequence"][0], a["succeeded"])
            for a in d["publish"]["attempts"]]
success_t = ts(d["publish"]["first_success_timestamp"])
secs_to_end = d["publish_to_removal"]["seconds_from_publish_to_transcript_end"]
msgs_to_end = d["publish_to_removal"]["messages_from_publish_to_transcript_end"]
hours_rejected = d["first_consequential_action"]["hours_from_first_attempt_to_success"]
first_attempt_t = attempts[0][0]

fig, (axL, axR) = plt.subplots(1, 2, figsize=(7.0, 2.6),
                               gridspec_kw={"width_ratios": [2.5, 1.0]})


def draw(ax, lo, hi, zoom):
    ax.axhline(0, color=RULE, lw=1.0, zorder=1)
    # the stretch of rejected attempts
    ax.plot([first_attempt_t, success_t], [0, 0], color=ROSE, lw=3.0, alpha=0.5,
            solid_capstyle="butt", zorder=2)
    # the public record ends shortly after the accepted upload
    ax.axvspan(success_t, end, facecolor=GREY, alpha=0.25, hatch="////",
               edgecolor=GREY, linewidth=0.0, zorder=1)

    ax.scatter([first_net], [0], marker="o", s=34, color=BLUE, zorder=5,
               edgecolor="white", lw=0.6)
    for t, code, ok in attempts:
        if ok:
            ax.scatter([t], [0], marker="*", s=150, color=TEAL, zorder=6,
                       edgecolor=INK, lw=0.4)
        else:
            ax.scatter([t], [0], marker="X", s=40, color=ROSE, zorder=5,
                       edgecolor="white", lw=0.5)
    ax.set_yticks([])
    ax.set_ylim(-1.0, 1.0)
    ax.set_xlim(lo, hi)
    ax.grid(axis="y", visible=False)
    ax.grid(axis="x", ls=":", alpha=0.7)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M" if not zoom else "%H:%M:%S"))
    for s in ("left",):
        ax.spines[s].set_visible(False)


draw(axL, pd.Timestamp("2026-07-18 00:50"), pd.Timestamp("2026-07-18 11:45"), False)
axL.xaxis.set_major_locator(mdates.HourLocator(interval=2))
axL.set_xlabel("wall clock, 18 July 2026 (UTC)")
axL.set_title("Whole session", loc="left")

axL.annotate("first internet call, 01:07:53",
             xy=(first_net, 0.08), xytext=(pd.Timestamp("2026-07-18 01:20"), 0.72),
             fontsize=7.5, color=BLUE, va="center", bbox=LABEL_BOX,
             arrowprops=dict(arrowstyle="->", color=BLUE, lw=0.7))
axL.annotate(f"uploads rejected, {hours_rejected:.1f} h",
             xy=(pd.Timestamp("2026-07-18 05:00"), -0.06),
             xytext=(pd.Timestamp("2026-07-18 02:20"), -0.72),
             fontsize=7.5, color=ROSE, va="center", bbox=LABEL_BOX,
             arrowprops=dict(arrowstyle="->", color=ROSE, lw=0.7))
axL.annotate("upload accepted, 11:27:24",
             xy=(success_t, 0.1), xytext=(pd.Timestamp("2026-07-18 07:10"), 0.72),
             fontsize=7.5, color=TEAL, fontweight="bold", va="center", bbox=LABEL_BOX,
             arrowprops=dict(arrowstyle="->", color=TEAL, lw=0.7))

Z0 = pd.Timestamp("2026-07-18 11:26:40")
Z1 = pd.Timestamp("2026-07-18 11:28:30")
draw(axR, Z0, Z1, True)
axR.xaxis.set_major_locator(mdates.SecondLocator(bysecond=[0, 30]))
axR.set_xlabel("UTC")
axR.set_title("Last two minutes", loc="left")
axR.annotate("400", xy=(attempts[3][0], 0.1), xytext=(attempts[3][0], 0.45),
             fontsize=7.5, color=ROSE, ha="center", bbox=LABEL_BOX)
axR.annotate("200", xy=(success_t, 0.14), xytext=(success_t, 0.45),
             fontsize=7.5, color=TEAL, ha="center", fontweight="bold", bbox=LABEL_BOX)
axR.annotate(f"record ends, {secs_to_end} s later",
             xy=(end, -0.1), xytext=(Z0 + pd.Timedelta(seconds=2), -0.72),
             fontsize=7.5, color=MUTED, va="center", bbox=LABEL_BOX,
             arrowprops=dict(arrowstyle="->", color=MUTED, lw=0.7))

fig.legend(handles=[
    Line2D([0], [0], marker="o", color="w", markerfacecolor=BLUE, markersize=5,
           label="first internet call"),
    Line2D([0], [0], marker="X", color="w", markerfacecolor=ROSE, markersize=6,
           label="upload rejected"),
    Line2D([0], [0], marker="*", color="w", markerfacecolor=TEAL,
           markeredgecolor=INK, markersize=10, label="upload accepted"),
    Patch(facecolor=GREY, alpha=0.25, hatch="////", edgecolor=GREY,
          label="after the record ends"),
], loc="lower left", bbox_to_anchor=(0.0, -0.20), ncol=4, fontsize=7.5)

plaintitle(fig, "The Mythos 5 session", y=1.06)
fig.tight_layout(w_pad=2.0)
save(fig, "fig4_mythos5")
