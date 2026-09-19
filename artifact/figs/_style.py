# /// script
# requires-python = ">=3.10"
# dependencies = ["matplotlib", "pandas", "numpy"]
# ///
"""Shared plot style for the "Caught From Outside" report figures.

Matched to the previous sprint's figure style
(the previous sprint's figure style): white ground,
muted categorical palette, thin light grid, no top/right spines, sans font at
8 pt, direct labels instead of dense legends, PDF output.

Figures are sized for a 1 in-margin US-letter page, where \textwidth = 6.5 in.
Widths here are 7.0 in so LaTeX scales them down slightly (8 pt -> ~7.4 pt),
which is what the previous report did.

Not a figure script: imported by fig1..fig5.
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# ── paths ────────────────────────────────────────────────────────────────
CFO = Path(__file__).resolve().parents[1]          # code/caught_from_outside
ROOT = Path(__file__).resolve().parents[3]          # repo root
OUT = ROOT / "report" / "latex" / "figs"
OUT.mkdir(parents=True, exist_ok=True)

# ── palette (muted, academic) ────────────────────────────────────────────
BLUE = "#2a78d6"
WARM = "#d4652a"
TEAL = "#1a8a6a"
ROSE = "#c74b7a"
SAND = "#b08a33"
GREY = "#8a8884"
INK = "#1a1a18"
MUTED = "#5a5955"
GRID = "#e8e7e2"
RULE = "#c3c2b7"

# detector class -> colour (same mapping as plot_timeline.py, restyled)
CLASS_COLOR = {
    "victim SOC": BLUE,
    "platform admin": TEAL,
    "registry scanner": SAND,
    "third-party evaluator": WARM,
    "lab retrospective review": ROSE,
    "lab real-time monitor": GREY,
    "classifier": BLUE,
    "human live observer": WARM,
    "egress control": TEAL,
    "third-party evaluator real-time": ROSE,
    "unknown": GREY,
}

# date precisions that mean "do not trust the exact day" (from verify.py)
FUZZY = {"month", "unknown"}

plt.rcParams.update({
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "axes.edgecolor": RULE,
    "axes.linewidth": 0.6,
    "axes.grid": True,
    "grid.color": GRID,
    "grid.linewidth": 0.5,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "font.family": "sans-serif",
    "font.sans-serif": ["Arial", "Helvetica", "DejaVu Sans"],
    "font.size": 8,
    "axes.titlesize": 9.5,
    "axes.titleweight": "bold",
    "axes.labelsize": 8.5,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
    "text.color": INK,
    "axes.labelcolor": MUTED,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "legend.frameon": False,
    "legend.fontsize": 7.5,
    "hatch.linewidth": 0.6,
})

LABEL_BOX = dict(facecolor="white", edgecolor="none", alpha=0.85, pad=1.5)

# short display names, one per ledger incident (from plot_timeline.py)
SHORT = {
    "HF": "Hugging Face intrusion",
    "WIKI": "German DSEWiki swarm",
    "ANTH_A": "Anthropic A (checkpoint)",
    "ANTH_B": "Anthropic B (internal)",
    "ANTH_C": "Anthropic C (Mythos 5 PyPI)",
    "ANTH_D": "Anthropic D (user records)",
    "AISI": "UK AISI evaluation",
    "IRREG": "Irregular / OpenAI eval",
    "RUBY": "RubyGems campaign",
}


def plaintitle(fig, text, y=1.0):
    """Short plain-noun title, left-aligned. No subtitle: the description of
    the figure lives in the LaTeX caption (see figures.md)."""
    fig.text(0.0, y, text, fontsize=10.5, fontweight="bold", va="top",
             ha="left", color=INK)


def save(fig, stem):
    p = OUT / f"{stem}.pdf"
    fig.savefig(p, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {p}")


# ── detection-latency rules (mirror of verify.py) ────────────────────────
# Kept here so figures 2 and 5 cannot drift apart from each other.
import calendar
from datetime import date

FIRM_PRECISION = {"hour", "day"}
# The only censored rows whose source notes fix one side of the latency.
ACTION_UPPER_BOUND = {
    "ANTH_B": (date(2026, 7, 23), "notes: 'placeholder before 23 Jul'"),
    "ANTH_D": (date(2026, 7, 23), "notes: found in the 23-24 Jul retrospective"),
}


def date_interval(d, precision):
    """verify.py: earliest/latest possible true date, or None if censored."""
    if d is None or d != d:                 # None or NaT
        return None
    d = d.date() if hasattr(d, "date") else d
    if precision in FIRM_PRECISION:
        return (d, d)
    if precision == "month":
        last = calendar.monthrange(d.year, d.month)[1]
        return (date(d.year, d.month, 1), date(d.year, d.month, last))
    return None


def latency_estimate(r):
    """verify.py: (kind, value) with kind in point/interval/lower_bound/none.

    r is a namedtuple-like row with first_action_date, first_action_precision,
    first_detection_date, detection_precision and incident_id.
    """
    act = date_interval(r.first_action_date, r.first_action_precision)
    det = date_interval(r.first_detection_date, r.detection_precision)
    if det is None:
        return "none", None
    if act is None:
        bound = ACTION_UPPER_BOUND.get(r.incident_id)
        if bound is None:
            return "none", None
        return "lower_bound", (det[0] - bound[0]).days
    lo = (det[0] - act[1]).days
    hi = (det[1] - act[0]).days
    return ("point", lo) if lo == hi else ("interval", (lo, hi))
