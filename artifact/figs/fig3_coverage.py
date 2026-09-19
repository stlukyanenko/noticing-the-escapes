# /// script
# requires-python = ">=3.10"
# dependencies = ["matplotlib", "pandas", "numpy"]
# ///
"""Figure 3 — how much of each incident a public detection rule would have caught.

The coverage audit lists, for each incident, the signals an operator could in
principle have seen, then checks each signal against five public rule corpora
pinned to the incident date (Sigma, Elastic, Falco, package-registry tooling,
security-vendor rules). A signal counts as covered when some rule in that
corpus matches it; it counts as firing when that rule would also trigger on the
agent's actual pattern rather than only on the human version of the same step.

The grid shows, per incident and corpus, how many of that incident's signals a
rule covered. The right-hand column collapses the corpora: a signal is covered
there if any corpus covers it. Cells where a rule exists but would not fire are
labelled, because that difference is the point of the audit.

Data: artifact/expansion/coverage.csv and signals.csv
      (regenerate with expansion/merge_coverage.py)
Run:  uv run artifact/figs/fig3_coverage.py
Out:  report/latex/figs/fig3_coverage.pdf
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import numpy as np
import pandas as pd

from _style import CFO, GREY, INK, MUTED, RULE, SHORT, plaintitle, save
import matplotlib.pyplot as plt

EXP = CFO / "expansion"
sig = pd.read_csv(EXP / "signals.csv")
cov = pd.read_csv(EXP / "coverage.csv")

CORPORA = ["sigma", "elastic", "falco", "registry", "vendor"]
CORPUS_LABEL = {
    "sigma": "Sigma",
    "elastic": "Elastic",
    "falco": "Falco",
    "registry": "registry\ntooling",
    "vendor": "vendor\nrules",
}

cov["_exists"] = cov["match"].str.lower() == "exists"
cov["_fires"] = cov["_exists"] & (cov["fires_on_agent_pattern"].str.lower() == "yes")

n_signals = sig.groupby("incident_id").size()
# incidents ordered by how many signals the public record yields
incidents = list(n_signals.sort_values(ascending=False).index)

E = np.full((len(incidents), len(CORPORA) + 1), np.nan)
F = np.full_like(E, np.nan)
for i, inc in enumerate(incidents):
    c_inc = cov[cov.incident_id == inc]
    for j, corp in enumerate(CORPORA):
        c = c_inc[c_inc.corpus == corp]
        if c.empty:                      # corpus not audited for this incident
            continue
        E[i, j] = c.groupby("signal_id")["_exists"].any().sum()
        F[i, j] = c.groupby("signal_id")["_fires"].any().sum()
    E[i, -1] = c_inc.groupby("signal_id")["_exists"].any().sum()
    F[i, -1] = c_inc.groupby("signal_id")["_fires"].any().sum()

tot_signals = int(n_signals.sum())
tot_exists = int(np.nansum(E[:, -1]))
tot_fires = int(np.nansum(F[:, -1]))

# colour = share of that incident's signals covered, so a 0 cell stays white
frac = E / n_signals.reindex(incidents).to_numpy()[:, None]

fig, ax = plt.subplots(figsize=(7.0, 3.1))
cmap = plt.get_cmap("Blues")
VMAX = 0.55  # the largest cell share is 10/20; a 0-1 scale would wash it out
im = ax.imshow(np.ma.masked_invalid(frac), cmap=cmap, vmin=0, vmax=VMAX,
               aspect="auto")
im.cmap.set_bad("#f4f3ef")               # corpus not audited for that incident

for i in range(len(incidents)):
    for j in range(len(CORPORA) + 1):
        if np.isnan(E[i, j]):
            ax.text(j, i, "n/a", ha="center", va="center", fontsize=7,
                    color=GREY, style="italic")
            continue
        e, f = int(E[i, j]), int(F[i, j])
        txt = str(e) if e == f else f"{e}  ({f} fire)"
        ax.text(j, i, txt, ha="center", va="center", fontsize=8,
                fontweight="bold" if e else "normal",
                color="white" if frac[i, j] > 0.38 else INK)

ax.set_xticks(range(len(CORPORA) + 1))
ax.set_xticklabels([CORPUS_LABEL[c] for c in CORPORA] + ["any of the\nfive corpora"],
                   fontsize=8)
ax.set_yticks(range(len(incidents)))
ax.set_yticklabels([f"{SHORT[i]}  ({n_signals[i]})" for i in incidents], fontsize=8)
ax.set_ylabel("incident  (observable signals)")
ax.grid(visible=False)
ax.tick_params(length=0)
for s in ax.spines.values():
    s.set_visible(False)
# separate the collapsed column from the per-corpus ones
ax.axvline(len(CORPORA) - 0.5, color=INK, lw=1.0)
ax.set_xlim(-0.5, len(CORPORA) + 0.5)

cb = fig.colorbar(im, ax=ax, fraction=0.028, pad=0.015)
cb.set_label("share of signals covered", fontsize=7.5)
cb.ax.tick_params(labelsize=7)
cb.outline.set_visible(False)

# The totals (21 of 86 covered, 20 of 86 firing) and the 42 alertable signals
# with no firing rule are stated in the caption, not inside the figure.

plaintitle(fig, "Rule coverage", y=1.04)
fig.tight_layout()
save(fig, "fig3_coverage")
