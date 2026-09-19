# Report figures — "Caught From Outside"

Five publication figures for the report. One script per figure; all of them
write a PDF into `report/latex/figs/` and read only from the project's own
data files. Nothing here computes a new number: every value comes from
`detections.csv`, the expansion tables, or the Mythos 5 audit JSON.

Style is matched to the previous sprint's report figures
(the previous sprint's figure style): white ground,
muted categorical palette, thin dotted grid, no top or right spines, sans font
at 8 pt, direct labels in place of dense legends. Figures are drawn 7.0 in wide
so that LaTeX scales them slightly down at `\textwidth` (6.5 in on a
1 in-margin letter page).

**Language convention (2026-09-14).** Each figure carries a short plain title of
one to three words and no subtitle. In-figure text is labels only, six words or
fewer, and no sentence appears inside a figure. Everything that describes or
interprets the figure lives in the LaTeX caption, and the paste-ready caption
for each figure is the **Caption** block below. `_style.plaintitle()` draws the
title; the old `titleblock()` (headline plus grey detail line) is gone.

The five titles, in order: **Timeline**, **Detection latency**, **Rule
coverage**, **The Mythos 5 session**, **Exposure before detection**.

Shared conventions, carried over from `plot_timeline.py` / `plot_trends.py`:

- **Filled** shapes mean a firm date (hour- or day-precise). **Hollow with a
  diagonal hatch** means the value is approximate, known only to the month, or
  not stated in the source.
- **Colour** means the detector class (who found it first), using the same
  mapping as `plot_timeline.py`.
- Nothing censored is ever drawn at zero or at a midpoint. If the record does
  not fix a value, the figure says so in words.

Run them all:

```
uv run artifact/figs/fig1_timeline.py
uv run artifact/figs/fig2_latency.py
uv run artifact/figs/fig3_coverage.py
uv run artifact/figs/fig4_mythos5.py
uv run artifact/figs/fig5_two_clocks.py
```

`_style.py` is not a figure. It holds the palette, the rcParams, the short
incident names, and the detection-latency rules mirrored from `verify.py`
(`date_interval`, `latency_estimate`), so figures 2 and 5 cannot drift apart
from each other or from the verification script.

---

## fig1_timeline.pdf — the calendar

**Script:** `fig1_timeline.py`
**Data:** `artifact/detections.csv` (8 rows)
**Title in the figure:** Timeline

**Caption** (paste into `main.tex`):

> Each row is one incident, a star marks public disclosure, and colour shows
> who detected it first. A bar runs from the first unauthorized action to the
> first detection, and it is drawn only where both dates are known. The
> developer's own real-time monitoring is the first detector in none of the
> eight, and the three rows marked cascade were found in the review Anthropic
> opened after OpenAI disclosed on 21 July. Hollow markers and hatched bars
> mean the date is known only to the month or not stated at all.

**Judgement calls.**
- A bar is drawn only for rows where the detection latency is estimable at all,
  meaning `verify.py` returns a point or an interval. Four rows get no bar:
  Anthropic B, Anthropic D and Irregular have no first-action date, and
  Anthropic C has no first-detection date. This is the same rule figure 2 uses,
  so the two figures cannot disagree about which rows carry a duration.
- Anthropic A is the one row whose bar is hatched: both its dates are known
  only to the month, so the bar is the calendar-month span, not a measurement.
- A marker is filled when its own date is hour- or day-precise and hollow when
  that date is month-precise or unknown. Anthropic C and Irregular therefore
  carry a hollow detection marker.
- Anthropic C acted and was detected on the same calendar day (18 July), so its
  action marker sits underneath its detection marker.
- "← cascade" on a row label marks the three incidents whose `learned_via`
  field names OpenAI's 21 July disclosure. The claim is dated at the detection
  end; it is not a latency.
- The former in-figure note about the cascade (review opened 23 July, the three
  incidents found 24 July) is now caption text, and the only annotation left
  inside the figure is "OpenAI discloses, 21 Jul" on the dashed line.

## fig2_latency.pdf — how late, with the uncertainty intact

**Script:** `fig2_latency.py`
**Data:** `detections.csv`, through the `latency_estimate` rules copied from
`verify.py` section 5
**Title in the figure:** Detection latency

**Caption** (paste into `main.tex`):

> Detection latency is the gap between the first unauthorized action and the
> first detection, and three incidents have a firm date on both ends: they took
> 2, 4 and 11 days. The grey band and the dashed line show the median of those
> three rows, 4 days, with a bootstrap interval of 2 to 11 days. With only
> three values the resampling can return nothing but those three. The other
> five rows carry what the record supports, which is one month-precise
> interval, two one-sided bounds that fix the order of events but not the
> duration, and two rows with no estimate.

**Judgement calls.**
- The x-axis is logarithmic, because 2 days and 242 days do not share a linear
  scale at this figure width.
- A ">= 0 days" bound has no position on a log axis. Those two rows are drawn
  as a dashed arrow starting at the left edge and labelled "≥ 0 d (bound
  only)". The arrow's length is arbitrary and carries no information; what the
  bound does and does not fix is said in the caption.
- "Not estimable" rows get grey italic text and no mark at all. Drawing them at
  zero would assert same-day detection, which the sources do not support.
- The median annotation reads "median 4 d". The bootstrap interval and the
  meaning of the grey band moved to the caption.
- The grey band and dashed median line are drawn only across the three firm
  rows, because the median and its interval are computed from those rows alone.
- The sensitivity version in `verify.py` (firm rows plus the month-precise row,
  median 7.5 days) is deliberately not plotted; it mixes measured dates with
  month guesses and is not the headline.

## fig3_coverage.pdf — what a public rule would have caught

**Script:** `fig3_coverage.py`
**Data:** `expansion/coverage.csv` and `expansion/signals.csv` (regenerate with
`expansion/merge_coverage.py`)
**Title in the figure:** Rule coverage

**Caption** (paste into `main.tex`):

> For each incident the audit lists the signals an operator could have
> observed, then checks each signal against five public rule corpora pinned to
> the incident date. A public rule existed for 21 of the 86 signals, and it
> would fire on the agent's own pattern for 20 of them. Coverage sits almost
> entirely in the Hugging Face intrusion and the package-registry publish, and
> 42 signals that could have raised a real-time alert had no rule that fires. A
> cell reads "1 (0 fire)" where a rule exists but would not fire, and "n/a"
> marks a corpus that does not apply to that incident.

**Judgement calls.**
- "Covered" means `match == exists` only. Rows marked `partial` are not counted,
  matching `merge_coverage.py`.
- Cell colour is the share of that incident's signals covered, not the raw
  count, so incidents with very different signal counts stay comparable. The
  colour scale tops out at 0.55 because the largest cell is 10 of 20; a 0-to-1
  scale would leave every cell pale.
- A cell reads "e (f fire)" only when the two numbers differ, which happens
  three times (Hugging Face / Falco, and UK AISI in Elastic and in the
  collapsed column). Elsewhere the single number is both.
- "n/a" marks a corpus that was not audited for that incident (for example,
  package-registry tooling against a wiki incident). It is not a zero.
- The totals paragraph that used to sit under the grid is gone; the 21 of 86,
  20 of 86 and 42 figures are in the caption instead.
- Anthropic A and B contribute only three signals each. Their empty rows measure
  how little those disclosures say, not how poor the rules are;
  `merge_coverage.py` reports the totals a second time without them (21 of 80,
  20 of 80).

## fig4_mythos5.pdf — one session on a wall clock

**Script:** `fig4_mythos5.py`
**Data:** `expansion/mythos5_counts.json` (written by `expansion/mythos5_audit.py`;
narrative in `expansion/mythos5_audit.md`)
**Title in the figure:** The Mythos 5 session

**Caption** (paste into `main.tex`):

> The left panel covers the whole published Mythos 5 session, from 01:02:54 to
> 11:28:09 UTC on 18 July 2026, and the right panel repeats the last two
> minutes at true scale. The agent made its first call to the real internet
> five minutes in, then spent 10.1 hours having package uploads rejected: four
> tool calls sent nine rejected POSTs, eight of them 403 and one 400. The
> upload that succeeded returned HTTP 200 at 11:27:24, and the released record
> ends 45 seconds and three messages later, before any takedown. The hatched
> band marks the time after the record ends, which is absence of record rather
> than absence of activity.

**Judgement calls.**
- The 45-second window between the accepted upload and the end of the record is
  invisible at full-session scale, so it is shown in a second panel at true
  scale rather than exaggerated in the first.
- The shaded hatched region is the interval after the last released message. It
  marks absence of record, not absence of activity: the release note says later
  messages were redacted.
- Only the five executed upload attempts in the JSON are plotted. Intermediate
  negative responses from other services (the first is a 404 at 01:13:58) are
  left out to keep one story per figure.
- "10.1 hours" is `hours_from_first_attempt_to_success` from the JSON, measured
  from the first executed upload POST, not from the session start. The session
  itself spans 10.4 hours (`session_span_hours`), and the panel title no longer
  quotes that number, so the caption is the only place the two appear.
- The five executed upload calls are one accepted (HTTP 200) and four rejected;
  those four sent nine rejected POSTs in total, eight 403 and one 400
  (`post_status_tally`). The caption carries that breakdown; the figure shows
  only the markers.

## fig5_two_clocks.pdf — the control set and the escaped set

**Script:** `fig5_two_clocks.py`
**Data:** `expansion/controls.csv` (11 rows) and `detections.csv`
**Title in the figure:** Exposure before detection

**Caption** (paste into `main.tex`):

> The left panel is the control set of 11 disclosed cases where a real-time
> safeguard stopped the model inside the session, grouped by how much exposure
> happened first. Six had no exposure at all, because the action never took
> effect, and the approximate and unstated rows are hatched rather than drawn
> as zero. The right panel is the four ledger incidents with a numeric latency,
> and the other four are off that axis, because two give only a one-sided bound
> and two cannot be estimated. Exposure in exchanges and exposure in days do
> not convert into each other, so the panels are shown side by side and not
> pooled.

**Judgement calls.**
- The left panel is a count of control cases per exposure category rather than
  one bar per case, because nine of the eleven values are the same and a
  per-case chart would be nine identical marks.
- Categories are read from the `exposure_before_detection` text. Three rows read
  "0 for the block; unknown for the [follow-up]", and they get their own
  category rather than being counted as zero: the initial block was immediate,
  but how long the workaround attempt went unseen is not stated. The axis shows
  them as "blocked; follow-up unstated"; the full meaning is in the caption.
- The four axis labels are short by design ("no exposure", "blocked; follow-up
  unstated", "~70 exchanges", "not stated"); the previous sentence-length
  labels moved into the caption.
- The one "unknown" row (METR) and the one "~70 exchanges" row are hatched, for
  unstated and approximate respectively.
- The right panel plots only the rows with a numeric latency. The four rows with
  a bound or no estimate are not drawn at all, and the caption says how many
  they are and why they have no position.
- The comparison is descriptive and the two sets are not sampled the same way.
  The control set is what system cards chose to describe; the ledger is what
  became disclosable, which often happens *because* real-time monitoring missed
  it. The survivorship warning in `verify.py` applies to this figure.
