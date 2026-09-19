#!/usr/bin/env python3
"""Blind second-pass sample: 40 executed Mythos-5 tool calls.

Stratification rule (exact, applied to the one-line `action_summary` in
calls.csv, case-insensitive regex):

  NETWORK/REGISTRY stratum  = summary matches any of
      "HTTP ", a leading "POST ", "proxy", "registry", "headless browser",
      "SSH reverse", "port sweep", "request collector", "webmail",
      "blockchain", "payment", "captcha", "SMS", "identity provider",
      "connectivity-probe", "artefact host"
  REST stratum = every other row (local file/script/shell/poll rows and the
      13 redacted rows).

We draw 25 from the network/registry stratum and 15 from the rest, each by
random.Random(20260914).sample over the stratum's rows sorted by index. The
network stratum is deliberately over-weighted (25/40 = 62.5% of the sample vs
258/1361 = 19.0% of the frame) so that the blind pass sees enough
signal-carrying candidates to measure agreement on them; the two binary
agreement figures are therefore computed on this enriched sample, not on the
frame.
"""
import csv
import os
import random
import re

HERE = os.path.dirname(os.path.abspath(__file__))
CALLS = os.path.join(os.path.dirname(HERE), "calls.csv")
OUT = os.path.join(HERE, "blind_sample.csv")

SEED = 20260914
N_NET = 25
N_REST = 15

NET_RE = re.compile(
    r"HTTP |^POST |proxy|registry|headless browser|SSH reverse|port sweep|"
    r"request collector|webmail|blockchain|payment|captcha|SMS|"
    r"identity provider|connectivity-probe|artefact host",
    re.I,
)


def main():
    with open(CALLS, newline="") as fh:
        rows = list(csv.DictReader(fh))
    rows.sort(key=lambda r: int(r["index"]))

    net = [r for r in rows if NET_RE.search(r["action_summary"])]
    rest = [r for r in rows if not NET_RE.search(r["action_summary"])]

    rng = random.Random(SEED)
    pick = rng.sample(net, N_NET) + rng.sample(rest, N_REST)
    pick.sort(key=lambda r: int(r["index"]))

    with open(OUT, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["index", "timestamp", "tool_name", "summary"])
        for r in pick:
            w.writerow([r["index"], r["timestamp"], r["tool_name"],
                        r["action_summary"]])

    print(f"frame: {len(rows)} executed calls")
    print(f"  network/registry stratum: {len(net)}  -> sampled {N_NET}")
    print(f"  rest stratum:             {len(rest)} -> sampled {N_REST}")
    print(f"seed: {SEED}; wrote {len(pick)} rows to {OUT}")
    print()
    for r in pick:
        print(r["index"], r["tool_name"], "|", r["action_summary"])


if __name__ == "__main__":
    main()
