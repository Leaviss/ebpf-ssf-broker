#!/usr/bin/env python3
"""Join one trial's logs into a single CSV row.

Timing points (all Unix nanoseconds on the single shared host clock):

    T0  kernel policy match — Tetragon's own event timestamp (via the SET)
    T6  the AuthorizationPolicy PATCH returns — revocation committed
    T8  first request from Service A denied (403) at B's sidecar

Spans: `pipeline` = T6 - T0 (everything the code can see), `enforce` = T8 - T6
(Istio config propagation), `end_to_end` = T8 - T0 (the headline number).

Prometheus cannot produce `end_to_end` (T8 - T0): T0 comes from a Tetragon event
timestamp carried on the SET, T8 from a Service A log line in a different
process, and there is no join across those domains. This script is that join.

Input is three captured log files from one trial; output is one appended row.
Every span is computed from the raw nanosecond stamps, so nothing here inherits
the histogram bucket-interpolation error (~6 ms at this scale).

A span whose endpoints are not both known is left **empty**, never zeroed — a
missing stamp costs one column instead of producing a plausible-looking wrong
number. Trials that failed to revoke are still written as rows: the headline
claim is a success *rate*, and a silently dropped failure would inflate it.

T8 is the one stamp that is *sampled* rather than logged by the thing it
measures: the deny goes live at B's sidecar at some instant the prober can only
bracket between two of its own requests. `find_deny_window` records both edges
of that bracket, so the quantisation is a measured per-trial number
(`t8_win_ms`) rather than an assumed ±interval. The `_mid` columns recompute
`enforce`/`end_to_end` against the bracket's midpoint — the unbiased estimate
(± t8_win_ms / 2); the raw upper-edge columns stay only so the correction can
be checked.
"""

from __future__ import annotations

import argparse
import calendar
import csv
import json
import re
import sys
from pathlib import Path

# One row per trial. The first eight columns are the core schema; the rest are
# free (already on the actuator's log line) and are what the per-stage
# breakdown is computed from.
COLUMNS = [
    "trial_id",
    "scenario",
    "t0_ns",
    "t6_ns",
    "t8_ns",
    "t8_lo_ns",
    "t8_win_ms",
    "pipeline_ms",
    "enforce_ms",
    "enforce_mid_ms",
    "end_to_end_ms",
    "end_to_end_mid_ms",
    "result",
    "jti",
    "subject",
    "detect_us",
    "translate_us",
    "transport_us",
    "actuate_us",
    "n_events",
    "n_deduped",
    "n_failed",
    "note",
]

# slog's TextHandler emits logfmt: bare `key=value`, or `key="value with spaces"`
# using Go's strconv.Quote escaping. Keys may themselves be quoted when they
# contain a space (the actuator logs one such: "SPIFFE Subject").
_PAIR = re.compile(r'("(?:[^"\\]|\\.)*"|[^\s=]+)=("(?:[^"\\]|\\.)*"|\S*)')

# Go's RFC3339Nano drops trailing zeros from the fraction, so the number of
# fractional digits varies between lines and cannot be assumed to be 9.
_RFC3339 = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$"
)


def unquote(tok: str) -> str:
    if len(tok) >= 2 and tok.startswith('"') and tok.endswith('"'):
        try:
            return json.loads(tok)
        except ValueError:
            return tok[1:-1]
    return tok


def parse_line(line: str) -> dict[str, str]:
    """Parse one logfmt line into a dict. Unparseable lines yield {}."""
    return {unquote(k): unquote(v) for k, v in _PAIR.findall(line)}


def rfc3339_ns(stamp: str) -> int | None:
    """RFC3339Nano (UTC) -> Unix nanoseconds, exactly.

    Done with integer arithmetic rather than datetime because
    datetime.fromisoformat truncates at microseconds, which would throw away
    three digits of a measurement whose whole point is sub-millisecond
    resolution.
    """
    m = _RFC3339.match(stamp)
    if not m:
        return None
    y, mo, d, h, mi, s, frac = m.groups()
    secs = calendar.timegm((int(y), int(mo), int(d), int(h), int(mi), int(s), 0, 0, 0))
    return secs * 1_000_000_000 + int((frac or "").ljust(9, "0"))


def read_lines(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    return [parse_line(ln) for ln in text.splitlines() if ln.strip()]


def ms(delta_ns: int) -> str:
    """Nanoseconds -> milliseconds, 3 dp (microsecond resolution preserved)."""
    return f"{delta_ns / 1_000_000:.3f}"


def trial_window_start(translator: list[dict[str, str]]) -> int | None:
    """Earliest timestamp in this trial's translator log, in Unix nanoseconds.

    The actuator is not restarted between trials — a restart makes its Prometheus
    counters unscrapable (docs/trial-reset.md) — so its log accumulates across a
    whole run and cannot be read as belonging to one trial. The translator *is*
    restarted by `make trial-reset`, so its log is fresh, and its first line marks
    the instant after which every actuator line belongs to this trial.

    Without this bound the join silently reports trial 1's numbers for every
    subsequent trial: the first `revoked` line stays the same while T8 advances,
    so `pipeline_ms` is frozen and `enforce_ms` grows by the elapsed run time.
    """
    stamps = [rfc3339_ns(r.get("time", "")) for r in translator]
    stamps = [s for s in stamps if s is not None]
    return min(stamps) if stamps else None


def within_trial(records: list[dict[str, str]], start_ns: int | None) -> list[dict[str, str]]:
    """Restrict actuator records to the ones logged during this trial."""
    if start_ns is None:
        return records
    kept = []
    for r in records:
        t = rfc3339_ns(r.get("time", ""))
        if t is not None and t >= start_ns:
            kept.append(r)
    return kept


def find_actuation(records: list[dict[str, str]]) -> tuple[dict | None, int, int, int]:
    """Pick the trial's latency sample out of the actuator log.

    One compromise emits N events (scenario 2 fires two connects), so the
    actuator sees a first `revoked` followed by `deduped` repeats. The first
    revoked line is the sample; the repeats are counted as trial hygiene but are
    not latency samples — a deduped event skips the API-server write, so its
    `actuate` span is a map lookup.

    `records` must already be narrowed to this trial by within_trial().
    """
    sample = None
    n_events = n_deduped = n_failed = 0
    for r in records:
        result = r.get("result")
        if result is None:
            # Not an event outcome line. The two failure paths return before the
            # outcome line is logged, so they carry no `result` field and have to
            # be counted off the message instead.
            if r.get("msg") in ("Failed to actuate revocation in mesh",
                                "Failed to decode SET"):
                n_events += 1
                n_failed += 1
            continue
        n_events += 1
        if result == "revoked" and sample is None:
            sample = r
        elif result == "deduped":
            n_deduped += 1
        elif result == "failed":
            n_failed += 1
    return sample, n_events, n_deduped, n_failed


def find_deny_window(
    records: list[dict[str, str]], after_ns: int | None
) -> tuple[int | None, int | None]:
    """T8 — when the deny went live at Service B's sidecar, as (upper, lower).

    The prober samples; it does not observe. Call the instant the deny goes live
    tau. The last request that got a 200 must have *arrived* at B's Envoy before
    tau, and the first request that got a 403 must have arrived at or after it,
    so tau lies in (arrival of last 200, arrival of first 403]. Neither arrival
    is logged directly, but each is bracketed by a stamp the prober does log:

        send(last 200) = log(last 200) - rtt  <  arrival(last 200)  <  tau
        tau  <=  arrival(first 403)  <  log(first 403)

    which gives the containment interval returned here. Both edges are
    deliberately the outer ones — the window is never narrower than the truth.

    Reporting only the upper edge (which is what `t8_ns` alone is) biases every
    `enforce`/`end_to_end` figure upward by half the probe interval and inflates
    its variance by the sampling jitter: at a 20 ms probe cadence that is +10 ms
    of bias and ~5.8 ms of spread that belong to the instrument, not the system. More trials do not remove either — they estimate
    the biased number more precisely. The midpoint of this window does.

    The upper edge is bounded below by T0 so a 403 left over from an earlier
    trial (a missed `make trial-reset`, docs/trial-reset.md) cannot be mistaken
    for this one's. The lower edge is not bounded by T0 or T6: a probe gap that
    straddles either is a real (if wide) bracket, and clamping it would forge
    precision the trial did not have.
    """
    lower = None  # send time of the most recent 200, i.e. tau's lower bound
    for r in records:
        if r.get("msg") != "recv":
            continue
        t = rfc3339_ns(r.get("time", ""))
        if t is None:
            continue
        status = r.get("status")
        if status == "200":
            # Without rtt there is no defensible lower bound: the log stamp is
            # *after* the response, so using it could exclude the true tau.
            # Drop the bound rather than narrow the window with a guess.
            rtt_us = r.get("rtt_us", "")
            lower = t - int(rtt_us) * 1000 if rtt_us.isdigit() else None
        elif status == "403" and (after_ns is None or t >= after_ns):
            return t, lower
    return None, None


def next_trial_id(csv_path: Path, scenario: str) -> str:
    n = 0
    if csv_path.exists():
        with csv_path.open(newline="") as fh:
            for row in csv.DictReader(fh):
                if row.get("scenario") == scenario:
                    n += 1
    return f"{scenario}-{n + 1:03d}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scenario", required=True, choices=["exec", "egress", "token-read"])
    ap.add_argument("--raw-dir", required=True, type=Path,
                    help="directory holding actuator.log / service-a.log / translator.log")
    ap.add_argument("--csv", required=True, type=Path)
    ap.add_argument("--trial-id", default=None,
                    help="default: <scenario>-<next index in the CSV>")
    ap.add_argument("--note", default="")
    args = ap.parse_args()

    actuator = read_lines(args.raw_dir / "actuator.log")
    prober = read_lines(args.raw_dir / "service-a.log")
    translator = read_lines(args.raw_dir / "translator.log")

    # The actuator outlives the run; the translator does not. Its first line is
    # this trial's start — see trial_window_start.
    start_ns = trial_window_start(translator)
    if start_ns is None:
        print(
            "  ! translator.log is empty or missing: cannot bound this trial in the "
            "actuator's log, so the row below may carry an earlier trial's numbers",
            file=sys.stderr,
        )
    sample, n_events, n_deduped, n_failed = find_actuation(within_trial(actuator, start_ns))

    row = dict.fromkeys(COLUMNS, "")
    row["trial_id"] = args.trial_id or next_trial_id(args.csv, args.scenario)
    row["scenario"] = args.scenario
    row["n_events"] = n_events
    row["n_deduped"] = n_deduped
    row["n_failed"] = n_failed
    row["note"] = args.note

    t0 = t6 = None
    if sample is not None:
        row["jti"] = sample.get("jti", "")
        row["subject"] = sample.get("subject", "")
        for stage in ("detect", "translate", "transport", "actuate"):
            row[f"{stage}_us"] = sample.get(f"{stage}_us", "")
        t0 = int(sample["t0_ns"]) if "t0_ns" in sample else None
        t6 = int(sample["t6_ns"]) if "t6_ns" in sample else None
        if t0 is not None:
            row["t0_ns"] = t0
        if t6 is not None:
            row["t6_ns"] = t6
        if t0 is not None and t6 is not None:
            row["pipeline_ms"] = ms(t6 - t0)

    t8, t8_lo = find_deny_window(prober, t0)
    t8_mid = None
    if t8 is not None:
        row["t8_ns"] = t8
        if t8_lo is not None and t8_lo < t8:
            row["t8_lo_ns"] = t8_lo
            row["t8_win_ms"] = ms(t8 - t8_lo)
            # Uniform over the window is the right prior: the compromise is
            # triggered at an arbitrary phase of the probe's ticker, so tau is
            # uncorrelated with it. The midpoint is that distribution's mean,
            # and the reported uncertainty is +/- t8_win_ms / 2.
            t8_mid = (t8_lo + t8) // 2
        if t6 is not None:
            row["enforce_ms"] = ms(t8 - t6)
            if t8_mid is not None:
                row["enforce_mid_ms"] = ms(t8_mid - t6)
        if t0 is not None:
            row["end_to_end_ms"] = ms(t8 - t0)
            if t8_mid is not None:
                row["end_to_end_mid_ms"] = ms(t8_mid - t0)

    # The outcome column §0 item 1 is counted from. `no_deny` is the one that
    # matters most: the pipeline ran but the deny never reached the prober,
    # which is an enforcement finding, not a broker failure.
    if sample is None:
        row["result"] = "no_revocation"
    elif t8 is None:
        row["result"] = "no_deny"
    else:
        row["result"] = "revoked"

    args.csv.parent.mkdir(parents=True, exist_ok=True)
    new = not args.csv.exists()
    with args.csv.open("a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS)
        if new:
            w.writeheader()
        w.writerow(row)

    print(
        f"{row['trial_id']}\tresult={row['result']}\t"
        f"pipeline_ms={row['pipeline_ms'] or '-'}\t"
        f"enforce_ms={row['enforce_mid_ms'] or row['enforce_ms'] or '-'}"
        f"{'+/-' + ms((t8 - t8_lo) // 2) if row['t8_win_ms'] else ''}\t"
        f"end_to_end_ms={row['end_to_end_mid_ms'] or row['end_to_end_ms'] or '-'}\t"
        f"events={n_events} deduped={n_deduped} failed={n_failed}",
        file=sys.stderr,
    )
    return 0 if row["result"] == "revoked" else 1


if __name__ == "__main__":
    raise SystemExit(main())
