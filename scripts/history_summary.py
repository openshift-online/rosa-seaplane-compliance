#!/usr/bin/env python3
"""Summaries of the run-record series: what the Class C rules ask the SDR to carry.

Rule SDR-CSX-KMT (Class C, MUST) asks, per applicable KSI, for: a summary of each
metric over the past 30 days, a summary up to the past year (where available), and ALL
daily metric data (including the status of persistent validation) up to the past year
(where available). The summaries are generated here from the stored series, never by
hand, and never replace the daily data, which is written out in full.

Definitions (also in the README):
  * A DAY is the UTC day a record COVERS (`covers_date`), not the day the run happened.
    A day's result for a method is the LATEST record of that day (by finished_at) that
    contains it; every record is kept in the series (a rerun appends). A `not_collected`
    result (a backfill cannot reconstruct past state) never replaces a real result for the
    same method and day, and is never counted as a pass: it is a gap FOR THAT METHOD.
    A KSI's day result is the worst of its methods: fail, then error, then not_collected,
    then pass.
  * The latest day counted is today if it has a record, else yesterday: a day that has not
    been covered yet is not a gap.
  * 30-day summary: the 30 days ending on the last counted day. `days_without_record`
    counts every day of those 30, including days before the history started.
  * Year summary: from the first day the subject has a record, capped at 365 days, up
    to the last counted day: the history that is AVAILABLE, stated explicitly.
  * Alarms (the rules' minimum cadence is a verification at least every 3 days,
    VDR-TFR-MVX), in two levels. A normal run covers yesterday, so a newest covered day older
    than that means a daily run was missed (and `make daily` fills it in on its next run):
      WARN   STALE: the newest covered day is more than 1 day behind yesterday (a daily run
             was missed; the 3-day cadence is not yet broken);
      ALERT  STALE: the newest covered day is more than 3 days old;
      ALERT  GAP: two consecutive covered days are more than 3 days apart;
      ALERT  NO-HISTORY: nothing has been recorded.

    history_summary.py [--out-dir output/history] [--metrics output/sdr/ksi-metrics.json]
"""
import argparse
import json
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import history  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
REQUIREMENT_DAYS = 365
WINDOW_DAYS = 30
MAX_INTERVAL_DAYS = 3
WARN_BEHIND_DAYS = 1
LEVELS = ("ALERT", "WARN")   # most serious first
SEVERITY = {"fail": 3, "error": 2, "not_collected": 1, "pass": 0}
RESULTS = ("pass", "fail", "error", "not_collected")
METRICS_NOTE = ("FedRAMP's SDR schema has no field for historical metrics and FedRAMP staff say providers "
                "choose the structure (Discussion #131), so this is our own structure: per KSI, every daily point "
                "(all runs of the day kept) and the 30-day and past-year summaries.")


def parse_ts(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def worst(results) -> str:
    results = list(results)
    return max(results, key=lambda r: SEVERITY[r]) if results else None


def group_days(records: list) -> dict:
    """date -> records covering that day, oldest first by finished_at (the latest one wins)."""
    days = {}
    for rec in records:
        days.setdefault(date.fromisoformat(rec["covers_date"]), []).append(rec)
    for day in days.values():
        day.sort(key=lambda r: (r["finished_at"], r["run_id"]))
    return days


def day_method_results(day_records: list) -> dict:
    """(ksi, ar) -> result for one day: the latest record that contains the method wins."""
    out = {}
    for rec in day_records:  # oldest first, so later records overwrite earlier ones...
        for m in rec["methods"]:
            key, new = (m["ksi"], m["ar"]), m["result"]
            if new == "not_collected" and out.get(key) not in (None, "not_collected"):
                continue  # ...except that 'could not be collected' never erases a real result
            out[key] = new
    return out


def counted_end(days: dict, today: date) -> date:
    return today if today in days else today - timedelta(days=1)


def _span(series: dict, start: date, end: date) -> dict:
    """Counts over [start, end] for a {date: result} series. A day with no collected result
    (no record, or not_collected) is a gap for longest_gap_days; only days with no record at all
    are listed as missing."""
    n = (end - start).days + 1 if end >= start else 0
    counts = {r: 0 for r in RESULTS}
    missing, uncollected = [], []
    longest = run = 0
    for i in range(n):
        d = start + timedelta(days=i)
        res = series.get(d)
        if res is None:
            missing.append(d)
        else:
            counts[res] += 1
            if res == "not_collected":
                uncollected.append(d)
        if res is None or res == "not_collected":
            run += 1
            longest = max(longest, run)
        else:
            run = 0
    return {"days": n, "recorded_days": n - len(missing), "pass_days": counts["pass"], "fail_days": counts["fail"],
            "error_days": counts["error"], "not_collected_days": counts["not_collected"],
            "days_without_record": len(missing), "missing_days": [d.isoformat() for d in missing],
            "not_collected_list": [d.isoformat() for d in uncollected], "longest_gap_days": longest}


def summarize_series(series: dict, today: date, end: date) -> dict:
    """series: {date: result} for one subject (a KSI or a method)."""
    s30 = _span(series, end - timedelta(days=WINDOW_DAYS - 1), end)
    for k in ("missing_days", "longest_gap_days", "not_collected_list"):
        s30.pop(k)
    if series:
        first = min(series)
        start = max(first, end - timedelta(days=REQUIREMENT_DAYS - 1))
        year = _span(series, start, end)
        year["first_record_day"] = first.isoformat()
    else:
        year = {"days": 0, "recorded_days": 0, "pass_days": 0, "fail_days": 0, "error_days": 0, "not_collected_days": 0,
                "days_without_record": 0, "missing_days": [], "not_collected_list": [], "longest_gap_days": 0,
                "first_record_day": None}
    year["requirement_days"] = REQUIREMENT_DAYS
    return {"summary30": s30, "summaryYear": year}


def strip(series: dict, end: date) -> list:
    """The last 30 days as [{date, result}], result 'no-record' where there is none."""
    return [{"date": (end - timedelta(days=i)).isoformat(),
             "result": series.get(end - timedelta(days=i), "no-record")} for i in range(WINDOW_DAYS - 1, -1, -1)]


def alarms(days: dict, records: list, today: date) -> list:
    """Alarms with a level (WARN, ALERT), most serious first."""
    if not records:
        return [{"code": "no-history", "level": "ALERT",
                 "message": "No run records yet: nothing has been appended to the history."}]
    out = []
    ds = sorted(days)
    age = (today - ds[-1]).days
    behind = (today - timedelta(days=1) - ds[-1]).days   # days behind yesterday, the day a normal run covers
    if age > MAX_INTERVAL_DAYS:
        out.append({"code": "stale", "level": "ALERT",
                    "message": f"The newest record covers {ds[-1]}, {age} days ago (the rules' minimum "
                               f"cadence is a verification at least every {MAX_INTERVAL_DAYS} days)."})
    elif behind > WARN_BEHIND_DAYS:
        out.append({"code": "stale", "level": "WARN",
                    "message": f"The newest record covers {ds[-1]}, {behind} days behind yesterday: a daily run was missed "
                               f"(`make daily` fills the missing days; the {MAX_INTERVAL_DAYS}-day cadence is broken after "
                               f"{MAX_INTERVAL_DAYS} days)."})
    worst_gap = max(((b - a).days, a, b) for a, b in zip(ds, ds[1:])) if len(ds) > 1 else None
    if worst_gap and worst_gap[0] > MAX_INTERVAL_DAYS:
        out.append({"code": "gap", "level": "ALERT",
                    "message": f"{worst_gap[0]} days passed between the covered days {worst_gap[1]} and "
                               f"{worst_gap[2]} (more than {MAX_INTERVAL_DAYS})."})
    return sorted(out, key=lambda a: LEVELS.index(a["level"]))


def summarize(records: list, now: datetime) -> dict:
    today = now.astimezone(timezone.utc).date()
    days = group_days(records)
    end = counted_end(days, today)
    first = min(days) if days else None
    available = min(REQUIREMENT_DAYS, (end - first).days + 1) if first else 0
    ksis, methods = {}, {}
    for d, recs in days.items():
        for (ksi, ar), res in day_method_results(recs).items():
            methods.setdefault((ksi, ar), {})[d] = res
    kinds, bases = {}, {}
    for rec in records:
        for m in rec["methods"]:
            kinds[(m["ksi"], m["ar"])], bases[(m["ksi"], m["ar"])] = m["method_kind"], m["basis"]
    ksi_series = {}
    for (ksi, ar), series in methods.items():
        ks = ksi_series.setdefault(ksi, {})
        for d, res in series.items():
            ks.setdefault(d, []).append(res)
    for ksi in sorted(ksi_series):
        series = {d: worst(rs) for d, rs in ksi_series[ksi].items()}
        entry = {"ksi": ksi, **summarize_series(series, today, end), "strip": strip(series, end), "methods": [],
                 "daily": []}
        for d in sorted(days):
            if d not in series:
                continue
            entry["daily"].append({
                "date": d.isoformat(), "result": series[d],
                "methods": {ar: res for (k, ar), res in sorted(day_method_results(days[d]).items()) if k == ksi},
                "runs": [{"run_id": r["run_id"], "recorded_at": r["recorded_at"], "finished_at": r["finished_at"],
                          "backfill": r["backfill"], "methods": {m["ar"]: m["result"] for m in r["methods"] if m["ksi"] == ksi}}
                         for r in days[d] if any(m["ksi"] == ksi for m in r["methods"])]})
        for (k, ar), mseries in sorted(methods.items()):
            if k == ksi:
                entry["methods"].append({"ar": ar, "method_kind": kinds[(k, ar)], "basis": bases[(k, ar)], **summarize_series(mseries, today, end),
                                         "strip": strip(mseries, end)})
        ksis[ksi] = entry
    return {
        "meta": {"generated_at": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "last_counted_day": end.isoformat(), "note": METRICS_NOTE},
        "history": {"record_count": len(records), "run_days": len(days),
                    "first_record_day": first.isoformat() if first else None,
                    "last_record_day": max(days).isoformat() if days else None,
                    "available_days": available, "requirement_days": REQUIREMENT_DAYS,
                    "statement": (f"History available: {available} days; the requirement is up to {REQUIREMENT_DAYS}."
                                  if first else f"History available: 0 days; the requirement is up to {REQUIREMENT_DAYS}.")},
        "alarms": alarms(days, records, today),
        "ksis": ksis,
    }


def history_sentence(entry: dict) -> str:
    """One line for the SDR about a KSI's 30 days, or '' when there is no history yet."""
    s = (entry or {}).get("summary30")
    if not s or not s["recorded_days"]:
        return ""
    parts = [f"{s['pass_days']} of {s['recorded_days']} recorded days passed", f"{s['fail_days']} failed"]
    if s["error_days"]:
        parts.append(f"{s['error_days']} could not be judged")
    if s["not_collected_days"]:
        parts.append(f"{s['not_collected_days']} not collected")
    parts.append(f"{s['days_without_record']} days without a record")
    return "30-day history: " + ", ".join(parts) + "."


def render_markdown(summary: dict) -> str:
    h = summary["history"]
    out = ["# History summary", "",
           "> Local run. Not certification evidence. This describes real findings: do not publish it.", "",
           f"Generated {summary['meta']['generated_at']}; counting through {summary['meta']['last_counted_day']}.", "",
           f"**{h['statement']}** {h['record_count']} records over {h['run_days']} days.", ""]
    if summary["alarms"]:
        out += ["## Alarms", ""] + [f"- **{a.get('level', 'ALERT')}** **{a['code'].upper()}**: {a['message']}" for a in summary["alarms"]] + [""]
    else:
        out += ["No alarms: records are within the minimum cadence.", ""]
    out += ["Results: pass = complete, every target reached, no violation; fail = at least one violation; "
            "error = could not be judged; not_collected = a backfill cannot reconstruct past state (neither is ever a pass). "
            "A record is about the day it COVERS. A day's result is the latest record of that day (a not_collected never "
            "replaces a real result); a KSI's is the worst of its methods.", "",
            "## Per KSI", "",
            "| KSI | 30 days: pass / fail / error / not collected / no record | Year (available): recorded / days | Longest gap (days) |",
            "| :-- | :-- | :-- | --: |"]
    for k, e in summary["ksis"].items():
        s, y = e["summary30"], e["summaryYear"]
        out.append(f"| {k} | {s['pass_days']} / {s['fail_days']} / {s['error_days']} / {s['not_collected_days']} / {s['days_without_record']} "
                   f"| {y['recorded_days']} / {y['days']} | {y['longest_gap_days']} |")
    out += ["", "## Per method", "", "| KSI | AR | kind, basis | 30 days: pass / fail / error / not collected / no record | Missing days in the available range |",
            "| :-- | :-- | :-- | :-- | :-- |"]
    for k, e in summary["ksis"].items():
        for m in e["methods"]:
            s, y = m["summary30"], m["summaryYear"]
            miss = ", ".join(y["missing_days"][:8]) + (f" (+{len(y['missing_days']) - 8} more)" if len(y["missing_days"]) > 8 else "")
            out.append(f"| {k} | {m['ar']} | {m['method_kind']}, {m['basis']} | {s['pass_days']} / {s['fail_days']} / "
                       f"{s['error_days']} / {s['not_collected_days']} / {s['days_without_record']} | {miss or 'none'} |")
    return "\n".join(out) + "\n"


def metrics_document(summary: dict) -> dict:
    """The daily series and summaries per KSI, for the SDR's trust-center companion."""
    return {"meta": {**summary["meta"], "structure": "rsc-ksi-metrics/1"}, "history": summary["history"],
            "alarms": summary["alarms"],
            "ksis": {k: {"daily": e["daily"], "summary30": e["summary30"], "summaryYear": e["summaryYear"],
                         "methods": [{"ar": m["ar"], "method_kind": m["method_kind"], "basis": m["basis"], "summary30": m["summary30"],
                                      "summaryYear": m["summaryYear"]} for m in e["methods"]]}
                     for k, e in summary["ksis"].items()}}


def write_outputs(summary: dict, out_dir: Path, metrics_path: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (out_dir / "summary.md").write_text(render_markdown(summary))
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(json.dumps(metrics_document(summary), indent=2, sort_keys=True) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out-dir", default=str(ROOT / "output/history"))
    ap.add_argument("--metrics", default=str(ROOT / "output/sdr/ksi-metrics.json"))
    args = ap.parse_args()
    now = datetime.now(timezone.utc)
    try:
        import build_record
        store = history.open_store()
        records = store.records(since=now.date() - timedelta(days=REQUIREMENT_DAYS + 1), validator=build_record.check_record)
    except history.StoreError as e:
        sys.exit(f"ERROR: {e}")
    summary = summarize(records, now)
    write_outputs(summary, Path(args.out_dir), Path(args.metrics))
    h = summary["history"]
    print(f"{h['statement']} {h['record_count']} records, {len(summary['ksis'])} KSIs; wrote {args.out_dir}/summary.json, summary.md and {args.metrics}")
    for a in summary["alarms"]:
        print(f"{a.get('level', 'ALERT')} {a['code']}: {a['message']}")


if __name__ == "__main__":
    main()
