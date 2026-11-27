#!/usr/bin/env python3
"""Render output/sdr/sdr.json and output/coverage.json as one local HTML page.

Self-contained and offline: no external scripts, fonts, images or network
requests, because the data describes real findings and stays on the laptop.
Every value is HTML-escaped (evidence can carry attacker-controlled text such
as PR titles). The only script is an inline filter for the KSI list.

Implementation state (how far the checks are) and result (what the latest
evaluation found) are separate signals, and neither implies the other.

With output/trace.json (scripts/build_trace.py) the page gains an "Assessment
requirements" tab: an index of ARs and one page per AR, laid out as an
hourglass (why it exists above, how it is checked and the proof below).
Results are AR-level only; the viewer says where to look for the reason.
"""
import argparse
import html
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import generate_sdr  # noqa: E402  (cycle wording shared with the SDR)

ROOT = Path(__file__).resolve().parent.parent
RESULT_RE = re.compile(r"^(\S+): (passed|failed|inconclusive|not evaluated)")
# Worst first: a KSI's overall result is its worst method result.
RESULT_ORDER = ["failed", "inconclusive", "not evaluated", "passed"]
RESULT_GLYPH = {"failed": "✗", "inconclusive": "?", "not evaluated": "–", "passed": "✓", "no results": "·"}
STATE_ORDER = ["Not started", "In progress", "Covered", "SDR-ready"]


def e(value) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def slug(ksi_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "-", ksi_id)


def results_by_ar(sdr_entry: dict) -> dict:
    """AR ID -> result word, from the SDR evidence text (the SDR is the single source)."""
    out = {}
    for ev in sdr_entry.get("ksiEvidence", []):
        m = RESULT_RE.match(ev.get("evidenceText", ""))
        if m:
            out[m.group(1)] = m.group(2)
    return out


def overall_result(results: dict) -> str:
    for r in RESULT_ORDER:
        if r in results.values():
            return r
    return "no results"


def state_badge(state: str) -> str:
    return f'<span class="state state-{slug(state.lower())}" title="Implementation state">{e(state)}</span>'


def result_badge(result: str) -> str:
    return (f'<span class="result result-{slug(result)}" title="Latest evaluation result">'
            f'<span aria-hidden="true">{RESULT_GLYPH[result]}</span> {e(result)}</span>')


def statements(items: list, empty: str) -> str:
    if not items:
        return f'<p class="muted">{e(empty)}</p>'
    return "".join(f"<p>{e(i)}</p>" for i in items)


def render_methods(row: dict, results: dict) -> str:
    if not row["methods"]:
        return '<p class="muted">No mapped assessment requirement yet.</p>'
    rows = []
    for m in row["methods"]:
        sc = m["scope"]
        reached = "not run" if not sc["run"] else f"{sc['reached']}/{sc['total']}"
        missing = f'<br><span class="muted">missing: {e(", ".join(sc["missing"]))}</span>' if sc["missing"] else ""
        res = results.get(m["ar"], "not evaluated")
        rows.append(
            f"<tr><td>{e(m['ar'])}</td><td>{e(m['kind'] or '?')}</td><td>{e(m['executor'] or 'none')}</td>"
            f"<td>{'implemented' if m['implemented'] else 'not implemented'}</td>"
            f"<td>{'yes' if m['fixtures'] else 'no'}</td><td>{e(reached)}{missing}</td>"
            f"<td>{result_badge(res)}</td></tr>")
    return ("<table><thead><tr><th>AR</th><th>Kind</th><th>Evaluator</th><th>Method</th><th>Fixtures</th>"
            "<th>Targets reached</th><th>Latest result</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>")


def render_controls(row: dict) -> str:
    c = row["controls"]
    parts = [f"<p>{row['controls_decided']}/{row['controls_total']} related controls decided.</p><ul>"]
    for label in ("addressed", "inherited", "not-applicable", "open"):
        if c[label]:
            parts.append(f"<li><strong>{e(label)}</strong>: {e(', '.join(c[label]))}</li>")
    parts.append("</ul>")
    return "".join(parts)


def render_ksi(row: dict, entry: dict, ar_links: list = None) -> str:
    results = results_by_ar(entry or {})
    overall = overall_result(results)
    haystack = f"{row['id']} {row['name']} {row['family']}".lower()
    status = (entry or {}).get("ksiImplementationStatus", "")
    return f"""
<details class="ksi" id="ksi-{slug(row['id'])}" data-state="{e(row['state'])}" data-result="{e(overall)}" data-family="{e(row['family'])}" data-text="{e(haystack)}">
<summary><span class="id">{e(row['id'])}</span> <span class="name">{e(row['name'])}</span>
 <span class="signals">{state_badge(row['state'])} {result_badge(overall)}</span></summary>
<div class="body">
<p class="statement">{e(row['statement'])}</p>
<p class="muted">Type: {e(row['type'])} · SDR status: {e(status)} · Methods {min(row['methods_implemented'], 2)}/2</p>
<h4>Implementation</h4>{statements((entry or {}).get('ksiImplementation', []), 'Nothing documented yet.')}
<h4>Validation</h4>{statements((entry or {}).get('ksiValidation', []), 'Nothing documented yet.')}
<h4>Methods</h4>{render_methods(row, results)}
{render_ar_links(ar_links)}
<h4>Latest evidence</h4>{statements([ev.get('evidenceText', '') for ev in (entry or {}).get('ksiEvidence', [])], 'No evidence yet.')}
<h4>Related controls</h4>{render_controls(row)}
<h4>Assessment</h4>{statements((entry or {}).get('ksiAssessment', []), 'No assessor content (assessment is independent).')}
</div></details>"""



# --- assessment requirement (AR) pages -------------------------------------------

STATUS_GLYPH = {"reached": "●", "error": "!", "not reached": "○", "not run": "·"}
UNDEFINED = '<span class="undefined">not defined yet</span>'


def ar_slug(ar_id: str) -> str:
    return "ar-" + slug(ar_id)


def render_ar_links(ar_links: list) -> str:
    """On a KSI card: the ARs that evidence it, linking to their pages."""
    if not ar_links:
        return ""
    items = "".join(f'<li><a href="#{e(ar_slug(a))}">{e(a)}</a></li>' for a in ar_links)
    return f"<h4>Assessment requirements</h4><ul>{items}</ul>"


def first_sentence(text: str, limit: int = 150) -> str:
    cut = text.split(". ")[0].split("; ")[0]
    return cut if len(cut) <= limit else cut[: limit - 1].rstrip() + "…"


def scope_strip(scope: dict) -> str:
    """One mark per target plus a count. Reach is scope, not a result."""
    targets = scope["targets"]
    marks = "".join(
        f'<span class="t t-{slug(t["status"])}" role="img" aria-label="{e(t["name"])}: {e(t["status"])}" '
        f'title="{e(t["name"])}: {e(t["status"])}">{STATUS_GLYPH[t["status"]]}</span>' for t in targets)
    if not scope["run"]:
        count = "not run"
    else:
        count = f"{sum(t['status'] == 'reached' for t in targets)}/{len(targets)} reached"
    return f'<span class="strip">{marks}</span> <span class="muted">{e(count)}</span>'


def ksi_chips(trace: dict, ar: dict) -> str:
    reqs = [trace["requirements"][k] for k in ar["requirements"]]
    ksis = [r for r in reqs if r["kind"] == "ksi"]
    others = len(reqs) - len(ksis)
    chips = "".join(f'<a class="chip" href="#ksi-{e(slug(r["id"]))}">{e(r["id"])}</a>' for r in ksis)
    if others:
        chips += f'<span class="muted"> +{others} control{"s" if others != 1 else ""}</span>'
    return chips or '<span class="muted">none</span>'


def ar_result(trace: dict, ar_id: str) -> str:
    return (trace["results"].get(ar_id) or {}).get("overall", "not evaluated")


def render_ar_index(trace: dict) -> str:
    ars = trace["ars"]
    n_impl = sum(a["implemented"] for a in ars.values())
    counts = {r: sum(ar_result(trace, i) == r for i in ars) for r in RESULT_ORDER}
    rows = []
    for ar_id, ar in ars.items():
        result = ar_result(trace, ar_id)
        text = f"{ar_id} {ar['text']} {ar['control']} " + " ".join(trace["requirements"][k]["id"] for k in ar["requirements"])
        rows.append(
            f'<tr class="arrow" data-text="{e(text.lower())}" data-state="{e(ar["implementation_state"])}" data-result="{e(result)}">'
            f'<td><a class="id" href="#{e(ar_slug(ar_id))}">{e(ar_id)}</a></td>'
            f'<td title="{e(ar["text"])}">{e(first_sentence(ar["text"]))}</td>'
            f'<td>{ksi_chips(trace, ar)}</td>'
            f'<td>{state_badge(ar["implementation_state"])}</td>'
            f'<td>{result_badge(result)}</td>'
            f'<td>{scope_strip(trace["scope"][ar_id])}</td></tr>')
    options = lambda items: "".join(f'<option value="{e(i)}">{e(i)}</option>' for i in items)
    return f"""
<h2>Assessment requirements</h2>
<p class="muted">An assessment requirement (AR) is one testable condition. It is the middle of the trail: above it, the requirements it evidences (KSIs, 800-53 controls); below it, how it is checked and what was found. Open one to read it top to bottom.</p>
<div class="kpis">
 <div>{len(ars)}<span>assessment requirements</span></div>
 <div>{n_impl}/{len(ars)}<span>implemented</span></div>
 <div>{counts['failed']}<span>failed</span></div>
 <div>{counts['passed']}<span>passed</span></div>
 <div>{counts['not evaluated'] + counts['inconclusive']}<span>not evaluated</span></div>
</div>
<p class="muted">Implementation state and result are separate signals. The strip shows targets reached (●), errored (!) or not reached (○) by collection: that is scope, not a pass/fail.</p>
<div class="filters">
 <input id="arq" type="search" placeholder="Filter by AR, text, control or KSI" aria-label="Filter assessment requirements">
 <select id="arstate" aria-label="Implementation state"><option value="">Any state</option>{options(["Implemented", "Not implemented"])}</select>
 <select id="arresult" aria-label="Result"><option value="">Any result</option>{options(RESULT_ORDER)}</select>
 <span id="arshown" class="muted"></span>
</div>
<table><thead><tr><th>AR</th><th>Requirement</th><th>Serves</th><th>Implementation</th><th>Latest result</th><th>Scope</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>"""


def code(text) -> str:
    return f"<code>{e(text)}</code>"


def render_why(trace: dict, ar: dict) -> str:
    out = []
    for fw in trace["frameworks"]:
        mine = [l for l in trace["links"] if l["ar"] == ar["id"] and l["framework"] == fw["id"]]
        out.append(f'<h4>{e(fw["title"])}</h4>')
        if not mine:
            out.append('<p class="muted">No mapping from this AR.</p>')
            continue
        items = []
        for l in mine:
            req = trace["requirements"][l["requirement"]]
            if req["kind"] == "ksi":
                label = (f'<a class="id" href="#ksi-{e(slug(req["id"]))}">{e(req["id"])}</a> {e(req["name"] or "")}'
                         f'<span class="muted"> · KSI is {e(req.get("state") or "unknown")}</span>')
            else:
                shown = req["display_id"] if req["display_id"] != req["id"] else req["id"]
                label = f'<span class="id">{e(shown)}</span>'
            why = f'<br><span class="rationale">{e(l["rationale"])}</span>' if l["rationale"] else ""
            strength = f' <span class="muted">(strength {e(l["strength"])})</span>' if l["strength"] is not None else ""
            items.append(f"<li>{label}{strength}{why}</li>")
        out.append("<ul>" + "".join(items) + "</ul>")
    out.append('<p class="muted">Another certification appears here as one more block once it has a mapping file under <code>mappings/</code>.</p>')
    return "".join(out)


def render_how(trace: dict, ar: dict) -> str:
    sc, impl, plan = trace["scope"][ar["id"]], ar["impl"], ar["plan"]
    res = trace["results"].get(ar["id"])

    def step(title, body):
        return f"<li><strong>{e(title)}</strong><div>{body}</div></li>"

    steps = []
    steps.append(step("Scope", f'{e(ar["applicability"][0] if ar["applicability"] else "unspecified")}: '
                               f'{len(sc["expected"])} expected target(s). {scope_strip(sc)}'
                               + ("<ul>" + "".join(
                                   f'<li>{e(t["name"])} <span class="muted">{e(t["status"])}'
                                   + (f': {e(t["error"])}' if t.get("error") else "") + "</span></li>"
                                   for t in sc["targets"]) + "</ul>" if sc["targets"] else "")))
    note = generate_sdr.automation_sentence(sc.get("automation"))
    if note:
        steps.append(step("Automation exemption", e(note) + ' <span class="muted">Bot-authored changes that merged on automation alone, under the conditions in <code>config/automation.yaml</code>.</span>'))
    if impl is None:
        for t in ("Source", "Shape", "Logic"):
            steps.append(step(t, '<span class="muted">No automated method in the policy yet.</span>'))
    else:
        steps.append(step("Source", f'collector {code(impl["collector"] or "missing")} writes '
                                    f'{code("evidence/output/" + ar["id"] + "/<target>.json")} and a manifest'))
        steps.append(step("Shape", f'{code(impl["schema"] or "missing")}'
                                   + (f' <span class="muted">(platform {e(impl["platform"])})</span>' if impl["platform"] else "")))
        fx = impl["fixtures"]
        steps.append(step("Logic", f'{code(impl["rego_file"] or "missing")} <span class="muted">package {e(impl["rego_package"])}</span>'
                                   f'<br>unit tests: {code(impl["rego_test_file"]) if impl["rego_test_file"] else "none"}'
                                   f'<br>fixtures: pass {"✓" if fx["pass"] else "✗ missing"}, fail {"✓" if fx["fail"] else "✗ missing"}'))
    steps.append(step("What it checks", e(ar["what_it_checks"]) if ar["what_it_checks"] else UNDEFINED))
    steps.append(step("Fails when", UNDEFINED if not ar["fails_when"] else e(ar["fails_when"])))
    steps.append(step("Failure handling", UNDEFINED if not ar["failure_handling"] else e(ar["failure_handling"])))
    if plan:
        steps.append(step("Cadence", f'{e(generate_sdr.cycle_text({plan["frequency"]} if plan["frequency"] else set()))} '
                                     f'<span class="muted">plan {e(plan["id"])}, evaluator {e(plan["executor"] or "none")}</span>'))
    else:
        steps.append(step("Cadence", '<span class="muted">No plan.</span>'))
    steps.append(step("Result", (f'{result_badge(ar_result(trace, ar["id"]))} <span class="muted">evaluated {e(res["evaluated_at"])}</span>'
                                 if res else f'{result_badge("not evaluated")} <span class="muted">no scan result yet</span>')))
    return '<ol class="trace">' + "".join(steps) + "</ol>"


def render_look_here(trace: dict, ar: dict) -> str:
    ar_id, res = ar["id"], trace["results"].get(ar["id"])
    sc = trace["scope"][ar_id]
    reached = [t["name"] for t in sc["targets"] if t["status"] == "reached"]
    example = reached[0].split("/")[-1] if reached else "<repo>"
    scan = trace["meta"].get("scan") or {}
    report = (res or {}).get("report_file") or scan.get("report_file")
    log = (res or {}).get("log_file") or scan.get("log_file")
    message = (f'<blockquote>{e(res["message"])}</blockquote>' if res and res.get("message")
               else '<p class="muted">The scan recorded no message for this AR.</p>')
    cmd_dir = f"opa/{ar['domain']}/policy"
    return f"""<div class="lookhere">
<h3>Why did it fail? Look here</h3>
<p>This page shows pass or fail only. The scan records one result and one message for the whole AR, not one per target, so the reason is outside this viewer:</p>
<ul>
 <li>Human-readable report of the latest scan: {code(report) if report else '<span class="muted">none yet (run make run-local)</span>'}</li>
 <li>Raw L5 record: {code(log) if log else '<span class="muted">none yet</span>'}</li>
 <li>The evidence collected, one file per target: {code("ls evidence/output/" + ar_id + "/")}</li>
 <li>The denials for one piece of evidence: {code(f"conftest test evidence/output/{ar_id}/{example}.json -p {cmd_dir} --all-namespaces")}</li>
</ul>
<p>The one message the scan recorded for this AR:</p>{message}
</div>"""


def render_ar_page(trace: dict, ar: dict) -> str:
    ctl = trace["controls"].get(ar["control"], {})
    res = trace["results"].get(ar["id"])
    own = ar["missing"]["own"]
    by_req = [f'{trace["requirements"][k]["id"]}: ' + "; ".join(v) for k, v in ar["missing"]["by_requirement"].items() if v]
    missing = own + by_req
    missing_html = "; ".join(e(m) for m in missing) if missing else "nothing known to be missing"
    return f"""
<section class="page arpage" id="{e(ar_slug(ar['id']))}">
<p><a href="#page-ars">← All assessment requirements</a></p>
<h2><span class="id">{e(ar['id'])}</span></h2>
<p class="statement">{e(ar['text'])}</p>
<p class="muted">Control {e(ar['control'])}: {e(ctl.get('title') or '')}</p>
<p class="signals2"><span class="muted">Implementation</span> {state_badge(ar['implementation_state'])}
 <span class="muted">Latest result</span> {result_badge(ar_result(trace, ar['id']))}
 {f'<span class="muted">evaluated {e(res["evaluated_at"])}</span>' if res else ''}</p>
<div class="hour">
<div class="why"><h3>Why it exists: what this evidences</h3>{render_why(trace, ar)}</div>
<div class="waist">{e(ar['id'])}</div>
<div class="how"><h3>How it is checked, and the proof</h3>{render_how(trace, ar)}</div>
</div>
{render_look_here(trace, ar)}
<p class="missing"><strong>Missing:</strong> {missing_html}.</p>
</section>"""


def render_overview(coverage: dict, results: dict) -> str:
    fam = defaultdict(lambda: {"n": 0, "states": defaultdict(int), "m": 0, "results": defaultdict(int)})
    for row in coverage["ksis"]:
        f = fam[row["family"]]
        f["n"] += 1
        f["states"][row["state"]] += 1
        f["m"] += min(row["methods_implemented"], 2)
        f["results"][overall_result(results.get(row["id"], {}))] += 1
    head = "".join(f"<th>{e(s)}</th>" for s in STATE_ORDER)
    rows = []
    for name in sorted(fam):
        f = fam[name]
        cells = "".join(f"<td>{f['states'].get(s, 0)}</td>" for s in STATE_ORDER)
        res = ", ".join(f"{f['results'][r]} {r}" for r in RESULT_ORDER + ["no results"] if f["results"].get(r))
        rows.append(f"<tr><td>{e(name)}</td><td>{f['n']}</td>{cells}<td>{f['m']}/{f['n'] * 2}</td><td>{e(res)}</td></tr>")
    return (f"<table><thead><tr><th>Family</th><th>KSIs</th>{head}<th>Methods</th><th>Latest results</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>")


CSS = """
:root{color-scheme:light dark;--bg:#fff;--fg:#1b1f24;--muted:#5b6570;--line:#d0d7de;--warn:#fff4d6;--warnfg:#5c3d00}
@media (prefers-color-scheme:dark){:root{--bg:#14181d;--fg:#e6e9ec;--muted:#9aa5b1;--line:#2d343c;--warn:#3a2f10;--warnfg:#ffd98a}}
body{font:15px/1.5 system-ui,sans-serif;margin:0;background:var(--bg);color:var(--fg)}
main{max-width:1100px;margin:0 auto;padding:1rem 1.25rem 4rem}
.banner{background:var(--warn);color:var(--warnfg);padding:.6rem 1.25rem;font-weight:600;border-bottom:1px solid var(--line)}
table{border-collapse:collapse;width:100%;margin:.5rem 0}th,td{border-bottom:1px solid var(--line);padding:.3rem .5rem;text-align:left;vertical-align:top}
.muted{color:var(--muted)}.kpis{display:flex;gap:1.5rem;flex-wrap:wrap;margin:.5rem 0}.kpis div{font-size:1.4rem}.kpis span{display:block;font-size:.8rem;color:var(--muted)}
.filters{display:flex;gap:.5rem;flex-wrap:wrap;margin:1rem 0}input,select{font:inherit;padding:.25rem .4rem;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:4px}
details.ksi{border:1px solid var(--line);border-radius:6px;margin:.4rem 0}details.ksi>summary{cursor:pointer;padding:.5rem .75rem;display:flex;gap:.75rem;align-items:baseline;flex-wrap:wrap}
.id{font-family:ui-monospace,monospace;font-weight:600}.signals{margin-left:auto;display:flex;gap:.5rem}.body{padding:0 1rem 1rem}
.state{border:1.5px solid var(--fg);border-radius:999px;padding:0 .6rem;font-size:.8rem}
.state-sdr-ready{border-width:3px}.state-not-started{border-style:dashed;color:var(--muted);border-color:var(--muted)}
.result{border-radius:4px;padding:0 .5rem;font-size:.8rem;border:1px solid var(--line);background:color-mix(in srgb,var(--fg) 6%,transparent)}
.result-failed{font-weight:700;background:color-mix(in srgb,#d1242f 22%,transparent);border-color:#d1242f}
.result-passed{background:color-mix(in srgb,#1a7f37 20%,transparent);border-color:#1a7f37}
h4{margin:1rem 0 .25rem}.hidden{display:none}
nav.tabs{display:flex;gap:.25rem;margin:1rem 0;border-bottom:1px solid var(--line)}nav.tabs a{padding:.4rem .9rem;text-decoration:none;color:var(--muted);border:1px solid transparent;border-bottom:0;border-radius:6px 6px 0 0}
nav.tabs a.active{color:var(--fg);font-weight:600;border-color:var(--line);background:color-mix(in srgb,var(--fg) 5%,transparent)}
a{color:inherit}.chip{display:inline-block;border:1px solid var(--line);border-radius:4px;padding:0 .4rem;margin:0 .2rem .1rem 0;font-family:ui-monospace,monospace;font-size:.8rem;text-decoration:none}
.state,.result{white-space:nowrap}input[type=search]{min-width:19rem}
.state-implemented{border-width:3px}.state-not-implemented{border-style:dashed;color:var(--muted);border-color:var(--muted)}
.strip{white-space:nowrap}.t{display:inline-block;width:1.1rem;text-align:center;font-size:.85rem}.t-error{font-weight:700;color:#d1242f}.t-not-reached{color:var(--muted)}
.undefined{border:1px dashed var(--muted);border-radius:4px;padding:0 .4rem;color:var(--muted);font-style:italic}
.signals2{display:flex;gap:.5rem;align-items:baseline;flex-wrap:wrap}
.hour{display:grid;gap:0;margin:1rem 0}.hour .why,.hour .how{border:1px solid var(--line);border-radius:8px;padding:.25rem 1rem 1rem}
.hour .why{border-bottom-left-radius:50% 1.2rem;border-bottom-right-radius:50% 1.2rem}.hour .how{border-top-left-radius:50% 1.2rem;border-top-right-radius:50% 1.2rem}
.hour .waist{justify-self:center;font-family:ui-monospace,monospace;font-weight:700;border:2px solid var(--fg);border-radius:999px;padding:.15rem 1rem;margin:-.6rem 0;background:var(--bg);z-index:1}
ol.trace{padding-left:1.4rem}ol.trace>li{margin:.5rem 0}ol.trace ul{margin:.2rem 0}.rationale{color:var(--muted)}
.lookhere{border:2px solid var(--warnfg);background:var(--warn);color:var(--warnfg);border-radius:8px;padding:.25rem 1rem .75rem;margin:1rem 0}
.lookhere h3{margin:.6rem 0 .3rem}.lookhere blockquote{margin:.3rem 0;padding:.3rem .75rem;border-left:4px solid var(--warnfg);overflow-wrap:anywhere}
code{font-family:ui-monospace,monospace;font-size:.85em;background:color-mix(in srgb,var(--fg) 8%,transparent);padding:0 .25rem;border-radius:3px;overflow-wrap:anywhere}
.missing{border-top:1px solid var(--line);padding-top:.6rem}
.dstrip{display:flex;gap:2px;flex-wrap:nowrap}.dc{display:inline-block;width:1.15rem;text-align:center;font-size:.8rem;line-height:1.3rem;border:1px solid var(--line);border-radius:3px}
.dc-pass{background:color-mix(in srgb,#1a7f37 22%,transparent)}.dc-fail{font-weight:700;border-color:#d1242f;background:color-mix(in srgb,#d1242f 22%,transparent)}
.dc-error{font-weight:700;border-style:dashed;border-color:var(--fg)}.dc-no-record{color:var(--muted);border-style:dotted}.dc-not_collected{color:var(--muted);border-style:double;border-width:3px}
.alarm{border:2px solid #d1242f;border-radius:8px;padding:.4rem 1rem;margin:.75rem 0;font-weight:600}
.alarm-warn{border-color:var(--warnfg);background:var(--warn);color:var(--warnfg)}
"""

FINDING_KIND_NOTE = {
    "violation": "The system does not meet the requirement.",
    "incomplete-evidence": "We could not tell: an incomplete collection, a cross-check mismatch, or a check that did not run. Never a pass.",
    "not-reached": "A target the collector could not reach. Unchecked, which is neither a pass nor a failure.",
}


def render_findings_page(rep: dict) -> str:
    """Findings, gaps and limits, kept apart. Every value is escaped: subjects and
    messages can carry attacker-controlled text (PR titles, names)."""
    meta, findings = rep["meta"], rep["findings"]
    counts = meta["counts"]["by_kind"]
    ev = meta["evidence_generated_at"]
    kinds = [k for k in ("violation", "incomplete-evidence", "not-reached") if any(f["kind"] == k for f in findings)]
    ar_ids = sorted({f["ar"] for f in findings})
    out = [f'<p class="muted">Environment {e(meta["environment"])} · generated {e(meta["generated_at"])} · evidence collected '
           f'{e(ev["oldest"])} to {e(ev["newest"])} · built from files on disk, no AI, no network.</p>',
           '<div class="kpis">'
           + "".join(f'<div>{counts.get(k, 0)}<span>{e(k)}</span></div>' for k in ("violation", "incomplete-evidence", "not-reached"))
           + "</div>",
           '<p class="muted">Findings are about the system. Gaps are about our own checks and records. Limits say what a check cannot see.</p>']
    if meta["unclassified"]:
        out.append(f'<p><strong>{meta["unclassified"]} denial(s) carry no rule id</strong>: a policy needs fixing.</p>')
    opts = lambda items: "".join(f'<option value="{e(i)}">{e(i)}</option>' for i in items)
    out.append('<h2>Findings</h2><div class="filters">'
               '<input id="fq" type="search" placeholder="Filter by rule, target or subject" aria-label="Filter findings">'
               f'<select id="fkind" aria-label="Kind"><option value="">Any kind</option>{opts(kinds)}</select>'
               f'<select id="far" aria-label="Requirement"><option value="">Any requirement</option>{opts(ar_ids)}</select>'
               '<span id="fshown" class="muted"></span></div>')
    groups = {}
    for f in findings:
        groups.setdefault((f["kind"], f["ar"], f["rule"]), []).append(f)
    if not groups:
        out.append("<p>No findings.</p>")
    for (kind, ar, rule), items in groups.items():
        head = items[0]
        targets = sorted({f["target"] for f in items})
        subjects = []
        for f in items:
            label = f["subject"] if f["subject"] == f["target"] else f'{f["target"]}: {f["subject"]}'
            if label not in subjects:
                subjects.append(label)
        text = " ".join([kind, ar, rule, head["title"], *targets, *subjects]).lower()
        # data-state / data-result are the attributes the shared filter reads: here they hold kind and requirement.
        out.append(
            f'<details class="ksi findrow" data-text="{e(text)}" data-state="{e(kind)}" data-result="{e(ar)}">'
            f'<summary><span class="id">{e(ar)}</span> <span class="name">{e(head["title"])}</span>'
            f' <span class="signals"><span class="state">{e(kind)}</span> <span class="muted">{len(items)} on {len(targets)} target(s)</span></span></summary>'
            f'<div class="body"><p class="muted">Rule <code>{e(rule)}</code>. Serves {e(", ".join(head["ksis"]) or "no KSI")}. '
            f'{e(FINDING_KIND_NOTE.get(kind, ""))}</p>'
            + (f'<p><strong>Fix:</strong> {e(head["fix"])}</p>' if head["fix"] else "")
            + "<ul>" + "".join(f"<li>{e(x)}</li>" for x in subjects) + "</ul>"
            f'<p class="muted">Example message: {e(head["message"])}</p></div></details>')

    out.append("<h2>Gaps in our own work</h2>")
    out.append('<table><thead><tr><th>KSI</th><th>State</th><th>Methods</th><th>Controls decided</th><th>Explanations</th><th>Next</th></tr></thead><tbody>')
    for g in [g for g in rep["gaps"] if g["state"] != "Not started"]:
        out.append(f'<tr><td><span class="id">{e(g["ksi"])}</span> {e(g["name"])}</td><td>{state_badge(g["state"])}</td>'
                   f'<td>{g["methods_implemented"]}/{g["methods_required"]}</td><td>{g["controls_decided"]}/{g["controls_total"]}</td>'
                   f'<td>{e(g["explanations"])}</td><td>{e("; ".join(g["next"]))}'
                   + (f'<br><span class="muted">open controls: {e(", ".join(g["open_controls"]))}</span>' if g["open_controls"] and g["state"] != "Not started" else "")
                   + (f'<br><span class="muted">not reached: {e(", ".join(t["target"] for t in g["targets_not_reached"]))}</span>' if g["targets_not_reached"] else "")
                   + "</td></tr>")
    out.append("</tbody></table>")
    idle = [g["ksi"] for g in rep["gaps"] if g["state"] == "Not started"]
    if idle:
        out.append(f'<p class="muted">Not started ({len(idle)}): {e(", ".join(idle))}</p>')

    out.append("<h2>Limits of the checks</h2><p class=\"muted\">What each check cannot see. A pass means no problem was found within these limits, not that none exists.</p>")
    for ar, spec in rep["limits"].items():
        if not spec["limits"]:
            continue
        out.append(f'<h4>{e(ar)}</h4>' + (f'<p class="muted">{e(spec["ar_text"])}</p>' if spec["ar_text"] else "")
                   + "<ul>" + "".join(f'<li>{e(x["text"])}</li>' for x in spec["limits"]) + "</ul>")
    return "".join(out)


DAY_GLYPH = {"pass": "✓", "fail": "✗", "error": "!", "not_collected": "–", "no-record": "·"}
DAY_WORD = {"pass": "passed", "fail": "failed", "error": "could not be judged", "not_collected": "not collected (a backfill cannot reconstruct past state)", "no-record": "no record"}


def day_strip(cells: list) -> str:
    """One cell per day. The glyph and the title carry the result, so colour is never the only signal."""
    return '<span class="dstrip" role="img" aria-label="last 30 days">' + "".join(
        f'<span class="dc dc-{e(c["result"])}" title="{e(c["date"])}: {e(DAY_WORD.get(c["result"], c["result"]))}">'
        f'{e(DAY_GLYPH.get(c["result"], "?"))}</span>' for c in cells) + "</span>"


def render_history_page(summary: dict) -> str:
    """The daily series and its summaries per KSI, with the alarms (WARN: a daily run was missed; ALERT: the cadence is broken). Every value is escaped."""
    h, meta = summary["history"], summary["meta"]
    out = [f'<p class="muted">Counting through {e(meta["last_counted_day"])} · generated {e(meta["generated_at"])} · '
           f'{h["record_count"]} record(s) over {h["run_days"]} day(s).</p>',
           f'<p><strong>{e(h["statement"])}</strong></p>']
    for a in summary["alarms"]:
        level = a.get("level") if a.get("level") in ("WARN", "ALERT") else "ALERT"
        out.append(f'<div class="alarm{" alarm-warn" if level == "WARN" else ""}" role="{"status" if level == "WARN" else "alert"}">'
                   f'{level} {e(a["code"])}: {e(a["message"])}</div>')
    if not summary["alarms"]:
        out.append('<p class="muted">No alarms: the records are within the minimum cadence.</p>')
    out.append('<p class="muted">Each record is about the UTC day it covers. Result of a day: the latest record of that day, and for a '
               'KSI the worst of its methods. ✓ pass: complete, every target reached, no violation. ✗ fail: at least one violation. '
               '! error: could not be judged. – not collected: a backfill cannot reconstruct past state, so that method has no result '
               'for the day. · no record: nothing was recorded that day. None of ! – · is ever a pass.</p>')
    out.append("<table><thead><tr><th>KSI</th><th>Last 30 days</th><th>30 days: pass / fail / error / not collected / none</th>"
               "<th>Year, available: recorded / days</th><th>Longest gap</th></tr></thead><tbody>")
    for ksi, ent in summary["ksis"].items():
        s30, yr = ent["summary30"], ent["summaryYear"]
        out.append(f'<tr><td><span class="id">{e(ksi)}</span></td><td>{day_strip(ent["strip"])}</td>'
                   f'<td>{s30["pass_days"]} / {s30["fail_days"]} / {s30["error_days"]} / {s30["not_collected_days"]} / {s30["days_without_record"]}</td>'
                   f'<td>{yr["recorded_days"]} / {yr["days"]} <span class="muted">(requirement: up to {yr["requirement_days"]})</span></td>'
                   f'<td>{yr["longest_gap_days"]} d</td></tr>')
        for m in ent["methods"]:
            ms = m["summary30"]
            out.append(f'<tr><td class="muted">&nbsp;&nbsp;{e(m["ar"])} <span class="muted">({e(m["method_kind"])}, {e(m["basis"])})</span></td>'
                       f'<td>{day_strip(m["strip"])}</td>'
                       f'<td class="muted">{ms["pass_days"]} / {ms["fail_days"]} / {ms["error_days"]} / {ms["not_collected_days"]} / {ms["days_without_record"]}</td><td></td><td></td></tr>')
    out.append("</tbody></table>")
    if not summary["ksis"]:
        out.append("<p>No records yet. Run <code>make history-init</code> and then <code>make daily</code>.</p>")
    return "".join(out)


JS = """
(function(){
  document.documentElement.className+=' js';
  var pages=[].slice.call(document.querySelectorAll('.page')),tabs=[].slice.call(document.querySelectorAll('nav.tabs a'));
  function show(){
    var id='';try{id=decodeURIComponent(location.hash.slice(1))}catch(x){}
    var t=id?document.getElementById(id):null,page=t?(t.classList.contains('page')?t:t.closest('.page')):null;
    if(!page)page=pages[0];
    pages.forEach(function(p){p.classList.toggle('hidden',p!==page)});
    tabs.forEach(function(a){var on=a.dataset.tab===page.id||(a.dataset.tab==='page-ars'&&page.classList.contains('arpage'));a.classList.toggle('active',on)});
    if(t&&t.tagName==='DETAILS')t.open=true;
    if(t&&t!==page)t.scrollIntoView();else window.scrollTo(0,0);
  }
  function filters(rows,q,st,rs,n,label){
    if(!q)return;
    function apply(){
      var t=q.value.toLowerCase(),shown=0;
      rows.forEach(function(c){
        var ok=(!t||c.dataset.text.indexOf(t)>-1)&&(!st.value||c.dataset.state===st.value)&&(!rs.value||c.dataset.result===rs.value);
        c.classList.toggle('hidden',!ok);if(ok)shown++;
      });
      n.textContent=shown+' of '+rows.length+' '+label+' shown';
    }
    [q,st,rs].forEach(function(el){el.addEventListener('input',apply)});apply();
  }
  var g=function(i){return document.getElementById(i)};
  filters([].slice.call(document.querySelectorAll('details.ksi')),g('q'),g('state'),g('result'),g('shown'),'KSIs');
  filters([].slice.call(document.querySelectorAll('tr.arrow')),g('arq'),g('arstate'),g('arresult'),g('arshown'),'ARs');
  filters([].slice.call(document.querySelectorAll('details.findrow')),g('fq'),g('fkind'),g('far'),g('fshown'),'findings');
  window.addEventListener('hashchange',show);show();
})();
"""


def render(sdr: dict, coverage: dict, trace: dict = None, findings: dict = None, history: dict = None) -> str:
    entries = {k["ksiId"]: k for k in sdr.get("keySecurityIndicators", [])}
    results = {kid: results_by_ar(ent) for kid, ent in entries.items()}
    s = coverage["summary"]
    options = lambda items: "".join(f'<option value="{e(i)}">{e(i)}</option>' for i in items)
    ars_for_ksi = {}
    for req in (trace or {}).get("requirements", {}).values():
        if req["kind"] == "ksi":
            ars_for_ksi[req["id"]] = req["ars"]
    cards = "".join(render_ksi(row, entries.get(row["id"]), ars_for_ksi.get(row["id"])) for row in coverage["ksis"])
    meta = sdr.get("metadata", {})
    nav = tab_pages = ""
    if trace or findings or history:
        links = []
        if trace:
            links.append('<a href="#page-ars" data-tab="page-ars">Assessment requirements</a>')
            tab_pages += f'<section class="page" id="page-ars">{render_ar_index(trace)}</section>'
        if findings:
            links.append('<a href="#page-findings" data-tab="page-findings">Findings</a>')
            tab_pages += f'<section class="page" id="page-findings">{render_findings_page(findings)}</section>'
        if history:
            links.append('<a href="#page-history" data-tab="page-history">History</a>')
            tab_pages += f'<section class="page" id="page-history">{render_history_page(history)}</section>'
        links.append('<a href="#page-ksis" data-tab="page-ksis">KSIs</a>')
        nav = '<nav class="tabs">' + "".join(links) + "</nav>"
    ar_pages = "".join(render_ar_page(trace, ar) for ar in trace["ars"].values()) if trace else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ROSA Seaplane SDR (local run)</title><style>{CSS}</style></head>
<body>
<div class="banner">Local run. Not certification evidence.</div>
<main>
<h1>ROSA Seaplane Security Decision Record</h1>
<p class="muted">{e(meta.get('updateSource', ''))} · generated {e(meta.get('lastUpdated', ''))} · SDR version {e(meta.get('version', ''))}</p>
{nav}
{tab_pages}
<section class="page" id="page-ksis">
<div class="kpis">
 <div>{s['covered']}/{s['ksis']}<span>KSIs covered</span></div>
 <div>{s['sdr_ready']}/{s['ksis']}<span>SDR-ready</span></div>
 <div>{s['methods_implemented']}/{s['methods_required']}<span>automated methods</span></div>
 <div>{s['deferred_process']}<span>process KSIs deferred</span></div>
</div>
<p class="muted">State is how far the checks are implemented. Result is what the latest evaluation found. Neither implies the other.</p>
<h2>Overview by family</h2>
{render_overview(coverage, results)}
<h2>KSIs</h2>
<div class="filters">
 <input id="q" type="search" placeholder="Filter by ID, name or family" aria-label="Filter">
 <select id="state" aria-label="State"><option value="">Any state</option>{options(STATE_ORDER)}</select>
 <select id="result" aria-label="Result"><option value="">Any result</option>{options(RESULT_ORDER + ['no results'])}</select>
 <span id="shown" class="muted"></span>
</div>
{cards}
</section>
{ar_pages}
</main>
<script>{JS}</script>
</body></html>
"""


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sdr", default=str(ROOT / "output/sdr/sdr.json"))
    ap.add_argument("--coverage", default=str(ROOT / "output/coverage.json"))
    ap.add_argument("--trace", default=str(ROOT / "output/trace.json"))
    ap.add_argument("--findings", default=str(ROOT / "output/findings.json"))
    ap.add_argument("--history", default=str(ROOT / "output/history/summary.json"))
    ap.add_argument("--out", default=str(ROOT / "output/sdr/index.html"))
    args = ap.parse_args()
    for p in (args.sdr, args.coverage):
        if not Path(p).is_file():
            sys.exit(f"ERROR: {p} not found; run `make sdr` first.")
    trace = None
    if Path(args.trace).is_file():
        trace = json.loads(Path(args.trace).read_text())
    else:
        print(f"NOTE: {args.trace} not found; rendering without the assessment requirements tab (run `make trace`).")
    findings = None
    if Path(args.findings).is_file():
        findings = json.loads(Path(args.findings).read_text())
    else:
        print(f"NOTE: {args.findings} not found; rendering without the Findings tab (run `make findings`).")
    history = None
    if Path(args.history).is_file():
        history = json.loads(Path(args.history).read_text())
    else:
        print(f"NOTE: {args.history} not found; rendering without the History tab (run `make history-summary`).")
    page = render(json.loads(Path(args.sdr).read_text()), json.loads(Path(args.coverage).read_text()), trace, findings, history)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(page)
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
