"""Self-contained interactive HTML threat-model report.

A single file (no external assets, no network) a reviewer can open in a browser
and actually work in: filter by STRIDE category and risk level, search, sort the
register, see the embedded DFD, and flip each threat's review status
(accept / edit / reject) locally. The review state is kept in the browser so a
reviewer can triage without any backend - the human-in-the-loop stage, made
usable.
"""

from __future__ import annotations

import html
import json

from ..model.schema import SystemModel
from ..reason.threat import Threat
from .dfd_render import render_svg

_STRIDE_FULL = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation",
                "I": "Information disclosure", "D": "Denial of service",
                "E": "Elevation of privilege"}


def render_html(model: SystemModel, threats: list[Threat]) -> str:
    svg = render_svg(model)
    data = [
        {
            "id": t.id, "component": t.component, "stride": t.stride,
            "strideName": _STRIDE_FULL.get(t.stride, t.stride), "title": t.title,
            "rationale": t.rationale, "mitigation": t.mitigation,
            "controls": t.controls, "cwe": t.cwe, "owasp": t.owasp_top10,
            "boundary": t.boundary, "likelihood": t.likelihood, "impact": t.impact,
            "risk": t.risk, "level": t.risk_level,
        }
        for t in threats
    ]
    counts = {c: sum(1 for t in threats if t.stride == c) for c in _STRIDE_FULL}
    n_crit = sum(1 for t in threats if t.risk_level == "Critical")
    n_high = sum(1 for t in threats if t.risk_level == "High")
    payload = json.dumps(data)
    title = html.escape(model.name)

    return _TEMPLATE.format(
        title=title,
        svg=svg,
        payload=payload,
        n_threats=len(threats),
        n_boundaries=len(model.boundaries),
        n_components=len([e for e in model.elements]),
        n_crit=n_crit,
        n_high=n_high,
        counts=json.dumps(counts),
    )


_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Threat Model - {title}</title>
<style>
  :root {{ --bg:#f6f8fa; --card:#fff; --ink:#1f2328; --muted:#656d76; --line:#d0d7de;
           --crit:#cf222e; --high:#e16f24; --med:#bf8700; --low:#1a7f37; --accent:#0969da; }}
  @media (prefers-color-scheme: dark) {{ :root {{ --bg:#0d1117; --card:#161b22;
    --ink:#e6edf3; --muted:#8b949e; --line:#30363d; --accent:#4493f8; }} }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
          background:var(--bg); color:var(--ink); }}
  header {{ padding:20px 24px; border-bottom:1px solid var(--line); background:var(--card); }}
  h1 {{ margin:0 0 4px; font-size:20px; }}
  .sub {{ color:var(--muted); font-size:13px; }}
  .note {{ background:#fff8c5; color:#4b3f00; padding:8px 12px; border-radius:6px;
           font-size:13px; margin-top:10px; }}
  @media (prefers-color-scheme: dark) {{ .note {{ background:#272115; color:#e3d9a6; }} }}
  .wrap {{ max-width:1100px; margin:0 auto; padding:20px 24px; }}
  .tiles {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:16px; }}
  .tile {{ background:var(--card); border:1px solid var(--line); border-radius:8px;
           padding:12px 16px; min-width:110px; }}
  .tile b {{ font-size:22px; display:block; }}
  .tile span {{ color:var(--muted); font-size:12px; }}
  .dfd {{ background:var(--card); border:1px solid var(--line); border-radius:8px;
          padding:12px; overflow:auto; margin-bottom:16px; }}
  .dfd svg {{ max-width:100%; height:auto; }}
  .controls {{ display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-bottom:12px; }}
  input,select {{ padding:6px 8px; border:1px solid var(--line); border-radius:6px;
                  background:var(--card); color:var(--ink); font-size:13px; }}
  table {{ width:100%; border-collapse:collapse; background:var(--card);
           border:1px solid var(--line); border-radius:8px; overflow:hidden; }}
  th,td {{ text-align:left; padding:9px 11px; border-bottom:1px solid var(--line);
           font-size:13px; vertical-align:top; }}
  th {{ cursor:pointer; user-select:none; background:var(--bg); position:sticky; top:0; }}
  tr:last-child td {{ border-bottom:none; }}
  .pill {{ display:inline-block; padding:1px 8px; border-radius:20px; font-size:11px;
           font-weight:600; color:#fff; }}
  .Critical {{ background:var(--crit); }} .High {{ background:var(--high); }}
  .Medium {{ background:var(--med); }} .Low {{ background:var(--low); }}
  .rev {{ font-size:11px; padding:2px 6px; border-radius:5px; border:1px solid var(--line);
          cursor:pointer; background:var(--card); color:var(--ink); }}
  .accepted {{ border-color:var(--low); color:var(--low); }}
  .rejected {{ border-color:var(--crit); color:var(--crit); text-decoration:line-through; }}
  details summary {{ cursor:pointer; color:var(--accent); font-size:12px; }}
  code {{ background:var(--bg); padding:1px 4px; border-radius:4px; font-size:12px; }}
  footer {{ color:var(--muted); font-size:12px; text-align:center; padding:24px; }}
</style></head>
<body>
<header>
  <h1>Threat Model — {title}</h1>
  <div class="sub">Generated by ThreatForge · {n_components} components ·
    {n_boundaries} trust boundaries · {n_threats} threats</div>
  <div class="note"><b>Draft for review, not a security sign-off.</b> Review each
    threat below (accept / edit / reject). Review state is saved in this browser only.</div>
</header>
<div class="wrap">
  <div class="tiles">
    <div class="tile"><b>{n_threats}</b><span>threats</span></div>
    <div class="tile"><b style="color:var(--crit)">{n_crit}</b><span>critical</span></div>
    <div class="tile"><b style="color:var(--high)">{n_high}</b><span>high</span></div>
    <div class="tile"><b>{n_boundaries}</b><span>trust boundaries</span></div>
  </div>
  <div class="dfd">{svg}</div>
  <div class="controls">
    <input id="q" placeholder="Search threats…" oninput="render()">
    <select id="stride" onchange="render()"><option value="">All STRIDE</option>
      <option value="S">Spoofing</option><option value="T">Tampering</option>
      <option value="R">Repudiation</option><option value="I">Information disclosure</option>
      <option value="D">Denial of service</option><option value="E">Elevation of privilege</option>
    </select>
    <select id="level" onchange="render()"><option value="">All risk levels</option>
      <option>Critical</option><option>High</option><option>Medium</option><option>Low</option>
    </select>
    <span id="count" class="sub"></span>
  </div>
  <table><thead><tr>
    <th onclick="sortBy('id')">ID</th><th onclick="sortBy('component')">Component</th>
    <th onclick="sortBy('strideName')">STRIDE</th><th>Threat</th>
    <th onclick="sortBy('risk')">Risk</th><th>Mapping</th><th>Review</th>
  </tr></thead><tbody id="rows"></tbody></table>
</div>
<footer>ThreatForge · © 2026 Krishita Sanjay Choksi · MIT License</footer>
<script>
const DATA = {payload};
const REV = JSON.parse(localStorage.getItem('tf_review_{title}')||'{{}}');
let sortKey='risk', sortDir=-1;
function sortBy(k){{ sortDir = (sortKey===k)? -sortDir : -1; sortKey=k; render(); }}
function cycle(id){{ const o=['proposed','accepted','rejected'];
  REV[id]=o[(o.indexOf(REV[id]||'proposed')+1)%3];
  localStorage.setItem('tf_review_{title}', JSON.stringify(REV)); render(); }}
function esc(s){{ return (s||'').replace(/[&<>]/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;'}}[c])); }}
function render(){{
  const q=document.getElementById('q').value.toLowerCase();
  const fs=document.getElementById('stride').value, fl=document.getElementById('level').value;
  let rows=DATA.filter(t=>(!fs||t.stride===fs)&&(!fl||t.level===fl)&&
    (!q||JSON.stringify(t).toLowerCase().includes(q)));
  rows.sort((a,b)=>{{ let x=a[sortKey],y=b[sortKey];
    return (x<y?-1:x>y?1:0)*sortDir; }});
  document.getElementById('count').textContent=rows.length+' of '+DATA.length+' shown';
  document.getElementById('rows').innerHTML=rows.map(t=>{{
    const rev=REV[t.id]||'proposed';
    const map=[t.cwe,t.owasp,...(t.controls||[])].filter(Boolean).map(esc).join('<br>');
    return `<tr>
      <td><code>${{t.id}}</code></td><td>${{esc(t.component)}}</td>
      <td>${{esc(t.strideName)}}</td>
      <td><b>${{esc(t.title)}}</b>${{t.boundary?'<br><span class=sub>⛓ '+esc(t.boundary)+'</span>':''}}
        <details><summary>why & fix</summary><div class=sub>${{esc(t.rationale)}}<br><br>
        <b>Mitigation:</b> ${{esc(t.mitigation)}}</div></details></td>
      <td><span class="pill ${{t.level}}">${{t.risk}} ${{t.level}}</span><br>
        <span class=sub>L${{t.likelihood}}×I${{t.impact}}</span></td>
      <td class=sub>${{map}}</td>
      <td><button class="rev ${{rev}}" onclick="cycle('${{t.id}}')">${{rev}}</button></td>
    </tr>`;}}).join('');
}}
render();
</script>
</body></html>
"""


def render_html_file(model: SystemModel, threats: list[Threat], path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_html(model, threats))
    return path
