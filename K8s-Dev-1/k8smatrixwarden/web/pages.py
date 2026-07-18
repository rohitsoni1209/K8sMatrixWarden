"""
HTML chrome for the web dashboard.

Reuses the report's own colour system (core.reporting._HTML_CSS) and the threat-matrix grid
(core.threat_matrix_render) so the dashboard, the per-scan report, and the matrix all look
like one product. Every page is a self-contained document (inline CSS/JS, no external hosts)
— the same constraint the HTML report honours.
"""
from __future__ import annotations

from ..core.reporting import _HTML_CSS, _esc
from ..core.results import ScanResult
from ..core.threat_matrix import ThreatMatrix
from ..core.threat_matrix_render import render_html_grid

_DASH_CSS = """
.topbar{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap;border-bottom:1px solid var(--bd);
 padding-bottom:1rem;margin-bottom:1rem}
.topbar h1{font-size:1.3rem;margin:0}.topbar .grow{flex:1}
.topbar a.nav{font-size:.85rem;color:var(--accent);text-decoration:none;padding:.3rem .6rem;
 border:1px solid var(--bd);border-radius:20px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.7rem;margin:1rem 0}
.kpi{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:.9rem 1rem}
.kpi .n{font-size:1.8rem;font-weight:700}.kpi .l{color:var(--muted);font-size:.78rem}
.kpi.crit .n{color:var(--crit)}.kpi.good .n{color:var(--low)}.kpi.warn .n{color:var(--high)}
table.rep{width:100%;border-collapse:collapse;margin-top:.5rem;font-size:.88rem}
table.rep th{text-align:left;color:var(--muted);font-weight:600;font-size:.75rem;
 text-transform:uppercase;letter-spacing:.03em;padding:.5rem .6rem;border-bottom:1px solid var(--bd)}
table.rep td{padding:.55rem .6rem;border-bottom:1px solid var(--bd);vertical-align:middle}
table.rep tr:hover td{background:var(--card)}
table.rep a{color:var(--accent);text-decoration:none}
.pill{display:inline-block;font-size:.72rem;font-weight:700;padding:.12rem .5rem;border-radius:20px;color:#fff}
.pill.Critical{background:var(--crit)}.pill.Poor{background:var(--high)}
.pill.Fair{background:var(--med)}.pill.Good,.pill.Excellent{background:var(--low)}
.pill.q{background:var(--muted)}
.panel{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:1rem 1.1rem;margin:1rem 0}
.panel h2{font-size:1rem;margin:.1rem 0 .7rem}
.scanform{display:flex;flex-wrap:wrap;gap:.6rem;align-items:end}
.scanform label{font-size:.75rem;color:var(--muted);display:block;margin-bottom:.2rem}
.scanform input,.scanform select{background:var(--bg);color:var(--fg);border:1px solid var(--bd);
 border-radius:8px;padding:.4rem .5rem;font-size:.85rem;min-width:150px}
.scanform button{background:var(--accent);color:#fff;border:0;border-radius:8px;padding:.5rem 1.1rem;
 font-size:.9rem;font-weight:600;cursor:pointer}
.scanform button:disabled{opacity:.6;cursor:progress}
.empty{color:var(--muted);padding:1.5rem;text-align:center;border:1px dashed var(--bd);border-radius:12px}
#scanmsg{font-size:.82rem;margin-top:.6rem;color:var(--muted)}
.crumbs{font-size:.82rem;color:var(--muted);margin-bottom:.6rem}
.crumbs a{color:var(--accent);text-decoration:none}
"""


def layout(title: str, body: str, *, extra_css: str = "") -> str:
    return (f"<!doctype html><html><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{_esc(title)}</title><style>{_HTML_CSS}{_DASH_CSS}{extra_css}</style></head>"
            f"<body><div class='wrap'>{body}</div></body></html>")


def _topbar(active: str = "") -> str:
    def nav(href, label, key):
        star = " style='border-color:var(--accent)'" if key == active else ""
        return f"<a class='nav' href='{href}'{star}>{label}</a>"
    return ("<div class='topbar'>"
            "<h1>🛡️ K8sMatrixWarden</h1><span class='grow'></span>"
            + nav("/", "Dashboard", "home")
            + nav("/matrix", "Coverage Matrix", "matrix")
            + nav("/api/reports", "API", "api")
            + "</div>")


def dashboard_page(reports: list, agg: dict) -> str:
    kpis = (
        f"<div class='kpi'><div class='n'>{agg['total_reports']}</div>"
        f"<div class='l'>saved scans</div></div>"
        f"<div class='kpi {_kpi_tone(agg['worst_rating'])}'><div class='n'>"
        f"{_esc(agg['worst_rating'])}</div><div class='l'>worst rating</div></div>"
        f"<div class='kpi warn'><div class='n'>{agg['total_findings']}</div>"
        f"<div class='l'>findings across all scans</div></div>"
        f"<div class='kpi'><div class='n'>{agg['latest_risk']}</div>"
        f"<div class='l'>latest risk /10</div></div>")

    if reports:
        rows = []
        for r in reports:
            pill = r.rating if r.rating in ("Critical", "Poor", "Fair", "Good",
                                            "Excellent") else "q"
            rows.append(
                f"<tr><td><a href='/report/{_esc(r.scan_id)}'><code>{_esc(r.scan_id)}</code></a></td>"
                f"<td>{_esc(r.generated_at)}</td>"
                f"<td><span class='pill {pill}'>{_esc(r.rating)}</span></td>"
                f"<td>{r.risk_score}</td><td>{r.total}</td>"
                f"<td><code>{_esc(r.scope)}</code></td>"
                f"<td><a href='/report/{_esc(r.scan_id)}'>report</a> · "
                f"<a href='/report/{_esc(r.scan_id)}/matrix'>matrix</a> · "
                f"<a href='/api/report/{_esc(r.scan_id)}?format=json'>json</a></td></tr>")
        table = ("<table class='rep'><thead><tr><th>Scan</th><th>Generated</th><th>Rating</th>"
                 "<th>Risk</th><th>Findings</th><th>Scope</th><th></th></tr></thead>"
                 "<tbody>" + "".join(rows) + "</tbody></table>")
    else:
        table = ("<div class='empty'>No saved scans yet. Run one below, or "
                 "<code>k8smatrixwarden scan --save</code> from the CLI.</div>")

    scanform = (
        "<div class='panel'><h2>▶️ Run a scan</h2>"
        "<div class='scanform'>"
        "<div><label>Scope</label><select id='scope'>"
        "<option value='cluster'>whole cluster</option>"
        "<option value='namespace'>namespace</option></select></div>"
        "<div><label>Namespace (if scoped)</label><input id='ns' placeholder='e.g. production'></div>"
        "<div><label>Selector (tactic / alias / module, optional)</label>"
        "<input id='sel' placeholder='e.g. Persistence'></div>"
        "<div><label>Cluster</label><select id='mock'>"
        "<option value='1'>bundled mock</option><option value='0'>live (--live)</option>"
        "</select></div>"
        "<button id='run' onclick='runScan()'>Scan &amp; save</button>"
        "</div><div id='scanmsg'></div></div>")

    return layout("K8sMatrixWarden · Dashboard",
                  _topbar("home")
                  + f"<div class='kpis'>{kpis}</div>"
                  + scanform
                  + "<div class='panel'><h2>🗂️ Saved scans</h2>" + table + "</div>"
                  + _SCAN_JS)


def matrix_page(tm: ThreatMatrix, *, result: ScanResult = None,
                title_note: str = "") -> str:
    # the threat-matrix grid CSS ships inside _HTML_CSS (see core/reporting.py), so
    # layout() already carries it — no extra_css needed here.
    crumb = ("<div class='crumbs'><a href='/'>Dashboard</a> › "
             + (f"<a href='/report/{_esc(tm.scan_id)}'>{_esc(tm.scan_id)}</a> › matrix"
                if result is not None else "coverage matrix") + "</div>")
    head = (f"<h1 style='font-size:1.3rem;margin:.2rem 0'>🗺️ Kubernetes Threat Matrix</h1>"
            f"<div class='sub'>{_esc(title_note or ('scan ' + tm.scan_id))} · "
            f"scope <code>{_esc(tm.scope)}</code> · "
            f"<a href='{tm.summary()['reference']}' target='_blank' rel='noopener'>"
            f"Redguard Kubernetes Threat Matrix ↗</a></div>")
    return layout("K8sMatrixWarden · Threat Matrix",
                  _topbar("matrix") + crumb + head + render_html_grid(tm))


def error_page(status: int, message: str) -> str:
    return layout(f"K8sMatrixWarden · {status}",
                  _topbar() + f"<div class='empty'><h2>{status}</h2><p>{_esc(message)}</p>"
                  "<p><a href='/'>← back to dashboard</a></p></div>")


def _kpi_tone(rating: str) -> str:
    return {"Critical": "crit", "Poor": "warn", "Fair": "warn",
            "Good": "good", "Excellent": "good"}.get(rating, "")


_SCAN_JS = """
<script>
async function runScan(){
 var btn=document.getElementById('run'), msg=document.getElementById('scanmsg');
 btn.disabled=true; msg.textContent='⏳ scanning…';
 var body={scope_level:document.getElementById('scope').value,
   namespace:document.getElementById('ns').value||null,
   selector:document.getElementById('sel').value||null,
   mock:document.getElementById('mock').value==='1'};
 try{
  var r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify(body)});
  var d=await r.json();
  if(!r.ok||d.error){msg.textContent='⚠️ '+(d.error||('HTTP '+r.status));btn.disabled=false;return;}
  msg.innerHTML='✅ '+d.scan_id+' — '+d.rating+' ('+d.risk+'/10), '+d.total_findings+
   ' findings. <a href="/report/'+d.scan_id+'">open report</a>';
  setTimeout(function(){location.reload();},900);
 }catch(e){msg.textContent='⚠️ '+e;btn.disabled=false;}
}
</script>
"""
