"""
HTML for the web dashboard.

The dashboard is a self-contained client-side app: `dashboard_page()` ships an inline-JS
shell that fetches `/api/dashboard` once and renders every view (KPIs, findings table with
search/filter/sort, interactive threat-matrix heatmap, attack path, runtime correlation)
in the browser. Zero external hosts, zero build step, theme-aware — the same constraints the
HTML report honours. The per-scan report page and the standalone matrix page stay
server-rendered (they reuse the ReportingEngine / threat-matrix grid directly).
"""
from __future__ import annotations

from ..core.reporting import _HTML_CSS, _esc
from ..core.results import ScanResult
from ..core.threat_matrix import ThreatMatrix
from ..core.threat_matrix_render import render_html_grid

_DASH_CSS = """
.topbar{display:flex;align-items:center;gap:1rem;flex-wrap:wrap;border-bottom:2px solid var(--bd);
 padding-bottom:1.2rem;margin-bottom:1.5rem}
.topbar h1{font-size:1.4rem;font-weight:800;margin:0;color:var(--fg)}.topbar .grow{flex:1}
.topbar a.nav{font-size:.87rem;color:var(--accent);text-decoration:none;padding:.4rem .8rem;
 border:1.5px solid var(--bd);border-radius:20px;font-weight:600;transition:all .2s}
.topbar a.nav:hover{border-color:var(--accent);background:rgba(0,0,0,0.02)}
.crumbs{font-size:.83rem;color:var(--muted);margin-bottom:.8rem}
.crumbs a{color:var(--accent);text-decoration:none;font-weight:500}
.empty{color:var(--muted);padding:2rem 1.5rem;text-align:center;border:1px dashed var(--bd);border-radius:14px;background:rgba(0,0,0,0.02)}
.panel{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:1.3rem;margin:1.5rem 0;box-shadow:0 1px 2px rgba(0,0,0,0.05)}
.panel h2{font-size:1.05rem;font-weight:700;margin:.2rem 0 .8rem;color:var(--fg)}
.pill{display:inline-block;font-size:.73rem;font-weight:700;padding:.15rem .6rem;border-radius:20px;color:#fff;box-shadow:0 1px 3px rgba(0,0,0,0.1)}
.pill.Critical{background:var(--crit)}.pill.Poor{background:var(--high)}
.pill.Fair{background:var(--med)}.pill.Good,.pill.Excellent{background:var(--low)}
"""

# The dashboard app's own styling — professional, dense, interactive.
_APP_CSS = """
:root{--crit:#e5484d;--high:#fb8500;--med:#ffb703;--low:#2ecc71;--info:#6c757d;
 --ease-spring:cubic-bezier(0.34,1.56,0.64,1);--ease-out:cubic-bezier(0.16,1,0.3,1)}
.tabs{display:flex;gap:.5rem;border-bottom:2px solid var(--bd);margin:2rem 0 1.5rem;flex-wrap:wrap}
.tab{padding:.7rem 1.2rem;font-size:.9rem;font-weight:600;color:var(--muted);cursor:pointer;
 border:0;background:none;border-bottom:3px solid transparent;margin-bottom:-2px;transition:all .25s var(--ease-out)}
.tab:hover{color:var(--fg);border-bottom-color:var(--bd)}.tab.on{color:var(--accent);border-bottom-color:var(--accent);background:rgba(0,0,0,0.02)}
.view{display:none}.view.on{display:block}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin:1.5rem 0}
.kpi{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:1.2rem;box-shadow:0 1px 3px rgba(0,0,0,0.05);transition:transform .35s var(--ease-spring),box-shadow .3s var(--ease-out)}
.kpi:hover{transform:translateY(-3px);box-shadow:0 6px 12px rgba(0,0,0,0.12)}
.kpi .n{font-size:2.2rem;font-weight:800;line-height:1.1}.kpi .l{color:var(--muted);font-size:.8rem;margin-top:.5rem;font-weight:500}
.kpi .s{font-size:.75rem;margin-top:.4rem;color:var(--muted)}
.kpi.crit .n{color:var(--crit)}.kpi.warn .n{color:var(--high)}.kpi.good .n{color:var(--low)}
.up{color:var(--crit);font-weight:700}.down{color:var(--low);font-weight:700}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin:1.5rem 0}@media(max-width:820px){.grid2{grid-template-columns:1fr}}
.fm{font-size:.8rem;color:var(--muted)}.fm code{background:var(--card);padding:.1rem .4rem;border-radius:4px;font-family:ui-monospace}
/* controls */
.ctl{display:flex;gap:.7rem;flex-wrap:wrap;align-items:center;margin:1rem 0}
.ctl input,.ctl select{background:var(--bg);color:var(--fg);border:1px solid var(--bd);
 border-radius:8px;padding:.5rem .7rem;font-size:.87rem;transition:border-color .2s var(--ease-out),box-shadow .2s var(--ease-out)}
.ctl input:focus,.ctl select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(200,220,255,0.4)}
.ctl input[type=search]{flex:1;min-width:200px}
.chip{font-size:.75rem;padding:.35rem .8rem;border-radius:20px;border:1px solid var(--bd);
 background:var(--bg);color:var(--muted);cursor:pointer;transition:all .25s var(--ease-out);font-weight:500}
.chip:hover{border-color:var(--accent);color:var(--accent);background:rgba(0,0,0,0.02)}
.chip.on{color:#fff;border-color:transparent;font-weight:600}
.chip.on[data-sev=CRITICAL]{background:var(--crit)}.chip.on[data-sev=HIGH]{background:var(--high)}
.chip.on[data-sev=MEDIUM]{background:var(--med)}.chip.on[data-sev=LOW]{background:var(--low)}
/* findings table */
table.ft{width:100%;border-collapse:collapse;font-size:.85rem}
table.ft th{text-align:left;color:var(--muted);font-weight:700;font-size:.73rem;text-transform:uppercase;
 letter-spacing:.05em;padding:.7rem .6rem;border-bottom:2px solid var(--bd);cursor:pointer;white-space:nowrap}
table.ft td{padding:.65rem .6rem;border-bottom:1px solid var(--bd);vertical-align:top}
table.ft tr:hover td{background:rgba(0,0,0,0.02)}
.sev{font-size:.7rem;font-weight:800;padding:.12rem .5rem;border-radius:6px;color:#fff}
.sev.CRITICAL{background:var(--crit)}.sev.HIGH{background:var(--high)}
.sev.MEDIUM{background:var(--med)}.sev.LOW{background:var(--low)}.sev.INFO{background:var(--info)}
/* matrix */
.mx{display:grid;grid-template-columns:repeat(9,1fr);gap:6px;margin:1rem 0;overflow-x:auto}
.mxcol{display:flex;flex-direction:column;gap:5px;min-width:80px}
.mxh{font-size:.65rem;font-weight:700;color:var(--fg);text-align:center;height:2.8em;line-height:1.2;
 display:flex;align-items:center;justify-content:center}
.cell{border-radius:6px;padding:.4rem .35rem;font-size:.62rem;min-height:36px;border:1px solid rgba(0,0,0,0.1);
 cursor:default;color:#fff;display:flex;flex-direction:column;justify-content:center;gap:2px;transition:transform .25s var(--ease-spring),box-shadow .2s var(--ease-out)}
.cell.gap{background:var(--card);color:var(--muted);border-color:var(--bd)}.cell.covered{background:var(--low)}
.cell.hit{cursor:pointer;box-shadow:0 0 0 0 rgba(0,0,0,0.1)}.cell.hit:hover{transform:scale(1.08);box-shadow:0 2px 6px rgba(0,0,0,0.2)}
.cell.hit[data-sev=CRITICAL]{background:var(--crit)}.cell.hit[data-sev=HIGH]{background:var(--high)}
.cell.hit[data-sev=MEDIUM]{background:var(--med)}.cell.hit[data-sev=LOW]{background:var(--low)}
.cell .c{font-weight:900;font-size:.75rem}
.leg{display:flex;gap:1.2rem;font-size:.75rem;color:var(--muted);flex-wrap:wrap;margin-top:.6rem}
.leg i{display:inline-block;width:14px;height:14px;border-radius:3px;vertical-align:-2px;margin-right:.4rem}
/* attack path */
.flow{display:flex;align-items:stretch;gap:.8rem;flex-wrap:wrap;margin:1rem 0}
.step{background:var(--card);border:1px solid var(--bd);border-left:4px solid var(--crit);border-radius:10px;
 padding:.8rem;min-width:140px;flex:1;box-shadow:0 1px 2px rgba(0,0,0,0.05);transition:transform .3s var(--ease-spring),box-shadow .25s var(--ease-out)}
.step:hover{transform:translateY(-2px);box-shadow:0 4px 8px rgba(0,0,0,0.12)}
.step .t{font-weight:700;font-size:.9rem;color:var(--fg)}.step .k{font-size:.75rem;color:var(--muted);margin-top:.3rem}
.arrow{display:flex;align-items:center;color:var(--muted);font-size:1.3rem;padding:0 .3rem}
.reach{font-weight:700}.reach.y{color:var(--crit)}.reach.n{color:var(--low)}
/* risk bars */
.bar{display:flex;align-items:center;gap:.8rem;margin-bottom:.8rem}
.barl{width:160px;font-size:.8rem;flex:0 0 auto;font-weight:500}
.bart{flex:1;height:26px;background:var(--card);border-radius:6px;overflow:hidden;border:1px solid var(--bd)}
.barf{height:100%;display:flex;align-items:center;justify-content:flex-end;padding-right:.6rem;color:#fff;
 font-size:.72rem;font-weight:700;white-space:nowrap;min-width:fit-content}
.trendbars{display:flex;align-items:flex-end;gap:5px;height:100px;margin-top:1rem}
.tb{flex:1;border-radius:4px 4px 0 0;min-height:8px;transition:opacity .2s}
/* runtime */
.rr{display:flex;align-items:center;gap:.6rem;font-size:.87rem;padding:.4rem 0;border-bottom:1px solid var(--bd)}
.rrdot{width:10px;height:10px;border-radius:50%;flex:0 0 auto;box-shadow:0 1px 3px rgba(0,0,0,0.2)}
.rrdot.ok{background:var(--low)}.rrdot.gap{background:var(--high)}
.rrn{margin-left:auto;font-size:.75rem;color:var(--muted)}.rrn.warn{color:var(--high);font-weight:600}
textarea{width:100%;min-height:140px;background:var(--bg);color:var(--fg);border:1px solid var(--bd);
 border-radius:10px;padding:.8rem;font-family:ui-monospace,monospace;font-size:.82rem;transition:border-color .2s var(--ease-out),box-shadow .2s var(--ease-out)}
textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(200,220,255,0.4)}
button.btn{background:var(--accent);color:#fff;border:0;border-radius:8px;padding:.6rem 1.2rem;
 font-size:.88rem;font-weight:600;cursor:pointer;transition:transform .3s var(--ease-spring),box-shadow .25s var(--ease-out);box-shadow:0 2px 4px rgba(0,0,0,0.1);active:scale(0.95)}
button.btn:hover{transform:translateY(-2px);box-shadow:0 6px 12px rgba(0,0,0,0.18)}
button.btn:active{transform:translateY(0);box-shadow:0 1px 2px rgba(0,0,0,0.1)}
button.btn.ghost{background:var(--card);color:var(--fg);border:1px solid var(--bd);box-shadow:none;transition:all .25s var(--ease-out)}
button.btn.ghost:hover{background:var(--bg);border-color:var(--accent);box-shadow:0 2px 4px rgba(0,0,0,0.05)}
.corr{border-left:4px solid var(--muted);background:var(--card);border-radius:0 10px 10px 0;padding:.8rem;margin-bottom:.7rem;box-shadow:0 1px 2px rgba(0,0,0,0.05)}
.corr.confirmed{border-left-color:var(--crit)}.corr.corroborated{border-left-color:var(--high)}
.corr.runtime-only{border-left-color:var(--info)}
.badge{font-size:.68rem;font-weight:800;padding:.15rem .55rem;border-radius:6px;color:#fff;text-transform:uppercase;letter-spacing:.02em}
.badge.confirmed{background:var(--crit)}.badge.corroborated{background:var(--high)}.badge.runtime-only{background:var(--info)}
/* scan form */
.scanform{display:flex;flex-wrap:wrap;gap:.8rem;align-items:end}
.scanform label{font-size:.78rem;color:var(--muted);display:block;margin-bottom:.35rem;font-weight:600}
.scanform input,.scanform select{background:var(--bg);color:var(--fg);border:1px solid var(--bd);
 border-radius:8px;padding:.5rem .7rem;font-size:.87rem;min-width:140px;transition:border-color .2s}
.scanform input:focus,.scanform select:focus{outline:none;border-color:var(--accent)}
#scanmsg{font-size:.84rem;margin-top:.8rem;color:var(--muted);font-weight:500}
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


def dashboard_page(has_scan: bool = False) -> str:
    """Client-side dashboard shell. All data comes from GET /api/dashboard."""
    shell = (_topbar("home")
             + "<div id='app'><div class='empty'>Loading…</div></div>")
    return layout("K8sMatrixWarden · Dashboard", shell + _APP_JS, extra_css=_APP_CSS)


def matrix_page(tm: ThreatMatrix, *, result: ScanResult = None,
                title_note: str = "") -> str:
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


# The whole dashboard app — vanilla JS, no framework, no external hosts.
_APP_JS = r"""
<script>
const $ = s => document.querySelector(s);
const esc = s => String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const SEV = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
let D=null, fSev=new Set(), fText='', fTactic='', sortKey='score', sortDir=-1;

async function boot(){
  const r = await fetch('/api/dashboard'); D = await r.json();
  if(!D.has_scan){ $('#app').innerHTML = emptyView(); wireScan(); return; }
  render();
}
function emptyView(){
  return `<div class='panel'><h2>▶️ Run your first scan</h2>
    <div class='fm'>No saved scans yet — the dashboard lights up once you save one.</div>
    ${scanForm()}</div>`;
}
function render(){
  $('#app').innerHTML = `
    ${hero()}
    <div class='tabs'>
      ${tab('overview','Overview')}${tab('findings','Findings ('+D.scan.total+')')}
      ${tab('matrix','Threat Matrix')}${tab('attack','Attack Path')}${tab('attackmap','Attack Map')}
      ${tab('runtime','Runtime')}${tab('scan','Scan')}
    </div>
    <div id='v-overview' class='view on'>${overview()}</div>
    <div id='v-findings' class='view'>${findingsView()}</div>
    <div id='v-matrix' class='view'>${matrixView()}</div>
    <div id='v-attack' class='view'>${attackView()}</div>
    <div id='v-attackmap' class='view'>${attackMapView()}</div>
    <div id='v-runtime' class='view'>${runtimeView()}</div>
    <div id='v-scan' class='view'>${scanView()}</div>`;
  renderFindings(); wireScan();
}
const tab=(id,l)=>`<button class='tab${id==='overview'?' on':''}' onclick="showTab('${id}')" id='t-${id}'>${l}</button>`;
function showTab(id){
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('on'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('on'));
  $('#v-'+id).classList.add('on'); $('#t-'+id).classList.add('on');
}
function hero(){
  const s=D.scan, t=D.trend||[], d=t.length>1?(t[t.length-1][1]-t[t.length-2][1]):null;
  const delta = d===null?'':(d<0?`<div class='s down'>↓ ${Math.abs(d).toFixed(1)} vs previous</div>`
    :d>0?`<div class='s up'>↑ ${d.toFixed(1)} vs previous</div>`:`<div class='s fm'>→ no change</div>`);
  const hp=(s.counts.CRITICAL||0)+(s.counts.HIGH||0);
  const cov=D.threat_matrix.summary.coverage_pct;
  const rk=s.cluster_risk>=7?'crit':s.cluster_risk>=4?'warn':'good';
  return `<div class='fm'>scan <code>${esc(s.scan_id)}</code> · ${esc(s.scope)} · mode <code>${esc(s.mode)}</code> · ${esc(s.generated_at)}</div>
  <div class='kpis'>
    <div class='kpi ${rk}'><div class='n'>${s.cluster_risk.toFixed(1)}</div><div class='l'>Risk score /10</div>${delta}</div>
    <div class='kpi ${rk}'><div class='n'>${esc(s.rating)}</div><div class='l'>Overall rating</div><div class='s fm'>${s.total} findings</div></div>
    <div class='kpi ${hp?'crit':'good'}'><div class='n'>${hp}</div><div class='l'>High+ findings</div><div class='s fm'>${hp?'requires action':'clear'}</div></div>
    <div class='kpi good'><div class='n'>${cov}%</div><div class='l'>Detection coverage</div><div class='s fm'>${D.threat_matrix.summary.techniques_covered} techniques</div></div>
  </div>`;
}
function overview(){
  return `<div class='grid2'>
    <div class='panel'><h2>🔴 Fix first — blocks production</h2>${priorityList()}</div>
    <div class='panel'><h2>📊 Risk by domain</h2>${domainBars()}</div>
    <div class='panel'><h2>🗺️ Attack surface</h2>${surfaceStrip()}</div>
    <div class='panel'><h2>📈 Risk trend</h2>${trendBars()}</div>
  </div>
  <div class='panel'><h2>📡 Runtime readiness</h2>${runtimeReadiness()}</div>
  <div class='panel'><h2>⏱️ Finding age — MTTD / MTTR</h2>${timelinePanel()}</div>`;
}
function timelinePanel(){
  const t=D.timeline;
  if(!t||(!t.open&&!t.resolved)) return "<div class='fm'>Save scans over time to track how long findings stay open (MTTD) and how fast they're fixed (MTTR).</div>";
  const oc=t.oldest_critical;
  const rows=(t.entries||[]).slice(0,6).map(e=>`<div class='rr'><span class='sev ${e.severity}'>${e.severity}</span>
    ${esc(e.title)} <span class='rrn'>${e.age_days}d open · <code>${esc(e.resource)}</code></span></div>`).join('');
  return `<div class='kpis' style='margin:.3rem 0'>
    <div class='kpi ${t.open?'warn':'good'}'><div class='n'>${t.open}</div><div class='l'>Open findings</div></div>
    <div class='kpi good'><div class='n'>${t.resolved}</div><div class='l'>Resolved (MTTR tracked)</div></div>
    <div class='kpi ${t.oldest_open_days>=7?'crit':''}'><div class='n'>${t.oldest_open_days}d</div><div class='l'>Oldest open</div></div>
    <div class='kpi'><div class='n'>${t.median_open_days}d</div><div class='l'>Median age</div></div>
  </div>
  ${oc?`<div class='fm'>Oldest critical: <b>${esc(oc.title)}</b> — ${oc.age_days}d on <code>${esc(oc.resource)}</code></div>`:''}
  ${rows}`;
}
function priorityList(){
  const top=[...D.findings].sort((a,b)=>SEV.indexOf(a.severity)-SEV.indexOf(b.severity)||b.score-a.score)
    .filter(f=>f.severity==='CRITICAL'||f.severity==='HIGH').slice(0,6);
  if(!top.length) return "<div class='fm'>No high-severity findings.</div>";
  return top.map(f=>`<div style='border-left:3px solid var(--${f.severity.toLowerCase()});padding:.5rem .7rem;background:var(--bg);border-radius:0 8px 8px 0;margin-bottom:.5rem'>
    <div style='font-weight:600;font-size:.88rem'><span class='sev ${f.severity}'>${f.severity}</span> ${esc(f.title)}</div>
    <div class='fm' style='margin-top:.25rem'><code>${esc(f.rule_id)}</code> · ${esc(f.owning_shard)} · <code>${esc(res(f))}</code></div></div>`).join('')
    + `<div class='fm' style='margin-top:.5rem'><a href='javascript:showTab("findings")'>See all ${D.scan.total} findings →</a></div>`;
}
function domainBars(){
  const by={}; D.findings.forEach(f=>{(by[f.owning_shard||'other']=by[f.owning_shard||'other']||[]).push(f)});
  const rows=Object.entries(by).map(([k,v])=>({k,n:v.length,w:Math.max(...v.map(f=>SEV.length-SEV.indexOf(f.severity)))}))
    .sort((a,b)=>b.w-a.w||b.n-a.n);
  const mx=Math.max(...rows.map(r=>r.n),1);
  return rows.map(r=>{const worst=SEV[SEV.length-r.w];
    return `<div class='bar'><div class='barl'>${esc(r.k)}</div><div class='bart'>
    <div class='barf' style='width:${Math.max(r.n/mx*100,14)}%;background:var(--${worst.toLowerCase()})'>${r.n} · ${worst}</div></div></div>`}).join('');
}
function surfaceStrip(){
  const cols=D.threat_matrix.columns, sm=D.threat_matrix.summary;
  const cells=cols.map(c=>{const st=c.techniques_hit?'hit':c.techniques_covered?'covered':'gap';
    const ab=c.tactic.split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase();
    const sev=(c.max_severity||'CRITICAL');
    return `<div class='cell ${st}' ${st==='hit'?`data-sev='${sev}'`:''} title="${esc(c.tactic)}${c.finding_count?': '+c.finding_count+' findings':''}" style='min-height:30px;text-align:center'>${ab}${c.finding_count?`<span class='c'>${c.finding_count}</span>`:''}</div>`}).join('');
  return `<div class='fm'>${sm.tactics_hit} of 9 tactics exposed · ${sm.techniques_hit} techniques hit</div>
    <div style='display:grid;grid-template-columns:repeat(9,1fr);gap:5px;margin:.6rem 0'>${cells}</div>
    <div class='leg'><span><i style='background:var(--crit)'></i>exposed</span><span><i style='background:var(--low)'></i>detectable</span><span><i style='background:var(--card);border:1px solid var(--bd)'></i>no rule</span></div>
    <div class='fm' style='margin-top:.5rem'><a href='javascript:showTab("attack")'>View kill-chain →</a></div>`;
}
function trendBars(){
  const t=(D.trend||[]).filter(p=>typeof p[1]==='number');
  if(t.length<2) return "<div class='fm'>Run more scans over time to see the trend.</div>";
  const vals=t.map(p=>p[1]),lo=Math.min(...vals),hi=Math.max(...vals),sp=(hi-lo)||1;
  const bars=t.slice(-12).map(([ts,v])=>{const h=10+Math.round(70*(v-lo)/sp);
    const c=v>=7?'crit':v>=4?'high':'low';return `<div class='tb' title='${esc(ts)}: ${v}' style='height:${h}%;background:var(--${c})'></div>`}).join('');
  const f=vals[0],l=vals[vals.length-1],ar=l<f?"<span class='down'>↓ improving</span>":l>f?"<span class='up'>↑ worsening</span>":'→ flat';
  return `<div class='fm'>Latest ${l} vs first ${f} · ${ar}</div><div class='trendbars'>${bars}</div>`;
}
function runtimeReadiness(){
  const rt=D.runtime, ex=rt.exposed_tactics||[];
  let covered=0;
  const rows=ex.map(t=>{const r=rt.by_tactic[t]||[];if(r.length){covered++;
    return `<div class='rr'><span class='rrdot ok'></span>${esc(t)}<span class='rrn'>${r.length} tripwire${r.length!==1?'s':''}</span></div>`}
    return `<div class='rr'><span class='rrdot gap'></span>${esc(t)}<span class='rrn warn'>⚠ blind at runtime</span></div>`}).join('');
  return `<div class='fm'>${covered}/${ex.length} exposed tactics have a runtime tripwire · ${rt.armed} detections armed</div>${rows}
    <div class='fm' style='margin-top:.5rem'>Feed live events in the <a href='javascript:showTab("runtime")'>Runtime</a> tab.</div>`;
}
/* ---- findings ---- */
function findingsView(){
  const chips=SEV.slice(0,4).map(s=>`<span class='chip' data-sev='${s}' onclick='toggleSev("${s}")'>${s}</span>`).join('');
  const tacs=[...new Set(D.findings.flatMap(f=>f.mitre.map(m=>m.tactic)))].sort();
  return `<div class='panel'>
    <div class='ctl'>
      <input type='search' id='fsearch' placeholder='Search title, rule, resource…' oninput='fText=this.value.toLowerCase();renderFindings()'>
      ${chips}
      <select id='ftac' onchange='fTactic=this.value;renderFindings()'><option value=''>All tactics</option>${tacs.map(t=>`<option>${esc(t)}</option>`).join('')}</select>
    </div>
    <div id='fcount' class='fm'></div>
    <table class='ft'><thead><tr>
      ${th('severity','Sev')}${th('title','Finding')}${th('owning_shard','Domain')}
      <th>Resource</th><th>Tactic</th>${th('score','Score')}
    </tr></thead><tbody id='fbody'></tbody></table></div>`;
}
const th=(k,l)=>`<th onclick='setSort("${k}")'>${l} ${sortKey===k?(sortDir<0?'▾':'▴'):''}</th>`;
function setSort(k){ if(sortKey===k)sortDir*=-1; else{sortKey=k;sortDir=-1} renderFindings(); }
function toggleSev(s){ fSev.has(s)?fSev.delete(s):fSev.add(s);
  document.querySelectorAll('.chip[data-sev]').forEach(c=>c.classList.toggle('on',fSev.has(c.dataset.sev))); renderFindings(); }
function renderFindings(){
  if(!$('#fbody')) return;
  let rows=D.findings.filter(f=>{
    if(fSev.size&&!fSev.has(f.severity))return false;
    if(fTactic&&!f.mitre.some(m=>m.tactic===fTactic))return false;
    if(fText){const h=(f.title+' '+f.rule_id+' '+res(f)+' '+f.owning_shard).toLowerCase();if(!h.includes(fText))return false;}
    return true;});
  rows.sort((a,b)=>{let x=a[sortKey],y=b[sortKey];
    if(sortKey==='severity'){x=SEV.indexOf(a.severity);y=SEV.indexOf(b.severity);return (x-y)*-sortDir;}
    if(typeof x==='string')return x.localeCompare(y)*sortDir; return ((x||0)-(y||0))*sortDir;});
  $('#fcount').textContent = rows.length+' of '+D.findings.length+' findings';
  $('#fbody').innerHTML = rows.slice(0,400).map(f=>`<tr>
    <td><span class='sev ${f.severity}'>${f.severity}</span></td>
    <td><b>${esc(f.title)}</b><div class='fm'><code>${esc(f.rule_id)}</code></div></td>
    <td class='fm'>${esc(f.owning_shard)}</td>
    <td><code>${esc(res(f))}</code></td>
    <td class='fm'>${f.mitre.map(m=>esc(m.tactic)).join(', ')||'—'}</td>
    <td>${(f.score||0).toFixed(0)}</td></tr>`).join('')
    + (rows.length>400?`<tr><td colspan=6 class='fm'>… ${rows.length-400} more (narrow the filter)</td></tr>`:'');
}
/* ---- matrix ---- */
function matrixView(){
  const cols=D.threat_matrix.columns;
  const maxlen=Math.max(...cols.map(c=>c.cells.length));
  let html="<div class='panel'><div class='fm'>Click a red cell to see its findings. Green = a rule exists, grey = no rule yet (coverage gap).</div><div class='mx'>";
  html+=cols.map(c=>{
    let col=`<div class='mxcol'><div class='mxh'>${esc(c.tactic)}</div>`;
    col+=c.cells.map(cell=>{const st=cell.state;const sev=cell.max_severity||'';
      return `<div class='cell ${st}' ${st==='hit'?`data-sev='${sev}' onclick='cellFindings(${JSON.stringify(cell.finding_rule_ids)},"${esc(cell.technique_name)}")'`:''} title="${esc(cell.technique_name)}${cell.technique_id?' ('+cell.technique_id+')':''}">
        ${esc(cell.technique_name)}${cell.count?`<span class='c'>${cell.count}</span>`:''}</div>`}).join('');
    return col+'</div>';}).join('');
  html+="</div><div class='leg'><span><i style='background:var(--crit)'></i>hit (by severity)</span><span><i style='background:var(--low)'></i>covered</span><span><i style='background:var(--card);border:1px solid var(--bd)'></i>gap</span></div>";
  html+="<div id='cellout'></div></div>";
  return html;
}
function cellFindings(ruleIds,tech){
  const fs=D.findings.filter(f=>ruleIds.includes(f.rule_id));
  $('#cellout').innerHTML=`<div style='margin-top:.8rem;border-top:1px solid var(--bd);padding-top:.6rem'>
    <b>${esc(tech)}</b> — ${fs.length} finding(s)
    ${fs.slice(0,20).map(f=>`<div class='fm' style='margin-top:.3rem'><span class='sev ${f.severity}'>${f.severity}</span> ${esc(f.title)} · <code>${esc(res(f))}</code></div>`).join('')}</div>`;
}
/* ---- attack path ---- */
function attackView(){
  const a=D.attack_path;
  if(!a.steps||!a.steps.length) return "<div class='panel'><div class='fm'>No attack path — no findings mapped to tactics.</div></div>";
  const steps=a.steps.map((s,i)=>`${i?`<div class='arrow'>→</div>`:''}
    <div class='step' style='border-left-color:var(--${(s.worst_severity||'CRITICAL').toLowerCase()})'>
      <div class='t'>${esc(s.tactic)}</div>
      <div class='k'>${s.techniques.slice(0,3).map(t=>esc(t.technique_name)).join('<br>')}</div>
    </div>`).join('');
  const rc=a.reaches_impact?"<span class='reach y'>⚠ reaches Impact — full kill-chain</span>":"<span class='reach n'>stops before Impact</span>";
  return `<div class='panel'><h2>🎯 Kill-chain exploit path</h2>
    <div class='fm'>${a.tactic_count} tactics chained · ${rc}</div>
    <div class='flow'>${steps}</div>
    <div class='fm'>Entry points: ${(a.entry_points||[]).map(e=>esc(e.technique_name)).join(', ')||'—'}</div></div>`;
}
/* ---- attack map (kill-chain with vulnerable resources) ---- */
function attackMapView(){
  const a=D.attack_path;
  if(!a.steps||!a.steps.length) return "<div class='panel'><div class='fm'>No attack path.</div></div>";
  const byTactic={};D.findings.forEach(f=>{f.mitre.forEach(m=>{if(!byTactic[m.tactic])byTactic[m.tactic]=[];
    byTactic[m.tactic].push(f)})});
  const steps=a.steps.map((s,i)=>{const fs=byTactic[s.tactic]||[];
    const resources={};fs.forEach(f=>{const k=f.resource.kind;if(!resources[k])resources[k]=new Set();
      resources[k].add((f.resource.name||'(unnamed)')+(f.resource.namespace?` (${f.resource.namespace})`:''))});
    const rRows=Object.entries(resources).map(([k,ns])=>`<div class='fm' style='margin:.3rem 0'>
      <b>${esc(k)}</b> · ${[...ns].slice(0,3).map(n=>esc(n)).join(', ')}${ns.size>3?` +${ns.size-3}`:''}</div>`).join('');
    return `<div class='step' style='border-left-color:var(--${(s.worst_severity||'CRITICAL').toLowerCase()});margin:.8rem 0;padding:1rem'>
      <div style='font-weight:700;font-size:.95rem;margin-bottom:.5rem'>${i+1}. ${esc(s.tactic)}</div>
      <div class='fm' style='margin-bottom:.5rem'>${s.techniques.map(t=>esc(t.technique_name)).join(', ')}</div>
      ${rRows||'<div class="fm">no exposed resources</div>'}</div>`}).join('');
  return `<div class='panel'><h2>🗺️ Attack Map — kill-chain with vulnerable resources</h2>
    <div class='fm'>Which Kubernetes resources are exposed at each stage of the attack path.</div>
    ${steps}</div>`;
}
/* ---- runtime ---- */
function runtimeView(){
  return `<div class='panel'><h2>📡 Runtime correlation & drift</h2>
    <div class='fm'>Paste Falco/audit events (JSON array) or load a sample, then correlate against the latest scan. Point falcosidekick at <code>POST /api/runtime</code> to automate.</div>
    <div class='ctl'><button class='btn ghost' onclick='loadSample()'>Load sample attack</button>
      <button class='btn' onclick='runCorrelate()'>Correlate + detect drift</button></div>
    <textarea id='evbox' placeholder='[{"source":"falco","proc":"bash","namespace":"default"}]'></textarea>
    <div id='rtout'></div></div>`;
}
function loadSample(){
  $('#evbox').value=JSON.stringify([
    {source:'falco',proc:'bash',namespace:'default',pod:'health-check-deployment-5f8b94447d-blxwg'},
    {source:'falco',connect:'169.254.169.254:80',namespace:'default'},
    {source:'audit',verb:'create',resource:'clusterrolebindings',namespace:'default'},
    {source:'falco',proc:'nsenter',namespace:'default',pod:'system-monitor-deployment-866f697c75-tsz9n',uid:'0'},
    {source:'falco',proc:'xmrig'}
  ],null,2);
}
async function runCorrelate(){
  let ev; try{ev=JSON.parse($('#evbox').value||'[]')}catch(e){$('#rtout').innerHTML=`<div class='fm' style='color:var(--crit)'>Invalid JSON: ${esc(e.message)}</div>`;return;}
  $('#rtout').innerHTML="<div class='fm'>⏳ correlating…</div>";
  const r=await fetch('/api/runtime',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({events:ev,scan_id:D.scan.scan_id})});
  const d=await r.json();
  if(d.error){$('#rtout').innerHTML=`<div class='fm' style='color:var(--crit)'>${esc(d.error)}</div>`;return;}
  const c=d.correlation, dr=d.drift;
  const corr=c.correlations.map(x=>`<div class='corr ${x.confidence}'>
    <span class='badge ${x.confidence}'>${x.confidence}</span> <b>${esc(x.tactic)}</b> · <span class='sev ${x.severity}'>${x.severity}</span>
    <div class='fm' style='margin-top:.25rem'>runtime: ${esc(x.runtime.title)}</div>
    ${x.static_findings.length?`<div class='fm'>static: ${esc(x.static_findings[0].title)} on <code>${esc(x.static_findings[0].resource)}</code></div>`:''}
    <div class='fm'>→ ${esc(x.verdict)}</div></div>`).join('');
  const drift=dr.drift.map(x=>`<div class='corr confirmed'><span class='badge confirmed'>DRIFT</span> <b>${esc(x.pod)}</b> (${esc(x.namespace)})
    <div class='fm' style='margin-top:.25rem'>declares <code>${esc(x.declared)}</code> but runtime shows <b>${esc(x.observed)}</b></div></div>`).join('');
  $('#rtout').innerHTML=`<div style='margin-top:.8rem'>
    <div class='kpis'>
      <div class='kpi crit'><div class='n'>${c.confirmed_exploitation}</div><div class='l'>Confirmed exploitation</div></div>
      <div class='kpi warn'><div class='n'>${c.correlated}</div><div class='l'>Correlated w/ scan</div></div>
      <div class='kpi crit'><div class='n'>${dr.drift_count}</div><div class='l'>Config drift</div></div>
      <div class='kpi'><div class='n'>${c.total_alerts}</div><div class='l'>Alerts fired</div></div>
    </div>
    ${drift?`<h2 style='font-size:.95rem;margin:.6rem 0 .4rem'>Config drift (policy bypass)</h2>${drift}`:''}
    <h2 style='font-size:.95rem;margin:.6rem 0 .4rem'>Correlations</h2>${corr||"<div class='fm'>none</div>"}</div>`;
}
/* ---- scan / history ---- */
function scanView(){
  const rows=D.history.map(r=>`<tr>
    <td><a href='/report/${esc(r.scan_id)}'><code>${esc(r.scan_id)}</code></a></td>
    <td class='fm'>${esc(r.generated_at)}</td>
    <td><span class='pill ${r.rating}'>${esc(r.rating)}</span></td>
    <td>${r.risk_score}</td><td>${r.total}</td><td><code>${esc(r.scope)}</code></td>
    <td><a href='/report/${esc(r.scan_id)}'>report</a> · <a href='/report/${esc(r.scan_id)}/matrix'>matrix</a> · <a href='/api/report/${esc(r.scan_id)}?format=json'>json</a></td></tr>`).join('');
  return `<div class='panel'><h2>▶️ Run a scan</h2>${scanForm()}</div>
    <div class='panel'><h2>🗂️ Scan history</h2><table class='ft'><thead><tr>
    <th>Scan</th><th>Generated</th><th>Rating</th><th>Risk</th><th>Findings</th><th>Scope</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`;
}
function scanForm(){
  return `<div class='scanform'>
    <div><label>Scope</label><select id='scope'><option value='cluster'>whole cluster</option><option value='namespace'>namespace</option></select></div>
    <div><label>Namespace</label><input id='ns' placeholder='e.g. default'></div>
    <div><label>Selector (optional)</label><input id='sel' placeholder='e.g. Persistence'></div>
    <div><label>Cluster</label><select id='mock'><option value='0'>live (--live)</option><option value='1'>bundled mock</option></select></div>
    <button class='btn' id='run' onclick='runScan()'>Scan &amp; save</button></div><div id='scanmsg'></div>`;
}
function wireScan(){}
async function runScan(){
  const btn=$('#run'),msg=$('#scanmsg');btn.disabled=true;msg.textContent='⏳ scanning…';
  const body={scope_level:$('#scope').value,namespace:$('#ns').value||null,selector:$('#sel').value||null,mock:$('#mock').value==='1'};
  try{const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await r.json();
    if(!r.ok||d.error){msg.textContent='⚠️ '+(d.error||('HTTP '+r.status));btn.disabled=false;return;}
    msg.innerHTML='✅ '+d.scan_id+' — '+d.rating+' ('+d.risk+'/10), '+d.total_findings+' findings. Reloading…';
    setTimeout(()=>location.reload(),800);
  }catch(e){msg.textContent='⚠️ '+e;btn.disabled=false;}
}
const res=f=>{const r=f.resource||{};return r.kind+'/'+r.name+(r.namespace?' ('+r.namespace+')':'')};
boot();
</script>
"""
