"""HTML + markdown for a FederationReport. Reuses the report shell + theme."""
from __future__ import annotations

from .federation import FederationReport
from .reporting import _HTML_CSS, _esc, THEME_BUTTON, THEME_JS

_SEV_CLS = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low", "INFO": "muted"}


def to_markdown(rep: FederationReport) -> str:
    L = ["# Federation Blast Radius\n", f"{rep.summary}\n"]
    L.append("\n## Clusters\n")
    L.append("| Cluster | Rating | Risk | Findings |\n|---|---|---|---|")
    for c in rep.clusters:
        L.append(f"| `{_esc(c['name'])}` | {_esc(c['rating'])} | {c['risk']:.1f} | {c['findings']} |")
    L.append("\n## Shared identities (cross-cluster lateral-movement paths)\n")
    if not rep.shared_identities:
        L.append("_None — clusters are independent blast radii on this evidence._")
    else:
        L.append("| Identity | Severity | Spans clusters | Tactics |\n|---|---|---|---|")
        for s in rep.shared_identities:
            L.append(f"| `{_esc(s.key)}` | {s.worst_severity} | {_esc(', '.join(s.clusters))} "
                     f"| {_esc(', '.join(s.tactics) or '—')} |")
    L.append("\n## Federated tactic exposure\n")
    for t, n in sorted(rep.federated_tactics.items(), key=lambda kv: -kv[1]):
        L.append(f"- **{_esc(t)}**: {n}")
    return "\n".join(L) + "\n"


def to_html(rep: FederationReport, *, standalone: bool = True) -> str:
    crit = sum(1 for s in rep.shared_identities if s.worst_severity == "CRITICAL")
    cls = "fail" if rep.shared_identities else "ok"
    cluster_rows = "".join(
        f"<tr><td><code>{_esc(c['name'])}</code></td><td>{_esc(c['rating'])}</td>"
        f"<td>{c['risk']:.1f}</td><td>{c['findings']}</td></tr>" for c in rep.clusters)
    if rep.shared_identities:
        id_rows = "".join(
            f"<tr class='fd-row {_SEV_CLS.get(s.worst_severity,'muted')}'>"
            f"<td><span class='fd-badge {_SEV_CLS.get(s.worst_severity,'muted')}'>{s.worst_severity}</span></td>"
            f"<td><b>{_esc(s.kind)}</b> <code>{_esc(s.name)}</code></td>"
            f"<td>{''.join(f'<span class=fd-chip>{_esc(c)}</span>' for c in s.clusters)}</td>"
            f"<td class='fm'>{_esc(', '.join(s.tactics) or '—')}</td></tr>"
            for s in rep.shared_identities)
        id_table = (f"<table class='fd-table'><thead><tr><th>Severity</th><th>Shared identity</th>"
                    f"<th>Spans</th><th>Tactics</th></tr></thead><tbody>{id_rows}</tbody></table>")
    else:
        id_table = ("<div class='fd-none'>No shared identity links these clusters — on this "
                    "evidence they are independent blast radii, not one federation.</div>")
    mx = max(rep.federated_tactics.values(), default=1)
    bars = "".join(
        f"<div class='fd-bar'><div class='fd-bl'>{_esc(t)}</div>"
        f"<div class='fd-bt'><div class='fd-bf' style='width:{max(n/mx*100,6):.0f}%'>{n}</div></div></div>"
        for t, n in sorted(rep.federated_tactics.items(), key=lambda kv: -kv[1]))

    themebar = f"<div class='themebar'>{THEME_BUTTON}</div>" if standalone else ""
    body = f"""
{themebar}
<h1>Federation Blast Radius</h1>
<div class='fd-attest {cls}'>{_esc(rep.summary)}</div>
<h2 class='fd-h'>Clusters in scope</h2>
<table class='fd-table'><thead><tr><th>Cluster</th><th>Rating</th><th>Risk</th><th>Findings</th></tr></thead>
<tbody>{cluster_rows}</tbody></table>
<h2 class='fd-h'>Shared identities — candidate cross-cluster lateral-movement paths <span class='fm'>({len(rep.shared_identities)} candidates · {crit} critical)</span></h2>
<div class='fm' style='margin-bottom:.6rem'>A row means the same non-default identity (by kind + name) exists in more than one cluster — a <b>candidate</b> shared trust principal to verify, not proof on its own (same name ≠ guaranteed same principal). Built-in defaults are excluded.</div>
{id_table}
<h2 class='fd-h'>Federated tactic exposure <span class='fm'>(all clusters combined)</span></h2>
{bars}
"""
    if not standalone:
        return f"<style>{_FD_CSS}</style>{body}"
    return (f"<!doctype html><html><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>Federation Blast Radius · K8sMatrixWarden</title>"
            f"<style>{_HTML_CSS}{_FD_CSS}</style></head><body><div class='wrap'>"
            f"{body}</div><script>{THEME_JS}</script></body></html>")


_FD_CSS = """
.fd-attest{font-size:1.05rem;font-weight:700;padding:.9rem 1.1rem;border-radius:10px;margin:1rem 0}
.fd-attest.fail{background:rgba(207,34,46,.12);color:var(--crit);border:1px solid var(--crit)}
.fd-attest.ok{background:rgba(26,127,55,.12);color:var(--low);border:1px solid var(--low)}
.fd-h{font-size:1.05rem;margin:1.4rem 0 .5rem}
.fd-table{width:100%;border-collapse:collapse;font-size:.87rem;margin:.4rem 0}
.fd-table th{text-align:left;color:var(--muted);font-size:.72rem;text-transform:uppercase;
 letter-spacing:.05em;padding:.55rem .6rem;border-bottom:2px solid var(--bd)}
.fd-table td{padding:.6rem .6rem;border-bottom:1px solid var(--bd);vertical-align:top}
.fd-row.crit{background:rgba(207,34,46,.05)}
.fd-badge{font-size:.72rem;font-weight:700;padding:.15rem .55rem;border-radius:20px;color:#fff}
.fd-badge.crit{background:var(--crit)}.fd-badge.high{background:var(--high)}
.fd-badge.med{background:var(--med)}.fd-badge.low{background:var(--low)}.fd-badge.muted{background:var(--muted)}
.fd-chip{display:inline-block;font-size:.72rem;padding:.1rem .5rem;margin:.1rem .25rem .1rem 0;
 border-radius:20px;border:1px solid var(--accent);color:var(--accent);background:var(--bg)}
.fd-none{padding:1rem;border:1px dashed var(--bd);border-radius:10px;color:var(--muted);background:var(--card)}
.fd-bar{display:flex;align-items:center;gap:.7rem;margin-bottom:.5rem}
.fd-bl{width:170px;font-size:.83rem;flex:0 0 auto}
.fd-bt{flex:1;height:22px;background:var(--card);border:1px solid var(--bd);border-radius:6px;overflow:hidden}
.fd-bf{height:100%;background:var(--accent);color:#fff;font-size:.72rem;font-weight:700;
 display:flex;align-items:center;justify-content:flex-end;padding-right:.5rem;min-width:fit-content}
"""
