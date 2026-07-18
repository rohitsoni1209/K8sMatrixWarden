"""
Reporting Engine (§18.2) — rich, multi-format, audit-grade security reports.

Renders a ScanResult in seven formats, each designed to be genuinely useful rather than a
flat dump. Every finding, in every format, carries the same seven report-grade sections
(sourced from `core.finding_context.build_finding_context()`, the single shared content
layer): Summary, Standards & Benchmark Mapping (with reference links), MITRE ATT&CK
Mapping (with reference links), Impact, Remediation (with reference links), and
Validation/reproduction steps.

  terminal  — rich panels + per-severity tables (falls back to `text` with no `rich`)
  text      — grouped, sectioned plain-text (zero dependency)
  markdown  — the flagship: frontmatter, verdict, risk gauge, coverage dashboards,
              full per-finding report cards, a prioritized remediation plan, an appendix
  json      — full structured data + a summary block + the same per-finding context
  sarif     — SARIF 2.1 with security-severity, tags, rich help.markdown, fingerprints
  html      — self-contained, responsive, dark/light card report with the same sections
  pdf       — a print/share-ready audit document (title page, executive summary,
              coverage, full per-finding write-ups); requires the optional `pdf` extra
              (`pip install -e ".[pdf]"`) — see core/pdf_report.py. Returns `bytes`, not
              `str` — the only format that does; callers must branch on this.

Tag-based filtering stays first-class because tags are finding metadata (§18.2).
"""
from __future__ import annotations

import json
import os
from typing import Optional

from .models import Finding, Severity
from .results import ScanResult
from .threat_matrix_render import THREAT_MATRIX_CSS

try:  # optional pretty terminal output
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    _RICH = True
except Exception:  # pragma: no cover
    _RICH = False

_SEV_DISPLAY = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


class ReportingEngine:
    def __init__(self, registry=None):
        #: optional RuleRegistry — supplies the threat matrix's *coverage* layer (which
        #: techniques have a rule at all, beyond what this scan hit). Set by bootstrap so
        #: `platform.reporting` renders the full 3-state matrix; a bare ReportingEngine()
        #: still works (findings-only matrix). See core/threat_matrix.py.
        self.registry = registry

    def render(self, result: ScanResult, fmt: str = "terminal"):
        """Render in the requested format. Every format returns `str` EXCEPT `pdf`,
        which returns raw `bytes` — callers must check the format and write/handle it
        accordingly (binary file mode, base64-encode for a JSON/text transport, etc.)."""
        fmt = (fmt or "terminal").lower()
        if fmt == "pdf":
            return self.pdf(result)
        return {
            "terminal": self.terminal, "text": self.text,
            "markdown": self.markdown, "md": self.markdown,
            "json": self.json, "sarif": self.sarif, "html": self.html,
        }.get(fmt, self.terminal)(result)

    # ================================================================== #
    # PDF (requires the optional `pdf` extra — fpdf2)
    # ================================================================== #
    def pdf(self, result: ScanResult) -> bytes:
        from .pdf_report import render_pdf
        return render_pdf(result)

    # ================================================================== #
    # TERMINAL (rich)
    # ================================================================== #
    def terminal(self, result: ScanResult) -> str:
        if not _RICH:
            return self.text(result)
        console = Console(record=True, width=100)
        r = result.risk
        c = result.counts

        summary = (
            f"[bold]{r.rating_emoji} Risk {r.cluster_risk}/10 ({r.rating})[/bold]   "
            f"Security score [bold]{r.security_score}/100[/bold]\n"
            f"Scope [cyan]{result.request.scope.describe()}[/cyan]   "
            f"Selector [cyan]{result.request.selector.describe()}[/cyan]   "
            f"Mode {result.mode}   Rules {len(result.resolved_rule_ids)}\n"
            f"🔴 {c['CRITICAL']} Critical   🟠 {c['HIGH']} High   "
            f"🟡 {c['MEDIUM']} Medium   🟢 {c['LOW']} Low")
        console.print(Panel(summary, title=f"🛡️  K8s Security Report · {result.scan_id}",
                            border_style=_rich_border(r.rating), expand=True))

        findings = _display_findings(result.findings)
        if not findings:
            console.print("[green]✅ No findings for this scan.[/green]")
            return console.export_text()

        for sev in _SEV_DISPLAY:
            group = [f for f in findings if f.severity == sev]
            if not group:
                continue
            table = Table(title=f"{sev.emoji} {sev.label} ({len(group)})",
                          show_lines=False, expand=True, border_style=_rich_sev(sev),
                          title_justify="left")
            table.add_column("Rule", style="dim", no_wrap=True)
            table.add_column("Resource")
            table.add_column("MITRE", no_wrap=True)
            table.add_column("Finding")
            for f in group:
                tag = "⚡" if len(f.tactics) > 1 else " "
                table.add_row(f"{tag}{f.rule_id}", str(f.resource),
                              _mitre_short(f), f.message)
            console.print(table)

        # A short prioritized fix list.
        top = [f for f in findings if f.remediation_ref][:5]
        if top:
            lines = []
            for i, f in enumerate(top, 1):
                title, cmds = _fix_commands(f)
                lines.append(f"[bold]{i}.[/bold] {f.title} — {f.resource}")
                if cmds:
                    lines.append(f"   [green]$ {cmds[0]}[/green]")
            console.print(Panel("\n".join(lines), title="🛠️  Top Remediations",
                                border_style="green", expand=True))
        return console.export_text()

    # ================================================================== #
    # TEXT (plain, zero-dep)
    # ================================================================== #
    def text(self, result: ScanResult) -> str:
        r = result.risk
        c = result.counts
        total = result.total()
        rule = "═" * 78
        # Left-aligned banner (no right border) — emoji render 2-wide and would break a
        # right border's alignment, so we deliberately avoid one.
        out = [
            rule,
            f"  🛡️  K8s SECURITY REPORT  ·  {result.scan_id}",
            rule,
            f"  Generated : {result.generated_at}",
            f"  Scope     : {result.request.scope.describe()}",
            f"  Selector  : {result.request.selector.describe()}",
            f"  Mode      : {result.mode}   ·   Rules run: {len(result.resolved_rule_ids)}",
            "  " + "─" * 60,
            f"  RISK   {r.rating_emoji} {r.cluster_risk}/10 ({r.rating})"
            f"   ·   Security score {r.security_score}/100",
            f"  {_risk_gauge(r.cluster_risk)}",
            "  " + "─" * 60,
        ]
        for sev in _SEV_DISPLAY:
            n = c[sev.label]
            out.append(f"  {sev.emoji} {sev.label:<9} {n:>3}   "
                       f"{_bar(_frac(n, total), 30)}  {_pct(n, total)}")
        out.append(rule)

        findings = _display_findings(result.findings)
        for sev in _SEV_DISPLAY:
            group = [f for f in findings if f.severity == sev]
            if not group:
                continue
            out += ["", f"── {sev.emoji} {sev.label} FINDINGS ({len(group)}) "
                    + "─" * (55 - len(sev.label))]
            for i, f in enumerate(group, 1):
                amp = "  ⚡ multi-tactic" if len(f.tactics) > 1 else ""
                out.append(f"\n  {i}. {f.title} — {f.resource}{amp}")
                out.append(f"     rule   : {f.rule_id}  [{f.owning_shard}]")
                out.append(f"     mitre  : {_mitre_long(f) or '-'}")
                out.append(f"     owasp  : {_owasp_label(f.owasp)}   "
                           f"cis: {', '.join(f.cis) or '-'}")
                out.append(f"     impact : exploitability={f.exploitability.label} · "
                           f"blast={f.blast_radius.label} · score={round(f.score, 1)}")
                out.append(f"     detail : {f.message}")
                from .finding_context import build_finding_context
                ctx = build_finding_context(f)
                if ctx.standards:
                    out.append("     standards : " + "  ".join(
                        f"{s.framework.split()[0]}:{s.control}" for s in ctx.standards))
                out.append(f"     why    : {_truncate(ctx.impact, 140)}")
                rem = ctx.remediation
                if rem.automatable and rem.kubectl_command:
                    out.append(f"     fix    : {rem.title}")
                    out.append(f"            $ {rem.kubectl_command}")
                elif rem.reason_not_automated:
                    out.append(f"     fix    : cannot be automated — "
                               f"{_truncate(rem.reason_not_automated, 120)}")
                if ctx.validation_steps:
                    out.append(f"     verify : {ctx.validation_steps[0]}")
        if not findings:
            out += ["", "  ✅ No findings for this scan."]
        return "\n".join(out)

    # ================================================================== #
    # MARKDOWN (flagship)
    # ================================================================== #
    def markdown(self, result: ScanResult) -> str:
        r = result.risk
        c = result.counts
        total = result.total()
        findings = _display_findings(result.findings)
        multi = [f for f in findings if len(f.tactics) > 1]

        md: list[str] = []

        # ---- frontmatter ------------------------------------------------ #
        md += [
            "---",
            'title: "K8s Security Report"',
            f'cluster: "{result.cluster_name}"',
            f'scan_id: "{result.scan_id}"',
            f'generated_at: "{result.generated_at}"',
            f'tool: "k8smatrixwarden {result.tool_version}"',
            f'mode: "{result.mode}"',
            f'scope: "{result.request.scope.describe()}"',
            f'selector: "{result.request.selector.describe()}"',
            f"rules_run: {len(result.resolved_rule_ids)}",
            f"risk_score: {r.cluster_risk}",
            f"security_score: {r.security_score}",
            f'rating: "{r.rating}"',
            f"critical: {c['CRITICAL']}", f"high: {c['HIGH']}",
            f"medium: {c['MEDIUM']}", f"low: {c['LOW']}",
            f"tactics_covered: {len(result.by_tactic)}",
            "---",
            "",
            f"# 🛡️ K8s Security Report",
            "",
            f"{_status_badges(result)}",
            "",
            f"> {_verdict(r.rating)}",
            "",
        ]

        # ---- table of contents ----------------------------------------- #
        md += [
            "<a id=\"top\"></a>",
            "## Contents",
            "",
            "1. [Executive Summary](#summary)",
            "2. [Kubernetes Threat Matrix](#matrix)",
            "3. [Coverage & Exposure](#coverage)",
            "4. [Findings](#findings)"
            + (" · [⚡ Attack-Path Amplified](#attackpaths)" if multi else ""),
            "5. [Prioritized Remediation Plan](#remediation)",
            "6. [Appendix](#appendix)",
            "",
            "---",
            "",
        ]

        # ---- executive summary ----------------------------------------- #
        md += [
            "<a id=\"summary\"></a>",
            "## 1. 📊 Executive Summary",
            "",
            f"**Overall risk:** {r.rating_emoji} **{r.cluster_risk} / 10 "
            f"({r.rating})**  ·  **Security score:** {r.security_score} / 100",
            "",
            "```",
            f"Risk  {_risk_gauge(r.cluster_risk)}",
            "```",
            "",
            "| Severity | Count | Share |",
            "|:--|--:|:--|",
        ]
        for sev in _SEV_DISPLAY:
            n = c[sev.label]
            md.append(f"| {sev.emoji} {sev.label} | **{n}** | "
                      f"`{_bar(_frac(n, total), 18)}` {_pct(n, total)} |")
        md += [
            f"| **Total** | **{total}** | |",
            "",
            f"- **Findings:** {total} actionable "
            f"({c['CRITICAL']} critical, {c['HIGH']} high, {c['MEDIUM']} medium, "
            f"{c['LOW']} low)",
            f"- **MITRE ATT&CK tactics implicated:** {len(result.by_tactic)} / 9",
            f"- **Attack-path amplified findings:** {len(multi)} "
            f"(one issue enabling multiple tactics)" if multi else
            "- **Attack-path amplified findings:** 0",
            f"- **Rules evaluated:** {len(result.resolved_rule_ids)} across "
            f"{len(result.by_shard)} domain(s)",
            "",
            "[↑ top](#top)",
            "",
            "---",
            "",
        ]

        # ---- threat matrix ---------------------------------------------- #
        from .threat_matrix import build_threat_matrix
        from .threat_matrix_render import render_markdown as _tm_md
        tm = build_threat_matrix(result, self.registry)
        md += ["<a id=\"matrix\"></a>", "## 2. 🗺️ Kubernetes Threat Matrix", "",
               _tm_md(tm, heading_level=3, include_heading=False),
               "[↑ top](#top)", "", "---", ""]

        # ---- coverage --------------------------------------------------- #
        md += ["<a id=\"coverage\"></a>", "## 3. 🎯 Coverage & Exposure", ""]

        if result.by_tactic:
            md += ["### By MITRE ATT&CK Tactic", "",
                   "| Tactic | Findings | Distribution |", "|:--|--:|:--|"]
            mx = max(result.by_tactic.values())
            for tactic, n in sorted(result.by_tactic.items(), key=lambda kv: -kv[1]):
                md.append(f"| {tactic} | {n} | `{_bar(_frac(n, mx), 16)}` |")
            md.append("")

        if result.by_shard:
            md += ["### By Security Domain (shard)", "",
                   "| Domain | Findings |", "|:--|--:|"]
            for shard, n in sorted(result.by_shard.items(), key=lambda kv: -kv[1]):
                md.append(f"| `{shard}` | {n} |")
            md.append("")

        owasp = _by_owasp(findings)
        if owasp:
            md += ["### OWASP Kubernetes Top 10 (2025)", "",
                   "| ID | Category | Findings |", "|:--|:--|--:|"]
            for code in sorted(owasp):
                md.append(f"| `{code}` | {_owasp_names().get(code, '—')} | {owasp[code]} |")
            md.append("")
        md += ["[↑ top](#top)", "", "---", ""]

        # ---- attack paths ---------------------------------------------- #
        if multi:
            md += [
                "<a id=\"attackpaths\"></a>",
                "## ⚡ Attack-Path Amplified Findings",
                "",
                "These single issues each enable **multiple** MITRE tactics, so an attacker "
                "can chain them — they are scored higher and should be fixed first.",
                "",
                "| Finding | Resource | Tactics enabled |",
                "|:--|:--|:--|",
            ]
            for f in sorted(multi, key=lambda x: -x.score):
                tactics = " → ".join(t.value for t in f.tactics)
                md.append(f"| **{f.title}** | `{f.resource}` | {tactics} |")
            md += ["", "---", ""]

        # ---- findings --------------------------------------------------- #
        md += ["<a id=\"findings\"></a>", "## 4. 🚨 Findings", ""]
        if not findings:
            md += ["_No findings for this scan._ ✅", ""]
        for sev in _SEV_DISPLAY:
            group = [f for f in findings if f.severity == sev]
            if not group:
                continue
            md += [f"<a id=\"sev-{sev.label.lower()}\"></a>",
                   f"### {sev.emoji} {sev.label} — {len(group)} finding(s)", ""]
            for i, f in enumerate(group, 1):
                md += _finding_card(f, i)
        md += ["[↑ top](#top)", "", "---", ""]

        # ---- remediation plan ------------------------------------------ #
        md += [
            "<a id=\"remediation\"></a>",
            "## 5. 🛠️ Prioritized Remediation Plan",
            "",
            "Fixes ordered by risk (highest first). Every command is shown exactly as it "
            "would run — **review before applying**; destructive actions require confirmation "
            "through the Remediation Agent.",
            "",
        ]
        fixable = [f for f in findings if _fix_commands(f)[1]][:15]
        if not fixable:
            md += ["_No automated remediations available for these findings._", ""]
        else:
            md += ["| # | Priority | Finding | Resource | Fix |",
                   "|--:|:--|:--|:--|:--|"]
            for i, f in enumerate(fixable, 1):
                _t, cmds = _fix_commands(f)
                cmd = _table_cmd(cmds[0]) if cmds else "—"
                md.append(f"| {i} | {f.severity.emoji} {f.severity.label} | {f.title} "
                          f"| `{f.resource}` | {cmd} |")
            md.append("")
        md += ["[↑ top](#top)", "", "---", ""]

        # ---- appendix --------------------------------------------------- #
        md += [
            "<a id=\"appendix\"></a>",
            "## 6. 📎 Appendix",
            "",
            "<details><summary><strong>Scan metadata</strong></summary>",
            "",
            "| Key | Value |", "|:--|:--|",
            f"| Scan ID | `{result.scan_id}` |",
            f"| Generated | {result.generated_at} |",
            f"| Tool version | k8smatrixwarden {result.tool_version} |",
            f"| Mode | {result.mode} |",
            f"| Scope | {result.request.scope.describe()} |",
            f"| Selector | {result.request.selector.describe()} |",
            f"| Rules evaluated | {len(result.resolved_rule_ids)} |",
            "",
            "</details>",
            "",
            "<details><summary><strong>Rules evaluated in this scan</strong></summary>",
            "",
            "```",
            ("\n".join(_wrap_ids(result.resolved_rule_ids)) or "(none)"),
            "```",
            "",
            "</details>",
            "",
            "---",
            f"<sub>Generated by 🛡️ k8smatrixwarden {result.tool_version} — "
            f"MITRE ATT&CK-aligned Kubernetes security scanner.</sub>",
        ]
        return "\n".join(md)

    # ================================================================== #
    # JSON (structured + summary + remediation)
    # ================================================================== #
    def json(self, result: ScanResult) -> str:
        doc = result.as_dict()
        c = result.counts
        total = result.total()
        doc["summary"] = {
            "rating": result.risk.rating,
            "risk_score": result.risk.cluster_risk,
            "security_score": result.risk.security_score,
            "total_findings": total,
            "severity_percent": {s.label: _pct_num(c[s.label], total)
                                 for s in _SEV_DISPLAY},
            "attack_path_amplified": sum(1 for f in result.findings
                                         if len(f.tactics) > 1 and f.severity.weight),
            "owasp": _by_owasp(result.findings),
        }
        # Full Kubernetes Threat Matrix projection (§12) — same structure the HTML/web
        # heatmap and the MCP build_threat_matrix tool return, so a JSON/API consumer gets
        # the adversary-behaviour map, not just a flat finding list.
        from .threat_matrix import build_threat_matrix
        doc["threat_matrix"] = build_threat_matrix(result, self.registry).as_dict()
        # attach the full report-grade context to each finding: summary, standards &
        # benchmark mapping (with links), MITRE mapping (with links), impact, validation
        # steps, and the schema-aware remediation breakdown (§8) — the same data every
        # other renderer (markdown/html/sarif/pdf) sources from build_finding_context(),
        # so a JSON/API consumer never sees less than a human-facing report does.
        from .finding_context import build_finding_context
        for fd, f in zip(doc["findings"], result.findings):
            ctx = build_finding_context(f)
            rem = ctx.remediation
            fd["summary"] = ctx.summary
            fd["impact"] = ctx.impact
            fd["validation_steps"] = ctx.validation_steps
            fd["standards"] = [{"framework": s.framework, "control": s.control,
                               "title": s.title, "url": s.url} for s in ctx.standards]
            fd["mitre_mapping"] = [{"tactic": m.tactic, "technique_id": m.technique_id,
                                    "technique_name": m.technique_name, "url": m.url}
                                   for m in ctx.mitre]
            fd["remediation"] = {
                "title": rem.title,
                "commands": [rem.kubectl_command] if rem.automatable and rem.kubectl_command
                            else [],
                "automatable": rem.automatable,
                "owner_resource": rem.owner_resource,
                "deployment_method": rem.deployment_method,
                "alternative_yaml": rem.alternative_yaml,
                "validation_commands": rem.validation_commands,
                "rollback_commands": rem.rollback_commands,
                "warnings": rem.warnings,
                "references": rem.references,
                "reason_not_automated": rem.reason_not_automated,
            }
        return json.dumps(doc, indent=2)

    # ================================================================== #
    # SARIF 2.1 (GitHub Code Scanning-ready)
    # ================================================================== #
    def sarif(self, result: ScanResult) -> str:
        from .finding_context import build_finding_context

        rules: dict[str, dict] = {}
        results = []
        for f in result.findings:
            if f.severity.weight == 0:
                continue
            if f.rule_id not in rules:
                ctx = build_finding_context(f)
                rem = ctx.remediation
                help_uri = (ctx.standards[0].url if ctx.standards else
                           (ctx.mitre[0].url if ctx.mitre else
                            "https://owasp.org/www-project-kubernetes-top-ten/"))
                rules[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": ctx.summary},
                    "helpUri": help_uri,
                    "help": {"text": _fix_text(f), "markdown": _sarif_help_md(ctx, rem)},
                    "defaultConfiguration": {"level": _sarif_level(f.severity)},
                    "properties": {
                        "security-severity": _security_severity(f.severity),
                        "tags": _sarif_tags(f),
                        "owasp": f.owasp,
                        "mitre": [m.technique_id for m in f.mitre],
                        "cis": f.cis,
                        "shard": f.owning_shard,
                        "impact": ctx.impact,
                        "standards": [{"framework": s.framework, "control": s.control,
                                      "url": s.url} for s in ctx.standards],
                        "validationSteps": ctx.validation_steps,
                    },
                }
            results.append({
                "ruleId": f.rule_id,
                "level": _sarif_level(f.severity),
                "message": {"text": f.message},
                "partialFingerprints": {
                    "k8smatrixwarden/v1": f"{f.rule_id}:{f.resource.namespace}:"
                                 f"{f.resource.kind}:{f.resource.name}"},
                "properties": {"security-severity": _security_severity(f.severity)},
                "locations": [{"logicalLocations": [{
                    "name": str(f.resource), "kind": f.resource.kind,
                    "fullyQualifiedName": _fqn(f)}]}],
            })
        doc = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "k8smatrixwarden",
                    "fullName": "k8smatrixwarden — MITRE ATT&CK-aligned Kubernetes scanner",
                    "version": result.tool_version,
                    "informationUri": "https://owasp.org/www-project-kubernetes-top-ten/",
                    "rules": list(rules.values()),
                }},
                "results": results,
                "properties": {"scan_id": result.scan_id,
                               "risk_score": result.risk.cluster_risk,
                               "rating": result.risk.rating},
            }],
        }
        return json.dumps(doc, indent=2)

    # ================================================================== #
    # HTML (self-contained, responsive, dark/light)
    # ================================================================== #
    def html(self, result: ScanResult) -> str:
        r = result.risk
        c = result.counts
        total = result.total()
        findings = _display_findings(result.findings)

        chips = (f"<span class='sev crit'>🔴 {c['CRITICAL']} Critical</span>"
                 f"<span class='sev high'>🟠 {c['HIGH']} High</span>"
                 f"<span class='sev med'>🟡 {c['MEDIUM']} Medium</span>"
                 f"<span class='sev low'>🟢 {c['LOW']} Low</span>")

        from .finding_context import build_finding_context

        cards = []
        for f in findings:
            ctx = build_finding_context(f)
            rem = ctx.remediation

            mitre_tags = " ".join(f"<span class='tag mitre'>{_esc(m.tactic)} · "
                                  f"{_esc(m.technique_id)}</span>" for m in ctx.mitre)
            std_tags = "".join(
                f"<span class='tag std'>{_esc(s.framework.split()[0])} "
                f"{_esc(s.control)}</span>" for s in ctx.standards)
            amp = "<span class='tag amp'>⚡ multi-tactic</span>" if len(f.tactics) > 1 else ""

            mitre_rows = "".join(
                f"<tr><td>{_esc(m.tactic)}</td><td>{_esc(m.technique_name)} "
                f"<code>{_esc(m.technique_id)}</code></td>"
                f"<td><a href='{_esc(m.url)}' target='_blank' rel='noopener'>Reference</a></td></tr>"
                for m in ctx.mitre) or "<tr><td colspan='3' class='muted'>Not mapped to a " \
                "MITRE ATT&amp;CK technique.</td></tr>"
            std_rows = "".join(
                f"<tr><td>{_esc(s.framework)}</td><td>{_esc(s.control)} — {_esc(s.title)}</td>"
                f"<td><a href='{_esc(s.url)}' target='_blank' rel='noopener'>Reference</a></td></tr>"
                for s in ctx.standards) or "<tr><td colspan='3' class='muted'>No named " \
                "standard or benchmark maps to this finding.</td></tr>"

            if rem.automatable and rem.kubectl_command:
                refs_html = ""
                if rem.references:
                    refs_html = "<div class='refs'>References: " + " · ".join(
                        f"<a href='{_esc(u)}' target='_blank' rel='noopener'>"
                        f"{_esc(_ref_label(u))}</a>" for u in rem.references) + "</div>"
                remediation_html = (
                    f"<details open><summary>🛠️ Remediation — {_esc(rem.title or '')}"
                    f"</summary><pre class='cmd'>{_esc(rem.kubectl_command)}</pre>{refs_html}</details>")
            elif rem.reason_not_automated:
                remediation_html = (f"<div class='callout warn'>⚠️ <strong>Cannot be safely "
                                    f"automated.</strong> {_esc(rem.reason_not_automated)}</div>")
            else:
                remediation_html = "<div class='muted'>No automated remediation registered "\
                                   "for this rule — review and fix manually.</div>"

            validation_html = ("<details><summary>✅ Validation — how to reproduce</summary>"
                               f"<pre class='cmd'>{_esc(chr(10).join(ctx.validation_steps))}"
                               "</pre></details>")
            warn_html = ""
            if rem.warnings:
                warn_html = ("<details><summary>⚠️ Warnings</summary><ul class='warnlist'>"
                            + "".join(f"<li>{_esc(w)}</li>" for w in rem.warnings)
                            + "</ul></details>")

            cards.append(
                f"<div class='card {f.severity.label.lower()}'>"
                f"<div class='chead'><span class='badge {f.severity.label.lower()}'>"
                f"{f.severity.emoji} {f.severity.label}</span>"
                f"<span class='ctitle'>{_esc(f.title)}</span>"
                f"<code class='res'>{_esc(str(f.resource))}</code>{amp}</div>"
                f"<div class='csummary'>{_esc(ctx.summary)}</div>"
                f"<div class='cmsg'><strong>Detected:</strong> {_esc(f.message)}</div>"
                f"<div class='tags'>{mitre_tags}{std_tags}"
                f"<span class='tag'>score {round(f.score,1)}</span>"
                f"<span class='tag'>{_esc(f.owning_shard)}</span></div>"
                f"<details><summary>📚 Standards &amp; Benchmark Mapping</summary>"
                f"<table class='ctx-table'>{std_rows}</table></details>"
                f"<details><summary>🎯 MITRE ATT&amp;CK Mapping</summary>"
                f"<table class='ctx-table'>{mitre_rows}</table></details>"
                f"<div class='cimpact'><strong>💥 Impact:</strong> {_esc(ctx.impact)}</div>"
                f"{remediation_html}{validation_html}{warn_html}"
                f"</div>")

        filters = ("<button data-f='all' class='on'>All</button>"
                   "<button data-f='critical'>Critical</button>"
                   "<button data-f='high'>High</button>"
                   "<button data-f='medium'>Medium</button>"
                   "<button data-f='low'>Low</button>")

        from .threat_matrix import build_threat_matrix
        from .threat_matrix_render import render_html_grid
        matrix_html = ("<section class='matrix'><h2>🗺️ Kubernetes Threat Matrix</h2>"
                       + render_html_grid(build_threat_matrix(result, self.registry))
                       + "</section>")

        return _HTML_TMPL.format(
            css=_HTML_CSS, js=_HTML_JS, scan=_esc(result.scan_id),
            matrix=matrix_html,
            cluster=_esc(result.cluster_name), rating=r.rating,
            risk=r.cluster_risk, sec=r.security_score,
            rating_emoji=r.rating_emoji, rating_class=r.rating.lower(),
            scope=_esc(result.request.scope.describe()),
            selector=_esc(result.request.selector.describe()),
            mode=result.mode, rules=len(result.resolved_rule_ids),
            generated=result.generated_at, verdict=_esc(_verdict(r.rating)),
            chips=chips, filters=filters,
            gaugepct=min(100, round(r.cluster_risk * 10)),
            cards=("".join(cards) or "<p class='ok'>✅ No findings for this scan.</p>"),
            total=total, tactics=len(result.by_tactic))


# ======================================================================= #
# helpers
# ======================================================================= #
def _display_findings(findings: list[Finding]) -> list[Finding]:
    from .scoring import RiskScoringEngine
    ranked = RiskScoringEngine.rank(findings)
    real = [f for f in ranked if f.severity.weight > 0]
    return real if real else []


def _finding_card(f: Finding, i: int) -> list[str]:
    """A full, report-grade finding write-up — the seven sections a professional scan
    report is expected to carry: Summary, Standards & Benchmark Mapping, MITRE ATT&CK
    Mapping, Impact, Remediation, Validation (how to reproduce), and Evidence. All
    content beyond the raw Finding fields comes from build_finding_context(), the single
    place this and every other renderer (html/json/sarif/pdf) source it from."""
    from .finding_context import build_finding_context
    ctx = build_finding_context(f)
    rem = ctx.remediation
    amp = " ⚡ Attack-Path Amplified" if len(f.tactics) > 1 else ""

    rows = [
        f"| **Rule ID** | `{f.rule_id}` |",
        f"| **Domain** | `{f.owning_shard}` |",
        f"| **Exploitability** | {f.exploitability.label} |",
        f"| **Blast radius** | {f.blast_radius.label} |",
        f"| **Risk score** | {round(f.score, 2)} |",
    ]
    if rem.owner_resource:
        rows.insert(2, f"| **Owner resource** | `{rem.owner_resource}` |")

    out = [
        f"#### {i}. {f.severity.emoji} {f.title}{amp}",
        "",
        f"`{f.resource}`",
        "",
        "##### Summary",
        "",
        ctx.summary,
        "",
        f"> **Detected:** {f.message}",
        "",
        "| | |",
        "|:--|:--|",
        *rows,
        "",
    ]

    # ---- standards & benchmark mapping ------------------------------- #
    out += ["##### 📚 Standards & Benchmark Mapping", ""]
    if ctx.standards:
        out += ["| Framework | Control | Reference |", "|:--|:--|:--|"]
        for s in ctx.standards:
            out.append(f"| {s.framework} | {s.control} — {s.title} | [Reference]({s.url}) |")
        out.append("")
    else:
        out += ["_No named standard or benchmark control maps to this finding._", ""]

    # ---- MITRE ATT&CK mapping ------------------------------------------ #
    out += ["##### 🎯 MITRE ATT&CK Mapping", ""]
    if ctx.mitre:
        out += ["| Tactic | Technique | Reference |", "|:--|:--|:--|"]
        for m in ctx.mitre:
            out.append(f"| {m.tactic} | {m.technique_name} (`{m.technique_id}`) | "
                       f"[Reference]({m.url}) |")
        out.append("")
    else:
        out += ["_Not mapped to a MITRE ATT&CK for Containers technique._", ""]

    # ---- impact --------------------------------------------------------- #
    out += ["##### 💥 Impact", "", ctx.impact, ""]

    # ---- remediation ------------------------------------------------------ #
    out += ["##### 🛠️ Remediation", ""]
    if rem.automatable and rem.kubectl_command:
        out += [f"**{rem.title}**", "", "```bash", rem.kubectl_command, "```", ""]
        if rem.alternative_yaml:
            out += ["<details><summary>Alternative — apply via YAML</summary>", "",
                    rem.alternative_yaml, "", "</details>", ""]
        if rem.rollback_commands:
            out += ["<details><summary>Rollback (if the fix causes issues)</summary>",
                    "", "```bash", *rem.rollback_commands, "```", "</details>", ""]
    elif rem.reason_not_automated:
        out += [f"⚠️ **This remediation cannot be safely automated.** "
                f"{rem.reason_not_automated}", ""]
        if rem.remediation_steps:
            out += ["Manual steps:", ""] + [f"{n}. {s}" for n, s in
                                            enumerate(rem.remediation_steps, 1)] + [""]
    elif f.remediation_ref:
        out += [f"_Remediation playbook: `{f.remediation_ref}`_", ""]
    else:
        out += ["_No automated remediation is registered for this rule — review and "
               "fix manually._", ""]
    if rem.references:
        out += ["_References:_ " + " · ".join(f"[{_ref_label(u)}]({u})"
                                              for u in rem.references), ""]

    # ---- validation / reproduction --------------------------------------- #
    out += ["##### ✅ Validation — How to Reproduce / Verify", "",
            "Run before remediating to confirm the finding, and again afterward to "
            "confirm it cleared:", "", "```bash"]
    out += ctx.validation_steps
    out += ["```", ""]
    if rem.validation_commands:
        out += ["_Post-remediation check:_", "", "```bash", *rem.validation_commands,
                "```", ""]

    if rem.warnings:
        out += ["<details><summary>⚠️ Warnings</summary>", ""]
        out += [f"- {w}" for w in rem.warnings]
        out += ["", "</details>", ""]
    if f.evidence:
        out += ["<details><summary>🔎 Evidence</summary>", "", "```json",
                json.dumps(f.evidence, indent=2, default=str), "```", "</details>", ""]
    out.append("---")
    out.append("")
    return out


def _ref_label(url: str) -> str:
    """A short, readable label for a reference URL in a markdown link."""
    for host, label in (("attack.mitre.org", "MITRE ATT&CK"),
                        ("kubernetes.io", "Kubernetes docs"),
                        ("cisecurity.org", "CIS Benchmark"),
                        ("owasp.org", "OWASP"),
                        ("media.defense.gov", "NSA/CISA Guide")):
        if host in url:
            return label
    return "Reference"


# -- fix commands: schema-aware, resource-aware (core/remediation_engine.py) -------- #
def _remediation(f: Finding):
    """Full RemediationResult for a finding — owner-resolved, schema-validated. See
    core/remediation_engine.py; this is the single source of truth every renderer below
    reads from, so markdown/json/sarif/html/terminal can never disagree with each other
    (or with `k8smatrixwarden chat`'s "how do I fix it") about what command is safe to run."""
    from .remediation_engine import generate_remediation
    return generate_remediation(f)


def _fix_commands(f: Finding):
    """Backward-compatible (title, [commands]) view for callers that only want a
    ready-to-run command line, not the full RemediationResult."""
    result = _remediation(f)
    cmds = [result.kubectl_command] if result.automatable and result.kubectl_command else []
    return result.title, cmds


def _fix_text(f: Finding) -> str:
    title, cmds = _fix_commands(f)
    if cmds:
        return f"{title}:\n" + "\n".join(cmds)
    result = _remediation(f)
    if result.reason_not_automated:
        return f"Manual remediation required: {result.reason_not_automated}"
    return f.message


# -- OWASP names (lazy cached) ------------------------------------------ #
_OWASP: Optional[dict] = None


def _owasp_names() -> dict:
    global _OWASP
    if _OWASP is None:
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "taxonomy", "owasp_k8s_top10.json")
        try:
            with open(path, encoding="utf-8") as fh:
                _OWASP = json.load(fh).get("categories", {})
        except Exception:
            _OWASP = {}
    return _OWASP


def _owasp_label(code: Optional[str]) -> str:
    if not code:
        return "—"
    name = _owasp_names().get(code)
    return f"`{code}` {name}" if name else f"`{code}`"


def _by_owasp(findings: list[Finding]) -> dict:
    out: dict[str, int] = {}
    for f in findings:
        if f.severity.weight and f.owasp:
            out[f.owasp] = out.get(f.owasp, 0) + 1
    return out


# -- MITRE ---------------------------------------------------------------- #
def _mitre_short(f: Finding) -> str:
    return f.mitre[0].technique_id if f.mitre else ""


def _mitre_long(f: Finding) -> str:
    return " · ".join(f"{m.tactic.value} → {m.technique_name} (`{m.technique_id}`)"
                      for m in f.mitre)


# -- bars / gauges / math ------------------------------------------------- #
def _frac(n: int, total: int) -> float:
    return (n / total) if total else 0.0


def _bar(frac: float, width: int) -> str:
    frac = max(0.0, min(1.0, frac))
    filled = round(frac * width)
    return "█" * filled + "░" * (width - filled)


def _risk_gauge(risk: float) -> str:
    return f"[{_bar(risk / 10.0, 30)}] {risk}/10"


def _pct(n: int, total: int) -> str:
    return f"{round(100 * n / total)}%" if total else "0%"


def _pct_num(n: int, total: int) -> float:
    return round(100 * n / total, 1) if total else 0.0


def _verdict(rating: str) -> str:
    return {
        "Excellent": "This cluster is in excellent shape. Maintain current controls and "
                     "watch for configuration drift.",
        "Good": "Good posture overall. Clear the remaining medium-severity findings to "
                "tighten it further.",
        "Fair": "Fair posture. Several high-severity issues need prioritized attention "
                "before they are chained together.",
        "Poor": "Poor posture. Critical, likely-exploitable issues are present and should "
                "be remediated promptly.",
        "Critical": "Critical risk. The cluster has severe, likely-exploitable exposures "
                    "requiring emergency remediation.",
    }.get(rating, "")


def _status_badges(result: ScanResult) -> str:
    r = result.risk
    return (f"**Scan** `{result.scan_id}` · **Generated** {result.generated_at} · "
            f"**Mode** `{result.mode}`\n\n"
            f"{r.rating_emoji} **Risk {r.cluster_risk}/10 ({r.rating})** · "
            f"**Security {r.security_score}/100** · "
            f"**{result.total()} findings** · "
            f"**{len(result.resolved_rule_ids)} rules** · "
            f"**scope** `{result.request.scope.describe()}`")


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def _table_cmd(cmd: str) -> str:
    """Make a shell command safe for a single markdown table cell: collapse newlines,
    neutralize inner backticks and pipes, truncate, wrap in one inline code span."""
    one = " ".join(str(cmd).split()).replace("`", "'").replace("|", "\\|")
    return "`" + _truncate(one, 68) + "`"


def _wrap_ids(ids: list[str], per_line: int = 4) -> list[str]:
    lines = []
    for i in range(0, len(ids), per_line):
        lines.append(", ".join(ids[i:i + per_line]))
    return lines


# -- SARIF helpers -------------------------------------------------------- #
def _sarif_help_md(ctx, rem) -> str:
    """GitHub Code Scanning (and most other SARIF viewers) render `help.markdown` in
    preference to `help.text` when both are present — give it the same substance as the
    markdown/html reports rather than the one-line `help.text` fallback."""
    lines = [f"**Impact:** {ctx.impact}", ""]
    if ctx.standards:
        lines.append("**Standards & Benchmark Mapping:**")
        lines += [f"- {s.framework} — {s.control}: [{s.title}]({s.url})" for s in ctx.standards]
        lines.append("")
    if rem.automatable and rem.kubectl_command:
        lines += ["**Remediation:**", "```bash", rem.kubectl_command, "```", ""]
    elif rem.reason_not_automated:
        lines += [f"**Remediation:** cannot be safely automated — {rem.reason_not_automated}", ""]
    if ctx.validation_steps:
        lines += ["**Validation:**", "```bash", *ctx.validation_steps, "```"]
    return "\n".join(lines)



def _sarif_level(sev: Severity) -> str:
    return {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
            "LOW": "note", "INFO": "note"}[sev.label]


def _security_severity(sev: Severity) -> str:
    # GitHub uses a 0-10 CVSS-like scale to sort/threshold.
    return {"CRITICAL": "9.5", "HIGH": "7.5", "MEDIUM": "5.0",
            "LOW": "2.5", "INFO": "0.0"}[sev.label]


def _sarif_tags(f: Finding) -> list[str]:
    tags = ["security", "kubernetes", f.owning_shard]
    if f.owasp:
        tags.append(f"owasp/{f.owasp}")
    for m in f.mitre:
        tags.append(f"mitre/{m.technique_id}")
    for cc in f.cis:
        tags.append(f"cis/{cc}")
    return tags


def _fqn(f: Finding) -> str:
    ns = f.resource.namespace or "-"
    return f"{ns}/{f.resource.kind}/{f.resource.name}"


def _rich_sev(sev: Severity) -> str:
    return {"CRITICAL": "red", "HIGH": "dark_orange", "MEDIUM": "yellow",
            "LOW": "green", "INFO": "grey50"}[sev.label]


def _rich_border(rating: str) -> str:
    return {"Excellent": "green", "Good": "green", "Fair": "yellow",
            "Poor": "dark_orange", "Critical": "red"}.get(rating, "white")


def _esc(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


# -- HTML template -------------------------------------------------------- #
_HTML_CSS = """
:root{--bg:#ffffff;--fg:#1f2328;--muted:#57606a;--card:#f6f8fa;--bd:#d0d7de;
 --crit:#cf222e;--high:#bc4c00;--med:#9a6700;--low:#1a7f37;--accent:#0969da}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#8b949e;
 --card:#161b22;--bd:#30363d;--crit:#f85149;--high:#f0883e;--med:#d29922;--low:#3fb950;
 --accent:#58a6ff}}
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,Segoe UI,Roboto,sans-serif;
 background:var(--bg);color:var(--fg);line-height:1.5}
.wrap{max-width:1000px;margin:0 auto;padding:2rem 1.25rem}
h1{font-size:1.6rem;margin:.2rem 0}.sub{color:var(--muted);font-size:.9rem}
.hero{border:1px solid var(--bd);border-radius:14px;padding:1.25rem;background:var(--card);
 margin:1rem 0}
.gauge{height:12px;border-radius:8px;background:linear-gradient(90deg,#1a7f37,#9a6700,#bc4c00,#cf222e);
 position:relative;margin:.75rem 0}
.gauge .pin{position:absolute;top:-4px;width:4px;height:20px;background:var(--fg);border-radius:2px}
.score{font-size:2rem;font-weight:700}.score.critical,.score.poor{color:var(--crit)}
.score.fair{color:var(--med)}.score.good,.score.excellent{color:var(--low)}
.sev{display:inline-block;padding:.15rem .55rem;margin:.15rem .3rem .15rem 0;border-radius:20px;
 font-size:.85rem;border:1px solid var(--bd);background:var(--bg)}
.filters{margin:1rem 0}.filters button{background:var(--card);color:var(--fg);border:1px solid var(--bd);
 border-radius:20px;padding:.35rem .8rem;margin-right:.4rem;cursor:pointer;font-size:.85rem}
.filters button.on{background:var(--accent);color:#fff;border-color:var(--accent)}
.card{border:1px solid var(--bd);border-left-width:5px;border-radius:10px;padding:.9rem 1rem;
 margin:.75rem 0;background:var(--card)}
.card.critical{border-left-color:var(--crit)}.card.high{border-left-color:var(--high)}
.card.medium{border-left-color:var(--med)}.card.low{border-left-color:var(--low)}
.chead{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem}
.badge{font-size:.72rem;font-weight:700;padding:.1rem .5rem;border-radius:6px;color:#fff}
.badge.critical{background:var(--crit)}.badge.high{background:var(--high)}
.badge.medium{background:var(--med)}.badge.low{background:var(--low)}
.ctitle{font-weight:600}.res{background:var(--bg);border:1px solid var(--bd);border-radius:6px;
 padding:.05rem .4rem;font-size:.82rem;color:var(--muted)}
.csummary{margin:.5rem 0;color:var(--fg);font-size:.95rem}
.cmsg{margin:.5rem 0;color:var(--muted);font-size:.85rem}
.cimpact{margin:.6rem 0;padding:.55rem .7rem;background:var(--bg);border:1px solid var(--bd);
 border-left:3px solid var(--high);border-radius:0 8px 8px 0;font-size:.85rem}
.tags{margin:.4rem 0}.tag{display:inline-block;font-size:.72rem;padding:.1rem .45rem;margin:.12rem .3rem .12rem 0;
 border:1px solid var(--bd);border-radius:20px;color:var(--muted);background:var(--bg)}
.tag.mitre{border-color:var(--accent);color:var(--accent)}
.tag.owasp{border-color:var(--high);color:var(--high)}
.tag.std{border-color:var(--low);color:var(--low)}
.tag.amp{border-color:var(--crit);color:var(--crit);font-weight:600}
details{margin-top:.5rem}summary{cursor:pointer;font-size:.85rem;color:var(--accent)}
pre.cmd{background:var(--bg);border:1px solid var(--bd);border-radius:8px;padding:.7rem;
 overflow:auto;font-size:.82rem;white-space:pre-wrap}
table.ctx-table{width:100%;border-collapse:collapse;margin-top:.4rem;font-size:.82rem}
table.ctx-table td{padding:.35rem .5rem;border-bottom:1px solid var(--bd);vertical-align:top}
table.ctx-table tr:last-child td{border-bottom:none}
table.ctx-table a{color:var(--accent)}
.muted{color:var(--muted);font-size:.85rem}
.callout{margin:.6rem 0;padding:.6rem .75rem;border-radius:0 8px 8px 0;font-size:.85rem}
.callout.warn{background:var(--bg);border:1px solid var(--bd);border-left:3px solid var(--high)}
.refs{margin-top:.5rem;font-size:.78rem;color:var(--muted)}
.refs a{color:var(--accent)}
ul.warnlist{margin:.4rem 0 0;padding-left:1.1rem;font-size:.82rem;color:var(--muted)}
.ok{color:var(--low);font-size:1.1rem}
section.matrix{margin:1.5rem 0}section.matrix>h2,body>h2{font-size:1.2rem;margin:1.5rem 0 .5rem}
footer{color:var(--muted);font-size:.8rem;margin-top:2rem;border-top:1px solid var(--bd);padding-top:1rem}
""" + THREAT_MATRIX_CSS

_HTML_JS = """
document.querySelectorAll('.filters button').forEach(function(b){
 b.onclick=function(){
  document.querySelectorAll('.filters button').forEach(function(x){x.classList.remove('on')});
  b.classList.add('on');var f=b.dataset.f;
  document.querySelectorAll('.card').forEach(function(c){
   c.style.display=(f==='all'||c.classList.contains(f))?'':'none';});};});
"""

_HTML_TMPL = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>K8s Security Report · {scan}</title><style>{css}</style></head>
<body><div class="wrap">
<h1>🛡️ K8s Security Report</h1>
<div class="sub">{cluster} · scan <code>{scan}</code> · {generated} · mode {mode}</div>
<div class="hero">
 <div class="score {rating_class}">{rating_emoji} {risk}/10 <span style="font-size:1rem">({rating})</span></div>
 <div class="gauge"><div class="pin" style="left:{gaugepct}%"></div></div>
 <div>Security score <strong>{sec}/100</strong> · <strong>{total}</strong> findings ·
  <strong>{tactics}/9</strong> MITRE tactics · <strong>{rules}</strong> rules ·
  scope <code>{scope}</code> · selector <code>{selector}</code></div>
 <p>{verdict}</p>
 <div>{chips}</div>
</div>
{matrix}
<h2>🚨 Findings</h2>
<div class="filters">{filters}</div>
{cards}
<footer>Generated by 🛡️ k8smatrixwarden — MITRE ATT&amp;CK-aligned Kubernetes security scanner.</footer>
</div><script>{js}</script></body></html>"""
