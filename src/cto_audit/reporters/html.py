"""
HTML Report — Report professionale self-contained.

Genera un file HTML con CSS inline (zero dipendenze esterne).
Stessa struttura del board report: header, executive summary,
score, compliance, finding, evidence.

CSS print-friendly con @media print.
"""

from __future__ import annotations

import html
from pathlib import Path

from cto_audit.core.models import AuditDelta, AuditResult, Severity


_SCORE_LABEL_MAP = [
    (80, "Buono", "#22c55e"),
    (60, "Attenzione", "#eab308"),
    (40, "Insufficiente", "#f97316"),
    (0, "Critico", "#ef4444"),
]

LAYER_NAMES: dict[str, str] = {
    "infra": "Infrastruttura",
    "architecture": "Architettura",
    "security": "Sicurezza",
    "quality": "Qualita Codice",
}

SEVERITY_COLORS: dict[str, str] = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
    "info": "#6b7280",
}


def _score_info(score: float) -> tuple[str, str]:
    """Restituisce (label, colore) per uno score."""
    for threshold, label, color in _SCORE_LABEL_MAP:
        if score >= threshold:
            return label, color
    return "Critico", "#ef4444"


def _esc(text: str) -> str:
    """Escape HTML."""
    return html.escape(str(text))


CSS = """
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       color: #1e293b; background: #f8fafc; line-height: 1.6; padding: 2rem; }
.container { max-width: 960px; margin: 0 auto; }
h1 { font-size: 1.8rem; margin-bottom: 0.5rem; }
h2 { font-size: 1.3rem; margin: 2rem 0 1rem; border-bottom: 2px solid #e2e8f0; padding-bottom: 0.4rem; }
h3 { font-size: 1.1rem; margin: 1.5rem 0 0.5rem; }
.meta { color: #64748b; font-size: 0.9rem; margin-bottom: 1.5rem; }
.meta span { margin-right: 1.5rem; }
.score-card { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0; }
.score-box { background: white; border-radius: 8px; padding: 1rem 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1);
             text-align: center; min-width: 160px; flex: 1; }
.score-box .value { font-size: 2rem; font-weight: 700; }
.score-box .label { font-size: 0.85rem; color: #64748b; margin-top: 0.25rem; }
.bar-bg { background: #e2e8f0; border-radius: 4px; height: 8px; margin-top: 0.5rem; }
.bar-fill { height: 8px; border-radius: 4px; transition: width 0.3s; }
table { width: 100%; border-collapse: collapse; margin: 0.5rem 0 1rem; font-size: 0.9rem; }
th { text-align: left; background: #f1f5f9; padding: 0.5rem 0.75rem; border-bottom: 2px solid #e2e8f0; }
td { padding: 0.5rem 0.75rem; border-bottom: 1px solid #e2e8f0; }
tr:hover td { background: #f8fafc; }
.badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem;
         font-weight: 600; color: white; }
.summary-text { background: white; border-radius: 8px; padding: 1.25rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                margin: 0.5rem 0 1rem; }
.footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #e2e8f0;
          color: #94a3b8; font-size: 0.8rem; text-align: center; }
@media print {
  body { background: white; padding: 0; }
  .score-box { box-shadow: none; border: 1px solid #e2e8f0; }
  .summary-text { box-shadow: none; border: 1px solid #e2e8f0; }
}
"""


MAX_INFO_PER_LAYER = 5


class HTMLReporter:
    """Report HTML self-contained con CSS inline."""

    def __init__(self, detailed: bool = False) -> None:
        self.detailed = detailed

    def report(self, result: AuditResult, delta: AuditDelta | None = None) -> str:
        """Genera il report HTML completo."""
        sections = [
            self._head(),
            '<body><div class="container">',
            self._header(result),
            self._executive_summary(result),
            self._score_cards(result),
        ]

        if delta:
            sections.append(self._delta_section(delta))

        sections.extend([
            self._findings_table(result),
            self._compliance_section(result),
            self._evidence_section(result),
            self._footer(result),
            "</div></body></html>",
        ])
        return "\n".join(sections)

    def save(
        self,
        result: AuditResult,
        output_path: Path,
        delta: AuditDelta | None = None,
    ) -> None:
        """Genera e salva il report su file."""
        content = self.report(result, delta=delta)
        output_path.write_text(content, encoding="utf-8")

    def _head(self) -> str:
        return (
            '<!DOCTYPE html>\n<html lang="it">\n<head>\n'
            '<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            "<title>CTO Audit Report</title>\n"
            f"<style>{CSS}</style>\n"
            "</head>"
        )

    def _header(self, result: AuditResult) -> str:
        meta = result.metadata
        stack = result.stack_info
        parts = ["<h1>CTO Audit Report</h1>", '<div class="meta">']

        if stack.languages:
            lang_parts = [
                f"{lang.capitalize()} ({pct:.0%})"
                for lang, pct in sorted(stack.languages.items(), key=lambda x: -x[1])[:5]
            ]
            parts.append(f"<span><b>Stack:</b> {_esc(', '.join(lang_parts))}</span>")

        if stack.frameworks:
            parts.append(f"<span><b>Framework:</b> {_esc(', '.join(stack.frameworks[:8]))}</span>")

        parts.append(f"<span><b>Profilo:</b> {_esc(meta.scoring_profile)}</span>")
        if meta.project_type:
            pt_label = meta.project_type.replace("_", " ").title()
            pt_conf = f" ({meta.project_type_confidence:.0%})" if meta.project_type_confidence else ""
            parts.append(f"<span><b>Tipo progetto:</b> {_esc(pt_label)}{_esc(pt_conf)}</span>")
        parts.append(f"<span><b>Data:</b> {meta.timestamp.strftime('%Y-%m-%d %H:%M')}</span>")
        parts.append("</div>")
        return "\n".join(parts)

    def _executive_summary(self, result: AuditResult) -> str:
        score = result.health_score.overall_score
        label, color = _score_info(score)

        critical = sum(
            1 for ls in result.health_score.layer_scores.values()
            for f in ls.findings if f.severity == Severity.CRITICAL
        )
        high = sum(
            1 for ls in result.health_score.layer_scores.values()
            for f in ls.findings if f.severity == Severity.HIGH
        )

        lines = [
            "<h2>Executive Summary</h2>",
            '<div class="summary-text">',
            f"<p>Il codebase ha ottenuto uno score di <b>{score:.0f}/100</b> "
            f'(<span style="color:{color}">{label}</span>).</p>',
        ]

        if critical > 0:
            lines.append(
                f"<p>Rilevati <b>{critical} problemi critici</b> che richiedono attenzione immediata.</p>"
            )
        if high > 0:
            lines.append(f"<p>Inoltre <b>{high} problemi ad alta severita</b> da affrontare a breve.</p>")
        if critical == 0 and high == 0:
            lines.append("<p>Non sono stati rilevati problemi critici o ad alta severita.</p>")

        lines.append("</div>")
        return "\n".join(lines)

    def _score_cards(self, result: AuditResult) -> str:
        lines = ["<h2>Score per Layer</h2>", '<div class="score-card">']

        # Overall
        score = result.health_score.overall_score
        _, color = _score_info(score)
        lines.append(
            f'<div class="score-box">'
            f'<div class="value" style="color:{color}">{score:.0f}</div>'
            f'<div class="label">Overall</div>'
            f'<div class="bar-bg"><div class="bar-fill" style="width:{score}%;background:{color}"></div></div>'
            f"</div>"
        )

        for layer_name in ["infra", "architecture", "security", "quality"]:
            if layer_name not in result.health_score.layer_scores:
                continue
            ls = result.health_score.layer_scores[layer_name]
            display = LAYER_NAMES.get(layer_name, layer_name)
            _, lcolor = _score_info(ls.score)
            conf_color = "#22c55e" if ls.confidence >= 0.7 else "#eab308" if ls.confidence >= 0.4 else "#ef4444"
            lines.append(
                f'<div class="score-box">'
                f'<div class="value" style="color:{lcolor}">{ls.score:.0f}</div>'
                f'<div class="label">{_esc(display)}</div>'
                f'<div class="bar-bg"><div class="bar-fill" style="width:{ls.score}%;background:{lcolor}"></div></div>'
                f'<div class="label" style="color:{conf_color}">Confidence: {ls.confidence:.0%}</div>'
                f"</div>"
            )

        lines.append("</div>")
        return "\n".join(lines)

    def _delta_section(self, delta: AuditDelta) -> str:
        """Genera la sezione delta rispetto all'ultimo audit."""
        sign = "+" if delta.score_delta > 0 else ""
        if delta.score_delta > 0:
            color = "#22c55e"
            direction = "migliorato"
        elif delta.score_delta < 0:
            color = "#ef4444"
            direction = "peggiorato"
        else:
            color = "#eab308"
            direction = "invariato"

        lines = [
            "<h2>Delta rispetto all'ultimo audit</h2>",
            '<div class="summary-text">',
            f"<p>Ultimo audit: <b>{_esc(delta.previous_timestamp.strftime('%Y-%m-%d %H:%M'))}</b> "
            f"({delta.days_since_previous:.1f} giorni fa)</p>",
            f'<p>Score: <b>{delta.previous_score:.0f}</b> &rarr; <b>{delta.current_score:.0f}</b> '
            f'(<span style="color:{color}">{sign}{delta.score_delta:.1f}</span>, {direction})</p>',
        ]

        # Layer deltas
        lines.append("<table><tr><th>Layer</th><th>Delta</th></tr>")
        for layer_name in ["infra", "architecture", "security", "quality"]:
            if layer_name in delta.layer_deltas:
                ld = delta.layer_deltas[layer_name]
                ld_sign = "+" if ld > 0 else ""
                ld_color = "#22c55e" if ld > 0 else "#ef4444" if ld < 0 else "#6b7280"
                display = LAYER_NAMES.get(layer_name, layer_name)
                lines.append(
                    f'<tr><td>{_esc(display)}</td>'
                    f'<td style="color:{ld_color}">{ld_sign}{ld:.1f}</td></tr>'
                )
        lines.append("</table>")

        # Finding summary
        if delta.resolved_findings:
            lines.append(
                f'<p style="color:#22c55e"><b>Risolti ({len(delta.resolved_findings)}):</b> '
                + ", ".join(_esc(r) for r in delta.resolved_findings) + "</p>"
            )
        if delta.new_findings:
            lines.append(
                f'<p style="color:#ef4444"><b>Nuovi ({len(delta.new_findings)}):</b> '
                + ", ".join(_esc(n) for n in delta.new_findings) + "</p>"
            )
        if delta.persistent_findings:
            lines.append(
                f"<p><b>Persistenti ({len(delta.persistent_findings)}):</b> "
                + ", ".join(_esc(p) for p in delta.persistent_findings) + "</p>"
            )

        lines.append("</div>")
        return "\n".join(lines)

    def _findings_table(self, result: AuditResult) -> str:
        lines = ["<h2>Finding</h2>"]

        for layer_name in ["infra", "architecture", "security", "quality"]:
            if layer_name not in result.health_score.layer_scores:
                continue
            ls = result.health_score.layer_scores[layer_name]

            if self.detailed:
                visible = ls.findings
            else:
                non_info = [f for f in ls.findings if f.severity != Severity.INFO]
                info = [f for f in ls.findings if f.severity == Severity.INFO]
                visible = non_info + info[:MAX_INFO_PER_LAYER]
                info_skipped = len(info) - min(len(info), MAX_INFO_PER_LAYER)

            if not visible:
                continue

            display = LAYER_NAMES.get(layer_name, layer_name)
            lines.append(f"<h3>{_esc(display)}</h3>")
            lines.append("<table><tr><th>Severita</th><th>Rule ID</th><th>Titolo</th><th>File</th></tr>")

            for f in visible:
                sev = f.severity.value
                color = SEVERITY_COLORS.get(sev, "#6b7280")
                lines.append(
                    f'<tr><td><span class="badge" style="background:{color}">{sev.upper()}</span></td>'
                    f"<td>{_esc(f.rule_id)}</td>"
                    f"<td>{_esc(f.title)}</td>"
                    f"<td>{_esc(f.file_path or '-')}</td></tr>"
                )

            if not self.detailed and info_skipped > 0:
                lines.append(
                    f'<tr><td colspan="4" style="text-align:center;color:#6b7280;font-style:italic">'
                    f"...e {info_skipped} altri finding informativi (usa --detailed per vederli tutti)"
                    f"</td></tr>"
                )

            lines.append("</table>")

        return "\n".join(lines)

    def _compliance_section(self, result: AuditResult) -> str:
        compliance_results = result.health_score.compliance_results
        if not compliance_results:
            return ""

        lines = ["<h2>Compliance</h2>"]

        for cr in compliance_results:
            lines.append(f"<h3>{_esc(cr.profile_name)}</h3>")
            lines.append(
                f"<p><b>{cr.checks_satisfied}/{cr.checks_total}</b> controlli soddisfatti"
            )
            if cr.checks_partial > 0:
                lines.append(f" | <b>{cr.checks_partial}</b> parziali")
            if cr.checks_not_satisfied > 0:
                lines.append(f" | <b>{cr.checks_not_satisfied}</b> non soddisfatti")
            lines.append("</p>")

            lines.append(
                "<table><tr><th>Controllo</th><th>Articolo</th>"
                "<th>Stato</th><th>Regole Violate</th></tr>"
            )

            status_colors = {
                "satisfied": "#22c55e",
                "partial": "#eab308",
                "failed": "#ef4444",
            }
            status_labels = {
                "satisfied": "PASS",
                "partial": "PARTIAL",
                "failed": "FAIL",
            }

            for detail in cr.details:
                status = detail.get("status", "")
                color = status_colors.get(status, "#6b7280")
                label = status_labels.get(status, "?")
                triggered = ", ".join(detail.get("triggered_rules", [])) or "-"
                lines.append(
                    f"<tr><td>{_esc(detail.get('title', ''))}</td>"
                    f"<td>{_esc(detail.get('article_ref', ''))}</td>"
                    f'<td><span class="badge" style="background:{color}">{label}</span></td>'
                    f"<td>{_esc(triggered)}</td></tr>"
                )

            lines.append("</table>")

        return "\n".join(lines)

    def _evidence_section(self, result: AuditResult) -> str:
        has_evidence = any(
            ls.evidence_chain
            for ls in result.health_score.layer_scores.values()
        )
        if not has_evidence:
            return ""

        lines = [
            "<h2>Evidence Chain</h2>",
            "<table><tr><th>Rule ID</th><th>Layer</th><th>Weight</th>"
            "<th>Penalty</th><th>Framework</th></tr>",
        ]

        for layer_name in ["infra", "architecture", "security", "quality"]:
            if layer_name not in result.health_score.layer_scores:
                continue
            ls = result.health_score.layer_scores[layer_name]
            display = LAYER_NAMES.get(layer_name, layer_name)
            for ev in ls.evidence_chain:
                if not self.detailed and ev.weight == 0 and ev.penalty == 0:
                    continue
                fw = ev.framework_ref or "-"
                lines.append(
                    f"<tr><td>{_esc(ev.rule_id)}</td><td>{_esc(display)}</td>"
                    f"<td>{ev.weight:.2f}</td><td>{ev.penalty:.1f}</td>"
                    f"<td>{_esc(fw)}</td></tr>"
                )

        lines.append("</table>")
        return "\n".join(lines)

    def _footer(self, result: AuditResult) -> str:
        meta = result.metadata
        return (
            '<div class="footer">'
            f"CTO Audit Agent v{_esc(meta.tool_version)} &mdash; "
            f"{meta.timestamp.strftime('%Y-%m-%d %H:%M')}"
            "</div>"
        )
