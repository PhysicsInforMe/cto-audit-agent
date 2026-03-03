"""
Comparison Report — Confronta due AuditResult e genera un delta report.

Use case:
- "Prima e dopo remediation"
- "Confronto due codebase in due diligence"
"""

from __future__ import annotations

from pathlib import Path

from cto_audit.core.models import AuditResult, Severity


LAYER_NAMES: dict[str, str] = {
    "infra": "Infrastruttura",
    "architecture": "Architettura",
    "security": "Sicurezza",
    "quality": "Qualita Codice",
}


def _delta_str(delta: float) -> str:
    """Formatta un delta con segno."""
    if delta > 0:
        return f"+{delta:.1f}"
    return f"{delta:.1f}"


class ComparisonReporter:
    """Genera un report di confronto tra due audit."""

    def compare(self, before: AuditResult, after: AuditResult) -> str:
        """
        Confronta due AuditResult e produce un report Markdown.

        Args:
            before: Risultato dell'audit precedente (baseline)
            after: Risultato dell'audit successivo (corrente)

        Returns:
            Report Markdown con le differenze
        """
        sections: list[str] = []
        sections.append(self._header(before, after))
        sections.append(self._overall_delta(before, after))
        sections.append(self._layer_deltas(before, after))
        sections.append(self._findings_delta(before, after))
        return "\n".join(sections)

    def save(self, before: AuditResult, after: AuditResult, output_path: Path) -> None:
        """Genera e salva il comparison report su file."""
        content = self.compare(before, after)
        output_path.write_text(content, encoding="utf-8")

    def _header(self, before: AuditResult, after: AuditResult) -> str:
        lines = [
            "# CTO Audit — Comparison Report",
            "",
            f"**Baseline:** {before.metadata.target_path} "
            f"({before.metadata.timestamp.strftime('%Y-%m-%d %H:%M')})",
            f"**Current:** {after.metadata.target_path} "
            f"({after.metadata.timestamp.strftime('%Y-%m-%d %H:%M')})",
            "",
        ]
        return "\n".join(lines)

    def _overall_delta(self, before: AuditResult, after: AuditResult) -> str:
        before_score = before.health_score.overall_score
        after_score = after.health_score.overall_score
        delta = after_score - before_score

        direction = "migliorato" if delta > 0 else "peggiorato" if delta < 0 else "invariato"

        lines = [
            "## Overall Score",
            "",
            f"| | Score | Delta |",
            f"|---|-------|-------|",
            f"| Baseline | {before_score:.0f}/100 | - |",
            f"| Current | {after_score:.0f}/100 | {_delta_str(delta)} |",
            "",
            f"Lo score complessivo e **{direction}** di **{abs(delta):.1f}** punti.",
            "",
        ]
        return "\n".join(lines)

    def _layer_deltas(self, before: AuditResult, after: AuditResult) -> str:
        lines = [
            "## Score per Layer",
            "",
            "| Layer | Baseline | Current | Delta |",
            "|-------|----------|---------|-------|",
        ]

        all_layers = set(before.health_score.layer_scores.keys()) | set(after.health_score.layer_scores.keys())
        for layer_name in ["infra", "architecture", "security", "quality"]:
            if layer_name not in all_layers:
                continue
            display = LAYER_NAMES.get(layer_name, layer_name)
            b_score = before.health_score.layer_scores.get(layer_name)
            a_score = after.health_score.layer_scores.get(layer_name)
            b_val = f"{b_score.score:.0f}" if b_score else "-"
            a_val = f"{a_score.score:.0f}" if a_score else "-"

            if b_score and a_score:
                delta = _delta_str(a_score.score - b_score.score)
            else:
                delta = "N/A"

            lines.append(f"| {display} | {b_val} | {a_val} | {delta} |")

        lines.append("")
        return "\n".join(lines)

    def _findings_delta(self, before: AuditResult, after: AuditResult) -> str:
        """Mostra finding risolti e nuovi."""
        # Raccogli rule_id -> finding per entrambi
        before_rules: set[str] = set()
        after_rules: set[str] = set()

        for ls in before.health_score.layer_scores.values():
            for f in ls.findings:
                if f.severity != Severity.INFO:
                    before_rules.add(f.rule_id)

        for ls in after.health_score.layer_scores.values():
            for f in ls.findings:
                if f.severity != Severity.INFO:
                    after_rules.add(f.rule_id)

        resolved = before_rules - after_rules
        new_issues = after_rules - before_rules
        persistent = before_rules & after_rules

        lines = ["## Finding Delta", ""]

        if resolved:
            lines.append(f"### Risolti ({len(resolved)})")
            lines.append("")
            for r in sorted(resolved):
                lines.append(f"- ~~{r}~~")
            lines.append("")

        if new_issues:
            lines.append(f"### Nuovi ({len(new_issues)})")
            lines.append("")
            for n in sorted(new_issues):
                lines.append(f"- **{n}**")
            lines.append("")

        if persistent:
            lines.append(f"### Persistenti ({len(persistent)})")
            lines.append("")
            for p in sorted(persistent):
                lines.append(f"- {p}")
            lines.append("")

        if not resolved and not new_issues:
            lines.append("Nessuna variazione nei finding rilevati.")
            lines.append("")

        return "\n".join(lines)
