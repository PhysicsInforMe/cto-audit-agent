"""
Markdown Reporter — Generazione report completo in formato Markdown.

Produce un file .md con:
- Intestazione con stack e metadati
- Health Score e score per layer
- Tabella finding per layer con severità e descrizione
- Catena di evidenze
- Azioni prioritarie
"""

from __future__ import annotations

from pathlib import Path

from cto_audit.core.models import (
    AuditDelta,
    AuditResult,
    Finding,
    HealthScore,
    Severity,
)


def _severity_emoji(severity: str) -> str:
    """Restituisce un indicatore testuale per la severità."""
    return {
        "critical": "[CRIT]",
        "high": "[HIGH]",
        "medium": "[MED]",
        "low": "[LOW]",
        "info": "[INFO]",
    }.get(severity, "[???]")


def _score_label(score: float) -> str:
    """Etichetta testuale per lo score."""
    if score >= 80:
        return "Buono"
    elif score >= 60:
        return "Attenzione"
    elif score >= 40:
        return "Insufficiente"
    else:
        return "Critico"


LAYER_NAMES: dict[str, str] = {
    "infra": "Infrastruttura",
    "architecture": "Architettura",
    "security": "Sicurezza",
    "quality": "Qualita Codice",
}


def _confidence_badge_md(confidence: float) -> str:
    """Restituisce un badge testuale per la confidence in Markdown."""
    pct = f"{confidence:.0%}"
    if confidence >= 0.7:
        return f"{pct} OK"
    elif confidence >= 0.4:
        return f"{pct} !"
    else:
        return f"{pct} !!"


# Massimo INFO finding mostrati per layer in modalita' default (non --detailed)
MAX_INFO_PER_LAYER = 5


class MarkdownReporter:
    """
    Reporter per output Markdown.

    Produce un report completo in formato Markdown, salvabile su file.
    In modalita' default, i finding INFO sono cappati e le evidence a peso
    zero sono omesse. Con --detailed, tutto e' incluso.
    """

    def __init__(self, detailed: bool = False) -> None:
        self.detailed = detailed

    def report(self, result: AuditResult, delta: AuditDelta | None = None) -> str:
        """
        Genera il report in formato Markdown.

        Args:
            result: Risultato dell'audit completo
            delta: Delta rispetto all'audit precedente (se disponibile)

        Returns:
            Stringa Markdown completa
        """
        sections: list[str] = []

        sections.append(self._header(result))
        sections.append(self._health_score(result.health_score))
        sections.append(self._layer_scores(result.health_score))

        if delta:
            sections.append(self._delta_section(delta))

        sections.append(self._top_actions(result.health_score))
        sections.append(self._findings_detail(result.health_score))
        sections.append(self._evidence_chain(result.health_score))
        sections.append(self._compliance(result))
        sections.append(self._footer(result))

        return "\n".join(sections)

    def save(
        self,
        result: AuditResult,
        output_path: Path,
        delta: AuditDelta | None = None,
    ) -> None:
        """
        Genera e salva il report Markdown su file.

        Args:
            result: Risultato dell'audit
            output_path: Percorso del file di output
            delta: Delta rispetto all'audit precedente
        """
        content = self.report(result, delta=delta)
        output_path.write_text(content, encoding="utf-8")

    def _header(self, result: AuditResult) -> str:
        """Genera l'intestazione del report."""
        stack = result.stack_info
        meta = result.metadata
        lines = ["# CTO Audit Report", ""]

        if stack.languages:
            lang_parts = [
                f"{lang.capitalize()} ({pct:.0%})"
                for lang, pct in sorted(stack.languages.items(), key=lambda x: -x[1])[:5]
            ]
            lines.append(f"**Stack:** {', '.join(lang_parts)}")

        if stack.frameworks:
            lines.append(f"**Framework:** {', '.join(stack.frameworks[:8])}")

        if stack.infra_type:
            lines.append(f"**Infra:** {', '.join(stack.infra_type[:8])}")

        lines.append(f"**File analizzati:** {len(result.classifications)}")
        lines.append(f"**Profilo scoring:** {meta.scoring_profile}")
        if meta.project_type:
            pt_label = meta.project_type.replace("_", " ").title()
            pt_conf = f" ({meta.project_type_confidence:.0%})" if meta.project_type_confidence else ""
            lines.append(f"**Tipo progetto:** {pt_label}{pt_conf}")
        lines.append(f"**Target:** {meta.target_path}")
        lines.append("")

        return "\n".join(lines)

    def _health_score(self, health: HealthScore) -> str:
        """Genera la sezione health score."""
        score = health.overall_score
        label = _score_label(score)
        return f"## Health Score: {score:.0f}/100 — {label}\n"

    def _layer_scores(self, health: HealthScore) -> str:
        """Genera la tabella degli score per layer."""
        lines = [
            "## Score per Layer",
            "",
            "| Layer | Score | Confidence | Stato | Finding |",
            "|-------|-------|------------|-------|---------|",
        ]

        for layer_name in ["infra", "architecture", "security", "quality"]:
            if layer_name not in health.layer_scores:
                continue
            ls = health.layer_scores[layer_name]
            display = LAYER_NAMES.get(layer_name, layer_name)
            label = _score_label(ls.score)
            num_findings = len([f for f in ls.findings if f.severity != Severity.INFO])
            conf_badge = _confidence_badge_md(ls.confidence)
            lines.append(
                f"| {display} | {ls.score:.0f}/100 | {conf_badge} | {label} | {num_findings} |"
            )

        lines.append("")
        return "\n".join(lines)

    def _top_actions(self, health: HealthScore) -> str:
        """Genera la sezione top 5 azioni prioritarie."""
        # Raccogli tutti i finding non-info con penalità
        action_items: list[tuple[float, Finding]] = []
        for layer_name, ls in health.layer_scores.items():
            for i, finding in enumerate(ls.findings):
                if finding.severity == Severity.INFO:
                    continue
                penalty = 0.0
                if i < len(ls.evidence_chain):
                    penalty = abs(ls.evidence_chain[i].penalty)
                action_items.append((penalty, finding))

        action_items.sort(key=lambda x: x[0], reverse=True)
        top_5 = action_items[:5]

        if not top_5:
            return "## Azioni Prioritarie\n\nNessuna azione richiesta.\n"

        lines = ["## Top 5 Azioni Prioritarie", ""]
        for idx, (penalty, finding) in enumerate(top_5, 1):
            sev = _severity_emoji(finding.severity.value)
            lines.append(f"{idx}. {sev} **{finding.title}**")
            if finding.description:
                # Prima riga della descrizione come sommario
                desc_line = finding.description.split("\n")[0][:120]
                lines.append(f"   {desc_line}")
            if finding.framework_ref:
                lines.append(f"   Riferimento: {finding.framework_ref}")
            lines.append("")

        return "\n".join(lines)

    def _delta_section(self, delta: AuditDelta) -> str:
        """Genera la sezione delta rispetto all'ultimo audit."""
        sign = "+" if delta.score_delta > 0 else ""
        direction = "migliorato" if delta.score_delta > 0 else "peggiorato" if delta.score_delta < 0 else "invariato"

        lines = [
            "## Delta rispetto all'ultimo audit",
            "",
            f"Ultimo audit: {delta.previous_timestamp.strftime('%Y-%m-%d %H:%M')} "
            f"({delta.days_since_previous:.1f} giorni fa)",
            "",
            f"**Score:** {delta.previous_score:.0f} -> {delta.current_score:.0f} "
            f"({sign}{delta.score_delta:.1f}, {direction})",
            "",
            "| Layer | Delta |",
            "|-------|-------|",
        ]

        for layer_name in ["infra", "architecture", "security", "quality"]:
            if layer_name in delta.layer_deltas:
                ld = delta.layer_deltas[layer_name]
                ld_sign = "+" if ld > 0 else ""
                display = LAYER_NAMES.get(layer_name, layer_name)
                lines.append(f"| {display} | {ld_sign}{ld:.1f} |")

        lines.append("")

        if delta.resolved_findings:
            lines.append(f"**Risolti ({len(delta.resolved_findings)}):** "
                         + ", ".join(f"~~{r}~~" for r in delta.resolved_findings))
        if delta.new_findings:
            lines.append(f"**Nuovi ({len(delta.new_findings)}):** "
                         + ", ".join(f"**{n}**" for n in delta.new_findings))
        if delta.persistent_findings:
            lines.append(f"**Persistenti ({len(delta.persistent_findings)}):** "
                         + ", ".join(delta.persistent_findings))

        lines.append("")
        return "\n".join(lines)

    def _findings_detail(self, health: HealthScore) -> str:
        """Genera il dettaglio dei finding per layer.

        In default mode, i finding INFO sono cappati a MAX_INFO_PER_LAYER
        per layer con un riepilogo "...e N altri". Con --detailed tutto incluso.
        """
        lines = ["## Dettaglio Finding", ""]

        for layer_name in ["infra", "architecture", "security", "quality"]:
            if layer_name not in health.layer_scores:
                continue
            ls = health.layer_scores[layer_name]
            if not ls.findings:
                continue

            display = LAYER_NAMES.get(layer_name, layer_name)
            lines.append(f"### {display}")
            lines.append("")
            lines.append("| Severita | Rule ID | Titolo | File |")
            lines.append("|----------|---------|--------|------|")

            info_count = 0
            info_skipped = 0
            for finding in ls.findings:
                if finding.severity == Severity.INFO and not self.detailed:
                    info_count += 1
                    if info_count > MAX_INFO_PER_LAYER:
                        info_skipped += 1
                        continue

                sev = finding.severity.value.upper()
                file_path = finding.file_path or "-"
                lines.append(
                    f"| {sev} | {finding.rule_id} | {finding.title} | {file_path} |"
                )

            if info_skipped > 0:
                lines.append(
                    f"| INFO | - | *...e {info_skipped} altri finding informativi "
                    f"(usa --detailed per vederli tutti)* | - |"
                )
            lines.append("")

        return "\n".join(lines)

    def _evidence_chain(self, health: HealthScore) -> str:
        """Genera la sezione catena di evidenze.

        In default mode, omette righe con weight=0 e penalty=0 (INFO finding).
        Con --detailed tutto incluso.
        """
        lines = ["## Catena di Evidenze", ""]

        for layer_name in ["infra", "architecture", "security", "quality"]:
            if layer_name not in health.layer_scores:
                continue
            ls = health.layer_scores[layer_name]
            if not ls.evidence_chain:
                continue

            display = LAYER_NAMES.get(layer_name, layer_name)
            lines.append(f"### {display} (Score: {ls.score:.0f}/100)")
            lines.append("")
            lines.append("| Rule ID | Weight | Penalty | Framework |")
            lines.append("|---------|--------|---------|-----------|")

            skipped = 0
            for ev in ls.evidence_chain:
                if not self.detailed and ev.weight == 0 and ev.penalty == 0:
                    skipped += 1
                    continue
                fw = ev.framework_ref or "-"
                lines.append(
                    f"| {ev.rule_id} | {ev.weight:.2f} | {ev.penalty:.1f} | {fw} |"
                )

            if skipped > 0:
                lines.append(
                    f"| - | - | - | *{skipped} evidence informativi omessi* |"
                )
            lines.append("")

        return "\n".join(lines)

    def _compliance(self, result: AuditResult) -> str:
        """Genera la sezione compliance."""
        compliance_results = result.health_score.compliance_results
        if not compliance_results:
            return ""

        lines = ["## Compliance", ""]

        for cr in compliance_results:
            lines.append(f"### {cr.profile_name}")
            lines.append("")
            lines.append(
                f"Controlli soddisfatti: **{cr.checks_satisfied}/{cr.checks_total}** "
                f"| Parziali: **{cr.checks_partial}** "
                f"| Non soddisfatti: **{cr.checks_not_satisfied}**"
            )
            lines.append("")

            lines.append("| Controllo | Articolo | Stato | Regole Violate |")
            lines.append("|-----------|----------|-------|----------------|")

            status_label = {
                "satisfied": "PASS",
                "partial": "PARTIAL",
                "failed": "FAIL",
            }

            for detail in cr.details:
                status = status_label.get(detail.get("status", ""), "?")
                triggered = ", ".join(detail.get("triggered_rules", [])) or "-"
                lines.append(
                    f"| {detail.get('title', '')} | "
                    f"{detail.get('article_ref', '')} | "
                    f"{status} | {triggered} |"
                )

            lines.append("")

        return "\n".join(lines)

    def _footer(self, result: AuditResult) -> str:
        """Genera il footer del report."""
        meta = result.metadata
        return (
            "---\n\n"
            f"*Report generato da CTO Audit Agent v{meta.tool_version} "
            f"il {meta.timestamp.strftime('%Y-%m-%d %H:%M')}*\n"
        )
