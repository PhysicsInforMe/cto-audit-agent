"""
Board Report — Report deterministico per board/management.

Sezioni:
1. Header (stack, contesto, maturity)
2. Executive Summary (template-based, sostituibile da LLM)
3. Azioni Prioritarie (top 5 da what-if + KB)
4. Red Flags (finding critical/high con risk_business dal KB)
5. Punti di Forza (layer a 100, best practice rilevate)
6. Score Details (layer scores, evidence chain)
7. Footer

Funziona 100% senza LLM.
"""

from __future__ import annotations

from pathlib import Path

from cto_audit.core.models import (
    AuditResult,
    Severity,
)
from cto_audit.remediation.context import MaturityLevel, ProjectContext
from cto_audit.remediation.loader import RemediationLoader
from cto_audit.remediation.models import RemediationPipelineResult, WhatIfResult


LAYER_NAMES: dict[str, str] = {
    "infra": "Infrastruttura",
    "architecture": "Architettura",
    "security": "Sicurezza",
    "quality": "Qualita Codice",
}

MATURITY_LABELS: dict[str, str] = {
    "prototype": "Prototype",
    "mvp": "MVP",
    "production": "Production",
}

_SCORE_LABEL_MAP = [
    (80, "Buono"),
    (60, "Attenzione"),
    (40, "Insufficiente"),
    (0, "Critico"),
]


def _score_label(score: float) -> str:
    for threshold, label in _SCORE_LABEL_MAP:
        if score >= threshold:
            return label
    return "Critico"


def _severity_icon(sev: str) -> str:
    return {
        "critical": "[CRIT]",
        "high": "[HIGH]",
        "medium": "[MED]",
        "low": "[LOW]",
        "info": "[INFO]",
    }.get(sev, "[???]")


class BoardReporter:
    """
    Report deterministico per board/management.

    Funziona 100% senza LLM. Se executive_summary_override e impostato
    (tipicamente da LLM), lo usa al posto del template.
    """

    def __init__(
        self,
        kb_loader: RemediationLoader | None = None,
        executive_summary_override: str | None = None,
    ) -> None:
        self._kb = kb_loader
        self._exec_override = executive_summary_override

    def report(self, result: AuditResult) -> str:
        """Genera il board report completo in Markdown."""
        remediation = result.remediation if hasattr(result, "remediation") and result.remediation else None
        context = remediation.context if remediation else None
        whatif_results = remediation.whatif_results if remediation else []

        # Se c'e un override LLM dall'InterpretationAgent, usalo
        exec_summary = self._exec_override
        if not exec_summary and remediation and remediation.executive_summary:
            exec_summary = remediation.executive_summary

        sections: list[str] = []
        sections.append(self._header(result, context))
        sections.append(self._executive_summary(result, context, exec_summary))
        sections.append(self._priority_actions(result, whatif_results))
        sections.append(self._red_flags(result))
        sections.append(self._strengths(result, context))
        sections.append(self._score_details(result))
        sections.append(self._compliance(result))
        sections.append(self._footer(result))

        return "\n".join(sections)

    def save(self, result: AuditResult, output_path: Path) -> None:
        """Genera e salva il board report su file."""
        content = self.report(result)
        output_path.write_text(content, encoding="utf-8")

    # --- Sezioni ---

    def _header(self, result: AuditResult, context: ProjectContext | None) -> str:
        stack = result.stack_info
        meta = result.metadata
        lines = ["# CTO Audit — Board Report", ""]

        if stack.languages:
            lang_parts = [
                f"{lang.capitalize()} ({pct:.0%})"
                for lang, pct in sorted(stack.languages.items(), key=lambda x: -x[1])[:5]
            ]
            lines.append(f"**Stack:** {', '.join(lang_parts)}")

        if stack.frameworks:
            lines.append(f"**Framework:** {', '.join(stack.frameworks[:8])}")

        if context:
            maturity_label = MATURITY_LABELS.get(context.maturity_level.value, context.maturity_level.value)
            lines.append(f"**Maturita progetto:** {maturity_label}")
            lines.append(f"**Team stimato:** {context.estimated_team_size} sviluppatori")
            lines.append(f"**File analizzati:** {context.total_files}")
            lines.append(f"**Righe di codice:** {context.total_loc:,}")
        else:
            lines.append(f"**File analizzati:** {len(result.classifications)}")

        lines.append(f"**Profilo scoring:** {meta.scoring_profile}")
        lines.append("")
        return "\n".join(lines)

    def _executive_summary(
        self,
        result: AuditResult,
        context: ProjectContext | None,
        override: str | None,
    ) -> str:
        lines = ["## Executive Summary", ""]

        if override:
            lines.append(override)
            lines.append("")
            return "\n".join(lines)

        # Template deterministico
        score = result.health_score.overall_score
        label = _score_label(score)

        lines.append(f"Il codebase ha ottenuto uno score di **{score:.0f}/100** ({label}).")

        if context:
            maturity = MATURITY_LABELS.get(context.maturity_level.value, context.maturity_level.value)
            lines.append(
                f"Il progetto si trova a livello **{maturity}** con un team stimato di "
                f"**{context.estimated_team_size}** sviluppatori."
            )

        # Conta finding per severita
        critical_count = 0
        high_count = 0
        for ls in result.health_score.layer_scores.values():
            for f in ls.findings:
                if f.severity == Severity.CRITICAL:
                    critical_count += 1
                elif f.severity == Severity.HIGH:
                    high_count += 1

        if critical_count > 0:
            lines.append(
                f"Sono stati rilevati **{critical_count} problemi critici** che richiedono "
                f"attenzione immediata."
            )
        if high_count > 0:
            lines.append(
                f"Ci sono inoltre **{high_count} problemi ad alta severita** da affrontare "
                f"a breve termine."
            )
        if critical_count == 0 and high_count == 0:
            lines.append("Non sono stati rilevati problemi critici o ad alta severita.")

        lines.append("")
        return "\n".join(lines)

    def _priority_actions(
        self,
        result: AuditResult,
        whatif_results: list[WhatIfResult],
    ) -> str:
        lines = ["## Azioni Prioritarie", ""]

        if not whatif_results:
            # Fallback: top 5 finding per penalita
            lines.append("Nessuna simulazione what-if disponibile.")
            lines.append("")
            return "\n".join(lines)

        top_5 = whatif_results[:5]

        lines.append("| # | Regola | Delta Score | Effort | Impatto/Effort |")
        lines.append("|---|--------|-------------|--------|----------------|")

        for idx, wif in enumerate(top_5, 1):
            effort_str = wif.effort.t_shirt if wif.effort else "-"
            hours_str = f"{wif.effort.min_hours}-{wif.effort.max_hours}h" if wif.effort else "-"
            lines.append(
                f"| {idx} | {wif.rule_id} | +{wif.delta:.1f} | "
                f"{effort_str} ({hours_str}) | {wif.impact_effort_ratio:.2f} |"
            )

        lines.append("")

        # Dettaglio per ogni azione
        for idx, wif in enumerate(top_5, 1):
            kb_entry = self._kb.get(wif.rule_id) if self._kb else None
            if kb_entry:
                lines.append(f"### {idx}. {wif.rule_id}")
                lines.append(f"**Rischio business:** {kb_entry.risk_business.strip()}")
                lines.append("")
                lines.append("**Remediation:**")
                for step in kb_entry.remediation_steps:
                    lines.append(f"- {step}")
                lines.append("")

        return "\n".join(lines)

    def _red_flags(self, result: AuditResult) -> str:
        lines = ["## Red Flags", ""]

        red_flags = []
        for ls in result.health_score.layer_scores.values():
            for f in ls.findings:
                if f.severity in (Severity.CRITICAL, Severity.HIGH):
                    red_flags.append(f)

        if not red_flags:
            lines.append("Nessun red flag rilevato.")
            lines.append("")
            return "\n".join(lines)

        # Ordina per severita (critical first)
        red_flags.sort(key=lambda f: (0 if f.severity == Severity.CRITICAL else 1))

        for f in red_flags:
            icon = _severity_icon(f.severity.value)
            lines.append(f"- {icon} **{f.title}** ({f.rule_id})")
            kb_entry = self._kb.get(f.rule_id) if self._kb else None
            if kb_entry:
                lines.append(f"  *{kb_entry.risk_business.strip()[:150]}*")

        lines.append("")
        return "\n".join(lines)

    def _strengths(self, result: AuditResult, context: ProjectContext | None) -> str:
        lines = ["## Punti di Forza", ""]

        strengths_found = False

        # Layer a 100
        for layer_name, ls in result.health_score.layer_scores.items():
            if ls.score == 100.0:
                display = LAYER_NAMES.get(layer_name, layer_name)
                lines.append(f"- **{display}**: score perfetto (100/100)")
                strengths_found = True

        # Best practice rilevate da context
        if context:
            if context.has_ci_cd:
                lines.append("- CI/CD pipeline presente")
                strengths_found = True
            if context.has_containers:
                lines.append("- Containerizzazione configurata")
                strengths_found = True
            if context.has_tests:
                lines.append("- Test automatizzati presenti")
                strengths_found = True
            if context.has_iac:
                lines.append("- Infrastructure as Code presente")
                strengths_found = True
            if context.has_monitoring:
                lines.append("- Monitoraggio configurato")
                strengths_found = True

        if not strengths_found:
            lines.append("Nessun punto di forza rilevato. Seguire le azioni prioritarie.")

        lines.append("")
        return "\n".join(lines)

    def _score_details(self, result: AuditResult) -> str:
        lines = ["## Score Details", ""]

        lines.append(f"**Overall Score: {result.health_score.overall_score:.0f}/100**")
        lines.append("")

        lines.append("| Layer | Score | Finding |")
        lines.append("|-------|-------|---------|")

        for layer_name in ["infra", "architecture", "security", "quality"]:
            if layer_name not in result.health_score.layer_scores:
                continue
            ls = result.health_score.layer_scores[layer_name]
            display = LAYER_NAMES.get(layer_name, layer_name)
            non_info = len([f for f in ls.findings if f.severity != Severity.INFO])
            lines.append(f"| {display} | {ls.score:.0f}/100 | {non_info} |")

        lines.append("")

        # Evidence chain
        has_evidence = any(
            ls.evidence_chain
            for ls in result.health_score.layer_scores.values()
        )
        if has_evidence:
            lines.append("### Evidence Chain")
            lines.append("")
            lines.append("| Rule ID | Layer | Weight | Penalty | Framework |")
            lines.append("|---------|-------|--------|---------|-----------|")

            for layer_name in ["infra", "architecture", "security", "quality"]:
                if layer_name not in result.health_score.layer_scores:
                    continue
                ls = result.health_score.layer_scores[layer_name]
                display = LAYER_NAMES.get(layer_name, layer_name)
                for ev in ls.evidence_chain:
                    # Skip INFO entries (weight=0, penalty=0) to reduce noise
                    if ev.weight == 0 and ev.penalty == 0:
                        continue
                    fw = ev.framework_ref or "-"
                    lines.append(
                        f"| {ev.rule_id} | {display} | {ev.weight:.2f} | "
                        f"{ev.penalty:.1f} | {fw} |"
                    )

            lines.append("")

        return "\n".join(lines)

    def _compliance(self, result: AuditResult) -> str:
        """Genera la sezione compliance con dettaglio per controllo."""
        compliance_results = result.health_score.compliance_results
        if not compliance_results:
            return ""

        lines = ["## Compliance", ""]

        for cr in compliance_results:
            lines.append(f"### {cr.profile_name}")
            lines.append("")
            lines.append(
                f"**{cr.checks_satisfied}/{cr.checks_total}** controlli soddisfatti"
            )
            if cr.checks_partial > 0:
                lines.append(f" | **{cr.checks_partial}** parziali")
            if cr.checks_not_satisfied > 0:
                lines.append(f" | **{cr.checks_not_satisfied}** non soddisfatti")
            lines.append("")

            # Tabella dettaglio
            lines.append("| Controllo | Articolo | Stato | Regole Violate |")
            lines.append("|-----------|----------|-------|----------------|")

            status_icon = {
                "satisfied": "PASS",
                "partial": "PARTIAL",
                "failed": "FAIL",
            }

            for detail in cr.details:
                status = status_icon.get(detail.get("status", ""), "?")
                triggered = ", ".join(detail.get("triggered_rules", [])) or "-"
                lines.append(
                    f"| {detail.get('title', '')} | "
                    f"{detail.get('article_ref', '')} | "
                    f"{status} | {triggered} |"
                )

            lines.append("")

            # Esposizione Normativa: riepilogo violazioni
            violations = [
                d for d in cr.details
                if d.get("status") in ("failed", "partial")
            ]
            if violations:
                lines.append("### Esposizione Normativa")
                lines.append("")
                for v in violations:
                    status_label = "NON CONFORME" if v.get("status") == "failed" else "PARZIALE"
                    lines.append(
                        f"- **{v.get('article_ref', '')}** — {v.get('title', '')} "
                        f"[{status_label}]: {', '.join(v.get('triggered_rules', []))}"
                    )
                lines.append("")

        return "\n".join(lines)

    def _footer(self, result: AuditResult) -> str:
        meta = result.metadata
        llm_note = ""
        if hasattr(result, "remediation") and result.remediation and result.remediation.llm_used:
            llm_note = " (con analisi LLM)"
        return (
            "---\n\n"
            f"*Board Report generato da CTO Audit Agent v{meta.tool_version} "
            f"il {meta.timestamp.strftime('%Y-%m-%d %H:%M')}{llm_note}*\n"
        )
