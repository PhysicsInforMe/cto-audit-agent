"""
Interpretation Agent — Genera executive summary e risk narrative via LLM.

Logica:
1. Se LLM disponibile → prompt strutturato con findings+KB+context+what-if → genera
2. Se LLM non disponibile → fallback deterministico con template da KB
3. Se HITL enabled → mostra output LLM, chiedi approvazione, se rifiutato → fallback
"""

from __future__ import annotations

from typing import Callable

from pydantic import BaseModel

from cto_audit.core.models import AuditDelta, AuditResult, Severity
from cto_audit.llm.provider import LLMConfig, TaskComplexity
from cto_audit.llm.router import LLMRouter
from cto_audit.remediation.context import ProjectContext
from cto_audit.remediation.loader import RemediationLoader
from cto_audit.remediation.models import WhatIfResult


class InterpretationResult(BaseModel):
    """Risultato dell'interpretation agent."""
    executive_summary: str
    risk_narrative: str
    delta_narrative: str | None = None
    llm_used: bool = False
    model_used: str | None = None
    hitl_approved: bool | None = None


class InterpretationAgent:
    """
    Genera interpretazione del codebase audit via LLM con fallback deterministico.
    """

    def __init__(
        self,
        router: LLMRouter,
        kb_loader: RemediationLoader,
        hitl_enabled: bool = False,
        hitl_input_fn: Callable[[str], str] | None = None,
    ) -> None:
        self._router = router
        self._kb = kb_loader
        self._hitl_enabled = hitl_enabled
        self._hitl_input_fn = hitl_input_fn or (lambda prompt: input(prompt))

    def interpret(
        self,
        result: AuditResult,
        whatif_results: list[WhatIfResult],
        context: ProjectContext,
        delta: AuditDelta | None = None,
    ) -> InterpretationResult:
        """
        Genera executive summary, risk narrative e delta narrative.

        Args:
            result: Risultato audit completo
            whatif_results: Risultati simulazione what-if
            context: Contesto progetto inferito
            delta: Delta rispetto all'audit precedente (se disponibile)

        Returns:
            InterpretationResult con summary, narrative e delta narrative
        """
        # Tenta LLM
        if self._router.is_available():
            prompt = self._build_prompt(result, whatif_results, context, delta=delta)
            config = LLMConfig(
                task_complexity=TaskComplexity.HIGH,
                temperature=0.2,
                max_tokens=2048,
                system_prompt="Sei un CTO esperto. Rispondi in italiano. Sii conciso e orientato all'azione.",
            )

            llm_response = self._router.generate(prompt, config)

            if llm_response is not None:
                summary, narrative, delta_narr = self._parse_llm_response(
                    llm_response.text, has_delta=delta is not None
                )

                # HITL gate
                if self._hitl_enabled:
                    approved = self._hitl_review(summary, narrative)
                    if not approved:
                        return self._deterministic_fallback(
                            result, whatif_results, context, delta=delta, hitl_approved=False
                        )

                    return InterpretationResult(
                        executive_summary=summary,
                        risk_narrative=narrative,
                        delta_narrative=delta_narr,
                        llm_used=True,
                        model_used=llm_response.model_used,
                        hitl_approved=True,
                    )

                return InterpretationResult(
                    executive_summary=summary,
                    risk_narrative=narrative,
                    delta_narrative=delta_narr,
                    llm_used=True,
                    model_used=llm_response.model_used,
                )

        # Fallback deterministico
        return self._deterministic_fallback(result, whatif_results, context, delta=delta)

    def _build_prompt(
        self,
        result: AuditResult,
        whatif_results: list[WhatIfResult],
        context: ProjectContext,
        delta: AuditDelta | None = None,
    ) -> str:
        """Costruisce il prompt strutturato per il LLM."""
        lines = [
            "Analizza questo codebase e produci un report esecutivo.",
            "",
            "CONTESTO:",
            f"- Maturita: {context.maturity_level.value}",
            f"- Team stimato: {context.estimated_team_size}",
            f"- Stack: {context.primary_language or 'N/A'}",
            f"- Framework: {context.primary_framework or 'N/A'}",
            f"- File: {context.total_files}",
            f"- LOC: {context.total_loc}",
            "",
            "SCORE:",
            f"- Overall: {result.health_score.overall_score:.0f}/100",
        ]

        for layer_name, ls in result.health_score.layer_scores.items():
            lines.append(f"- {layer_name}: {ls.score:.0f}/100")

        # Top 5 finding critici
        critical_findings = []
        for ls in result.health_score.layer_scores.values():
            for f in ls.findings:
                if f.severity in (Severity.CRITICAL, Severity.HIGH):
                    critical_findings.append(f)
        critical_findings.sort(
            key=lambda f: (0 if f.severity == Severity.CRITICAL else 1)
        )

        if critical_findings:
            lines.append("")
            lines.append("FINDING CRITICI:")
            for f in critical_findings[:5]:
                kb_entry = self._kb.get(f.rule_id)
                risk = kb_entry.risk_business.strip()[:100] if kb_entry else f.description
                lines.append(f"- [{f.severity.value.upper()}] {f.rule_id}: {risk}")

        # Top 5 what-if
        if whatif_results:
            lines.append("")
            lines.append("SIMULAZIONE WHAT-IF (top 5):")
            for wif in whatif_results[:5]:
                effort_str = f"{wif.effort.t_shirt} ({wif.effort.min_hours}-{wif.effort.max_hours}h)" if wif.effort else "N/A"
                lines.append(
                    f"- {wif.rule_id}: +{wif.delta:.1f} punti, effort {effort_str}"
                )

        # Delta section
        if delta:
            lines.append("")
            lines.append("DELTA RISPETTO ALL'ULTIMO AUDIT:")
            lines.append(f"- Score precedente: {delta.previous_score:.0f}/100")
            lines.append(f"- Score attuale: {delta.current_score:.0f}/100")
            sign = "+" if delta.score_delta > 0 else ""
            lines.append(f"- Delta: {sign}{delta.score_delta:.1f}")
            lines.append(f"- Giorni trascorsi: {delta.days_since_previous:.1f}")
            if delta.resolved_findings:
                lines.append(f"- Finding risolti: {', '.join(delta.resolved_findings)}")
            if delta.new_findings:
                lines.append(f"- Finding nuovi: {', '.join(delta.new_findings)}")
            if delta.persistent_findings:
                lines.append(f"- Finding persistenti: {', '.join(delta.persistent_findings)}")

        num_sections = 3 if delta else 2
        lines.extend([
            "",
            "ISTRUZIONI:",
            f"Produci esattamente {num_sections} sezioni, separate da '---':",
            "1. EXECUTIVE SUMMARY (3-5 righe, non-tecnico, per board/investitori)",
            "2. RISCHI PRINCIPALI (bullet list dei rischi business piu importanti)",
        ])

        if delta:
            lines.append(
                "3. DELTA NARRATIVE (2-3 righe che descrivono l'evoluzione: "
                "cosa e' migliorato, cosa persiste, cosa e' peggiorato)"
            )

        return "\n".join(lines)

    @staticmethod
    def _parse_llm_response(
        text: str, has_delta: bool = False
    ) -> tuple[str, str, str | None]:
        """Separa la risposta LLM in executive summary, risk narrative e delta narrative."""
        parts = text.split("---")
        summary = parts[0].strip() if len(parts) > 0 else ""
        narrative = parts[1].strip() if len(parts) > 1 else ""
        delta_narr = parts[2].strip() if len(parts) > 2 and has_delta else None

        # Cleanup: rimuovi headers se presenti
        for prefix in ["EXECUTIVE SUMMARY", "Executive Summary", "# Executive Summary"]:
            if summary.startswith(prefix):
                summary = summary[len(prefix):].strip().lstrip(":").strip()

        for prefix in ["RISCHI PRINCIPALI", "Rischi Principali", "# Rischi Principali"]:
            if narrative.startswith(prefix):
                narrative = narrative[len(prefix):].strip().lstrip(":").strip()

        if delta_narr:
            for prefix in ["DELTA NARRATIVE", "Delta Narrative", "# Delta Narrative",
                           "DELTA", "Delta"]:
                if delta_narr.startswith(prefix):
                    delta_narr = delta_narr[len(prefix):].strip().lstrip(":").strip()

        return summary, narrative, delta_narr

    def _hitl_review(self, summary: str, narrative: str) -> bool:
        """Mostra output LLM e chiede approvazione HITL."""
        review_text = (
            "\n=== OUTPUT LLM ===\n"
            f"\nEXECUTIVE SUMMARY:\n{summary}\n"
            f"\nRISCHI PRINCIPALI:\n{narrative}\n"
            "\n=== FINE OUTPUT LLM ===\n"
            "\nApprovare output LLM? [s/n]: "
        )
        response = self._hitl_input_fn(review_text)
        return response.strip().lower() in ("s", "si", "y", "yes")

    def _deterministic_fallback(
        self,
        result: AuditResult,
        whatif_results: list[WhatIfResult],
        context: ProjectContext,
        delta: AuditDelta | None = None,
        hitl_approved: bool | None = None,
    ) -> InterpretationResult:
        """Genera interpretazione deterministica senza LLM."""
        summary = self._build_deterministic_summary(result, context)
        narrative = self._build_deterministic_narrative(result)
        delta_narr = self._build_deterministic_delta_narrative(delta) if delta else None

        return InterpretationResult(
            executive_summary=summary,
            risk_narrative=narrative,
            delta_narrative=delta_narr,
            llm_used=False,
            model_used=None,
            hitl_approved=hitl_approved,
        )

    def _build_deterministic_summary(
        self,
        result: AuditResult,
        context: ProjectContext,
    ) -> str:
        """Template deterministico per executive summary."""
        score = result.health_score.overall_score
        maturity = context.maturity_level.value.capitalize()

        critical = sum(
            1 for ls in result.health_score.layer_scores.values()
            for f in ls.findings if f.severity == Severity.CRITICAL
        )
        high = sum(
            1 for ls in result.health_score.layer_scores.values()
            for f in ls.findings if f.severity == Severity.HIGH
        )

        lines = [
            f"Il codebase analizzato ha ottenuto uno score di {score:.0f}/100.",
            f"Il progetto si trova a livello {maturity} con un team stimato di {context.estimated_team_size} sviluppatori.",
        ]

        if critical > 0:
            lines.append(f"Sono stati rilevati {critical} problemi critici che richiedono intervento immediato.")
        if high > 0:
            lines.append(f"Sono presenti {high} problemi ad alta severita da affrontare a breve termine.")
        if critical == 0 and high == 0:
            lines.append("Non sono stati rilevati problemi critici o ad alta severita.")

        return " ".join(lines)

    def _build_deterministic_narrative(self, result: AuditResult) -> str:
        """Template deterministico per risk narrative."""
        risks: list[str] = []

        for ls in result.health_score.layer_scores.values():
            for f in ls.findings:
                if f.severity in (Severity.CRITICAL, Severity.HIGH):
                    kb_entry = self._kb.get(f.rule_id)
                    if kb_entry:
                        risks.append(f"- {kb_entry.risk_business.strip()[:150]}")
                    else:
                        risks.append(f"- {f.title}: {f.description[:100]}")

        if not risks:
            return "Nessun rischio significativo rilevato."

        return "\n".join(risks[:10])

    @staticmethod
    def _build_deterministic_delta_narrative(delta: AuditDelta) -> str:
        """Template deterministico per delta narrative."""
        parts: list[str] = []

        # Trend
        if delta.score_delta > 0:
            parts.append(
                f"Lo score e migliorato di {delta.score_delta:.1f} punti "
                f"negli ultimi {delta.days_since_previous:.0f} giorni."
            )
        elif delta.score_delta < 0:
            parts.append(
                f"Lo score e peggiorato di {abs(delta.score_delta):.1f} punti "
                f"negli ultimi {delta.days_since_previous:.0f} giorni."
            )
        else:
            parts.append(
                f"Lo score e rimasto invariato "
                f"negli ultimi {delta.days_since_previous:.0f} giorni."
            )

        # Risolti
        if delta.resolved_findings:
            parts.append(
                f"Il team ha risolto {len(delta.resolved_findings)} "
                f"problemi: {', '.join(delta.resolved_findings[:5])}."
            )

        # Nuovi
        if delta.new_findings:
            parts.append(
                f"Sono emersi {len(delta.new_findings)} nuovi "
                f"problemi: {', '.join(delta.new_findings[:5])}."
            )

        # Persistenti
        if delta.persistent_findings:
            parts.append(
                f"{len(delta.persistent_findings)} problemi persistono "
                f"dall'ultimo audit."
            )

        return " ".join(parts)
