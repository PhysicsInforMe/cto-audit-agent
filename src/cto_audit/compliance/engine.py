"""
Compliance Engine — Mappa finding esistenti a controlli normativi.

NON esegue check aggiuntivi. Prende i finding gia prodotti dagli analyzer
e li mappa a controlli definiti nei profili di compliance.

Per ogni controllo:
- Se nessuno dei required_rules e stato triggerato -> SATISFIED
- Se alcuni triggerati -> PARTIAL
- Se tutti triggerati -> FAILED
"""

from __future__ import annotations

from cto_audit.compliance.models import (
    ComplianceProfile,
    ControlEvaluation,
    ControlStatus,
)
from cto_audit.core.models import ComplianceResult, Finding, Severity


class ComplianceEngine:
    """Engine per la valutazione di compliance."""

    def evaluate(
        self,
        profile: ComplianceProfile,
        findings: list[Finding],
    ) -> ComplianceResult:
        """
        Valuta la compliance di un set di finding contro un profilo.

        Args:
            profile: Profilo di compliance caricato
            findings: Tutti i finding prodotti dagli analyzer

        Returns:
            ComplianceResult con dettagli per ogni controllo
        """
        # Raccogli tutti i rule_id triggerati (esclusi INFO)
        triggered_rules: set[str] = {
            f.rule_id for f in findings
            if f.severity != Severity.INFO
        }

        details: list[ControlEvaluation] = []
        satisfied = 0
        partial = 0
        failed = 0

        for control in profile.controls:
            all_rules = control.required_rules + control.contributing_rules
            triggered_in_control = [r for r in all_rules if r in triggered_rules]

            if not triggered_in_control:
                status = ControlStatus.SATISFIED
                satisfied += 1
            elif len(triggered_in_control) == len(all_rules):
                status = ControlStatus.FAILED
                failed += 1
            else:
                status = ControlStatus.PARTIAL
                partial += 1

            details.append(ControlEvaluation(
                control_id=control.control_id,
                title=control.title,
                article_ref=control.article_ref,
                status=status,
                triggered_rules=triggered_in_control,
                total_rules=len(all_rules),
            ))

        return ComplianceResult(
            profile_name=profile.name,
            checks_total=len(profile.controls),
            checks_satisfied=satisfied,
            checks_partial=partial,
            checks_not_satisfied=failed,
            details=[
                {
                    "control_id": d.control_id,
                    "title": d.title,
                    "article_ref": d.article_ref,
                    "status": d.status.value,
                    "triggered_rules": d.triggered_rules,
                    "total_rules": d.total_rules,
                }
                for d in details
            ],
        )
