"""
What-If Simulator — Simula rimozione finding e proiezione score.

Per ogni rule_id, rimuove i finding con quel rule_id,
ricalcola con ScoringEngine.calculate(), misura il delta.
Ordina per impact/effort ratio.
"""

from __future__ import annotations

from cto_audit.core.models import Finding, HealthScore
from cto_audit.remediation.models import EffortRange, WhatIfResult
from cto_audit.scoring.engine import ScoringEngine


class WhatIfSimulator:
    """
    Simula l'impatto della risoluzione di specifiche regole sullo score.

    Usa ScoringEngine.calculate() per ricalcolare lo score senza
    i finding di una data regola, misurando il delta.
    """

    def __init__(self, engine: ScoringEngine) -> None:
        self.engine = engine

    def simulate(
        self,
        health: HealthScore,
        rule_ids: list[str],
        effort_map: dict[str, EffortRange] | None = None,
    ) -> list[WhatIfResult]:
        """
        Simula la risoluzione di una lista di regole specifiche.

        Args:
            health: HealthScore corrente (con finding)
            rule_ids: Lista di rule_id da simulare
            effort_map: Mappa rule_id → EffortRange (opzionale)

        Returns:
            Lista di WhatIfResult ordinata per impact_effort_ratio decrescente
        """
        effort_map = effort_map or {}
        all_findings = self._extract_all_findings(health)
        current_score = health.overall_score

        results: list[WhatIfResult] = []
        for rule_id in rule_ids:
            result = self._simulate_single(
                all_findings, current_score, rule_id, effort_map.get(rule_id)
            )
            if result is not None:
                results.append(result)

        results.sort(key=lambda r: r.impact_effort_ratio, reverse=True)
        return results

    def simulate_all(
        self,
        health: HealthScore,
        effort_map: dict[str, EffortRange] | None = None,
    ) -> list[WhatIfResult]:
        """
        Simula la risoluzione di tutte le regole con finding attivi.

        Args:
            health: HealthScore corrente
            effort_map: Mappa rule_id → EffortRange

        Returns:
            Lista di WhatIfResult ordinata per impact_effort_ratio decrescente
        """
        all_findings = self._extract_all_findings(health)
        rule_ids = list({f.rule_id for f in all_findings})
        return self.simulate(health, rule_ids, effort_map)

    def _simulate_single(
        self,
        all_findings: list[Finding],
        current_score: float,
        rule_id: str,
        effort: EffortRange | None,
    ) -> WhatIfResult | None:
        """Simula la rimozione di una singola regola."""
        filtered = [f for f in all_findings if f.rule_id != rule_id]

        # Se nessun finding rimosso, skip
        if len(filtered) == len(all_findings):
            return None

        projected_health = self.engine.calculate(filtered)
        projected_score = projected_health.overall_score
        delta = projected_score - current_score

        # Calcola impact/effort ratio
        if effort is not None and effort.avg_hours > 0:
            ratio = delta / effort.avg_hours
        else:
            ratio = delta  # Senza effort, ratio = delta puro

        return WhatIfResult(
            rule_id=rule_id,
            current_score=current_score,
            projected_score=projected_score,
            delta=round(delta, 2),
            effort=effort,
            impact_effort_ratio=round(ratio, 4),
        )

    @staticmethod
    def _extract_all_findings(health: HealthScore) -> list[Finding]:
        """Estrae tutti i finding da tutti i layer."""
        findings: list[Finding] = []
        for layer_score in health.layer_scores.values():
            findings.extend(layer_score.findings)
        return findings
