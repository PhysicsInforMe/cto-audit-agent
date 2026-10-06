"""
Scoring Engine — Calcolo score tracciabili per layer e complessivo.

Riceve finding + profilo e produce:
- LayerScore per ogni layer (100 - sum(penalità))
- Catena di evidenze completa (finding → regola → peso → penalità → framework)
- HealthScore aggregato con pesi per layer

Finding senza regola nel profilo: gestiti con peso default (non ignorati).
Penalità basate sulla severità del finding per regole non nel profilo.
"""

from __future__ import annotations

from cto_audit.core.models import (
    EvidenceChain,
    Finding,
    HealthScore,
    Layer,
    LayerScore,
    ProjectType,
    Severity,
)
from cto_audit.scoring.profile import ScoringProfile


# Penalità default per severità quando una regola non è nel profilo
DEFAULT_PENALTIES: dict[str, float] = {
    "critical": -20.0,
    "high": -10.0,
    "medium": -5.0,
    "low": -2.0,
    "info": 0.0,
}

# Regole note per layer (per calcolo confidence coverage)
LAYER_RULES: dict[str, list[str]] = {
    "infra": [
        "INFRA-CICD-001", "INFRA-DOCKER-001", "INFRA-IAC-001",
        "INFRA-DEPS-001", "INFRA-CONFIG-001", "INFRA-CONFIG-002",
        "INFRA-MON-001", "INFRA-ENVEXAMPLE-001",
    ],
    "security": [
        "SEC-DEPS-001", "SEC-AUTH-001", "SEC-HTTPS-001",
        "SEC-CORS-001", "SEC-SQL-001", "SEC-SECRETS-CODE-001",
        "SEC-HEADERS-001", "SEC-CRYPTO-001",
    ],
    "architecture": [
        "ARCH-STRUCT-001", "ARCH-COUPLING-001",
        "ARCH-COUPLING-002", "ARCH-SCALE-001",
        "ARCH-TEST-001", "ARCH-DB-001",
    ],
    "quality": [
        "QUAL-DOC-001", "QUAL-DOC-002", "QUAL-LINT-001",
        "QUAL-TYPING-001", "QUAL-COMPLEXITY-001", "QUAL-DUP-001",
        "QUAL-PRECOMMIT-001", "QUAL-EDITORCONFIG-001",
        "QUAL-CONTRIBUTING-001", "QUAL-CHANGELOG-001",
    ],
    "provenance": [
        "PROV-LICENSE-001", "PROV-COPYLEFT-001", "PROV-COPYLEFT-002",
        "PROV-COMMERCIAL-001", "PROV-VENDORED-001", "PROV-COPYRIGHT-001",
        "PROV-CLAIMS-001", "PROV-SBOM-001",
    ],
    "team": [
        "TEAM-BUSFACTOR-001", "TEAM-ACTIVITY-001", "TEAM-ACTIVITY-002",
        "TEAM-HISTORY-001", "TEAM-HISTORY-002", "TEAM-RELEASE-001",
        "TEAM-MSGQUAL-001",
    ],
}

# Regole che richiedono un web framework per essere applicabili
WEB_ONLY_RULES: set[str] = {
    "SEC-AUTH-001", "SEC-CORS-001", "SEC-HEADERS-001", "SEC-SQL-001",
}


class ScoringEngine:
    """
    Engine di scoring pluggable.

    Calcola score tracciabili basandosi su un profilo YAML.
    Ogni score numerico ha la catena di evidenze completa
    che mostra come è stato calcolato.
    """

    def __init__(
        self,
        profile: ScoringProfile,
        project_type: ProjectType | None = None,
    ) -> None:
        self.profile = profile
        self.project_type = project_type

    def score_layer(self, layer: Layer, findings: list[Finding]) -> LayerScore:
        """
        Calcola lo score per un singolo layer.

        Formula: score = max(0, 100 - sum(|penalità| * peso))
        Ogni finding produce un'EvidenceChain che traccia il calcolo.

        Args:
            layer: Layer da calcolare
            findings: Lista di finding per questo layer

        Returns:
            LayerScore con score, findings e catena di evidenze
        """
        evidence_chain: list[EvidenceChain] = []
        total_penalty = 0.0

        for finding in findings:
            rule = self.profile.get_rule(finding.rule_id)

            if rule is not None:
                # Regola trovata nel profilo
                weight = rule.weight
                penalty = rule.penalty
                framework_ref = rule.framework_ref or finding.framework_ref
            else:
                # Regola non nel profilo → usa peso default e penalità per severità
                weight = self.profile.default_rule_weight
                penalty = DEFAULT_PENALTIES.get(finding.severity.value, -5.0)
                framework_ref = finding.framework_ref

            # Penalità effettiva = |penalità| * peso
            effective_penalty = abs(penalty) * weight

            # Aggiungi alla catena di evidenze
            evidence_chain.append(EvidenceChain(
                finding_id=finding.id,
                rule_id=finding.rule_id,
                weight=weight,
                penalty=-effective_penalty,  # Sempre negativo nel modello
                framework_ref=framework_ref,
            ))

            total_penalty += effective_penalty

        # Score = 100 - totale penalità, minimo 0
        score = max(0.0, 100.0 - total_penalty)

        # Calcola confidence
        confidence = self._compute_layer_confidence(layer, findings)

        return LayerScore(
            layer=layer,
            score=round(score, 2),
            confidence=confidence,
            findings=findings,
            evidence_chain=evidence_chain,
        )

    def calculate(self, all_findings: list[Finding]) -> HealthScore:
        """
        Calcola lo HealthScore complessivo.

        1. Raggruppa i finding per layer
        2. Calcola LayerScore per ogni layer attivo (anche senza finding → 100).
           Un layer e attivo se ha un peso nel profilo oppure se ha prodotto
           finding: cosi i profili a 4 layer restano identici a prima e i layer
           di due diligence compaiono solo quando pesati o analizzati.
        3. Aggrega con media pesata usando layer_weights del profilo

        Args:
            all_findings: Tutti i finding da tutti gli analyzer

        Returns:
            HealthScore con overall_score e breakdown per layer
        """
        # Raggruppa finding per layer
        findings_by_layer: dict[Layer, list[Finding]] = {
            layer: [] for layer in Layer
        }
        for finding in all_findings:
            findings_by_layer[finding.layer].append(finding)

        # Calcola score per ogni layer attivo
        layer_scores: dict[str, LayerScore] = {}
        for layer in Layer:
            if layer.value not in self.profile.layer_weights and not findings_by_layer[layer]:
                continue
            layer_score = self.score_layer(layer, findings_by_layer[layer])
            layer_scores[layer.value] = layer_score

        # Calcola overall score con media pesata
        overall = 0.0
        overall_confidence = 0.0
        for layer_name, weight in self.profile.layer_weights.items():
            if layer_name in layer_scores:
                overall += layer_scores[layer_name].score * weight
                overall_confidence += layer_scores[layer_name].confidence * weight

        return HealthScore(
            overall_score=round(overall, 2),
            overall_confidence=round(overall_confidence, 2),
            layer_scores=layer_scores,
        )

    def _compute_layer_confidence(
        self, layer: Layer, findings: list[Finding]
    ) -> float:
        """
        Calcola la confidence di uno score per layer.

        La confidence riflette:
        1. Coverage: quante regole del layer sono state verificate
        2. Applicabilità: quante regole hanno senso per il tipo di progetto
        3. Finding confidence: media della confidence dei finding rilevati

        Formula: confidence = 70% coverage + 30% finding confidence
        """
        all_rules = LAYER_RULES.get(layer.value, [])
        if not all_rules:
            return 1.0

        # Determina regole applicabili per tipo progetto
        if self.project_type not in (
            ProjectType.WEB_APP, ProjectType.FULL_STACK, None
        ):
            applicable = [r for r in all_rules if r not in WEB_ONLY_RULES]
        else:
            applicable = list(all_rules)

        if not applicable:
            return 1.0

        # Regole che hanno prodotto almeno 1 finding non-INFO
        found_rules = {
            f.rule_id for f in findings if f.severity != Severity.INFO
        }
        # Regole che hanno prodotto un finding INFO (checked + clean)
        info_rules = {
            f.rule_id for f in findings if f.severity == Severity.INFO
        }
        checked = found_rules | info_rules

        coverage = len(checked & set(applicable)) / max(len(applicable), 1)

        # Media confidence dei finding non-INFO
        non_info = [f for f in findings if f.severity != Severity.INFO]
        if non_info:
            avg_finding_conf = sum(f.confidence for f in non_info) / len(non_info)
        else:
            avg_finding_conf = 1.0

        # Confidence = 70% coverage + 30% finding confidence
        return round(min(1.0, coverage * 0.7 + avg_finding_conf * 0.3), 2)
