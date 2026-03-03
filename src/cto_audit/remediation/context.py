"""
Context Collector — Inferisce contesto progetto da dati audit.

Infra signals inferiti dai finding:
  se INFRA-CICD-001 NON triggered → has_ci_cd=True
  se INFRA-DOCKER-001 NON triggered → has_containers=True
  etc.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from cto_audit.core.models import AuditResult, Severity


class MaturityLevel(str, Enum):
    """Livello di maturita del progetto."""
    PROTOTYPE = "prototype"    # <20 file, no CI, no Docker
    MVP = "mvp"                # 20-100 file, qualche infra
    PRODUCTION = "production"  # >100 file, CI+Docker+test+IaC


class ProjectContext(BaseModel):
    """Contesto inferito del progetto."""
    maturity_level: MaturityLevel
    estimated_team_size: str = Field(..., description="1-2, 3-5, 5-10, 10+")
    primary_language: str | None = None
    primary_framework: str | None = None
    has_ci_cd: bool = False
    has_containers: bool = False
    has_iac: bool = False
    has_tests: bool = False
    has_monitoring: bool = False
    total_files: int = 0
    total_loc: int = 0
    sensitive_files_count: int = 0


# Rule IDs che, se assenti, indicano presenza dell'infra
_INFRA_NEGATIVE_SIGNALS = {
    "INFRA-CICD-001": "has_ci_cd",
    "INFRA-DOCKER-001": "has_containers",
    "INFRA-IAC-001": "has_iac",
    "INFRA-MON-001": "has_monitoring",
    "ARCH-TEST-001": "has_tests",
}


class ContextCollector:
    """Raccoglie contesto progetto da AuditResult senza accesso al filesystem."""

    def collect(self, result: AuditResult) -> ProjectContext:
        """
        Inferisce contesto progetto dai dati audit.

        Args:
            result: AuditResult completo

        Returns:
            ProjectContext con tutte le inferenze
        """
        # Conteggi base
        total_files = len(result.classifications)
        total_loc = sum(
            c.file_info.lines_of_code
            for c in result.classifications
        )
        sensitive_count = sum(
            1 for c in result.classifications
            if c.category.value == "sensitive"
        )

        # Inferisci infra signals dai finding (assenza = presente)
        triggered_rules = self._get_triggered_rules(result)
        infra_flags: dict[str, bool] = {}
        for rule_id, flag_name in _INFRA_NEGATIVE_SIGNALS.items():
            infra_flags[flag_name] = rule_id not in triggered_rules

        # Linguaggio e framework primario
        primary_language = _get_primary_language(result)
        primary_framework = _get_primary_framework(result)

        # Team size stimato
        team_size = _estimate_team_size(total_files, total_loc)

        # Maturity level
        maturity = _infer_maturity(
            total_files=total_files,
            has_ci_cd=infra_flags["has_ci_cd"],
            has_containers=infra_flags["has_containers"],
            has_tests=infra_flags["has_tests"],
            has_iac=infra_flags["has_iac"],
        )

        return ProjectContext(
            maturity_level=maturity,
            estimated_team_size=team_size,
            primary_language=primary_language,
            primary_framework=primary_framework,
            total_files=total_files,
            total_loc=total_loc,
            sensitive_files_count=sensitive_count,
            **infra_flags,
        )

    @staticmethod
    def _get_triggered_rules(result: AuditResult) -> set[str]:
        """Restituisce l'insieme di rule_id triggered (non-info)."""
        triggered: set[str] = set()
        for layer_score in result.health_score.layer_scores.values():
            for finding in layer_score.findings:
                if finding.severity != Severity.INFO:
                    triggered.add(finding.rule_id)
        return triggered


def _get_primary_language(result: AuditResult) -> str | None:
    """Restituisce il linguaggio con la percentuale piu alta."""
    langs = result.stack_info.languages
    if not langs:
        return None
    return max(langs, key=langs.get)  # type: ignore[arg-type]


def _get_primary_framework(result: AuditResult) -> str | None:
    """Restituisce il primo framework rilevato."""
    frameworks = result.stack_info.frameworks
    return frameworks[0] if frameworks else None


def _estimate_team_size(total_files: int, total_loc: int) -> str:
    """Stima la dimensione del team dal numero di file e LOC."""
    if total_files < 20 and total_loc < 2000:
        return "1-2"
    elif total_files < 100 and total_loc < 20000:
        return "3-5"
    elif total_files < 500 and total_loc < 100000:
        return "5-10"
    else:
        return "10+"


def _infer_maturity(
    total_files: int,
    has_ci_cd: bool,
    has_containers: bool,
    has_tests: bool,
    has_iac: bool,
) -> MaturityLevel:
    """Inferisce il livello di maturita del progetto."""
    infra_score = sum([has_ci_cd, has_containers, has_tests, has_iac])

    if total_files < 20 and infra_score == 0:
        return MaturityLevel.PROTOTYPE

    if total_files > 100 and infra_score >= 3:
        return MaturityLevel.PRODUCTION

    return MaturityLevel.MVP
