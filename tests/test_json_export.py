"""
Test per JSON Export.

Verifica:
- Serializzazione AuditResult completa
- Struttura JSON corretta
- Compliance inclusa se presente
- Salvataggio su file
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cto_audit.core.models import (
    AuditMetadata,
    AuditResult,
    ComplianceResult,
    Finding,
    HealthScore,
    Layer,
    LayerScore,
    Severity,
    StackInfo,
)
from cto_audit.reporters.json_export import JSONExporter


@pytest.fixture
def sample_result() -> AuditResult:
    """AuditResult di test."""
    return AuditResult(
        health_score=HealthScore(
            overall_score=72.5,
            layer_scores={
                "infra": LayerScore(
                    layer=Layer.INFRA,
                    score=80.0,
                    findings=[
                        Finding(
                            id="f-001",
                            layer=Layer.INFRA,
                            severity=Severity.MEDIUM,
                            rule_id="INFRA-CICD-001",
                            title="No CI/CD",
                            description="Nessuna CI/CD pipeline rilevata",
                        ),
                    ],
                ),
                "security": LayerScore(
                    layer=Layer.SECURITY,
                    score=65.0,
                    findings=[
                        Finding(
                            id="f-002",
                            layer=Layer.SECURITY,
                            severity=Severity.HIGH,
                            rule_id="SEC-AUTH-001",
                            title="No auth framework",
                            description="Nessun framework di autenticazione",
                        ),
                    ],
                ),
            },
        ),
        stack_info=StackInfo(
            languages={"python": 0.8, "javascript": 0.2},
            frameworks=["FastAPI"],
        ),
        classifications=[],
        metadata=AuditMetadata(
            target_path="/test/repo",
            scoring_profile="default",
        ),
    )


class TestJSONExporter:
    """Test per JSONExporter."""

    def test_export_returns_valid_json(self, sample_result: AuditResult) -> None:
        """L'export produce JSON valido."""
        exporter = JSONExporter()
        output = exporter.export(sample_result)
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_export_contains_health_score(self, sample_result: AuditResult) -> None:
        """Il JSON contiene health_score con overall_score."""
        exporter = JSONExporter()
        data = json.loads(exporter.export(sample_result))

        assert "health_score" in data
        assert data["health_score"]["overall_score"] == 72.5

    def test_export_contains_layer_scores(self, sample_result: AuditResult) -> None:
        """Il JSON contiene gli score per layer."""
        exporter = JSONExporter()
        data = json.loads(exporter.export(sample_result))

        layer_scores = data["health_score"]["layer_scores"]
        assert "infra" in layer_scores
        assert layer_scores["infra"]["score"] == 80.0
        assert "security" in layer_scores
        assert layer_scores["security"]["score"] == 65.0

    def test_export_contains_findings(self, sample_result: AuditResult) -> None:
        """Il JSON contiene i finding con dettagli."""
        exporter = JSONExporter()
        data = json.loads(exporter.export(sample_result))

        infra_findings = data["health_score"]["layer_scores"]["infra"]["findings"]
        assert len(infra_findings) == 1
        assert infra_findings[0]["rule_id"] == "INFRA-CICD-001"
        assert infra_findings[0]["severity"] == "medium"

    def test_export_contains_stack_info(self, sample_result: AuditResult) -> None:
        """Il JSON contiene stack_info."""
        exporter = JSONExporter()
        data = json.loads(exporter.export(sample_result))

        assert "stack_info" in data
        assert data["stack_info"]["languages"]["python"] == 0.8
        assert "FastAPI" in data["stack_info"]["frameworks"]

    def test_export_contains_metadata(self, sample_result: AuditResult) -> None:
        """Il JSON contiene metadata."""
        exporter = JSONExporter()
        data = json.loads(exporter.export(sample_result))

        assert "metadata" in data
        assert data["metadata"]["target_path"] == "/test/repo"
        assert data["metadata"]["scoring_profile"] == "default"

    def test_export_with_compliance(self, sample_result: AuditResult) -> None:
        """Il JSON include compliance results se presenti."""
        sample_result.health_score.compliance_results = [
            ComplianceResult(
                profile_name="NIS2",
                checks_total=10,
                checks_satisfied=7,
                checks_partial=2,
                checks_not_satisfied=1,
                details=[],
            ),
        ]

        exporter = JSONExporter()
        data = json.loads(exporter.export(sample_result))

        compliance = data["health_score"]["compliance_results"]
        assert len(compliance) == 1
        assert compliance[0]["profile_name"] == "NIS2"
        assert compliance[0]["checks_satisfied"] == 7

    def test_export_no_compliance(self, sample_result: AuditResult) -> None:
        """Senza compliance, il campo e null."""
        exporter = JSONExporter()
        data = json.loads(exporter.export(sample_result))

        assert data["health_score"]["compliance_results"] is None

    def test_save_to_file(self, sample_result: AuditResult, tmp_path: Path) -> None:
        """Il JSON viene salvato correttamente su file."""
        output_path = tmp_path / "report.json"
        exporter = JSONExporter()
        exporter.save(sample_result, output_path)

        assert output_path.exists()
        data = json.loads(output_path.read_text(encoding="utf-8"))
        assert data["health_score"]["overall_score"] == 72.5

    def test_json_is_indented(self, sample_result: AuditResult) -> None:
        """Il JSON e indentato per leggibilita."""
        exporter = JSONExporter()
        output = exporter.export(sample_result)
        # Indentato = contiene newline + spazi
        assert "\n" in output
        assert "  " in output
