"""
Test per HTML Report.

Verifica:
- Struttura HTML valida
- Sezioni presenti (header, score, findings, compliance)
- CSS inline
- Salvataggio su file
"""

from __future__ import annotations

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
from cto_audit.reporters.html import HTMLReporter


@pytest.fixture
def sample_result() -> AuditResult:
    """AuditResult di test."""
    return AuditResult(
        health_score=HealthScore(
            overall_score=68.0,
            layer_scores={
                "infra": LayerScore(
                    layer=Layer.INFRA,
                    score=75.0,
                    findings=[
                        Finding(
                            id="f-001",
                            layer=Layer.INFRA,
                            severity=Severity.MEDIUM,
                            rule_id="INFRA-CICD-001",
                            title="No CI/CD",
                            description="Nessuna CI/CD pipeline",
                        ),
                    ],
                ),
                "security": LayerScore(
                    layer=Layer.SECURITY,
                    score=55.0,
                    findings=[
                        Finding(
                            id="f-002",
                            layer=Layer.SECURITY,
                            severity=Severity.CRITICAL,
                            rule_id="SEC-SECRETS-CODE-001",
                            title="Secrets hardcodati",
                            description="Trovati secrets nel codice",
                            file_path="config.py",
                        ),
                    ],
                ),
            },
        ),
        stack_info=StackInfo(
            languages={"python": 0.9, "javascript": 0.1},
            frameworks=["FastAPI", "React"],
        ),
        classifications=[],
        metadata=AuditMetadata(
            target_path="/test/repo",
            scoring_profile="default",
        ),
    )


class TestHTMLReporter:
    """Test per HTMLReporter."""

    def test_report_is_valid_html(self, sample_result: AuditResult) -> None:
        """Il report contiene struttura HTML base."""
        reporter = HTMLReporter()
        html = reporter.report(sample_result)

        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html
        assert "<head>" in html
        assert "<body>" in html

    def test_report_contains_css(self, sample_result: AuditResult) -> None:
        """Il CSS e inline nel report."""
        reporter = HTMLReporter()
        html = reporter.report(sample_result)

        assert "<style>" in html
        assert "font-family" in html
        assert "@media print" in html

    def test_report_contains_title(self, sample_result: AuditResult) -> None:
        """Il report contiene il titolo."""
        reporter = HTMLReporter()
        html = reporter.report(sample_result)

        assert "<title>CTO Audit Report</title>" in html
        assert "<h1>CTO Audit Report</h1>" in html

    def test_report_contains_score(self, sample_result: AuditResult) -> None:
        """Il report mostra lo score overall."""
        reporter = HTMLReporter()
        html = reporter.report(sample_result)

        assert "68" in html  # overall score
        assert "Overall" in html

    def test_report_contains_layer_scores(self, sample_result: AuditResult) -> None:
        """Il report mostra gli score per layer."""
        reporter = HTMLReporter()
        html = reporter.report(sample_result)

        assert "Infrastruttura" in html
        assert "Sicurezza" in html
        assert "75" in html  # infra score
        assert "55" in html  # security score

    def test_report_contains_findings(self, sample_result: AuditResult) -> None:
        """Il report include i finding."""
        reporter = HTMLReporter()
        html = reporter.report(sample_result)

        assert "INFRA-CICD-001" in html
        assert "SEC-SECRETS-CODE-001" in html
        assert "CRITICAL" in html

    def test_report_contains_stack_info(self, sample_result: AuditResult) -> None:
        """Il report mostra lo stack."""
        reporter = HTMLReporter()
        html = reporter.report(sample_result)

        assert "Python" in html
        assert "FastAPI" in html

    def test_report_contains_executive_summary(self, sample_result: AuditResult) -> None:
        """Il report include l'executive summary."""
        reporter = HTMLReporter()
        html = reporter.report(sample_result)

        assert "Executive Summary" in html
        assert "68/100" in html

    def test_report_with_compliance(self, sample_result: AuditResult) -> None:
        """Il report include compliance se presente."""
        sample_result.health_score.compliance_results = [
            ComplianceResult(
                profile_name="NIS2",
                checks_total=10,
                checks_satisfied=7,
                checks_partial=2,
                checks_not_satisfied=1,
                details=[
                    {
                        "control_id": "NIS2-ART21-2A",
                        "title": "Analisi dei rischi",
                        "article_ref": "Art. 21(2)(a)",
                        "status": "satisfied",
                        "triggered_rules": [],
                        "total_rules": 3,
                    },
                ],
            ),
        ]

        reporter = HTMLReporter()
        html = reporter.report(sample_result)

        assert "Compliance" in html
        assert "NIS2" in html
        assert "7/10" in html
        assert "PASS" in html

    def test_report_no_compliance(self, sample_result: AuditResult) -> None:
        """Senza compliance, la sezione non appare."""
        reporter = HTMLReporter()
        html = reporter.report(sample_result)

        # No compliance section header (but "Compliance" might appear in other contexts)
        assert "<h2>Compliance</h2>" not in html

    def test_save_to_file(self, sample_result: AuditResult, tmp_path: Path) -> None:
        """Il report viene salvato correttamente su file."""
        output_path = tmp_path / "report.html"
        reporter = HTMLReporter()
        reporter.save(sample_result, output_path)

        assert output_path.exists()
        content = output_path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "68" in content

    def test_severity_badges_have_colors(self, sample_result: AuditResult) -> None:
        """I badge severita hanno colori diversi."""
        reporter = HTMLReporter()
        html = reporter.report(sample_result)

        # CRITICAL badge should have red color
        assert "#ef4444" in html
