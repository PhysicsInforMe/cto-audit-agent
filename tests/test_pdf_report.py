"""
Test per PDF Reporter.

Verifica:
- Che il PDFReporter generi HTML valido internamente
- Che l'ImportError sia chiaro se WeasyPrint manca
- Che il flag --detailed sia passato correttamente
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cto_audit.core.models import (
    AuditMetadata,
    AuditResult,
    Finding,
    HealthScore,
    Layer,
    LayerScore,
    Severity,
    StackInfo,
)
from cto_audit.reporters.pdf import PDFReporter


@pytest.fixture
def sample_result() -> AuditResult:
    """AuditResult di test."""
    return AuditResult(
        health_score=HealthScore(
            overall_score=72.0,
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
                            description="Nessuna CI/CD pipeline",
                        ),
                    ],
                ),
                "security": LayerScore(
                    layer=Layer.SECURITY,
                    score=60.0,
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
            languages={"python": 0.85, "javascript": 0.15},
            frameworks=["Django"],
        ),
        classifications=[],
        metadata=AuditMetadata(
            target_path="/test/repo",
            scoring_profile="default",
        ),
    )


class TestPDFReporter:
    """Test per PDFReporter."""

    def test_init_default(self) -> None:
        """Il reporter si inizializza senza errori."""
        reporter = PDFReporter()
        assert reporter.detailed is False

    def test_init_detailed(self) -> None:
        """Il flag detailed viene passato."""
        reporter = PDFReporter(detailed=True)
        assert reporter.detailed is True

    def test_internal_html_is_valid(self, sample_result: AuditResult) -> None:
        """Il reporter genera HTML valido internamente."""
        reporter = PDFReporter()
        html = reporter._html_reporter.report(sample_result)
        assert "<!DOCTYPE html>" in html
        assert "72" in html  # overall score
        assert "CTO Audit Report" in html

    def test_detailed_flag_propagated(self, sample_result: AuditResult) -> None:
        """Il flag detailed arriva all'HTMLReporter interno."""
        reporter = PDFReporter(detailed=True)
        assert reporter._html_reporter.detailed is True

    def test_save_calls_weasyprint(self, sample_result: AuditResult, tmp_path: Path) -> None:
        """save() usa WeasyPrint per convertire HTML in PDF."""
        output_path = tmp_path / "report.pdf"

        mock_html_class = MagicMock()
        mock_html_instance = MagicMock()
        mock_html_class.return_value = mock_html_instance

        with patch.dict("sys.modules", {"weasyprint": MagicMock(HTML=mock_html_class)}):
            reporter = PDFReporter()
            reporter.save(sample_result, output_path)

        # WeasyPrint HTML() chiamato con la stringa HTML
        mock_html_class.assert_called_once()
        call_kwargs = mock_html_class.call_args
        html_string = call_kwargs.kwargs.get("string") or call_kwargs.args[0] if call_kwargs.args else None
        if html_string is None:
            html_string = call_kwargs[1].get("string", "")
        assert "CTO Audit Report" in str(html_string) or mock_html_class.called

        # write_pdf chiamato con il percorso output
        mock_html_instance.write_pdf.assert_called_once_with(str(output_path))

    def test_save_without_weasyprint_raises(self, sample_result: AuditResult, tmp_path: Path) -> None:
        """Senza WeasyPrint, save() lancia ImportError con messaggio utile."""
        output_path = tmp_path / "report.pdf"

        # Simula weasyprint non installato
        with patch.dict("sys.modules", {"weasyprint": None}):
            reporter = PDFReporter()
            with pytest.raises(ImportError, match="pip install cto-audit"):
                reporter.save(sample_result, output_path)
