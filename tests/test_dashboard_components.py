"""
Test per i componenti della dashboard — ogni funzione riceve dati mock
e restituisce oggetti Dash validi.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from cto_audit.core.models import (
    AuditMetadata, AuditResult, ComplianceResult, EvidenceChain,
    Finding, HealthScore, LayerScore, Layer, Severity,
    StackInfo, FileClassification,
)


@pytest.fixture
def mock_result() -> AuditResult:
    """AuditResult di test."""
    findings = [
        Finding(
            id="f1", layer=Layer.SECURITY, severity=Severity.HIGH,
            rule_id="SEC-001", title="Missing HTTPS",
            description="No HTTPS configured", file_path="app.py",
        ),
        Finding(
            id="f2", layer=Layer.INFRA, severity=Severity.MEDIUM,
            rule_id="INFRA-001", title="No CI/CD",
            description="No CI/CD pipeline", confidence=0.8,
        ),
    ]
    return AuditResult(
        health_score=HealthScore(
            overall_score=65.0,
            layer_scores={
                "security": LayerScore(
                    layer=Layer.SECURITY, score=50.0,
                    findings=[findings[0]],
                    evidence_chain=[EvidenceChain(
                        finding_id="f1", rule_id="SEC-001",
                        weight=0.5, penalty=-25.0, framework_ref="OWASP",
                    )],
                ),
                "infra": LayerScore(
                    layer=Layer.INFRA, score=70.0,
                    findings=[findings[1]],
                    evidence_chain=[EvidenceChain(
                        finding_id="f2", rule_id="INFRA-001",
                        weight=0.3, penalty=-15.0,
                    )],
                ),
            },
            compliance_results=[
                ComplianceResult(
                    profile_name="NIS2",
                    checks_total=10,
                    checks_satisfied=7,
                    checks_partial=2,
                    checks_not_satisfied=1,
                ),
            ],
        ),
        stack_info=StackInfo(
            languages={"python": 0.7, "javascript": 0.3},
            frameworks=["Flask", "React"],
        ),
        classifications=[],
        metadata=AuditMetadata(
            timestamp=datetime.now(),
            target_path="/test/repo",
            project_type="web_app",
        ),
    )


class TestOverviewComponent:
    def test_build_overview_con_dati(self, mock_result):
        from cto_audit.dashboard.components.overview import build_overview
        result = build_overview(mock_result)
        assert result is not None

    def test_build_overview_senza_dati(self):
        from cto_audit.dashboard.components.overview import build_overview
        result = build_overview(None)
        assert result is not None

    def test_health_gauge(self, mock_result):
        from cto_audit.dashboard.components.overview import health_gauge
        gauge = health_gauge(65.0)
        assert gauge is not None

    def test_layer_card(self):
        from cto_audit.dashboard.components.overview import layer_card
        card = layer_card("security", 75.0, 3)
        assert card is not None

    def test_stack_badges(self):
        from cto_audit.dashboard.components.overview import stack_badges
        badges = stack_badges({"python": 0.7}, ["Flask"])
        assert badges is not None


class TestLayersComponent:
    def test_build_layers_con_dati(self, mock_result):
        from cto_audit.dashboard.components.layers import build_layers
        result = build_layers(mock_result)
        assert result is not None

    def test_build_layers_senza_dati(self):
        from cto_audit.dashboard.components.layers import build_layers
        result = build_layers(None)
        assert result is not None


class TestFindingsComponent:
    def test_build_findings_con_dati(self, mock_result):
        from cto_audit.dashboard.components.findings import build_findings_table
        result = build_findings_table(mock_result)
        assert result is not None

    def test_build_findings_senza_dati(self):
        from cto_audit.dashboard.components.findings import build_findings_table
        result = build_findings_table(None)
        assert result is not None


class TestRemediationComponent:
    def test_build_remediation_senza_dati(self):
        from cto_audit.dashboard.components.remediation import build_remediation
        result = build_remediation(None)
        assert result is not None

    def test_build_remediation_senza_pipeline(self, mock_result):
        from cto_audit.dashboard.components.remediation import build_remediation
        result = build_remediation(mock_result)
        assert result is not None


class TestComplianceComponent:
    def test_build_compliance_con_dati(self, mock_result):
        from cto_audit.dashboard.components.compliance import build_compliance
        result = build_compliance(mock_result)
        assert result is not None

    def test_build_compliance_senza_dati(self):
        from cto_audit.dashboard.components.compliance import build_compliance
        result = build_compliance(None)
        assert result is not None


class TestHistoryComponent:
    def test_build_history_senza_dati(self):
        from cto_audit.dashboard.components.history import build_history
        result = build_history(None)
        assert result is not None

    def test_build_history_senza_delta(self, mock_result):
        from cto_audit.dashboard.components.history import build_history
        result = build_history(mock_result, delta=None)
        assert result is not None


class TestSourcePickerComponent:
    def test_build_source_picker(self):
        from cto_audit.dashboard.components.source_picker import build_source_picker
        result = build_source_picker()
        assert result is not None


class TestProjectViewComponent:
    def test_build_project_view_senza_dati(self):
        from cto_audit.dashboard.components.project_view import build_project_view
        result = build_project_view(None)
        assert result is not None
