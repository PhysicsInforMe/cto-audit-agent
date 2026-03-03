"""
Test per Context Collector.
"""

import pytest
from datetime import datetime

from cto_audit.core.models import (
    AuditMetadata,
    AuditResult,
    FileClassification,
    FileInfo,
    Finding,
    HealthScore,
    Layer,
    LayerScore,
    PrivacyCategory,
    Severity,
    StackInfo,
)
from cto_audit.remediation.context import (
    ContextCollector,
    MaturityLevel,
    ProjectContext,
)


def _make_classification(path: str, loc: int = 50, category: PrivacyCategory = PrivacyCategory.SAFE) -> FileClassification:
    return FileClassification(
        file_info=FileInfo(path=path, size=loc * 30, extension=".py", lines_of_code=loc),
        category=category,
        reason="test",
    )


def _make_finding(rule_id: str, layer: Layer, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        id=f"test-{rule_id}",
        layer=layer,
        severity=severity,
        rule_id=rule_id,
        title=f"Test {rule_id}",
        description=f"Finding for {rule_id}",
    )


def _make_result(
    classifications: list[FileClassification] | None = None,
    findings: list[Finding] | None = None,
    languages: dict[str, float] | None = None,
    frameworks: list[str] | None = None,
) -> AuditResult:
    classifications = classifications or []
    findings = findings or []
    languages = languages or {}
    frameworks = frameworks or []

    # Build health score with findings distributed by layer
    layer_scores: dict[str, LayerScore] = {}
    for layer in Layer:
        layer_findings = [f for f in findings if f.layer == layer]
        layer_scores[layer.value] = LayerScore(
            layer=layer, score=100.0, findings=layer_findings,
        )

    return AuditResult(
        health_score=HealthScore(overall_score=100.0, layer_scores=layer_scores),
        stack_info=StackInfo(languages=languages, frameworks=frameworks),
        classifications=classifications,
        metadata=AuditMetadata(target_path="/test"),
    )


class TestPrototypeDetection:
    def test_prototype_few_files_no_infra(self):
        """< 20 file, nessuna infra → prototype."""
        classifications = [_make_classification(f"file{i}.py") for i in range(10)]
        findings = [
            _make_finding("INFRA-CICD-001", Layer.INFRA, Severity.CRITICAL),
            _make_finding("INFRA-DOCKER-001", Layer.INFRA, Severity.CRITICAL),
            _make_finding("INFRA-IAC-001", Layer.INFRA, Severity.HIGH),
            _make_finding("INFRA-MON-001", Layer.INFRA, Severity.MEDIUM),
            _make_finding("ARCH-TEST-001", Layer.ARCHITECTURE, Severity.HIGH),
        ]
        result = _make_result(classifications=classifications, findings=findings)

        ctx = ContextCollector().collect(result)
        assert ctx.maturity_level == MaturityLevel.PROTOTYPE
        assert not ctx.has_ci_cd
        assert not ctx.has_containers
        assert not ctx.has_tests


class TestMVPDetection:
    def test_mvp_medium_files_some_infra(self):
        """20-100 file, qualche infra → mvp."""
        classifications = [_make_classification(f"file{i}.py") for i in range(50)]
        # No INFRA-CICD-001 → has_ci_cd=True
        findings = [
            _make_finding("INFRA-DOCKER-001", Layer.INFRA, Severity.CRITICAL),
            _make_finding("INFRA-IAC-001", Layer.INFRA, Severity.HIGH),
        ]
        result = _make_result(classifications=classifications, findings=findings)

        ctx = ContextCollector().collect(result)
        assert ctx.maturity_level == MaturityLevel.MVP
        assert ctx.has_ci_cd  # Not triggered
        assert not ctx.has_containers  # Triggered


class TestProductionDetection:
    def test_production_many_files_full_infra(self):
        """> 100 file, CI+Docker+test+IaC → production."""
        classifications = [_make_classification(f"file{i}.py") for i in range(150)]
        # Nessun finding infra → tutto presente
        result = _make_result(classifications=classifications, findings=[])

        ctx = ContextCollector().collect(result)
        assert ctx.maturity_level == MaturityLevel.PRODUCTION
        assert ctx.has_ci_cd
        assert ctx.has_containers
        assert ctx.has_iac
        assert ctx.has_tests
        assert ctx.has_monitoring


class TestTeamSize:
    def test_small_team(self):
        classifications = [_make_classification(f"f{i}.py", loc=50) for i in range(10)]
        result = _make_result(classifications=classifications)
        ctx = ContextCollector().collect(result)
        assert ctx.estimated_team_size == "1-2"

    def test_medium_team(self):
        classifications = [_make_classification(f"f{i}.py", loc=100) for i in range(50)]
        result = _make_result(classifications=classifications)
        ctx = ContextCollector().collect(result)
        assert ctx.estimated_team_size == "3-5"

    def test_large_team(self):
        classifications = [_make_classification(f"f{i}.py", loc=200) for i in range(200)]
        result = _make_result(classifications=classifications)
        ctx = ContextCollector().collect(result)
        assert ctx.estimated_team_size == "5-10"

    def test_very_large_team(self):
        classifications = [_make_classification(f"f{i}.py", loc=300) for i in range(600)]
        result = _make_result(classifications=classifications)
        ctx = ContextCollector().collect(result)
        assert ctx.estimated_team_size == "10+"


class TestPrimaryLanguage:
    def test_primary_language_detected(self):
        result = _make_result(languages={"python": 0.7, "javascript": 0.3})
        ctx = ContextCollector().collect(result)
        assert ctx.primary_language == "python"

    def test_no_languages(self):
        result = _make_result(languages={})
        ctx = ContextCollector().collect(result)
        assert ctx.primary_language is None

    def test_primary_framework(self):
        result = _make_result(
            languages={"python": 1.0},
            frameworks=["FastAPI", "SQLAlchemy"],
        )
        ctx = ContextCollector().collect(result)
        assert ctx.primary_framework == "FastAPI"


class TestSensitiveFiles:
    def test_sensitive_count(self):
        classifications = [
            _make_classification("app.py"),
            _make_classification(".env", category=PrivacyCategory.SENSITIVE),
            _make_classification("secret.key", category=PrivacyCategory.SENSITIVE),
        ]
        result = _make_result(classifications=classifications)
        ctx = ContextCollector().collect(result)
        assert ctx.sensitive_files_count == 2


class TestInfoFindingsIgnored:
    def test_info_findings_dont_affect_flags(self):
        """INFO findings non devono influenzare le flag infra."""
        findings = [
            # INFO finding per CI/CD - should NOT set has_ci_cd=False
            _make_finding("INFRA-CICD-001", Layer.INFRA, Severity.INFO),
        ]
        classifications = [_make_classification(f"f{i}.py") for i in range(50)]
        result = _make_result(classifications=classifications, findings=findings)
        ctx = ContextCollector().collect(result)
        # INFO severity is excluded from triggered rules, so has_ci_cd should be True
        assert ctx.has_ci_cd
