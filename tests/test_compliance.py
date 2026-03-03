"""
Test per il Compliance Engine.

Verifica:
- Caricamento profili YAML
- Valutazione controlli: SATISFIED, PARTIAL, FAILED
- Integrazione con finding reali
- Sezione compliance nei reporter
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
import yaml

from cto_audit.compliance.engine import ComplianceEngine
from cto_audit.compliance.models import (
    ComplianceControl,
    ComplianceProfile,
    ControlStatus,
)
from cto_audit.compliance.profile import load_compliance_profile
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


# --- Fixtures ---


@pytest.fixture
def sample_profile() -> ComplianceProfile:
    """Profilo compliance di test con 3 controlli."""
    return ComplianceProfile(
        name="TestProfile",
        description="Profilo di test",
        version="1.0",
        controls=[
            ComplianceControl(
                control_id="TEST-001",
                title="Controllo A",
                article_ref="Art. 1",
                description="Primo controllo di test",
                required_rules=["SEC-AUTH-001", "SEC-HTTPS-001"],
                contributing_rules=["SEC-HEADERS-001"],
            ),
            ComplianceControl(
                control_id="TEST-002",
                title="Controllo B",
                article_ref="Art. 2",
                description="Secondo controllo di test",
                required_rules=["INFRA-CICD-001"],
                contributing_rules=[],
            ),
            ComplianceControl(
                control_id="TEST-003",
                title="Controllo C",
                article_ref="Art. 3",
                description="Terzo controllo di test",
                required_rules=["QUAL-DOC-001"],
                contributing_rules=["QUAL-DOC-002"],
            ),
        ],
    )


def _make_finding(rule_id: str, severity: Severity = Severity.MEDIUM) -> Finding:
    """Crea un finding di test con il rule_id specificato."""
    return Finding(
        id="test-1234",
        layer=Layer.SECURITY,
        severity=severity,
        rule_id=rule_id,
        title=f"Test finding {rule_id}",
        description=f"Finding di test per {rule_id}",
    )


# --- Test ComplianceEngine ---


class TestComplianceEngine:
    """Test per ComplianceEngine.evaluate()."""

    def test_all_satisfied_no_findings(self, sample_profile: ComplianceProfile) -> None:
        """Nessun finding -> tutti i controlli SATISFIED."""
        engine = ComplianceEngine()
        result = engine.evaluate(sample_profile, [])

        assert result.profile_name == "TestProfile"
        assert result.checks_total == 3
        assert result.checks_satisfied == 3
        assert result.checks_partial == 0
        assert result.checks_not_satisfied == 0

    def test_all_satisfied_only_info(self, sample_profile: ComplianceProfile) -> None:
        """Finding INFO non triggerano controlli."""
        findings = [_make_finding("SEC-AUTH-001", Severity.INFO)]
        engine = ComplianceEngine()
        result = engine.evaluate(sample_profile, findings)

        assert result.checks_satisfied == 3

    def test_partial_control(self, sample_profile: ComplianceProfile) -> None:
        """Un finding su regola required -> controllo PARTIAL."""
        findings = [_make_finding("SEC-AUTH-001", Severity.HIGH)]
        engine = ComplianceEngine()
        result = engine.evaluate(sample_profile, findings)

        # TEST-001 ha 3 regole, solo 1 triggered -> PARTIAL
        detail_001 = next(d for d in result.details if d["control_id"] == "TEST-001")
        assert detail_001["status"] == "partial"
        assert "SEC-AUTH-001" in detail_001["triggered_rules"]

        # TEST-002, TEST-003 non toccati -> SATISFIED
        assert result.checks_partial == 1
        assert result.checks_satisfied == 2

    def test_failed_control_all_triggered(self, sample_profile: ComplianceProfile) -> None:
        """Tutte le regole triggerare -> controllo FAILED."""
        findings = [
            _make_finding("SEC-AUTH-001", Severity.HIGH),
            _make_finding("SEC-HTTPS-001", Severity.MEDIUM),
            _make_finding("SEC-HEADERS-001", Severity.LOW),
        ]
        engine = ComplianceEngine()
        result = engine.evaluate(sample_profile, findings)

        detail_001 = next(d for d in result.details if d["control_id"] == "TEST-001")
        assert detail_001["status"] == "failed"
        assert result.checks_not_satisfied == 1

    def test_mixed_statuses(self, sample_profile: ComplianceProfile) -> None:
        """Mix di SATISFIED, PARTIAL, FAILED."""
        findings = [
            # TEST-001: tutti e 3 triggered -> FAILED
            _make_finding("SEC-AUTH-001", Severity.HIGH),
            _make_finding("SEC-HTTPS-001", Severity.MEDIUM),
            _make_finding("SEC-HEADERS-001", Severity.LOW),
            # TEST-002: 1 su 1 triggered -> FAILED
            _make_finding("INFRA-CICD-001", Severity.MEDIUM),
            # TEST-003: QUAL-DOC-001 triggered, QUAL-DOC-002 no -> PARTIAL
            _make_finding("QUAL-DOC-001", Severity.MEDIUM),
        ]
        engine = ComplianceEngine()
        result = engine.evaluate(sample_profile, findings)

        assert result.checks_not_satisfied == 2  # TEST-001 and TEST-002
        assert result.checks_partial == 1  # TEST-003
        assert result.checks_satisfied == 0

    def test_details_structure(self, sample_profile: ComplianceProfile) -> None:
        """Verifica la struttura dei dettagli restituiti."""
        engine = ComplianceEngine()
        result = engine.evaluate(sample_profile, [])

        assert len(result.details) == 3
        for detail in result.details:
            assert "control_id" in detail
            assert "title" in detail
            assert "article_ref" in detail
            assert "status" in detail
            assert "triggered_rules" in detail
            assert "total_rules" in detail

    def test_returns_compliance_result(self, sample_profile: ComplianceProfile) -> None:
        """Il risultato e un ComplianceResult valido."""
        engine = ComplianceEngine()
        result = engine.evaluate(sample_profile, [])

        assert isinstance(result, ComplianceResult)
        assert result.checks_total == result.checks_satisfied + result.checks_partial + result.checks_not_satisfied


# --- Test Profile Loader ---


class TestProfileLoader:
    """Test per il caricamento profili YAML."""

    def test_load_nis2_profile(self) -> None:
        """Carica il profilo NIS2 reale."""
        profile = load_compliance_profile("nis2")

        assert profile.name == "NIS2"
        assert len(profile.controls) == 10  # Art. 21(2) a-j

    def test_nis2_has_all_articles(self) -> None:
        """Il profilo NIS2 copre tutti gli articoli a-j."""
        profile = load_compliance_profile("nis2")

        article_refs = {c.article_ref for c in profile.controls}
        expected = {f"Art. 21(2)({letter})" for letter in "abcdefghij"}
        assert article_refs == expected

    def test_nis2_control_ids(self) -> None:
        """Ogni controllo NIS2 ha un ID corretto."""
        profile = load_compliance_profile("nis2")

        for control in profile.controls:
            assert control.control_id.startswith("NIS2-ART21")
            assert len(control.required_rules) > 0

    def test_nonexistent_profile_raises(self) -> None:
        """Profilo inesistente -> FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="non trovato"):
            load_compliance_profile("nonexistent-profile-xyz")

    def test_profile_round_trip(self, tmp_path: Path) -> None:
        """Crea un profilo YAML temporaneo e verificane il caricamento."""
        profile_data = {
            "name": "TestYAML",
            "description": "Test profile",
            "version": "0.1",
            "controls": [
                {
                    "control_id": "T-001",
                    "title": "Test Control",
                    "article_ref": "Art. X",
                    "description": "A test control",
                    "required_rules": ["RULE-001"],
                    "contributing_rules": [],
                },
            ],
        }
        yaml_path = tmp_path / "test-profile.yml"
        yaml_path.write_text(yaml.dump(profile_data), encoding="utf-8")

        # Load tramite path manipulation — testa il modello
        from cto_audit.compliance.models import ComplianceControl, ComplianceProfile

        raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        controls = [
            ComplianceControl(
                control_id=c["control_id"],
                title=c["title"],
                article_ref=c["article_ref"],
                description=c.get("description", ""),
                required_rules=c.get("required_rules", []),
                contributing_rules=c.get("contributing_rules", []),
            )
            for c in raw["controls"]
        ]
        profile = ComplianceProfile(
            name=raw["name"],
            description=raw["description"],
            version=raw["version"],
            controls=controls,
        )

        assert profile.name == "TestYAML"
        assert len(profile.controls) == 1
        assert profile.controls[0].required_rules == ["RULE-001"]


# --- Test NIS2 Rule Mapping ---


class TestNIS2RuleMapping:
    """Verifica che le regole nel profilo NIS2 esistano nel scoring profile."""

    def test_all_nis2_rules_exist_in_scoring(self) -> None:
        """Ogni rule_id usato nel profilo NIS2 deve esistere nel scoring profile."""
        from cto_audit.scoring.profile import load_profile

        profile = load_compliance_profile("nis2")
        scoring = load_profile("default")

        # Raccogli tutti i rule_id dal scoring (keys del dict)
        scoring_rules = set(scoring.rules.keys())

        # Verifica che ogni regola NIS2 esista
        for control in profile.controls:
            for rule_id in control.required_rules:
                assert rule_id in scoring_rules, (
                    f"Rule {rule_id} in NIS2 control {control.control_id} "
                    f"non esiste nel scoring profile"
                )
            for rule_id in control.contributing_rules:
                assert rule_id in scoring_rules, (
                    f"Contributing rule {rule_id} in NIS2 control {control.control_id} "
                    f"non esiste nel scoring profile"
                )


# --- Test Compliance in Reporter ---


class TestComplianceInReporter:
    """Verifica che i reporter includano la sezione compliance."""

    @pytest.fixture
    def result_with_compliance(self) -> AuditResult:
        """AuditResult con risultati compliance."""
        return AuditResult(
            health_score=HealthScore(
                overall_score=75.0,
                layer_scores={
                    "infra": LayerScore(layer=Layer.INFRA, score=80.0),
                    "architecture": LayerScore(layer=Layer.ARCHITECTURE, score=70.0),
                    "security": LayerScore(layer=Layer.SECURITY, score=65.0),
                    "quality": LayerScore(layer=Layer.QUALITY, score=85.0),
                },
                compliance_results=[
                    ComplianceResult(
                        profile_name="NIS2",
                        checks_total=10,
                        checks_satisfied=6,
                        checks_partial=2,
                        checks_not_satisfied=2,
                        details=[
                            {
                                "control_id": "NIS2-ART21-2A",
                                "title": "Analisi dei rischi",
                                "article_ref": "Art. 21(2)(a)",
                                "status": "satisfied",
                                "triggered_rules": [],
                                "total_rules": 3,
                            },
                            {
                                "control_id": "NIS2-ART21-2D",
                                "title": "Supply chain",
                                "article_ref": "Art. 21(2)(d)",
                                "status": "failed",
                                "triggered_rules": ["INFRA-DEPS-001", "SEC-DEPS-001"],
                                "total_rules": 2,
                            },
                        ],
                    ),
                ],
            ),
            stack_info=StackInfo(),
            classifications=[],
            metadata=AuditMetadata(
                target_path="/test",
                scoring_profile="default",
            ),
        )

    def test_board_report_includes_compliance(self, result_with_compliance: AuditResult) -> None:
        """Il board report include la sezione compliance."""
        from cto_audit.reporters.board import BoardReporter

        reporter = BoardReporter()
        report = reporter.report(result_with_compliance)

        assert "## Compliance" in report
        assert "NIS2" in report
        assert "6/10" in report
        assert "PASS" in report
        assert "FAIL" in report
        assert "INFRA-DEPS-001" in report

    def test_markdown_report_includes_compliance(self, result_with_compliance: AuditResult) -> None:
        """Il markdown report include la sezione compliance."""
        from cto_audit.reporters.markdown import MarkdownReporter

        reporter = MarkdownReporter()
        report = reporter.report(result_with_compliance)

        assert "## Compliance" in report
        assert "NIS2" in report
        assert "6/10" in report
        assert "PASS" in report
        assert "FAIL" in report

    def test_no_compliance_no_section(self) -> None:
        """Senza compliance, la sezione non appare."""
        from cto_audit.reporters.board import BoardReporter

        result = AuditResult(
            health_score=HealthScore(
                overall_score=80.0,
                layer_scores={},
            ),
            stack_info=StackInfo(),
            classifications=[],
            metadata=AuditMetadata(
                target_path="/test",
                scoring_profile="default",
            ),
        )

        reporter = BoardReporter()
        report = reporter.report(result)
        assert "## Compliance" not in report
