"""
Test per Board Report deterministico.
"""

import pytest
from datetime import datetime

from cto_audit.core.models import (
    AuditMetadata,
    AuditResult,
    EvidenceChain,
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
from cto_audit.remediation.context import MaturityLevel, ProjectContext
from cto_audit.remediation.loader import RemediationLoader
from cto_audit.remediation.models import (
    EffortRange,
    RemediationPipelineResult,
    WhatIfResult,
)
from cto_audit.reporters.board import BoardReporter


def _make_finding(rule_id: str, layer: Layer, severity: Severity) -> Finding:
    return Finding(
        id=f"test-{rule_id}",
        layer=layer,
        severity=severity,
        rule_id=rule_id,
        title=f"Test finding {rule_id}",
        description=f"Desc for {rule_id}",
    )


def _make_whatif(rule_id: str, delta: float, t_shirt: str = "M") -> WhatIfResult:
    return WhatIfResult(
        rule_id=rule_id,
        current_score=50.0,
        projected_score=50.0 + delta,
        delta=delta,
        effort=EffortRange(min_hours=4, max_hours=16, t_shirt=t_shirt),
        impact_effort_ratio=delta / 10.0,
    )


def _make_context(**kwargs) -> ProjectContext:
    defaults = dict(
        maturity_level=MaturityLevel.MVP,
        estimated_team_size="3-5",
        primary_language="python",
        primary_framework="FastAPI",
        has_ci_cd=True,
        has_containers=False,
        has_iac=False,
        has_tests=True,
        has_monitoring=False,
        total_files=50,
        total_loc=5000,
        sensitive_files_count=1,
    )
    defaults.update(kwargs)
    return ProjectContext(**defaults)


def _make_result_with_remediation(
    findings: list[Finding] | None = None,
    context: ProjectContext | None = None,
    whatif_results: list[WhatIfResult] | None = None,
    executive_summary: str | None = None,
    llm_used: bool = False,
) -> AuditResult:
    findings = findings or []
    whatif_results = whatif_results or []

    layer_scores: dict[str, LayerScore] = {}
    for layer in Layer:
        layer_findings = [f for f in findings if f.layer == layer]
        evidence = [
            EvidenceChain(
                finding_id=f.id, rule_id=f.rule_id,
                weight=0.8, penalty=-10.0,
            )
            for f in layer_findings
        ]
        layer_scores[layer.value] = LayerScore(
            layer=layer, score=100.0 if not layer_findings else 50.0,
            findings=layer_findings, evidence_chain=evidence,
        )

    remediation = RemediationPipelineResult(
        context=context,
        whatif_results=whatif_results,
        executive_summary=executive_summary,
        llm_used=llm_used,
    )

    result = AuditResult(
        health_score=HealthScore(overall_score=75.0, layer_scores=layer_scores),
        stack_info=StackInfo(
            languages={"python": 0.8, "javascript": 0.2},
            frameworks=["FastAPI"],
        ),
        classifications=[],
        metadata=AuditMetadata(target_path="/test/project"),
    )
    result.remediation = remediation  # type: ignore[attr-defined]
    return result


class TestBoardReportSections:
    def test_all_sections_present(self):
        """Verifica che tutte le sezioni principali siano presenti."""
        result = _make_result_with_remediation(
            findings=[
                _make_finding("INFRA-CICD-001", Layer.INFRA, Severity.CRITICAL),
            ],
            context=_make_context(),
            whatif_results=[_make_whatif("INFRA-CICD-001", 8.75)],
        )
        kb = RemediationLoader.from_yaml("default")
        reporter = BoardReporter(kb_loader=kb)
        md = reporter.report(result)

        assert "# CTO Audit" in md
        assert "## Executive Summary" in md
        assert "## Azioni Prioritarie" in md
        assert "## Red Flags" in md
        assert "## Punti di Forza" in md
        assert "## Score Details" in md
        assert "Board Report generato" in md

    def test_header_with_context(self):
        result = _make_result_with_remediation(context=_make_context())
        reporter = BoardReporter()
        md = reporter.report(result)

        assert "MVP" in md
        assert "3-5" in md
        assert "Python" in md

    def test_executive_summary_template(self):
        result = _make_result_with_remediation(
            findings=[_make_finding("INFRA-CICD-001", Layer.INFRA, Severity.CRITICAL)],
            context=_make_context(),
        )
        reporter = BoardReporter()
        md = reporter.report(result)

        assert "75/100" in md
        assert "1 problemi critici" in md

    def test_executive_summary_override(self):
        result = _make_result_with_remediation(context=_make_context())
        reporter = BoardReporter(executive_summary_override="Custom LLM summary here.")
        md = reporter.report(result)

        assert "Custom LLM summary here." in md

    def test_executive_summary_from_remediation(self):
        result = _make_result_with_remediation(
            context=_make_context(),
            executive_summary="LLM-generated executive summary.",
        )
        reporter = BoardReporter()
        md = reporter.report(result)

        assert "LLM-generated executive summary." in md

    def test_priority_actions_with_whatif(self):
        result = _make_result_with_remediation(
            whatif_results=[
                _make_whatif("INFRA-CICD-001", 8.75),
                _make_whatif("INFRA-DOCKER-001", 6.30),
            ],
        )
        kb = RemediationLoader.from_yaml("default")
        reporter = BoardReporter(kb_loader=kb)
        md = reporter.report(result)

        assert "INFRA-CICD-001" in md
        assert "INFRA-DOCKER-001" in md
        assert "+8.8" in md  # 8.75 rounds to 8.8
        assert "Rischio business:" in md

    def test_priority_actions_empty(self):
        result = _make_result_with_remediation(whatif_results=[])
        reporter = BoardReporter()
        md = reporter.report(result)

        assert "Nessuna simulazione what-if" in md

    def test_red_flags_critical_and_high(self):
        result = _make_result_with_remediation(
            findings=[
                _make_finding("INFRA-CICD-001", Layer.INFRA, Severity.CRITICAL),
                _make_finding("INFRA-DEPS-001", Layer.INFRA, Severity.HIGH),
            ],
        )
        kb = RemediationLoader.from_yaml("default")
        reporter = BoardReporter(kb_loader=kb)
        md = reporter.report(result)

        assert "[CRIT]" in md
        assert "[HIGH]" in md
        assert "INFRA-CICD-001" in md
        assert "INFRA-DEPS-001" in md

    def test_red_flags_none(self):
        result = _make_result_with_remediation(findings=[])
        reporter = BoardReporter()
        md = reporter.report(result)

        assert "Nessun red flag" in md

    def test_strengths_perfect_layers(self):
        result = _make_result_with_remediation(
            context=_make_context(has_ci_cd=True, has_tests=True),
        )
        reporter = BoardReporter()
        md = reporter.report(result)

        # All layers have 100.0 score since no findings
        assert "score perfetto" in md
        assert "CI/CD pipeline presente" in md
        assert "Test automatizzati presenti" in md

    def test_strengths_none(self):
        result = _make_result_with_remediation(
            findings=[
                _make_finding("INFRA-CICD-001", Layer.INFRA, Severity.CRITICAL),
                _make_finding("ARCH-TEST-001", Layer.ARCHITECTURE, Severity.HIGH),
            ],
            context=_make_context(
                has_ci_cd=False, has_containers=False,
                has_iac=False, has_tests=False, has_monitoring=False,
            ),
        )
        reporter = BoardReporter()
        md = reporter.report(result)

        # security and quality layers are still 100
        assert "Sicurezza" in md or "Qualita" in md

    def test_score_details(self):
        result = _make_result_with_remediation(
            findings=[_make_finding("INFRA-CICD-001", Layer.INFRA, Severity.CRITICAL)],
        )
        reporter = BoardReporter()
        md = reporter.report(result)

        assert "Overall Score: 75/100" in md
        assert "Infrastruttura" in md
        assert "Evidence Chain" in md

    def test_footer_without_llm(self):
        result = _make_result_with_remediation(llm_used=False)
        reporter = BoardReporter()
        md = reporter.report(result)

        assert "Board Report generato" in md
        assert "con analisi LLM" not in md

    def test_footer_with_llm(self):
        result = _make_result_with_remediation(llm_used=True)
        reporter = BoardReporter()
        md = reporter.report(result)

        assert "con analisi LLM" in md


class TestBoardReportSave:
    def test_save_to_file(self, tmp_path):
        result = _make_result_with_remediation(context=_make_context())
        reporter = BoardReporter()
        out = tmp_path / "board.md"
        reporter.save(result, out)

        content = out.read_text(encoding="utf-8")
        assert "# CTO Audit" in content
        assert "## Executive Summary" in content


class TestBoardReportScenarios:
    """Test su scenari realistici."""

    def test_prototype_scenario(self):
        """Progetto prototype con molti problemi."""
        findings = [
            _make_finding("INFRA-CICD-001", Layer.INFRA, Severity.CRITICAL),
            _make_finding("INFRA-DOCKER-001", Layer.INFRA, Severity.CRITICAL),
            _make_finding("INFRA-IAC-001", Layer.INFRA, Severity.HIGH),
            _make_finding("ARCH-TEST-001", Layer.ARCHITECTURE, Severity.HIGH),
        ]
        context = _make_context(
            maturity_level=MaturityLevel.PROTOTYPE,
            estimated_team_size="1-2",
            has_ci_cd=False, has_containers=False, has_iac=False, has_tests=False,
            total_files=10, total_loc=500,
        )
        whatif = [
            _make_whatif("INFRA-CICD-001", 8.75),
            _make_whatif("INFRA-DOCKER-001", 6.30),
            _make_whatif("INFRA-IAC-001", 2.45),
            _make_whatif("ARCH-TEST-001", 4.50),
        ]
        result = _make_result_with_remediation(
            findings=findings, context=context, whatif_results=whatif,
        )
        kb = RemediationLoader.from_yaml("default")
        reporter = BoardReporter(kb_loader=kb)
        md = reporter.report(result)

        assert "Prototype" in md
        assert "2 problemi critici" in md
        assert len(md) > 500

    def test_production_clean_scenario(self):
        """Progetto production senza problemi."""
        context = _make_context(
            maturity_level=MaturityLevel.PRODUCTION,
            estimated_team_size="5-10",
            has_ci_cd=True, has_containers=True, has_iac=True,
            has_tests=True, has_monitoring=True,
            total_files=200, total_loc=50000,
        )
        result = _make_result_with_remediation(
            findings=[], context=context, whatif_results=[],
        )
        reporter = BoardReporter()
        md = reporter.report(result)

        assert "Production" in md
        assert "Nessun red flag" in md
        assert "score perfetto" in md

    def test_mvp_mixed_scenario(self):
        """Progetto MVP con mix di problemi."""
        findings = [
            _make_finding("INFRA-DEPS-001", Layer.INFRA, Severity.HIGH),
            _make_finding("ARCH-COUPLING-002", Layer.ARCHITECTURE, Severity.MEDIUM),
        ]
        context = _make_context()
        whatif = [_make_whatif("INFRA-DEPS-001", 4.20)]
        result = _make_result_with_remediation(
            findings=findings, context=context, whatif_results=whatif,
        )
        kb = RemediationLoader.from_yaml("default")
        reporter = BoardReporter(kb_loader=kb)
        md = reporter.report(result)

        assert "MVP" in md
        assert "1 problemi ad alta" in md

    def test_no_remediation_data(self):
        """Risultato senza dati remediation (backward compatibility)."""
        result = AuditResult(
            health_score=HealthScore(
                overall_score=100.0,
                layer_scores={
                    l.value: LayerScore(layer=l, score=100.0) for l in Layer
                },
            ),
            stack_info=StackInfo(),
            classifications=[],
            metadata=AuditMetadata(target_path="/test"),
        )
        reporter = BoardReporter()
        md = reporter.report(result)

        assert "# CTO Audit" in md
        assert "100/100" in md

    def test_with_llm_override_scenario(self):
        """Scenario con executive summary da LLM."""
        result = _make_result_with_remediation(
            context=_make_context(),
            executive_summary="LLM ha analizzato il codebase e ha determinato...",
            llm_used=True,
        )
        reporter = BoardReporter()
        md = reporter.report(result)

        assert "LLM ha analizzato" in md
        assert "con analisi LLM" in md
