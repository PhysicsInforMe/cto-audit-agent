"""
Test per LLM Interpretation Agent.

Test con mock LLM, fallback deterministico, HITL gate accept/reject.
"""

import pytest
from datetime import datetime

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
from cto_audit.llm.agent import InterpretationAgent, InterpretationResult
from cto_audit.llm.provider import LLMConfig, LLMResponse
from cto_audit.llm.router import LLMRouter
from cto_audit.remediation.context import MaturityLevel, ProjectContext
from cto_audit.remediation.loader import RemediationLoader
from cto_audit.remediation.models import EffortRange, WhatIfResult


def _make_finding(rule_id: str, layer: Layer, severity: Severity) -> Finding:
    return Finding(
        id=f"test-{rule_id}",
        layer=layer,
        severity=severity,
        rule_id=rule_id,
        title=f"Finding {rule_id}",
        description=f"Description for {rule_id}",
    )


def _make_context(**overrides) -> ProjectContext:
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
        sensitive_files_count=0,
    )
    defaults.update(overrides)
    return ProjectContext(**defaults)


def _make_result(findings: list[Finding] | None = None) -> AuditResult:
    findings = findings or []
    layer_scores = {}
    for layer in Layer:
        lf = [f for f in findings if f.layer == layer]
        layer_scores[layer.value] = LayerScore(layer=layer, score=100.0 if not lf else 50.0, findings=lf)

    return AuditResult(
        health_score=HealthScore(overall_score=65.0, layer_scores=layer_scores),
        stack_info=StackInfo(languages={"python": 0.8}, frameworks=["FastAPI"]),
        classifications=[],
        metadata=AuditMetadata(target_path="/test"),
    )


def _make_whatif(rule_id: str, delta: float) -> WhatIfResult:
    return WhatIfResult(
        rule_id=rule_id,
        current_score=50.0,
        projected_score=50.0 + delta,
        delta=delta,
        effort=EffortRange(min_hours=4, max_hours=16, t_shirt="M"),
        impact_effort_ratio=delta / 10.0,
    )


class _MockProvider:
    def __init__(self, available=True, response_text="Summary here\n---\nRisk narrative here"):
        self._available = available
        self._response_text = response_text

    def generate(self, prompt, config=None):
        return LLMResponse(
            text=self._response_text,
            model_used="mock-model",
            tokens_used=50,
            provider="mock",
        )

    def is_available(self):
        return self._available

    @property
    def provider_name(self):
        return "mock"


class TestInterpretationAgentLLM:
    def test_llm_available_generates_interpretation(self):
        """Quando LLM e disponibile, genera interpretazione."""
        provider = _MockProvider(available=True)
        router = LLMRouter(providers=[provider])
        kb = RemediationLoader.from_yaml("default")

        agent = InterpretationAgent(router, kb)
        result = agent.interpret(
            _make_result(findings=[_make_finding("INFRA-CICD-001", Layer.INFRA, Severity.CRITICAL)]),
            [_make_whatif("INFRA-CICD-001", 8.75)],
            _make_context(),
        )

        assert isinstance(result, InterpretationResult)
        assert result.llm_used is True
        assert result.model_used == "mock-model"
        assert result.executive_summary == "Summary here"
        assert result.risk_narrative == "Risk narrative here"

    def test_llm_response_parsing(self):
        """Il parser separa correttamente summary e narrative."""
        text = "EXECUTIVE SUMMARY: Il codebase...\n---\nRISCHI PRINCIPALI:\n- Rischio 1\n- Rischio 2"
        summary, narrative, delta_narr = InterpretationAgent._parse_llm_response(text)
        assert "codebase" in summary
        assert "Rischio 1" in narrative
        assert delta_narr is None


class TestInterpretationAgentFallback:
    def test_fallback_when_llm_unavailable(self):
        """Senza LLM, usa fallback deterministico."""
        provider = _MockProvider(available=False)
        router = LLMRouter(providers=[provider])
        kb = RemediationLoader.from_yaml("default")

        agent = InterpretationAgent(router, kb)
        result = agent.interpret(
            _make_result(findings=[_make_finding("INFRA-CICD-001", Layer.INFRA, Severity.CRITICAL)]),
            [_make_whatif("INFRA-CICD-001", 8.75)],
            _make_context(),
        )

        assert result.llm_used is False
        assert result.model_used is None
        assert "65/100" in result.executive_summary
        assert "1 problemi critici" in result.executive_summary

    def test_fallback_narrative_with_kb(self):
        """Il fallback usa i risk_business dalla KB."""
        provider = _MockProvider(available=False)
        router = LLMRouter(providers=[provider])
        kb = RemediationLoader.from_yaml("default")

        agent = InterpretationAgent(router, kb)
        result = agent.interpret(
            _make_result(findings=[_make_finding("INFRA-CICD-001", Layer.INFRA, Severity.CRITICAL)]),
            [],
            _make_context(),
        )

        assert "CI/CD" in result.risk_narrative

    def test_fallback_no_critical_findings(self):
        """Fallback senza finding critici."""
        provider = _MockProvider(available=False)
        router = LLMRouter(providers=[provider])
        kb = RemediationLoader.from_yaml("default")

        agent = InterpretationAgent(router, kb)
        result = agent.interpret(
            _make_result(findings=[]),
            [],
            _make_context(),
        )

        assert "Nessun" in result.risk_narrative or "Non sono" in result.executive_summary


class TestInterpretationAgentHITL:
    def test_hitl_approved(self):
        """HITL approvato: usa output LLM."""
        provider = _MockProvider(available=True, response_text="LLM Summary\n---\nLLM Risks")
        router = LLMRouter(providers=[provider])
        kb = RemediationLoader.from_yaml("default")

        agent = InterpretationAgent(
            router, kb,
            hitl_enabled=True,
            hitl_input_fn=lambda _: "s",
        )
        result = agent.interpret(
            _make_result(),
            [],
            _make_context(),
        )

        assert result.llm_used is True
        assert result.hitl_approved is True
        assert result.executive_summary == "LLM Summary"

    def test_hitl_rejected(self):
        """HITL rifiutato: usa fallback deterministico."""
        provider = _MockProvider(available=True, response_text="Bad LLM output\n---\nBad risks")
        router = LLMRouter(providers=[provider])
        kb = RemediationLoader.from_yaml("default")

        agent = InterpretationAgent(
            router, kb,
            hitl_enabled=True,
            hitl_input_fn=lambda _: "n",
        )
        result = agent.interpret(
            _make_result(),
            [],
            _make_context(),
        )

        assert result.llm_used is False
        assert result.hitl_approved is False
        assert "Bad" not in result.executive_summary


class TestPromptBuilding:
    def test_prompt_contains_context(self):
        """Il prompt contiene tutte le sezioni necessarie."""
        provider = _MockProvider(available=True)
        router = LLMRouter(providers=[provider])
        kb = RemediationLoader.from_yaml("default")

        agent = InterpretationAgent(router, kb)
        prompt = agent._build_prompt(
            _make_result(findings=[_make_finding("INFRA-CICD-001", Layer.INFRA, Severity.CRITICAL)]),
            [_make_whatif("INFRA-CICD-001", 8.75)],
            _make_context(),
        )

        assert "CONTESTO:" in prompt
        assert "SCORE:" in prompt
        assert "FINDING CRITICI:" in prompt
        assert "SIMULAZIONE WHAT-IF" in prompt
        assert "EXECUTIVE SUMMARY" in prompt
        assert "python" in prompt.lower()
        assert "INFRA-CICD-001" in prompt
