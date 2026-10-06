"""
Test gate HITL obbligatorio sull'output LLM nella pipeline di remediation.

Regola: nessun testo generato da LLM entra in un report senza approvazione
umana esplicita. Senza revisore (--auto-approve) o con --no-llm si usa il
template deterministico.
"""

from __future__ import annotations

from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from cto_audit.core.models import Layer
from cto_audit.core.orchestrator import AuditOrchestrator
from cto_audit.llm.provider import LLMResponse
from cto_audit.llm.router import LLMRouter
from cto_audit.reporters.due_diligence import DueDiligenceReporter
from cto_audit.scoring.engine import ScoringEngine
from cto_audit.scoring.profile import load_profile
from cto_audit.sources.local import LocalRepoSource

LLM_TEXT = "Sintesi generata dal modello\n---\nRischio narrato dal modello"


class _MockProvider:
    def __init__(self) -> None:
        self.calls = 0

    def generate(self, prompt, config=None):
        self.calls += 1
        return LLMResponse(text=LLM_TEXT, model_used="mock-model", tokens_used=10, provider="mock")

    def is_available(self) -> bool:
        return True

    @property
    def provider_name(self) -> str:
        return "mock"


def _write(base: Path, rel: str, content: str) -> None:
    p = base / Path(rel)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


@pytest.fixture
def repo(tmp_path) -> Path:
    _write(tmp_path, "README.md", "# App\n")
    _write(tmp_path, "app.py", "x = 1\n")
    return tmp_path


def _orchestrator(repo: Path, provider: _MockProvider, **kwargs) -> AuditOrchestrator:
    return AuditOrchestrator(
        source=LocalRepoSource(repo), target_path=repo,
        scoring_profile="due-diligence", offline=True,
        console=Console(file=StringIO()), board_report=True,
        llm_router=LLMRouter(providers=[provider]),
        **kwargs,
    )


def _run_pipeline(orch: AuditOrchestrator):
    """Esegue la pipeline di remediation su un risultato minimo senza il gate privacy."""
    orch.auto_approve_privacy_for_test = True
    profile = load_profile("due-diligence")
    engine = ScoringEngine(profile)
    from cto_audit.core.models import AuditMetadata, AuditResult, StackInfo
    result = AuditResult(
        health_score=engine.calculate([]),
        stack_info=StackInfo(languages={"python": 1.0}),
        classifications=[],
        metadata=AuditMetadata(target_path=str(orch.target_path), scoring_profile="due-diligence"),
    )
    return orch._run_remediation_pipeline(result, engine, result.stack_info), result


class TestApprovalRequired:
    def test_auto_approve_non_interpella_llm(self, repo):
        provider = _MockProvider()
        orch = _orchestrator(repo, provider, auto_approve=True, no_llm=False)
        remediation, _ = _run_pipeline(orch)
        assert provider.calls == 0
        assert remediation.llm_used is False
        assert remediation.llm_hitl_approved is None
        assert "revisore" in (remediation.llm_skipped_reason or "")
        # Narrativa presente ma da template: nessun testo del modello
        assert remediation.executive_summary
        assert "Sintesi generata dal modello" not in remediation.executive_summary

    def test_no_llm_non_interpella_llm(self, repo):
        provider = _MockProvider()
        orch = _orchestrator(repo, provider, auto_approve=False, no_llm=True)
        remediation, _ = _run_pipeline(orch)
        assert provider.calls == 0
        assert remediation.llm_used is False
        assert "--no-llm" in (remediation.llm_skipped_reason or "")

    def test_revisore_approva(self, repo):
        provider = _MockProvider()
        orch = _orchestrator(repo, provider, auto_approve=False, no_llm=False)
        orch._llm_approval_input = lambda prompt: "s"
        remediation, _ = _run_pipeline(orch)
        assert provider.calls == 1
        assert remediation.llm_used is True
        assert remediation.llm_hitl_approved is True
        assert remediation.executive_summary == "Sintesi generata dal modello"
        assert remediation.llm_skipped_reason is None

    def test_revisore_rifiuta_usa_template(self, repo):
        provider = _MockProvider()
        orch = _orchestrator(repo, provider, auto_approve=False, no_llm=False)
        orch._llm_approval_input = lambda prompt: "n"
        remediation, _ = _run_pipeline(orch)
        assert provider.calls == 1
        assert remediation.llm_used is False
        assert remediation.llm_hitl_approved is False
        assert "rifiutato" in (remediation.llm_skipped_reason or "")
        # Il testo del modello non deve comparire da nessuna parte
        assert "Sintesi generata dal modello" not in (remediation.executive_summary or "")
        assert remediation.executive_summary  # template deterministico presente

    def test_eof_vale_come_rifiuto(self, repo):
        provider = _MockProvider()
        orch = _orchestrator(repo, provider, auto_approve=False, no_llm=False)

        class _EOFConsole:
            def print(self, *a, **k): pass
            def input(self, *a, **k): raise EOFError

        orch.console = _EOFConsole()  # type: ignore[assignment]
        remediation, _ = _run_pipeline(orch)
        assert remediation.llm_used is False
        assert remediation.llm_hitl_approved is False


class TestReportLabels:
    def test_report_dd_etichetta_origine_del_testo(self, repo):
        provider = _MockProvider()
        orch = _orchestrator(repo, provider, auto_approve=False, no_llm=False)
        orch._llm_approval_input = lambda prompt: "s"
        remediation, result = _run_pipeline(orch)
        result.remediation = remediation
        text = DueDiligenceReporter().report(result)
        assert "generato da LLM, approvato dal revisore" in text

    def test_report_dd_spiega_perche_niente_llm(self, repo):
        provider = _MockProvider()
        orch = _orchestrator(repo, provider, auto_approve=True, no_llm=False)
        remediation, result = _run_pipeline(orch)
        result.remediation = remediation
        text = DueDiligenceReporter().report(result)
        assert "template deterministico" in text
        assert "revisore" in text


class TestEndToEnd:
    def test_scan_headless_non_usa_mai_llm(self, repo):
        """Percorso CLI tipico in CI: --auto-approve senza --no-llm."""
        provider = _MockProvider()
        orch = _orchestrator(repo, provider, auto_approve=True, no_llm=False)
        result = orch.run()
        assert result.remediation is not None
        assert result.remediation.llm_used is False
        assert provider.calls == 0
        assert Layer.PROVENANCE.value in result.health_score.layer_scores
