"""
Test integrazione completa — Remediation Pipeline end-to-end.

Verifica che la pipeline completa funzioni correttamente:
KB → Context → What-If → LLM fallback → Board Report.
"""

from __future__ import annotations

from datetime import datetime
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

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
from cto_audit.core.orchestrator import AuditOrchestrator
from cto_audit.remediation.context import ContextCollector, MaturityLevel
from cto_audit.remediation.loader import RemediationLoader
from cto_audit.remediation.models import RemediationPipelineResult
from cto_audit.remediation.simulator import WhatIfSimulator
from cto_audit.reporters.board import BoardReporter
from cto_audit.scoring.engine import ScoringEngine
from cto_audit.scoring.profile import load_profile
from cto_audit.sources.local import LocalRepoSource


# --- Helper per creare file ---

def _write(base: Path, rel: str, content: str) -> None:
    p = base / Path(rel)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _make_finding(rule_id: str, layer: Layer, severity: Severity) -> Finding:
    return Finding(
        id=f"test-{rule_id}",
        layer=layer,
        severity=severity,
        rule_id=rule_id,
        title=f"Finding {rule_id}",
        description=f"Description for {rule_id}",
    )


# --- Test Pipeline Completa su Fixture ---

class TestRemediationPipelineOnFixture:
    """Pipeline completa su finding predefiniti (no filesystem)."""

    @pytest.fixture
    def engine(self):
        return ScoringEngine(load_profile("default"))

    @pytest.fixture
    def kb(self):
        return RemediationLoader.from_yaml("default")

    def test_full_pipeline_prototype(self, engine, kb):
        """Pipeline su prototipo con molti problemi."""
        findings = [
            _make_finding("INFRA-CICD-001", Layer.INFRA, Severity.HIGH),
            _make_finding("INFRA-DOCKER-001", Layer.INFRA, Severity.MEDIUM),
            _make_finding("INFRA-IAC-001", Layer.INFRA, Severity.HIGH),
            _make_finding("INFRA-DEPS-001", Layer.INFRA, Severity.HIGH),
            _make_finding("INFRA-CONFIG-001", Layer.INFRA, Severity.HIGH),
            _make_finding("INFRA-MON-001", Layer.INFRA, Severity.MEDIUM),
            _make_finding("ARCH-TEST-001", Layer.ARCHITECTURE, Severity.CRITICAL),
            _make_finding("ARCH-STRUCT-001", Layer.ARCHITECTURE, Severity.MEDIUM),
        ]

        # 1. Calculate health
        health = engine.calculate(findings)
        assert health.overall_score < 85

        # 2. Build effort map from KB
        effort_map = {rid: e.effort_range for rid, e in kb.all_entries().items()}

        # 3. What-If simulation
        whatif = WhatIfSimulator(engine).simulate_all(health, effort_map)
        assert len(whatif) == 8
        assert all(w.delta > 0 for w in whatif)
        assert whatif[0].impact_effort_ratio >= whatif[-1].impact_effort_ratio

        # 4. Context inference
        result = AuditResult(
            health_score=health,
            stack_info=StackInfo(languages={"python": 0.9}, frameworks=["Flask"]),
            classifications=[],
            metadata=AuditMetadata(target_path="/test"),
        )
        context = ContextCollector().collect(result)
        assert not context.has_ci_cd
        assert not context.has_containers
        assert not context.has_tests

        # 5. Build RemediationPipelineResult
        pipeline_result = RemediationPipelineResult(
            context=context,
            whatif_results=whatif,
            executive_summary=None,
            llm_used=False,
        )
        result.remediation = pipeline_result

        # 6. Board report
        reporter = BoardReporter(kb_loader=kb)
        md = reporter.report(result)

        assert "# CTO Audit" in md
        assert "Executive Summary" in md
        assert "Azioni Prioritarie" in md
        assert "Red Flags" in md
        assert "INFRA-CICD-001" in md
        assert "Rischio business:" in md
        assert len(md) > 1000

    def test_full_pipeline_clean(self, engine, kb):
        """Pipeline su progetto pulito."""
        health = engine.calculate([])
        assert health.overall_score == 100.0

        whatif = WhatIfSimulator(engine).simulate_all(health)
        assert whatif == []

        result = AuditResult(
            health_score=health,
            stack_info=StackInfo(),
            classifications=[],
            metadata=AuditMetadata(target_path="/test"),
        )
        context = ContextCollector().collect(result)

        pipeline_result = RemediationPipelineResult(
            context=context, whatif_results=[], llm_used=False,
        )
        result.remediation = pipeline_result

        reporter = BoardReporter(kb_loader=kb)
        md = reporter.report(result)

        assert "100/100" in md
        assert "Nessun red flag" in md

    def test_whatif_top_action_is_highest_roi(self, engine, kb):
        """L'azione con il miglior ROI e al primo posto."""
        findings = [
            _make_finding("INFRA-CICD-001", Layer.INFRA, Severity.CRITICAL),  # -25, M
            _make_finding("INFRA-DEPS-001", Layer.INFRA, Severity.HIGH),     # -12, S
        ]
        health = engine.calculate(findings)
        effort_map = {rid: e.effort_range for rid, e in kb.all_entries().items()}

        whatif = WhatIfSimulator(engine).simulate_all(health, effort_map)
        assert len(whatif) == 2

        # Verify sorted by impact_effort_ratio
        assert whatif[0].impact_effort_ratio >= whatif[1].impact_effort_ratio


# --- Test Pipeline via Orchestrator ---

class TestOrchestratorBoardReport:
    """Pipeline remediation via orchestrator su repo simulata."""

    @pytest.fixture
    def prototype_repo(self, tmp_path) -> Path:
        """Repo prototipo minima."""
        _write(tmp_path, "app.py", "print('hello')\n")
        _write(tmp_path, "utils.py", "def helper(): pass\n")
        _write(tmp_path, ".env", "SECRET_KEY=mysupersecretkey123456\n")
        return tmp_path

    def test_orchestrator_board_report_on(self, prototype_repo):
        """Orchestrator con board_report=True popola result.remediation."""
        source = LocalRepoSource(prototype_repo)
        orchestrator = AuditOrchestrator(
            source=source,
            target_path=prototype_repo,
            auto_approve=True,
            board_report=True,
            no_llm=True,
            console=Console(file=StringIO()),
        )
        result = orchestrator.run()

        assert result.remediation is not None
        assert isinstance(result.remediation, RemediationPipelineResult)
        assert result.remediation.context is not None
        assert len(result.remediation.whatif_results) > 0
        assert result.remediation.llm_used is False

    def test_orchestrator_board_report_off(self, prototype_repo):
        """Orchestrator senza board_report non popola remediation."""
        source = LocalRepoSource(prototype_repo)
        orchestrator = AuditOrchestrator(
            source=source,
            target_path=prototype_repo,
            auto_approve=True,
            board_report=False,
            console=Console(file=StringIO()),
        )
        result = orchestrator.run()

        assert result.remediation is None

    def test_board_report_saved_to_file(self, prototype_repo, tmp_path):
        """Board report salvato su file tramite BoardReporter."""
        source = LocalRepoSource(prototype_repo)
        orchestrator = AuditOrchestrator(
            source=source,
            target_path=prototype_repo,
            auto_approve=True,
            board_report=True,
            no_llm=True,
            console=Console(file=StringIO()),
        )
        result = orchestrator.run()

        kb = RemediationLoader.from_yaml("default")
        reporter = BoardReporter(kb_loader=kb)
        out_path = tmp_path / "board-output.md"
        reporter.save(result, out_path)

        content = out_path.read_text(encoding="utf-8")
        assert "# CTO Audit" in content
        assert "Executive Summary" in content


# --- Test Board Report sui 5 Scenari Realistici ---

def _run_audit_with_board(repo_path: Path) -> AuditResult:
    source = LocalRepoSource(repo_path)
    orchestrator = AuditOrchestrator(
        source=source,
        target_path=repo_path,
        auto_approve=True,
        board_report=True,
        no_llm=True,
        console=Console(file=StringIO()),
    )
    return orchestrator.run()


def _write_large_java(base: Path, rel: str, min_lines: int = 600) -> None:
    lines = [
        "package com.corp.controllers;",
        "",
        "import org.springframework.web.bind.annotation.*;",
        "",
        "@RestController",
        "public class Controller {",
    ]
    for i in range(min_lines):
        lines.append(f"    public void method{i}() {{ }}")
    lines.append("}")
    _write(base, rel, "\n".join(lines))


@pytest.fixture(scope="module")
def shopfast_board(tmp_path_factory) -> AuditResult:
    base = tmp_path_factory.mktemp("shopfast_board")
    _write(base, ".github/workflows/ci.yml", "name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n")
    _write(base, "Dockerfile", "FROM python:3.11-slim\nWORKDIR /app\nCOPY . .\nCMD ['python', 'app.py']\n")
    _write(base, "requirements.txt", "flask>=3.0\nsqlalchemy>=2.0\n")
    _write(base, ".env", "DB_PASSWORD=supersecret123\n")
    _write(base, "src/api/main.py", "from flask import Flask\napp = Flask(__name__)\n")
    _write(base, "src/api/__init__.py", "")
    return _run_audit_with_board(base)


@pytest.fixture(scope="module")
def datadump_board(tmp_path_factory) -> AuditResult:
    base = tmp_path_factory.mktemp("datadump_board")
    _write(base, "scraper.py", "import requests\ndef scrape(): pass\n")
    _write(base, "db.py", "DB_PASSWORD='secret'\ndef save(): pass\n")
    _write(base, ".env", "API_KEY=sk_secret_key_123\n")
    return _run_audit_with_board(base)


@pytest.fixture(scope="module")
def cloudapi_board(tmp_path_factory) -> AuditResult:
    base = tmp_path_factory.mktemp("cloudapi_board")
    _write(base, ".github/workflows/ci.yml", "name: CI\non: push\n")
    _write(base, "Dockerfile", "FROM python:3.12-slim AS builder\nWORKDIR /app\nFROM python:3.12-slim\nRUN useradd appuser\nUSER appuser\nHEALTHCHECK CMD curl -f http://localhost/health\n")
    _write(base, ".dockerignore", ".git\n")
    _write(base, "terraform/main.tf", "resource \"aws\" {}\n")
    _write(base, "poetry.lock", "# lock\n")
    _write(base, "pyproject.toml", "[project]\nname='test'\n")
    _write(base, "prometheus.yml", "scrape_configs: []\n")
    _write(base, "src/main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    _write(base, "tests/test_main.py", "def test_ok(): assert True\n")
    _write(base, "migrations/001.py", "def upgrade(): pass\n")
    return _run_audit_with_board(base)


class TestBoardReportRealisticScenarios:
    def test_shopfast_board_report(self, shopfast_board):
        assert shopfast_board.remediation is not None
        kb = RemediationLoader.from_yaml("default")
        md = BoardReporter(kb_loader=kb).report(shopfast_board)
        assert "# CTO Audit" in md
        assert "Azioni Prioritarie" in md
        assert len(md) > 500

    def test_datadump_board_report(self, datadump_board):
        assert datadump_board.remediation is not None
        kb = RemediationLoader.from_yaml("default")
        md = BoardReporter(kb_loader=kb).report(datadump_board)
        assert "Red Flags" in md
        assert "INFRA-CICD-001" in md

    def test_cloudapi_board_report(self, cloudapi_board):
        assert cloudapi_board.remediation is not None
        kb = RemediationLoader.from_yaml("default")
        md = BoardReporter(kb_loader=kb).report(cloudapi_board)
        assert "Punti di Forza" in md

    def test_prototype_has_more_actions_than_production(self, datadump_board, cloudapi_board):
        assert len(datadump_board.remediation.whatif_results) > len(cloudapi_board.remediation.whatif_results)
