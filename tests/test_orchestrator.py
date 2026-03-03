"""
Test per il Blocco 10 — Orchestrator + Report + Integrazione End-to-End.

Copre:
- AuditOrchestrator: flusso completo, focus su singolo layer, repo vuota
- TerminalReporter: output Rich con health score, layer scores, top 5 azioni
- MarkdownReporter: report completo in Markdown, salvataggio su file
- Integrazione CLI end-to-end su fixture repo "sana" e "problematica"
- Score con catena di evidenze verificabile
- --focus infra esegue solo layer infra
- --output report.md produce file Markdown
"""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from cto_audit.cli import app
from cto_audit.core.models import (
    AuditResult,
    Finding,
    HealthScore,
    Layer,
    Severity,
)
from cto_audit.core.orchestrator import AuditOrchestrator
from cto_audit.reporters.markdown import MarkdownReporter
from cto_audit.reporters.terminal import TerminalReporter
from cto_audit.sources.local import LocalRepoSource

runner = CliRunner()


# ============================================================
# Fixture repo — "sana" (ben strutturata)
# ============================================================

@pytest.fixture
def repo_sana(tmp_path: Path) -> Path:
    """
    Repo ben strutturata con CI/CD, Docker best practices,
    test, lockfile, IaC e monitoraggio.
    """
    tmp_path = tmp_path / "sana"
    tmp_path.mkdir()

    # Struttura layered
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "core").mkdir()
    (tmp_path / "src" / "services").mkdir()
    (tmp_path / "src" / "core" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "src" / "core" / "models.py").write_text(
        "class User:\n    pass\n\nclass Product:\n    pass\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "services" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "src" / "services" / "auth.py").write_text(
        "from src.core.models import User\n\ndef authenticate(u): return True\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "app.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n\n"
        "@app.get('/health')\ndef health(): return {'status': 'ok'}\n",
        encoding="utf-8",
    )

    # Dipendenze con lockfile
    (tmp_path / "requirements.txt").write_text("fastapi>=0.100\nuvicorn>=0.23\n", encoding="utf-8")
    (tmp_path / "poetry.lock").write_text("# lockfile\n", encoding="utf-8")

    # CI/CD
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
        encoding="utf-8",
    )

    # Docker con best practices
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11-slim AS builder\nCOPY . /app\nRUN pip install -r requirements.txt\n\n"
        "FROM python:3.11-slim\nCOPY --from=builder /app /app\nUSER appuser\n"
        "HEALTHCHECK CMD curl -f http://localhost:8000/health || exit 1\n"
        "CMD [\"uvicorn\", \"app:app\"]\n",
        encoding="utf-8",
    )
    (tmp_path / ".dockerignore").write_text(".git\n__pycache__\n.env\n", encoding="utf-8")

    # IaC
    (tmp_path / "terraform").mkdir()
    (tmp_path / "terraform" / "main.tf").write_text(
        'resource "aws_instance" "web" { ami = "ami-123" }\n',
        encoding="utf-8",
    )

    # Test
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "tests" / "test_auth.py").write_text(
        "def test_auth():\n    assert True\n",
        encoding="utf-8",
    )

    # Monitoraggio (health check nel codice FastAPI + Sentry)
    (tmp_path / "sentry.properties").write_text("dsn=https://example.sentry.io\n", encoding="utf-8")

    return tmp_path


# ============================================================
# Fixture repo — "problematica" (molti problemi)
# ============================================================

@pytest.fixture
def repo_problematica(tmp_path: Path) -> Path:
    """
    Repo con molti problemi: flat structure, no CI/CD, no Docker,
    no test, no lockfile, secrets in chiaro, no IaC.
    """
    tmp_path = tmp_path / "problematica"
    tmp_path.mkdir()

    # File tutti nella root (flat)
    (tmp_path / "app.py").write_text(
        "import os\nDB_PASSWORD = os.environ.get('DB_PASSWORD', 'secret')\n"
        "def main(): pass\n",
        encoding="utf-8",
    )
    (tmp_path / "utils.py").write_text(
        "def helper(): return True\n",
        encoding="utf-8",
    )
    (tmp_path / "models.py").write_text(
        "class User: pass\n",
        encoding="utf-8",
    )
    (tmp_path / "views.py").write_text(
        "def index(): return 'hello'\n",
        encoding="utf-8",
    )
    (tmp_path / "config.py").write_text(
        "API_KEY = 'sk-1234567890abcdef'\nDATABASE_URL = 'postgres://user:pass@host/db'\n",
        encoding="utf-8",
    )

    # Dipendenze senza lockfile
    (tmp_path / "requirements.txt").write_text("flask>=3.0\npytest>=8.0\n", encoding="utf-8")

    # File .env con secrets
    (tmp_path / ".env").write_text(
        "DB_PASSWORD=supersecret123\nAPI_KEY=sk-abcdef123456\n",
        encoding="utf-8",
    )

    # Package JSON senza lock
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"express": "^4.0"}}),
        encoding="utf-8",
    )

    return tmp_path


# ============================================================
# Test AuditOrchestrator
# ============================================================

class TestAuditOrchestrator:
    """Test per il coordinatore del flusso di audit."""

    def test_flusso_completo_repo_sana(self, repo_sana: Path):
        """Il flusso completo su repo sana produce un AuditResult valido."""
        source = LocalRepoSource(repo_sana)
        orchestrator = AuditOrchestrator(
            source=source,
            target_path=repo_sana,
            auto_approve=True,
            console=Console(file=StringIO()),
        )
        result = orchestrator.run()

        assert isinstance(result, AuditResult)
        assert 0 <= result.health_score.overall_score <= 100
        assert result.stack_info.languages  # Deve rilevare almeno un linguaggio
        assert len(result.classifications) > 0
        assert result.metadata.target_path == str(repo_sana)

    def test_flusso_completo_repo_problematica(self, repo_problematica: Path):
        """La repo problematica ha score più basso della sana."""
        source = LocalRepoSource(repo_problematica)
        orchestrator = AuditOrchestrator(
            source=source,
            target_path=repo_problematica,
            auto_approve=True,
            console=Console(file=StringIO()),
        )
        result = orchestrator.run()

        assert isinstance(result, AuditResult)
        # Score basso per la repo problematica
        assert result.health_score.overall_score < 100

    def test_score_repo_sana_migliore(self, repo_sana: Path, repo_problematica: Path):
        """La repo sana ha score migliore della problematica."""
        source_sana = LocalRepoSource(repo_sana)
        orch_sana = AuditOrchestrator(
            source=source_sana, target_path=repo_sana,
            auto_approve=True, console=Console(file=StringIO()),
        )
        result_sana = orch_sana.run()

        source_prob = LocalRepoSource(repo_problematica)
        orch_prob = AuditOrchestrator(
            source=source_prob, target_path=repo_problematica,
            auto_approve=True, console=Console(file=StringIO()),
        )
        result_prob = orch_prob.run()

        assert result_sana.health_score.overall_score > result_prob.health_score.overall_score

    def test_focus_infra(self, repo_problematica: Path):
        """Con --focus infra, solo i finding infra vengono prodotti."""
        source = LocalRepoSource(repo_problematica)
        orchestrator = AuditOrchestrator(
            source=source,
            target_path=repo_problematica,
            focus=Layer.INFRA,
            auto_approve=True,
            console=Console(file=StringIO()),
        )
        result = orchestrator.run()

        # I finding del layer architecture non devono esserci
        infra_findings = result.health_score.layer_scores["infra"].findings
        arch_findings = result.health_score.layer_scores["architecture"].findings
        assert len(infra_findings) > 0
        assert len(arch_findings) == 0

    def test_focus_architecture(self, repo_problematica: Path):
        """Con --focus architecture, solo i finding architecture vengono prodotti."""
        source = LocalRepoSource(repo_problematica)
        orchestrator = AuditOrchestrator(
            source=source,
            target_path=repo_problematica,
            focus=Layer.ARCHITECTURE,
            auto_approve=True,
            console=Console(file=StringIO()),
        )
        result = orchestrator.run()

        infra_findings = result.health_score.layer_scores["infra"].findings
        arch_findings = result.health_score.layer_scores["architecture"].findings
        assert len(infra_findings) == 0
        assert len(arch_findings) > 0

    def test_repo_vuota(self, tmp_path: Path):
        """Repo vuota produce score 100/100."""
        source = LocalRepoSource(tmp_path)
        orchestrator = AuditOrchestrator(
            source=source,
            target_path=tmp_path,
            auto_approve=True,
            console=Console(file=StringIO()),
        )
        result = orchestrator.run()
        assert result.health_score.overall_score == 100.0

    def test_catena_evidenze_presente(self, repo_problematica: Path):
        """Lo score ha catena di evidenze verificabile."""
        source = LocalRepoSource(repo_problematica)
        orchestrator = AuditOrchestrator(
            source=source,
            target_path=repo_problematica,
            auto_approve=True,
            console=Console(file=StringIO()),
        )
        result = orchestrator.run()

        # Almeno un layer deve avere evidenze
        has_evidence = False
        for ls in result.health_score.layer_scores.values():
            if ls.evidence_chain:
                has_evidence = True
                # Ogni evidenza ha i campi obbligatori
                for ev in ls.evidence_chain:
                    assert ev.finding_id
                    assert ev.rule_id
                    assert ev.penalty <= 0
        assert has_evidence

    def test_metadata_completa(self, repo_sana: Path):
        """I metadati del risultato sono completi."""
        source = LocalRepoSource(repo_sana)
        orchestrator = AuditOrchestrator(
            source=source,
            target_path=repo_sana,
            scoring_profile="default",
            offline=True,
            auto_approve=True,
            console=Console(file=StringIO()),
        )
        result = orchestrator.run()

        assert result.metadata.scoring_profile == "default"
        assert result.metadata.offline_mode is True
        assert result.metadata.target_path == str(repo_sana)


# ============================================================
# Test TerminalReporter
# ============================================================

class TestTerminalReporter:
    """Test per il reporter terminale Rich."""

    def test_report_completo(self, repo_problematica: Path):
        """Il report terminale mostra health score, layer scores e azioni."""
        source = LocalRepoSource(repo_problematica)
        orchestrator = AuditOrchestrator(
            source=source, target_path=repo_problematica,
            auto_approve=True, console=Console(file=StringIO()),
        )
        result = orchestrator.run()

        output = StringIO()
        console = Console(file=output, force_terminal=True, width=100)
        reporter = TerminalReporter(console=console)
        reporter.report(result)

        text = output.getvalue().lower()
        assert "health score" in text
        assert "infrastruttura" in text
        assert "architettura" in text
        assert "/100" in text

    def test_report_mostra_azioni(self, repo_problematica: Path):
        """Il report terminale mostra le top 5 azioni prioritarie."""
        source = LocalRepoSource(repo_problematica)
        orchestrator = AuditOrchestrator(
            source=source, target_path=repo_problematica,
            auto_approve=True, console=Console(file=StringIO()),
        )
        result = orchestrator.run()

        output = StringIO()
        console = Console(file=output, force_terminal=True, width=100)
        reporter = TerminalReporter(console=console)
        reporter.report(result)

        text = output.getvalue().lower()
        assert "azioni prioritarie" in text

    def test_report_con_evidence(self, repo_problematica: Path):
        """Con show_evidence=True, mostra la catena di evidenze."""
        source = LocalRepoSource(repo_problematica)
        orchestrator = AuditOrchestrator(
            source=source, target_path=repo_problematica,
            auto_approve=True, console=Console(file=StringIO()),
        )
        result = orchestrator.run()

        output = StringIO()
        console = Console(file=output, force_terminal=True, width=100)
        reporter = TerminalReporter(console=console)
        reporter.report(result, show_evidence=True)

        text = output.getvalue().lower()
        assert "evidenz" in text

    def test_report_repo_sana(self, repo_sana: Path):
        """Il report sulla repo sana mostra score alto."""
        source = LocalRepoSource(repo_sana)
        orchestrator = AuditOrchestrator(
            source=source, target_path=repo_sana,
            auto_approve=True, console=Console(file=StringIO()),
        )
        result = orchestrator.run()

        output = StringIO()
        console = Console(file=output, force_terminal=True, width=100)
        reporter = TerminalReporter(console=console)
        reporter.report(result)

        text = output.getvalue()
        # Deve mostrare health score
        assert "HEALTH SCORE" in text

    def test_report_nessuna_azione(self, tmp_path: Path):
        """Repo vuota: nessuna azione richiesta."""
        source = LocalRepoSource(tmp_path)
        orchestrator = AuditOrchestrator(
            source=source, target_path=tmp_path,
            auto_approve=True, console=Console(file=StringIO()),
        )
        result = orchestrator.run()

        output = StringIO()
        console = Console(file=output, force_terminal=True, width=100)
        reporter = TerminalReporter(console=console)
        reporter.report(result)

        text = output.getvalue().lower()
        assert "nessuna azione" in text or "100/100" in text


# ============================================================
# Test MarkdownReporter
# ============================================================

class TestMarkdownReporter:
    """Test per il reporter Markdown."""

    def test_report_contiene_sezioni(self, repo_problematica: Path):
        """Il report Markdown contiene tutte le sezioni principali."""
        source = LocalRepoSource(repo_problematica)
        orchestrator = AuditOrchestrator(
            source=source, target_path=repo_problematica,
            auto_approve=True, console=Console(file=StringIO()),
        )
        result = orchestrator.run()

        reporter = MarkdownReporter()
        md = reporter.report(result)

        assert "# CTO Audit Report" in md
        assert "## Health Score" in md
        assert "## Score per Layer" in md
        assert "## Top 5 Azioni Prioritarie" in md
        assert "## Dettaglio Finding" in md
        assert "## Catena di Evidenze" in md

    def test_report_contiene_stack(self, repo_sana: Path):
        """Il report Markdown mostra lo stack rilevato."""
        source = LocalRepoSource(repo_sana)
        orchestrator = AuditOrchestrator(
            source=source, target_path=repo_sana,
            auto_approve=True, console=Console(file=StringIO()),
        )
        result = orchestrator.run()

        reporter = MarkdownReporter()
        md = reporter.report(result)

        assert "**Stack:**" in md
        assert "Python" in md

    def test_salva_su_file(self, repo_problematica: Path, tmp_path: Path):
        """MarkdownReporter.save() crea il file correttamente."""
        source = LocalRepoSource(repo_problematica)
        orchestrator = AuditOrchestrator(
            source=source, target_path=repo_problematica,
            auto_approve=True, console=Console(file=StringIO()),
        )
        result = orchestrator.run()

        output_file = tmp_path / "report.md"
        reporter = MarkdownReporter()
        reporter.save(result, output_file)

        assert output_file.exists()
        content = output_file.read_text(encoding="utf-8")
        assert "# CTO Audit Report" in content
        assert "Health Score" in content

    def test_report_contiene_finding(self, repo_problematica: Path):
        """Il report Markdown contiene il dettaglio dei finding."""
        source = LocalRepoSource(repo_problematica)
        orchestrator = AuditOrchestrator(
            source=source, target_path=repo_problematica,
            auto_approve=True, console=Console(file=StringIO()),
        )
        result = orchestrator.run()

        reporter = MarkdownReporter()
        md = reporter.report(result)

        # Almeno una regola INFRA o ARCH deve apparire
        assert "INFRA-" in md or "ARCH-" in md

    def test_report_contiene_evidenze(self, repo_problematica: Path):
        """Il report Markdown contiene la catena di evidenze."""
        source = LocalRepoSource(repo_problematica)
        orchestrator = AuditOrchestrator(
            source=source, target_path=repo_problematica,
            auto_approve=True, console=Console(file=StringIO()),
        )
        result = orchestrator.run()

        reporter = MarkdownReporter()
        md = reporter.report(result)

        assert "Catena di Evidenze" in md
        # Deve contenere almeno una riga tabella con weight/penalty
        assert "| INFRA-" in md or "| ARCH-" in md


# ============================================================
# Test Integrazione CLI end-to-end
# ============================================================

class TestCLIEndToEnd:
    """Test end-to-end sulla CLI completa."""

    def test_e2e_repo_sana(self, repo_sana: Path):
        """cto-audit scan su repo sana produce output completo."""
        result = runner.invoke(app, ["scan", str(repo_sana), "--auto-approve"])
        assert result.exit_code == 0
        output = result.output.lower()
        # Deve mostrare health score
        assert "health score" in output
        # Deve mostrare i layer
        assert "infrastruttura" in output or "architettura" in output

    def test_e2e_repo_problematica(self, repo_problematica: Path):
        """cto-audit scan su repo problematica produce output con finding."""
        result = runner.invoke(app, ["scan", str(repo_problematica), "--auto-approve"])
        assert result.exit_code == 0
        output = result.output.lower()
        assert "health score" in output
        assert "azioni prioritarie" in output

    def test_e2e_focus_infra(self, repo_problematica: Path):
        """--focus infra esegue solo il layer infra."""
        result = runner.invoke(app, [
            "scan", str(repo_problematica),
            "--focus", "infra",
            "--auto-approve",
        ])
        assert result.exit_code == 0
        output = result.output.lower()
        assert "health score" in output

    def test_e2e_output_markdown(self, repo_problematica: Path, tmp_path: Path):
        """--output report.md produce file Markdown."""
        output_file = tmp_path / "report.md"
        result = runner.invoke(app, [
            "scan", str(repo_problematica),
            "--auto-approve",
            "--output", str(output_file),
        ])
        assert result.exit_code == 0
        assert output_file.exists()
        content = output_file.read_text(encoding="utf-8")
        assert "# CTO Audit Report" in content
        assert "Health Score" in content
        assert "Catena di Evidenze" in content

    def test_e2e_repo_vuota(self, tmp_path: Path):
        """Repo vuota non fa crash."""
        result = runner.invoke(app, ["scan", str(tmp_path), "--auto-approve"])
        # Potrebbe exit con 0 (nessun file) — non deve crashare
        assert result.exit_code == 0

    def test_e2e_scoring_default(self, repo_sana: Path):
        """Il profilo scoring default è usato per default."""
        result = runner.invoke(app, ["scan", str(repo_sana), "--auto-approve"])
        assert result.exit_code == 0
        assert "default" in result.output.lower() or "/100" in result.output

    def test_e2e_tutte_opzioni(self, repo_sana: Path):
        """Test con tutte le opzioni contemporaneamente."""
        result = runner.invoke(app, [
            "scan", str(repo_sana),
            "--focus", "infra",
            "--compliance", "nis2",
            "--scoring", "default",
            "--offline",
            "--auto-approve",
        ])
        assert result.exit_code == 0

    def test_e2e_path_inesistente(self):
        """Path inesistente → errore leggibile."""
        result = runner.invoke(app, ["scan", "/path/inesistente/abc123"])
        assert result.exit_code == 1

    def test_e2e_focus_invalido(self, repo_sana: Path):
        """--focus invalido → errore leggibile."""
        result = runner.invoke(app, [
            "scan", str(repo_sana),
            "--focus", "banana",
            "--auto-approve",
        ])
        assert result.exit_code == 1
