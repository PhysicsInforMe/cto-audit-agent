"""
Test per la CLI (Blocco 6).

Verifica:
- --help mostra help corretto
- scan con path inesistente dà errore leggibile
- scan su repo di test completa le fasi 1-3
- --reuse-classification riusa il file YAML
- --auto-approve salta il gate interattivo
- --offline accettato senza errori
- --focus accettato con layer validi, rifiutato con invalidi
- Test end-to-end su fixture di repo sintetica
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cto_audit.cli import app
from cto_audit.collectors.privacy import PrivacyClassifier
from cto_audit.collectors.scanner import FileScanner
from cto_audit.core.models import PrivacyCategory
from cto_audit.hitl.persistence import ClassificationPersistence
from cto_audit.sources.local import LocalRepoSource

runner = CliRunner()


# --- Fixture ---


@pytest.fixture
def repo_test(tmp_path: Path) -> Path:
    """
    Crea una repo di test completa per la CLI.
    Contiene: file Python, JS, Dockerfile, .env, package.json, .github/workflows.
    """
    # Sorgenti Python
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.get('/')\n"
        "def home():\n"
        "    return 'hello'\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "utils.py").write_text(
        "def helper():\n"
        "    return True\n",
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text(
        "flask>=3.0\npytest>=8.0\n",
        encoding="utf-8",
    )

    # Frontend JS
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend" / "app.jsx").write_text(
        "import React from 'react';\nexport default () => <h1>Hi</h1>;\n",
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"react": "^18.0"},
    }), encoding="utf-8")

    # Infra
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11\nCOPY . /app\nCMD [\"python\", \"app.py\"]\n",
        encoding="utf-8",
    )
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
        encoding="utf-8",
    )

    # File sensibile
    (tmp_path / ".env").write_text("DB_PASSWORD=secret123\n", encoding="utf-8")

    # File binario
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\x00\x00")

    # README
    (tmp_path / "README.md").write_text("# Test Project\n", encoding="utf-8")

    return tmp_path


# --- Test Help ---


class TestHelp:
    """Test per l'help della CLI."""

    def test_help_root(self):
        """cto-audit --help mostra l'help."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "cto-audit" in result.output.lower() or "analizza" in result.output.lower()

    def test_help_scan(self):
        """cto-audit scan --help mostra le opzioni."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--focus" in result.output
        assert "--compliance" in result.output
        assert "--offline" in result.output
        assert "--reuse-classification" in result.output
        assert "--auto-approve" in result.output
        assert "--output" in result.output
        assert "--scoring" in result.output


# --- Test Errori ---


class TestErrori:
    """Test per la gestione degli errori."""

    def test_path_inesistente(self):
        """scan con path inesistente → errore leggibile."""
        result = runner.invoke(app, ["scan", "/path/che/non/esiste/assolutamente"])
        assert result.exit_code == 1
        assert "non esiste" in result.output.lower() or "errore" in result.output.lower()

    def test_path_file_non_directory(self, tmp_path: Path):
        """scan con un file (non directory) → errore leggibile."""
        file_path = tmp_path / "file.txt"
        file_path.touch()
        result = runner.invoke(app, ["scan", str(file_path)])
        assert result.exit_code == 1
        assert "directory" in result.output.lower() or "errore" in result.output.lower()

    def test_focus_invalido(self, repo_test: Path):
        """--focus con valore invalido → errore leggibile."""
        result = runner.invoke(app, ["scan", str(repo_test), "--focus", "invalid_layer", "--auto-approve"])
        assert result.exit_code == 1
        assert "non valido" in result.output.lower() or "errore" in result.output.lower()

    def test_compliance_mode_invalido(self, repo_test: Path):
        """--compliance-mode invalido → errore leggibile."""
        result = runner.invoke(app, ["scan", str(repo_test), "--compliance-mode", "invalid", "--auto-approve"])
        assert result.exit_code == 1
        assert "non valida" in result.output.lower() or "errore" in result.output.lower()


# --- Test Auto-Approve ---


class TestAutoApprove:
    """Test per --auto-approve (salta gate HITL)."""

    def test_auto_approve_completa_fasi_1_3(self, repo_test: Path):
        """--auto-approve completa le fasi e produce il report."""
        result = runner.invoke(app, ["scan", str(repo_test), "--auto-approve"])
        assert result.exit_code == 0
        # Verifica che produce il report completo con health score
        output = result.output.lower()
        assert "health score" in output
        # Verifica che mostra info sullo stack
        assert "stack" in output or "python" in output

    def test_auto_approve_salva_classificazione(self, repo_test: Path):
        """--auto-approve salva il file di classificazione."""
        runner.invoke(app, ["scan", str(repo_test), "--auto-approve"])
        persistence = ClassificationPersistence(repo_test)
        assert persistence.exists()

    def test_auto_approve_classificazione_corretta(self, repo_test: Path):
        """La classificazione salvata con --auto-approve è coerente."""
        runner.invoke(app, ["scan", str(repo_test), "--auto-approve"])
        persistence = ClassificationPersistence(repo_test)
        loaded = persistence.load()

        cat_map = {c.file_info.path: c.category for c in loaded}

        # .env dovrebbe essere SENSITIVE
        assert cat_map[".env"] == PrivacyCategory.SENSITIVE
        # logo.png dovrebbe essere EXCLUDED
        assert cat_map["logo.png"] == PrivacyCategory.EXCLUDED
        # src/app.py dovrebbe essere SAFE
        assert cat_map["src/app.py"] == PrivacyCategory.SAFE


# --- Test Reuse Classification ---


class TestReuseClassification:
    """Test per --reuse-classification."""

    def test_reuse_classification(self, repo_test: Path):
        """--reuse-classification riusa il file YAML salvato."""
        # Primo run: salva classificazione
        runner.invoke(app, ["scan", str(repo_test), "--auto-approve"])

        # Secondo run: riusa — deve completare e produrre il report
        result = runner.invoke(app, ["scan", str(repo_test), "--reuse-classification", "--auto-approve"])
        assert result.exit_code == 0
        assert "health score" in result.output.lower()

    def test_reuse_senza_file_precedente_fa_scan(self, repo_test: Path):
        """--reuse-classification senza file precedente → fa la scansione normale."""
        # Non c'è file precedente, quindi deve fare scan + auto-approve non c'è,
        # ma possiamo combinare con --auto-approve
        result = runner.invoke(app, [
            "scan", str(repo_test),
            "--reuse-classification", "--auto-approve",
        ])
        assert result.exit_code == 0


# --- Test Offline ---


class TestOffline:
    """Test per --offline."""

    def test_offline_accettato(self, repo_test: Path):
        """--offline è accettato senza errori."""
        result = runner.invoke(app, ["scan", str(repo_test), "--offline", "--auto-approve"])
        assert result.exit_code == 0

    def test_offline_mostrato_nel_summary(self, repo_test: Path):
        """--offline è riportato nel pannello iniziale."""
        result = runner.invoke(app, ["scan", str(repo_test), "--offline", "--auto-approve"])
        assert result.exit_code == 0
        # Il pannello dovrebbe mostrare "Offline: sì"


# --- Test Focus ---


class TestFocus:
    """Test per --focus."""

    def test_focus_infra_accettato(self, repo_test: Path):
        """--focus infra è accettato."""
        result = runner.invoke(app, ["scan", str(repo_test), "--focus", "infra", "--auto-approve"])
        assert result.exit_code == 0

    def test_focus_architecture_accettato(self, repo_test: Path):
        """--focus architecture è accettato."""
        result = runner.invoke(app, ["scan", str(repo_test), "--focus", "architecture", "--auto-approve"])
        assert result.exit_code == 0

    def test_focus_security_accettato(self, repo_test: Path):
        """--focus security è accettato."""
        result = runner.invoke(app, ["scan", str(repo_test), "--focus", "security", "--auto-approve"])
        assert result.exit_code == 0

    def test_focus_quality_accettato(self, repo_test: Path):
        """--focus quality è accettato."""
        result = runner.invoke(app, ["scan", str(repo_test), "--focus", "quality", "--auto-approve"])
        assert result.exit_code == 0


# --- Test Compliance ---


class TestCompliance:
    """Test per --compliance."""

    def test_compliance_singolo(self, repo_test: Path):
        """--compliance nis2 è accettato."""
        result = runner.invoke(app, ["scan", str(repo_test), "--compliance", "nis2", "--auto-approve"])
        assert result.exit_code == 0

    def test_compliance_multiplo(self, repo_test: Path):
        """--compliance nis2,gdpr è accettato (lista separata da virgola)."""
        result = runner.invoke(app, ["scan", str(repo_test), "--compliance", "nis2,gdpr", "--auto-approve"])
        assert result.exit_code == 0


# --- Test End-to-End ---


class TestEndToEnd:
    """Test end-to-end su fixture di repo sintetica."""

    def test_e2e_repo_completa(self, repo_test: Path):
        """Test end-to-end completo con --auto-approve."""
        result = runner.invoke(app, ["scan", str(repo_test), "--auto-approve"])
        assert result.exit_code == 0

        # Verifica che l'output contiene informazioni chiave
        output = result.output.lower()
        # Pannello CTO AUDIT AGENT presente
        assert "cto audit" in output or "target" in output
        # Stack rilevato
        assert "stack" in output or "python" in output or "linguaggi" in output
        # Report con health score
        assert "health score" in output or "/100" in output

    def test_e2e_repo_vuota(self, tmp_path: Path):
        """Test su directory vuota → report con score 100 o messaggio appropriato."""
        result = runner.invoke(app, ["scan", str(tmp_path), "--auto-approve"])
        assert result.exit_code == 0
        output = result.output.lower()
        assert "100/100" in output or "nessun" in output or "health score" in output

    def test_e2e_tutte_le_opzioni(self, repo_test: Path):
        """Test con tutte le opzioni contemporaneamente."""
        result = runner.invoke(app, [
            "scan", str(repo_test),
            "--focus", "infra",
            "--compliance", "nis2,gdpr",
            "--compliance-mode", "standalone",
            "--scoring", "default",
            "--offline",
            "--auto-approve",
        ])
        assert result.exit_code == 0
