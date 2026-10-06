"""
Test per il comando agent — audit headless con output JSON.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cto_audit.cli import app

runner = CliRunner()


@pytest.fixture
def repo_test(tmp_path: Path) -> Path:
    """Repo sintetica per test agent."""
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# Test\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("flask>=3.0\n", encoding="utf-8")
    return tmp_path


class TestAgentMode:
    def test_help(self):
        result = runner.invoke(app, ["agent", "--help"])
        assert result.exit_code == 0
        assert "--output" in result.output

    def test_agent_stdout(self, repo_test):
        """Agent senza -o produce JSON su stdout."""
        result = runner.invoke(app, ["agent", str(repo_test), "--offline"])
        assert result.exit_code == 0
        # L'output dovrebbe essere JSON valido
        output_lines = result.output.strip()
        parsed = json.loads(output_lines)
        assert "health_score" in parsed

    def test_agent_output_file(self, repo_test, tmp_path):
        """Agent con -o produce file JSON."""
        output_file = tmp_path / "report.json"
        result = runner.invoke(app, [
            "agent", str(repo_test),
            "-o", str(output_file),
            "--offline",
        ])
        assert result.exit_code == 0
        assert output_file.exists()
        parsed = json.loads(output_file.read_text(encoding="utf-8"))
        assert "health_score" in parsed

    def test_agent_json_ha_campi_attesi(self, repo_test, tmp_path):
        """Il JSON output contiene tutti i campi attesi."""
        output_file = tmp_path / "report.json"
        runner.invoke(app, [
            "agent", str(repo_test),
            "-o", str(output_file),
            "--offline",
        ])
        parsed = json.loads(output_file.read_text(encoding="utf-8"))
        assert "health_score" in parsed
        assert "stack_info" in parsed
        assert "metadata" in parsed
        assert "overall_score" in parsed["health_score"]

    def test_agent_path_inesistente(self):
        """Agent con path inesistente → exit code 1."""
        result = runner.invoke(app, ["agent", "/path/che/non/esiste", "--offline"])
        assert result.exit_code == 1

    def test_agent_exit_code_0_su_successo(self, repo_test):
        """Exit code 0 su successo."""
        result = runner.invoke(app, ["agent", str(repo_test), "--offline"])
        assert result.exit_code == 0

    def test_agent_auto_approve_implicito(self, repo_test, tmp_path):
        """Agent usa auto-approve implicitamente (non chiede conferma)."""
        output_file = tmp_path / "report.json"
        # Se auto-approve non fosse implicito, resterebbe in attesa di input
        result = runner.invoke(app, [
            "agent", str(repo_test),
            "-o", str(output_file),
            "--offline",
        ])
        assert result.exit_code == 0
        assert output_file.exists()
