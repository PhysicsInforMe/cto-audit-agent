"""
Integration test — flusso completo: comando agent su repo sintetica → JSON output.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cto_audit.cli import app
from cto_audit.core.models import AuditResult

runner = CliRunner()


@pytest.fixture
def synth_repo(tmp_path: Path) -> Path:
    """Repo sintetica completa."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.get('/')\n"
        "def home():\n"
        "    return 'hello'\n",
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("flask>=3.0\npytest>=8.0\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nCOPY . /app\n", encoding="utf-8")
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text("# My Flask App\n", encoding="utf-8")
    return tmp_path


class TestAgentIntegration:
    def test_flusso_completo(self, synth_repo, tmp_path):
        """Flusso completo: agent → JSON output → AuditResult deserializzabile."""
        output_file = tmp_path / "report.json"
        result = runner.invoke(app, [
            "agent", str(synth_repo),
            "-o", str(output_file),
            "--offline",
        ])
        assert result.exit_code == 0
        assert output_file.exists()

        # Deserializza e valida
        json_str = output_file.read_text(encoding="utf-8")
        audit_result = AuditResult.model_validate_json(json_str)

        assert audit_result.health_score.overall_score >= 0
        assert audit_result.health_score.overall_score <= 100
        assert len(audit_result.health_score.layer_scores) > 0
        assert "python" in audit_result.stack_info.languages

    def test_health_score_presente(self, synth_repo, tmp_path):
        """L'output contiene health_score con layer breakdown."""
        output_file = tmp_path / "report.json"
        runner.invoke(app, [
            "agent", str(synth_repo),
            "-o", str(output_file),
            "--offline",
        ])
        parsed = json.loads(output_file.read_text(encoding="utf-8"))
        hs = parsed["health_score"]
        assert "overall_score" in hs
        assert "layer_scores" in hs
        assert len(hs["layer_scores"]) > 0

    def test_findings_presenti(self, synth_repo, tmp_path):
        """L'output contiene findings nelle layer_scores."""
        output_file = tmp_path / "report.json"
        runner.invoke(app, [
            "agent", str(synth_repo),
            "-o", str(output_file),
            "--offline",
        ])
        parsed = json.loads(output_file.read_text(encoding="utf-8"))
        # Almeno un layer dovrebbe avere findings
        total_findings = sum(
            len(ls["findings"])
            for ls in parsed["health_score"]["layer_scores"].values()
        )
        assert total_findings > 0

    def test_metadata_corretti(self, synth_repo, tmp_path):
        """L'output contiene metadata corretti."""
        output_file = tmp_path / "report.json"
        runner.invoke(app, [
            "agent", str(synth_repo),
            "-o", str(output_file),
            "--offline",
        ])
        parsed = json.loads(output_file.read_text(encoding="utf-8"))
        meta = parsed["metadata"]
        assert "timestamp" in meta
        assert meta["offline_mode"] is True
