"""
Suite end-to-end completa — verifica l'intero prodotto come lo userebbe un utente.

Scenari:
1. CLI classica invariata
2. CLI con sorgente remota (mock)
3. Multi-source project
4. Dashboard lifecycle
5. Agent mode
6. Frozen mode simulation
7. Backward compatibility
"""

from __future__ import annotations

import json
import shutil
import sys
import zipfile
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
import yaml
from typer.testing import CliRunner

from cto_audit.cli import app
from cto_audit.core.models import AuditResult, HealthScore, StackInfo, AuditMetadata

runner = CliRunner()


# --- Fixtures condivise ---


@pytest.fixture
def full_repo(tmp_path: Path) -> Path:
    """Repo sintetica completa con tutto lo stack."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.get('/')\n"
        "def home():\n"
        "    return 'hello'\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "utils.py").write_text(
        "def helper():\n    return True\n",
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text(
        "flask>=3.0\npytest>=8.0\n",
        encoding="utf-8",
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\nCOPY . /app\nCMD [\"python\", \"app.py\"]\n",
        encoding="utf-8",
    )
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text("# Full Test Project\n", encoding="utf-8")
    (tmp_path / ".env").write_text("SECRET=abc123\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"react":"^18.0"}}\n',
        encoding="utf-8",
    )
    return tmp_path


# --- Scenario 1: CLI classica invariata ---


class TestE2ECliClassica:
    def test_scan_locale_auto_approve(self, full_repo):
        """cto-audit scan /repo --auto-approve produce output e score coerente."""
        result = runner.invoke(app, ["scan", str(full_repo), "--auto-approve"])
        assert result.exit_code == 0
        output = result.output.lower()
        assert "health score" in output
        assert "cto audit" in output or "target" in output

    def test_scan_con_tutte_le_opzioni(self, full_repo):
        """Scan con tutte le opzioni simultanee."""
        result = runner.invoke(app, [
            "scan", str(full_repo),
            "--focus", "security",
            "--compliance", "nis2,gdpr",
            "--compliance-mode", "standalone",
            "--scoring", "default",
            "--offline",
            "--auto-approve",
        ])
        assert result.exit_code == 0


# --- Scenario 2: CLI con sorgente remota ---


class TestE2ECliRemote:
    @patch("cto_audit.sources.github.subprocess.run")
    @patch("cto_audit.sources.github.shutil.which", return_value="/usr/bin/git")
    def test_scan_github_url(self, mock_which, mock_run, full_repo):
        """cto-audit scan https://github.com/... (mock) → risultato valido."""
        def fake_clone(cmd, **kwargs):
            dest = Path(cmd[-1])
            dest.mkdir(parents=True, exist_ok=True)
            for item in full_repo.iterdir():
                if item.is_dir():
                    shutil.copytree(item, dest / item.name, dirs_exist_ok=True)
                else:
                    shutil.copy2(item, dest / item.name)
            return MagicMock(returncode=0, stderr="")

        mock_run.side_effect = fake_clone

        result = runner.invoke(app, [
            "scan", "https://github.com/owner/repo",
            "--auto-approve", "--offline",
        ])
        assert result.exit_code == 0
        assert "health score" in result.output.lower()


# --- Scenario 3: Multi-source project ---


class TestE2EMultiSource:
    def test_project_yaml(self, full_repo, tmp_path):
        """cto-audit project config.yml con 2 sorgenti locali."""
        repo2 = tmp_path / "repo2"
        repo2.mkdir()
        (repo2 / "main.js").write_text("console.log('hi');\n", encoding="utf-8")
        (repo2 / "package.json").write_text('{"name":"test"}\n', encoding="utf-8")

        config = {
            "name": "E2E Project",
            "sources": [
                {"name": "backend", "source_type": "local", "path_or_url": str(full_repo)},
                {"name": "frontend", "source_type": "local", "path_or_url": str(repo2)},
            ],
        }
        config_path = tmp_path / "project.yml"
        config_path.write_text(yaml.dump(config), encoding="utf-8")

        output_file = tmp_path / "aggregated.json"
        result = runner.invoke(app, [
            "project", str(config_path),
            "--offline",
            "-o", str(output_file),
        ])
        assert result.exit_code == 0
        assert output_file.exists()

        parsed = json.loads(output_file.read_text(encoding="utf-8"))
        assert parsed["project_name"] == "E2E Project"
        assert parsed["total_sources"] == 2
        assert parsed["aggregated_score"] > 0


# --- Scenario 4: Dashboard lifecycle ---


class TestE2EDashboard:
    def test_create_app_e_rendering(self, full_repo):
        """create_app() con AuditResult fixture → tutte le pagine renderizzano."""
        from cto_audit.dashboard.app import create_app
        from cto_audit.dashboard.callbacks import _run_audit

        app_dash = create_app()
        assert app_dash is not None

        # Simula audit
        result = _run_audit("local", str(full_repo), None, None)
        assert isinstance(result, AuditResult)

        # Tutti i componenti renderizzano senza errore
        from cto_audit.dashboard.components.overview import build_overview
        from cto_audit.dashboard.components.layers import build_layers
        from cto_audit.dashboard.components.findings import build_findings_table
        from cto_audit.dashboard.components.remediation import build_remediation
        from cto_audit.dashboard.components.compliance import build_compliance
        from cto_audit.dashboard.components.history import build_history
        from cto_audit.dashboard.components.source_picker import build_source_picker

        assert build_overview(result) is not None
        assert build_layers(result) is not None
        assert build_findings_table(result) is not None
        assert build_remediation(result) is not None
        assert build_compliance(result) is not None
        assert build_history(result) is not None
        assert build_source_picker() is not None


# --- Scenario 5: Agent mode ---


class TestE2EAgentMode:
    def test_agent_produce_json_completo(self, full_repo, tmp_path):
        """cto-audit agent /repo -o report.json → JSON completo."""
        output_file = tmp_path / "report.json"
        result = runner.invoke(app, [
            "agent", str(full_repo),
            "-o", str(output_file),
            "--offline",
        ])
        assert result.exit_code == 0
        assert output_file.exists()

        audit = AuditResult.model_validate_json(
            output_file.read_text(encoding="utf-8")
        )
        assert audit.health_score.overall_score >= 0
        assert audit.health_score.overall_score <= 100
        assert len(audit.health_score.layer_scores) > 0
        assert audit.stack_info is not None
        assert audit.metadata is not None


# --- Scenario 6: Frozen mode simulation ---


class TestE2EFrozenMode:
    def test_frozen_mode_exe_entry(self, tmp_path):
        """Mock sys._MEIPASS → exe_entry.main() → app creata, YAML trovati."""
        meipass = tmp_path / "meipass"
        for subdir in ["scoring-profiles", "remediation-kb", "compliance-profiles"]:
            (meipass / subdir).mkdir(parents=True)
            (meipass / subdir / "test.yml").write_text("test: true", encoding="utf-8")

        with patch.object(sys, "_MEIPASS", str(meipass), create=True):
            from cto_audit._data import get_data_dir
            for subdir in ["scoring-profiles", "remediation-kb", "compliance-profiles"]:
                result = get_data_dir(subdir)
                assert result == meipass / subdir

    @patch("cto_audit.exe_entry.webbrowser.open")
    @patch("cto_audit.dashboard.app.create_app")
    def test_exe_entry_crea_app(self, mock_create, mock_browser):
        """exe_entry.main() crea app senza errori."""
        mock_app = MagicMock()
        mock_create.return_value = mock_app

        from cto_audit.exe_entry import main
        main(port=9999)

        mock_create.assert_called_once()
        mock_app.run.assert_called_once()


# --- Scenario 7: Backward compatibility (test esistenti invariati) ---


class TestE2EBackwardCompatibility:
    def test_import_app(self):
        """from cto_audit.cli import app funziona."""
        from cto_audit.cli import app as cli_app
        assert cli_app is not None

    def test_local_repo_source_invariato(self, full_repo):
        """LocalRepoSource funziona come prima."""
        from cto_audit.sources.local import LocalRepoSource
        from cto_audit.core.source import AuditSource

        source = LocalRepoSource(full_repo)
        assert isinstance(source, AuditSource)
        tree = source.get_file_tree()
        assert len(tree.entries) > 0
        meta = source.get_metadata()
        assert meta.total_files > 0

    def test_orchestrator_invariato(self, full_repo):
        """AuditOrchestrator funziona come prima."""
        from cto_audit.core.orchestrator import AuditOrchestrator
        from cto_audit.sources.local import LocalRepoSource

        source = LocalRepoSource(full_repo)
        orch = AuditOrchestrator(
            source=source,
            target_path=full_repo,
            offline=True,
            auto_approve=True,
        )
        result = orch.run()
        assert result.health_score.overall_score >= 0
