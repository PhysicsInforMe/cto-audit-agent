"""
Test per le nuove opzioni CLI di sorgente remota + integration test.

Verifica:
- Parsing --source-type, --token, --branch, --tag
- Auto-detection da URL
- Integration: CLI con mock source → orchestrator → risultato valido
"""

from __future__ import annotations

import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from typer.testing import CliRunner

from cto_audit.cli import app

runner = CliRunner()


@pytest.fixture
def repo_test(tmp_path: Path) -> Path:
    """Crea una repo di test per la CLI."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n",
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("flask>=3.0\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# Test\n", encoding="utf-8")
    return tmp_path


# --- Test nuove opzioni ---


class TestNewCliOptions:
    """Test per il parsing delle nuove opzioni."""

    def test_help_mostra_source_type(self):
        result = runner.invoke(app, ["scan", "--help"])
        assert "--source-type" in result.output

    def test_help_mostra_token(self):
        result = runner.invoke(app, ["scan", "--help"])
        assert "--token" in result.output

    def test_help_mostra_branch(self):
        result = runner.invoke(app, ["scan", "--help"])
        assert "--branch" in result.output

    def test_help_mostra_tag(self):
        result = runner.invoke(app, ["scan", "--help"])
        assert "--tag" in result.output

    def test_source_type_local_esplicito(self, repo_test):
        """--source-type local funziona come prima."""
        result = runner.invoke(app, [
            "scan", str(repo_test),
            "--source-type", "local",
            "--auto-approve",
        ])
        assert result.exit_code == 0
        assert "health score" in result.output.lower()

    def test_source_type_invalido(self, repo_test):
        """--source-type con valore non supportato → errore."""
        result = runner.invoke(app, [
            "scan", str(repo_test),
            "--source-type", "svn",
            "--auto-approve",
        ])
        assert result.exit_code == 1
        assert "errore" in result.output.lower() or "non supportato" in result.output.lower()

    def test_backward_compatible_no_options(self, repo_test):
        """CLI senza nuove opzioni funziona identica a prima."""
        result = runner.invoke(app, ["scan", str(repo_test), "--auto-approve"])
        assert result.exit_code == 0
        assert "health score" in result.output.lower()


# --- Test auto-detection ---


class TestAutoDetection:
    """Test che l'auto-detection funzioni nella CLI."""

    def test_local_path_auto_detected(self, repo_test):
        """Un path locale è auto-detected come 'local'."""
        result = runner.invoke(app, [
            "scan", str(repo_test), "--auto-approve",
        ])
        assert result.exit_code == 0
        # L'output dovrebbe mostrare il tipo sorgente
        assert "local" in result.output.lower()


# --- Integration test: CLI con mock remote source ---


class TestCliSourcesIntegration:
    """Integration test end-to-end: CLI con sorgenti mock."""

    @patch("cto_audit.sources.github.subprocess.run")
    @patch("cto_audit.sources.github.shutil.which", return_value="/usr/bin/git")
    def test_github_source_via_cli(self, mock_which, mock_run, repo_test):
        """CLI con URL GitHub usa GitHubSource (mock clone)."""
        # Il mock di subprocess.run deve creare una repo nella temp dir
        def fake_clone(cmd, **kwargs):
            # L'ultimo argomento è la directory di destinazione
            dest = cmd[-1]
            dest_path = Path(dest)
            dest_path.mkdir(parents=True, exist_ok=True)
            # Copia la fixture nella dest
            for item in repo_test.iterdir():
                if item.is_dir():
                    shutil.copytree(item, dest_path / item.name, dirs_exist_ok=True)
                else:
                    shutil.copy2(item, dest_path / item.name)
            return MagicMock(returncode=0, stderr="")

        mock_run.side_effect = fake_clone

        result = runner.invoke(app, [
            "scan", "https://github.com/owner/repo",
            "--auto-approve", "--offline",
        ])
        assert result.exit_code == 0
        assert "health score" in result.output.lower()

    def test_archive_source_via_cli(self, repo_test, tmp_path):
        """CLI con file ZIP usa ArchiveSource."""
        import zipfile
        archive_path = tmp_path / "repo.zip"
        with zipfile.ZipFile(archive_path, "w") as zf:
            for root, _dirs, files in repo_test.walk():
                for f in files:
                    full = root / f
                    zf.write(full, full.relative_to(repo_test))

        result = runner.invoke(app, [
            "scan", str(archive_path),
            "--auto-approve", "--offline",
        ])
        assert result.exit_code == 0
        assert "health score" in result.output.lower()
