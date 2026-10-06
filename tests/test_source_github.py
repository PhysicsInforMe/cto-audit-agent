"""
Test per GitHubSource — mock subprocess.run, verifica args clone.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from cto_audit.sources.github import GitHubSource, _check_git_available


class TestCheckGitAvailable:
    """Test per la verifica di git su PATH."""

    def test_git_non_trovato(self):
        """Solleva RuntimeError se git non è su PATH."""
        with patch("cto_audit.sources.github.shutil.which", return_value=None):
            with pytest.raises(RuntimeError, match="Git non trovato"):
                _check_git_available()

    def test_git_trovato(self):
        """Non solleva eccezione se git è disponibile."""
        with patch("cto_audit.sources.github.shutil.which", return_value="/usr/bin/git"):
            _check_git_available()  # No exception


class TestGitHubSourceInit:
    """Test per l'inizializzazione di GitHubSource."""

    def test_init_senza_token(self):
        """Inizializzazione senza token."""
        with patch("cto_audit.sources.github.shutil.which", return_value="/usr/bin/git"):
            source = GitHubSource("https://github.com/owner/repo")
            assert source._url == "https://github.com/owner/repo"
            assert source._token is None

    def test_init_con_token(self):
        """Inizializzazione con token."""
        with patch("cto_audit.sources.github.shutil.which", return_value="/usr/bin/git"):
            source = GitHubSource("https://github.com/owner/repo", token="ghp_abc123")
            assert source._token == "ghp_abc123"

    def test_init_git_non_disponibile(self):
        """Solleva RuntimeError se git non è disponibile."""
        with patch("cto_audit.sources.github.shutil.which", return_value=None):
            with pytest.raises(RuntimeError, match="Git non trovato"):
                GitHubSource("https://github.com/owner/repo")


class TestGitHubSourceCloneUrl:
    """Test per la costruzione dell'URL di clone."""

    def test_url_senza_token(self):
        """URL senza token resta invariato."""
        with patch("cto_audit.sources.github.shutil.which", return_value="/usr/bin/git"):
            source = GitHubSource("https://github.com/owner/repo")
            assert source._build_clone_url() == "https://github.com/owner/repo"

    def test_url_con_token(self):
        """URL con token include il token."""
        with patch("cto_audit.sources.github.shutil.which", return_value="/usr/bin/git"):
            source = GitHubSource("https://github.com/owner/repo", token="ghp_abc123")
            assert source._build_clone_url() == "https://ghp_abc123@github.com/owner/repo"


class TestGitHubSourceMaterialize:
    """Test per il clone (con mock subprocess)."""

    @patch("cto_audit.sources.github.shutil.which", return_value="/usr/bin/git")
    @patch("cto_audit.sources.github.subprocess.run")
    def test_clone_shallow_default(self, mock_run, mock_which, tmp_path):
        """Clone shallow per default."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        source = GitHubSource("https://github.com/owner/repo")
        source._materialize(tmp_path)

        args = mock_run.call_args[0][0]
        assert "--depth" in args
        assert "1" in args
        assert str(tmp_path) in args

    @patch("cto_audit.sources.github.shutil.which", return_value="/usr/bin/git")
    @patch("cto_audit.sources.github.subprocess.run")
    def test_clone_full(self, mock_run, mock_which, tmp_path):
        """Clone full (non shallow)."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        source = GitHubSource("https://github.com/owner/repo", shallow=False)
        source._materialize(tmp_path)

        args = mock_run.call_args[0][0]
        assert "--depth" not in args

    @patch("cto_audit.sources.github.shutil.which", return_value="/usr/bin/git")
    @patch("cto_audit.sources.github.subprocess.run")
    def test_clone_con_branch(self, mock_run, mock_which, tmp_path):
        """Clone con branch specifico."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        source = GitHubSource("https://github.com/owner/repo", branch="develop")
        source._materialize(tmp_path)

        args = mock_run.call_args[0][0]
        assert "--branch" in args
        assert "develop" in args

    @patch("cto_audit.sources.github.shutil.which", return_value="/usr/bin/git")
    @patch("cto_audit.sources.github.subprocess.run")
    def test_clone_con_tag(self, mock_run, mock_which, tmp_path):
        """Clone con tag specifico (usa --branch)."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        source = GitHubSource("https://github.com/owner/repo", branch="v1.0.0")
        source._materialize(tmp_path)

        args = mock_run.call_args[0][0]
        assert "--branch" in args
        assert "v1.0.0" in args

    @patch("cto_audit.sources.github.shutil.which", return_value="/usr/bin/git")
    @patch("cto_audit.sources.github.subprocess.run")
    def test_clone_con_token_nell_url(self, mock_run, mock_which, tmp_path):
        """Il token è inserito nell'URL passato a git."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        source = GitHubSource("https://github.com/owner/repo", token="ghp_abc123")
        source._materialize(tmp_path)

        args = mock_run.call_args[0][0]
        clone_url = [a for a in args if "github.com" in a][0]
        assert "ghp_abc123@github.com" in clone_url

    @patch("cto_audit.sources.github.shutil.which", return_value="/usr/bin/git")
    @patch("cto_audit.sources.github.subprocess.run")
    def test_clone_fallito_errore_senza_token(self, mock_run, mock_which, tmp_path):
        """Errore di clone non espone il token."""
        mock_run.return_value = MagicMock(returncode=128, stderr="fatal: error")
        source = GitHubSource("https://github.com/owner/repo", token="ghp_secret")

        with pytest.raises(RuntimeError, match="Errore nel clone"):
            source._materialize(tmp_path)

    @patch("cto_audit.sources.github.shutil.which", return_value="/usr/bin/git")
    @patch("cto_audit.sources.github.subprocess.run")
    def test_clone_fallito_token_non_nel_messaggio(self, mock_run, mock_which, tmp_path):
        """Il messaggio di errore non contiene il token."""
        mock_run.return_value = MagicMock(returncode=128, stderr="fatal: error")
        source = GitHubSource("https://github.com/owner/repo", token="ghp_secret")

        with pytest.raises(RuntimeError) as exc_info:
            source._materialize(tmp_path)
        assert "ghp_secret" not in str(exc_info.value)
