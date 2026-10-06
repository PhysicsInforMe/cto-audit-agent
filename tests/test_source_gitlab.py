"""
Test per GitLabSource — verifica URL format oauth2:{token}@.
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from cto_audit.sources.gitlab import GitLabSource


class TestGitLabSourceInit:
    """Test per l'inizializzazione."""

    @patch("cto_audit.sources.gitlab.shutil.which", return_value="/usr/bin/git")
    def test_init_base(self, mock_which):
        source = GitLabSource("https://gitlab.com/owner/repo")
        assert source._url == "https://gitlab.com/owner/repo"
        assert source._source_type == "gitlab"

    def test_init_git_non_disponibile(self):
        with patch("cto_audit.sources.gitlab.shutil.which", return_value=None):
            with pytest.raises(RuntimeError, match="Git non trovato"):
                GitLabSource("https://gitlab.com/owner/repo")


class TestGitLabSourceCloneUrl:
    """Test per il formato URL oauth2."""

    @patch("cto_audit.sources.gitlab.shutil.which", return_value="/usr/bin/git")
    def test_url_senza_token(self, mock_which):
        source = GitLabSource("https://gitlab.com/owner/repo")
        assert source._build_clone_url() == "https://gitlab.com/owner/repo"

    @patch("cto_audit.sources.gitlab.shutil.which", return_value="/usr/bin/git")
    def test_url_con_token_formato_oauth2(self, mock_which):
        source = GitLabSource("https://gitlab.com/owner/repo", token="glpat-abc123")
        url = source._build_clone_url()
        assert url == "https://oauth2:glpat-abc123@gitlab.com/owner/repo"

    @patch("cto_audit.sources.gitlab.shutil.which", return_value="/usr/bin/git")
    def test_url_self_hosted(self, mock_which):
        source = GitLabSource("https://git.mycompany.com/team/project", token="tok123")
        url = source._build_clone_url()
        assert url == "https://oauth2:tok123@git.mycompany.com/team/project"


class TestGitLabSourceMaterialize:
    """Test per il clone."""

    @patch("cto_audit.sources.gitlab.shutil.which", return_value="/usr/bin/git")
    @patch("cto_audit.sources.gitlab.subprocess.run")
    def test_clone_shallow(self, mock_run, mock_which, tmp_path):
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        source = GitLabSource("https://gitlab.com/owner/repo")
        source._materialize(tmp_path)

        args = mock_run.call_args[0][0]
        assert "--depth" in args
        assert "1" in args

    @patch("cto_audit.sources.gitlab.shutil.which", return_value="/usr/bin/git")
    @patch("cto_audit.sources.gitlab.subprocess.run")
    def test_clone_con_branch(self, mock_run, mock_which, tmp_path):
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        source = GitLabSource("https://gitlab.com/owner/repo", branch="main")
        source._materialize(tmp_path)

        args = mock_run.call_args[0][0]
        assert "--branch" in args
        assert "main" in args

    @patch("cto_audit.sources.gitlab.shutil.which", return_value="/usr/bin/git")
    @patch("cto_audit.sources.gitlab.subprocess.run")
    def test_clone_fallito(self, mock_run, mock_which, tmp_path):
        mock_run.return_value = MagicMock(returncode=128, stderr="fatal: error")
        source = GitLabSource("https://gitlab.com/owner/repo", token="secret")

        with pytest.raises(RuntimeError, match="Errore nel clone"):
            source._materialize(tmp_path)

    @patch("cto_audit.sources.gitlab.shutil.which", return_value="/usr/bin/git")
    @patch("cto_audit.sources.gitlab.subprocess.run")
    def test_token_non_nel_messaggio_errore(self, mock_run, mock_which, tmp_path):
        mock_run.return_value = MagicMock(returncode=128, stderr="fatal: error")
        source = GitLabSource("https://gitlab.com/owner/repo", token="secret_token")

        with pytest.raises(RuntimeError) as exc_info:
            source._materialize(tmp_path)
        assert "secret_token" not in str(exc_info.value)
