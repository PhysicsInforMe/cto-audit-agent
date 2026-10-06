"""
Test per BitbucketSource — verifica URL format cloud e server.
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from cto_audit.sources.bitbucket import BitbucketSource


class TestBitbucketSourceInit:
    @patch("cto_audit.sources.bitbucket.shutil.which", return_value="/usr/bin/git")
    def test_init_base(self, mock_which):
        source = BitbucketSource("https://bitbucket.org/owner/repo")
        assert source._source_type == "bitbucket"

    def test_init_git_non_disponibile(self):
        with patch("cto_audit.sources.bitbucket.shutil.which", return_value=None):
            with pytest.raises(RuntimeError, match="Git non trovato"):
                BitbucketSource("https://bitbucket.org/owner/repo")


class TestBitbucketSourceCloneUrl:
    """Test per URL format cloud vs server."""

    @patch("cto_audit.sources.bitbucket.shutil.which", return_value="/usr/bin/git")
    def test_url_senza_token(self, mock_which):
        source = BitbucketSource("https://bitbucket.org/owner/repo")
        assert source._build_clone_url() == "https://bitbucket.org/owner/repo"

    @patch("cto_audit.sources.bitbucket.shutil.which", return_value="/usr/bin/git")
    def test_url_cloud_con_token(self, mock_which):
        """Bitbucket Cloud usa x-token-auth:{token}@."""
        source = BitbucketSource(
            "https://bitbucket.org/owner/repo", token="bb_tok123"
        )
        url = source._build_clone_url()
        assert url == "https://x-token-auth:bb_tok123@bitbucket.org/owner/repo"

    @patch("cto_audit.sources.bitbucket.shutil.which", return_value="/usr/bin/git")
    def test_url_server_con_token(self, mock_which):
        """Bitbucket Server usa {token}@ direttamente."""
        source = BitbucketSource(
            "https://bitbucket.mycompany.com/scm/proj/repo.git",
            token="pat_123",
            server=True,
        )
        url = source._build_clone_url()
        assert url == "https://pat_123@bitbucket.mycompany.com/scm/proj/repo.git"


class TestBitbucketSourceMaterialize:
    @patch("cto_audit.sources.bitbucket.shutil.which", return_value="/usr/bin/git")
    @patch("cto_audit.sources.bitbucket.subprocess.run")
    def test_clone_shallow(self, mock_run, mock_which, tmp_path):
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        source = BitbucketSource("https://bitbucket.org/owner/repo")
        source._materialize(tmp_path)
        args = mock_run.call_args[0][0]
        assert "--depth" in args

    @patch("cto_audit.sources.bitbucket.shutil.which", return_value="/usr/bin/git")
    @patch("cto_audit.sources.bitbucket.subprocess.run")
    def test_clone_con_branch(self, mock_run, mock_which, tmp_path):
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        source = BitbucketSource("https://bitbucket.org/owner/repo", branch="main")
        source._materialize(tmp_path)
        args = mock_run.call_args[0][0]
        assert "--branch" in args

    @patch("cto_audit.sources.bitbucket.shutil.which", return_value="/usr/bin/git")
    @patch("cto_audit.sources.bitbucket.subprocess.run")
    def test_clone_fallito(self, mock_run, mock_which, tmp_path):
        mock_run.return_value = MagicMock(returncode=128, stderr="fatal: error")
        source = BitbucketSource("https://bitbucket.org/owner/repo", token="secret")
        with pytest.raises(RuntimeError, match="Errore nel clone"):
            source._materialize(tmp_path)
