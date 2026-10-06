"""
Test per AzureDevOpsSource — verifica URL format Azure DevOps.
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from cto_audit.sources.azure_devops import AzureDevOpsSource


class TestAzureDevOpsSourceInit:
    @patch("cto_audit.sources.azure_devops.shutil.which", return_value="/usr/bin/git")
    def test_init_base(self, mock_which):
        source = AzureDevOpsSource("https://dev.azure.com/org/project/_git/repo")
        assert source._source_type == "azure-devops"

    def test_init_git_non_disponibile(self):
        with patch("cto_audit.sources.azure_devops.shutil.which", return_value=None):
            with pytest.raises(RuntimeError, match="Git non trovato"):
                AzureDevOpsSource("https://dev.azure.com/org/project/_git/repo")


class TestAzureDevOpsSourceCloneUrl:
    @patch("cto_audit.sources.azure_devops.shutil.which", return_value="/usr/bin/git")
    def test_url_senza_token(self, mock_which):
        source = AzureDevOpsSource("https://dev.azure.com/org/project/_git/repo")
        assert source._build_clone_url() == "https://dev.azure.com/org/project/_git/repo"

    @patch("cto_audit.sources.azure_devops.shutil.which", return_value="/usr/bin/git")
    def test_url_con_token(self, mock_which):
        source = AzureDevOpsSource(
            "https://dev.azure.com/org/project/_git/repo", token="pat-abc"
        )
        url = source._build_clone_url()
        assert url == "https://pat-abc@dev.azure.com/org/project/_git/repo"


class TestAzureDevOpsSourceMaterialize:
    @patch("cto_audit.sources.azure_devops.shutil.which", return_value="/usr/bin/git")
    @patch("cto_audit.sources.azure_devops.subprocess.run")
    def test_clone_shallow(self, mock_run, mock_which, tmp_path):
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        source = AzureDevOpsSource("https://dev.azure.com/org/project/_git/repo")
        source._materialize(tmp_path)
        args = mock_run.call_args[0][0]
        assert "--depth" in args

    @patch("cto_audit.sources.azure_devops.shutil.which", return_value="/usr/bin/git")
    @patch("cto_audit.sources.azure_devops.subprocess.run")
    def test_clone_con_branch(self, mock_run, mock_which, tmp_path):
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        source = AzureDevOpsSource(
            "https://dev.azure.com/org/project/_git/repo", branch="develop"
        )
        source._materialize(tmp_path)
        args = mock_run.call_args[0][0]
        assert "--branch" in args
        assert "develop" in args

    @patch("cto_audit.sources.azure_devops.shutil.which", return_value="/usr/bin/git")
    @patch("cto_audit.sources.azure_devops.subprocess.run")
    def test_clone_fallito(self, mock_run, mock_which, tmp_path):
        mock_run.return_value = MagicMock(returncode=128, stderr="fatal: error")
        source = AzureDevOpsSource(
            "https://dev.azure.com/org/project/_git/repo", token="secret"
        )
        with pytest.raises(RuntimeError, match="Errore nel clone"):
            source._materialize(tmp_path)

    @patch("cto_audit.sources.azure_devops.shutil.which", return_value="/usr/bin/git")
    @patch("cto_audit.sources.azure_devops.subprocess.run")
    def test_token_non_nel_messaggio_errore(self, mock_run, mock_which, tmp_path):
        mock_run.return_value = MagicMock(returncode=128, stderr="fatal: error")
        source = AzureDevOpsSource(
            "https://dev.azure.com/org/project/_git/repo", token="my_secret_pat"
        )
        with pytest.raises(RuntimeError) as exc_info:
            source._materialize(tmp_path)
        assert "my_secret_pat" not in str(exc_info.value)
