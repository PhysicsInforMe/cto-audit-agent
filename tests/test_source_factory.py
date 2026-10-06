"""
Test per SourceFactory — routing per ogni tipo, errore su tipo sconosciuto.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from cto_audit.sources.factory import SourceFactory
from cto_audit.sources.local import LocalRepoSource


class TestSourceFactoryCreate:
    """Test per la creazione di sorgenti."""

    def test_crea_local(self, tmp_path):
        source = SourceFactory.create("local", str(tmp_path))
        assert isinstance(source, LocalRepoSource)

    @patch("cto_audit.sources.github.shutil.which", return_value="/usr/bin/git")
    def test_crea_github(self, mock_which):
        from cto_audit.sources.github import GitHubSource
        source = SourceFactory.create("github", "https://github.com/owner/repo")
        assert isinstance(source, GitHubSource)

    @patch("cto_audit.sources.gitlab.shutil.which", return_value="/usr/bin/git")
    def test_crea_gitlab(self, mock_which):
        from cto_audit.sources.gitlab import GitLabSource
        source = SourceFactory.create("gitlab", "https://gitlab.com/owner/repo")
        assert isinstance(source, GitLabSource)

    @patch("cto_audit.sources.azure_devops.shutil.which", return_value="/usr/bin/git")
    def test_crea_azure_devops(self, mock_which):
        from cto_audit.sources.azure_devops import AzureDevOpsSource
        source = SourceFactory.create("azure-devops", "https://dev.azure.com/org/project/_git/repo")
        assert isinstance(source, AzureDevOpsSource)

    @patch("cto_audit.sources.bitbucket.shutil.which", return_value="/usr/bin/git")
    def test_crea_bitbucket(self, mock_which):
        from cto_audit.sources.bitbucket import BitbucketSource
        source = SourceFactory.create("bitbucket", "https://bitbucket.org/owner/repo")
        assert isinstance(source, BitbucketSource)

    def test_crea_archive_zip(self, tmp_path):
        archive = tmp_path / "test.zip"
        import zipfile
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("file.txt", "hello")
        source = SourceFactory.create("zip", str(archive))
        from cto_audit.sources.archive import ArchiveSource
        assert isinstance(source, ArchiveSource)

    def test_crea_archive_alias(self, tmp_path):
        archive = tmp_path / "test.zip"
        import zipfile
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("file.txt", "hello")
        source = SourceFactory.create("archive", str(archive))
        from cto_audit.sources.archive import ArchiveSource
        assert isinstance(source, ArchiveSource)

    def test_tipo_sconosciuto(self):
        with pytest.raises(ValueError, match="non supportato"):
            SourceFactory.create("svn", "/some/path")

    @patch("cto_audit.sources.github.shutil.which", return_value="/usr/bin/git")
    def test_passa_token(self, mock_which):
        from cto_audit.sources.github import GitHubSource
        source = SourceFactory.create(
            "github", "https://github.com/owner/repo", token="tok123"
        )
        assert isinstance(source, GitHubSource)
        assert source._token == "tok123"

    @patch("cto_audit.sources.github.shutil.which", return_value="/usr/bin/git")
    def test_passa_branch(self, mock_which):
        source = SourceFactory.create(
            "github", "https://github.com/owner/repo", branch="develop"
        )
        assert source._branch == "develop"


class TestSourceFactoryAutoDetect:
    """Test per l'auto-detection del tipo."""

    def test_detect_github(self):
        assert SourceFactory.detect_type("https://github.com/owner/repo") == "github"

    def test_detect_gitlab(self):
        assert SourceFactory.detect_type("https://gitlab.com/owner/repo") == "gitlab"

    def test_detect_azure_devops(self):
        assert SourceFactory.detect_type("https://dev.azure.com/org/project/_git/repo") == "azure-devops"

    def test_detect_azure_visualstudio(self):
        assert SourceFactory.detect_type("https://org.visualstudio.com/project/_git/repo") == "azure-devops"

    def test_detect_bitbucket(self):
        assert SourceFactory.detect_type("https://bitbucket.org/owner/repo") == "bitbucket"

    def test_detect_zip(self):
        assert SourceFactory.detect_type("/path/to/archive.zip") == "archive"

    def test_detect_tar_gz(self):
        assert SourceFactory.detect_type("/path/to/archive.tar.gz") == "archive"

    def test_detect_tgz(self):
        assert SourceFactory.detect_type("/path/to/archive.tgz") == "archive"

    def test_detect_local_default(self):
        assert SourceFactory.detect_type("/path/to/repo") == "local"

    def test_detect_local_windows_path(self):
        assert SourceFactory.detect_type("C:\\Users\\project") == "local"

    @patch("cto_audit.sources.github.shutil.which", return_value="/usr/bin/git")
    def test_auto_detection_via_create(self, mock_which):
        """auto detection funziona tramite create()."""
        from cto_audit.sources.github import GitHubSource
        source = SourceFactory.create("auto", "https://github.com/owner/repo")
        assert isinstance(source, GitHubSource)

    def test_auto_detection_local(self, tmp_path):
        source = SourceFactory.create("auto", str(tmp_path))
        assert isinstance(source, LocalRepoSource)
