"""
Integration test — verifica che ogni sorgente produca FileTree, SourceMetadata validi
e sia consumabile dal FileScanner e StackDetector esistenti.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from cto_audit.collectors.scanner import FileScanner
from cto_audit.collectors.stack import StackDetector
from cto_audit.core.models import FileTree, SourceMetadata
from cto_audit.core.source import AuditSource
from cto_audit.sources.archive import ArchiveSource
from cto_audit.sources.base import TempDirSourceMixin
from cto_audit.sources.local import LocalRepoSource


# --- Fixture ---


@pytest.fixture
def synth_repo(tmp_path: Path) -> Path:
    """Repo sintetica con file Python e infra."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n",
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("flask>=3.0\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# My App\n", encoding="utf-8")
    return tmp_path


@pytest.fixture
def synth_zip(tmp_path: Path, synth_repo: Path) -> Path:
    """Crea un zip dalla repo sintetica."""
    archive_path = tmp_path / "repo.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        for root, _dirs, files in (synth_repo).walk():
            for f in files:
                full = root / f
                zf.write(full, full.relative_to(synth_repo))
    return archive_path


# --- Classe helper per simulare una sorgente remota clonata ---


class MockGitSource(TempDirSourceMixin):
    """Simula una sorgente git che 'clona' dalla repo sintetica."""

    def __init__(self, synth_repo: Path) -> None:
        super().__init__(source_type="github")
        self._synth_repo = synth_repo

    def _materialize(self, target_dir: Path) -> None:
        """Copia i file dalla repo sintetica invece di clonare."""
        import shutil
        for item in self._synth_repo.iterdir():
            if item.is_dir():
                shutil.copytree(item, target_dir / item.name)
            else:
                shutil.copy2(item, target_dir / item.name)


# --- Test Protocol conformance ---


class TestProtocolConformance:
    """Verifica che tutte le sorgenti soddisfino AuditSource Protocol."""

    def test_local_source_is_audit_source(self, synth_repo):
        source = LocalRepoSource(synth_repo)
        assert isinstance(source, AuditSource)

    def test_temp_source_is_audit_source(self, synth_repo):
        """TempDirSourceMixin soddisfa AuditSource quando materializzata."""
        source = MockGitSource(synth_repo)
        with source:
            assert isinstance(source, AuditSource)

    def test_archive_source_is_audit_source(self, synth_zip):
        source = ArchiveSource(synth_zip)
        with source:
            assert isinstance(source, AuditSource)


# --- Test integrazione con FileScanner ---


class TestFileScannerIntegration:
    """Verifica che le sorgenti siano consumabili dal FileScanner."""

    def test_scanner_con_local_source(self, synth_repo):
        source = LocalRepoSource(synth_repo)
        scanner = FileScanner(source)
        files = scanner.scan()
        assert len(files) > 0
        paths = [f.path for f in files]
        assert "src/app.py" in paths

    def test_scanner_con_temp_source(self, synth_repo):
        with MockGitSource(synth_repo) as source:
            scanner = FileScanner(source)
            files = scanner.scan()
            assert len(files) > 0
            paths = [f.path for f in files]
            assert "src/app.py" in paths

    def test_scanner_con_archive_source(self, synth_zip):
        with ArchiveSource(synth_zip) as source:
            scanner = FileScanner(source)
            files = scanner.scan()
            assert len(files) > 0


# --- Test integrazione con StackDetector ---


class TestStackDetectorIntegration:
    """Verifica che le sorgenti siano consumabili dal StackDetector."""

    def test_stack_con_local_source(self, synth_repo):
        source = LocalRepoSource(synth_repo)
        scanner = FileScanner(source)
        files = scanner.scan()
        detector = StackDetector(source)
        stack = detector.detect(files)
        assert "python" in stack.languages

    def test_stack_con_temp_source(self, synth_repo):
        with MockGitSource(synth_repo) as source:
            scanner = FileScanner(source)
            files = scanner.scan()
            detector = StackDetector(source)
            stack = detector.detect(files)
            assert "python" in stack.languages


# --- Test FileTree e SourceMetadata ---


class TestFileTreeMetadata:
    """Verifica che le sorgenti producano FileTree e SourceMetadata validi."""

    def test_local_file_tree(self, synth_repo):
        source = LocalRepoSource(synth_repo)
        tree = source.get_file_tree()
        assert isinstance(tree, FileTree)
        assert len(tree.entries) > 0

    def test_local_metadata(self, synth_repo):
        source = LocalRepoSource(synth_repo)
        meta = source.get_metadata()
        assert isinstance(meta, SourceMetadata)
        assert meta.total_files > 0
        assert meta.total_loc > 0

    def test_temp_source_file_tree(self, synth_repo):
        with MockGitSource(synth_repo) as source:
            tree = source.get_file_tree()
            assert isinstance(tree, FileTree)
            assert len(tree.entries) > 0

    def test_temp_source_metadata(self, synth_repo):
        with MockGitSource(synth_repo) as source:
            meta = source.get_metadata()
            assert isinstance(meta, SourceMetadata)
            assert meta.source_type == "github"
            assert meta.total_files > 0

    def test_archive_file_tree(self, synth_zip):
        with ArchiveSource(synth_zip) as source:
            tree = source.get_file_tree()
            assert isinstance(tree, FileTree)
            assert len(tree.entries) > 0

    def test_archive_metadata(self, synth_zip):
        with ArchiveSource(synth_zip) as source:
            meta = source.get_metadata()
            assert isinstance(meta, SourceMetadata)
            assert meta.source_type == "archive"
