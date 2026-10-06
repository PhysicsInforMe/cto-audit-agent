"""
Test per TempDirSourceMixin — creazione/cleanup temp dir, context manager.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cto_audit.core.models import FileTree, SourceMetadata
from cto_audit.sources.base import TempDirSourceMixin


class ConcreteTempSource(TempDirSourceMixin):
    """Implementazione concreta per testing."""

    def __init__(self) -> None:
        super().__init__(source_type="test")

    def _materialize(self, target_dir: Path) -> None:
        (target_dir / "hello.py").write_text("print('hello')\n", encoding="utf-8")
        (target_dir / "sub").mkdir()
        (target_dir / "sub" / "world.py").write_text("x = 1\n", encoding="utf-8")


class FailingTempSource(TempDirSourceMixin):
    """Sorgente che fallisce durante _materialize."""

    def __init__(self) -> None:
        super().__init__(source_type="failing")

    def _materialize(self, target_dir: Path) -> None:
        raise RuntimeError("Clone fallito")


class TestTempDirSourceMixin:
    """Test per il mixin base."""

    def test_context_manager_crea_temp_dir(self):
        """__enter__ crea una directory temporanea."""
        source = ConcreteTempSource()
        with source:
            assert source._temp_dir is not None
            assert source._temp_dir.exists()
            assert source._temp_dir.is_dir()

    def test_context_manager_cleanup(self):
        """__exit__ rimuove la directory temporanea."""
        source = ConcreteTempSource()
        with source:
            temp_path = source._temp_dir
        assert not temp_path.exists()

    def test_cleanup_after_exception(self):
        """La temp dir viene rimossa anche dopo eccezione."""
        source = ConcreteTempSource()
        temp_path = None
        with pytest.raises(ValueError):
            with source:
                temp_path = source._temp_dir
                raise ValueError("test error")
        assert temp_path is not None
        assert not temp_path.exists()

    def test_cleanup_after_materialize_failure(self):
        """La temp dir viene rimossa se _materialize fallisce."""
        source = FailingTempSource()
        with pytest.raises(RuntimeError, match="Clone fallito"):
            with source:
                pass
        # Dopo __exit__, la dir dovrebbe essere pulita
        assert source._temp_dir is None

    def test_get_file_tree(self):
        """get_file_tree restituisce un FileTree valido."""
        source = ConcreteTempSource()
        with source:
            tree = source.get_file_tree()
            assert isinstance(tree, FileTree)
            file_paths = [e.path for e in tree.entries if not e.is_dir]
            assert "hello.py" in file_paths
            assert "sub/world.py" in file_paths

    def test_read_file(self):
        """read_file legge il contenuto del file."""
        source = ConcreteTempSource()
        with source:
            content = source.read_file("hello.py")
            assert "print('hello')" in content

    def test_get_metadata(self):
        """get_metadata restituisce metadati validi con source_type corretto."""
        source = ConcreteTempSource()
        with source:
            meta = source.get_metadata()
            assert isinstance(meta, SourceMetadata)
            assert meta.source_type == "test"
            assert meta.total_files == 2

    def test_access_outside_context_raises(self):
        """Accedere ai dati fuori dal context manager solleva RuntimeError."""
        source = ConcreteTempSource()
        with pytest.raises(RuntimeError, match="context manager"):
            source.get_file_tree()
        with pytest.raises(RuntimeError, match="context manager"):
            source.read_file("hello.py")
        with pytest.raises(RuntimeError, match="context manager"):
            source.get_metadata()

    def test_local_source_none_after_exit(self):
        """Dopo __exit__, _local_source è None."""
        source = ConcreteTempSource()
        with source:
            assert source._local_source is not None
        assert source._local_source is None
        assert source._temp_dir is None
