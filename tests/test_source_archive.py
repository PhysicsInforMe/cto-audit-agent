"""
Test per ArchiveSource — crea ZIP/tar.gz reali con fixture, verifica estrazione.
"""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

import pytest

from cto_audit.sources.archive import ArchiveSource


@pytest.fixture
def zip_archive(tmp_path: Path) -> Path:
    """Crea un archivio ZIP di test."""
    archive_path = tmp_path / "test.zip"
    src_dir = tmp_path / "src_content"
    src_dir.mkdir()
    (src_dir / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (src_dir / "sub").mkdir()
    (src_dir / "sub" / "utils.py").write_text("x = 1\n", encoding="utf-8")

    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.write(src_dir / "app.py", "app.py")
        zf.write(src_dir / "sub" / "utils.py", "sub/utils.py")

    return archive_path


@pytest.fixture
def tar_gz_archive(tmp_path: Path) -> Path:
    """Crea un archivio tar.gz di test."""
    archive_path = tmp_path / "test.tar.gz"
    src_dir = tmp_path / "src_content"
    src_dir.mkdir()
    (src_dir / "main.py").write_text("import os\n", encoding="utf-8")
    (src_dir / "README.md").write_text("# Test\n", encoding="utf-8")

    with tarfile.open(archive_path, "w:gz") as tf:
        tf.add(src_dir / "main.py", "main.py")
        tf.add(src_dir / "README.md", "README.md")

    return archive_path


class TestArchiveSourceInit:
    def test_init_valido(self, zip_archive):
        source = ArchiveSource(zip_archive)
        assert source._archive_path == zip_archive

    def test_init_path_inesistente(self):
        with pytest.raises(FileNotFoundError, match="non esiste"):
            ArchiveSource("/path/che/non/esiste.zip")

    def test_init_path_directory(self, tmp_path):
        with pytest.raises(ValueError, match="non è un file"):
            ArchiveSource(tmp_path)

    def test_init_accetta_stringa(self, zip_archive):
        source = ArchiveSource(str(zip_archive))
        assert source._archive_path.exists()


class TestArchiveSourceZip:
    def test_estrae_zip(self, zip_archive):
        with ArchiveSource(zip_archive) as source:
            tree = source.get_file_tree()
            file_paths = [e.path for e in tree.entries if not e.is_dir]
            assert "app.py" in file_paths
            assert "sub/utils.py" in file_paths

    def test_legge_file_da_zip(self, zip_archive):
        with ArchiveSource(zip_archive) as source:
            content = source.read_file("app.py")
            assert "print('hello')" in content

    def test_metadata_zip(self, zip_archive):
        with ArchiveSource(zip_archive) as source:
            meta = source.get_metadata()
            assert meta.source_type == "archive"
            assert meta.total_files == 2

    def test_cleanup_dopo_context_manager(self, zip_archive):
        source = ArchiveSource(zip_archive)
        with source:
            temp_path = source._temp_dir
            assert temp_path.exists()
        assert not temp_path.exists()


class TestArchiveSourceTar:
    def test_estrae_tar_gz(self, tar_gz_archive):
        with ArchiveSource(tar_gz_archive) as source:
            tree = source.get_file_tree()
            file_paths = [e.path for e in tree.entries if not e.is_dir]
            assert "main.py" in file_paths
            assert "README.md" in file_paths

    def test_legge_file_da_tar_gz(self, tar_gz_archive):
        with ArchiveSource(tar_gz_archive) as source:
            content = source.read_file("main.py")
            assert "import os" in content


class TestArchiveSourceFormato:
    def test_formato_non_supportato(self, tmp_path):
        bad_file = tmp_path / "test.rar"
        bad_file.write_bytes(b"not a real archive")
        source = ArchiveSource(bad_file)
        with pytest.raises(ValueError, match="non supportato"):
            with source:
                pass
