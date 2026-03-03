"""
Test per AuditSource Protocol e LocalRepoSource (Blocco 2).

Verifica:
- LocalRepoSource costruisce il file tree corretto
- Legge file con encoding diversi
- Rispetta .gitignore
- Gestisce errori: path inesistente, file binari, permessi negati
- Implementa correttamente il Protocol AuditSource
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from cto_audit.core.models import FileTree, SourceMetadata
from cto_audit.core.source import AuditSource
from cto_audit.sources.local import LocalRepoSource


# --- Fixture per creare repo di test ---


@pytest.fixture
def repo_base(tmp_path: Path) -> Path:
    """
    Crea una repo di test con struttura base:
    - src/app.py (Python)
    - src/utils.py (Python)
    - index.js (JavaScript)
    - Dockerfile
    - .env (file sensibile)
    - README.md
    """
    # Directory
    (tmp_path / "src").mkdir()

    # File Python
    (tmp_path / "src" / "app.py").write_text(
        "# Applicazione principale\n"
        "from flask import Flask\n"
        "\n"
        "app = Flask(__name__)\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    app.run()\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "utils.py").write_text(
        "# Utility functions\n"
        "def helper():\n"
        "    return True\n",
        encoding="utf-8",
    )

    # File JS
    (tmp_path / "index.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.listen(3000);\n",
        encoding="utf-8",
    )

    # Dockerfile
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11\nCOPY . /app\nCMD [\"python\", \"app.py\"]\n",
        encoding="utf-8",
    )

    # File sensibile
    (tmp_path / ".env").write_text(
        "DB_PASSWORD=secret123\nAPI_KEY=abc-def-ghi\n",
        encoding="utf-8",
    )

    # README
    (tmp_path / "README.md").write_text("# Test Project\n", encoding="utf-8")

    return tmp_path


@pytest.fixture
def repo_con_gitignore(tmp_path: Path) -> Path:
    """
    Crea una repo con .gitignore che esclude alcune directory e file.
    """
    # Struttura
    (tmp_path / "src").mkdir()
    (tmp_path / "node_modules" / "lodash").mkdir(parents=True)
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "dist").mkdir()
    (tmp_path / ".git" / "objects").mkdir(parents=True)

    # File
    (tmp_path / "src" / "main.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / "node_modules" / "lodash" / "index.js").write_text(
        "module.exports = {};\n", encoding="utf-8"
    )
    (tmp_path / "__pycache__" / "main.cpython-311.pyc").write_bytes(b"\x00\x01\x02")
    (tmp_path / "dist" / "bundle.js").write_text("// built\n", encoding="utf-8")
    (tmp_path / ".git" / "objects" / "abc123").write_bytes(b"\x00\x01\x02")
    (tmp_path / "README.md").write_text("# Test\n", encoding="utf-8")
    (tmp_path / "notes.log").write_text("log entry\n", encoding="utf-8")

    # .gitignore
    (tmp_path / ".gitignore").write_text(
        "node_modules/\n"
        "__pycache__/\n"
        "dist/\n"
        "*.log\n"
        "# Questo è un commento\n"
        "\n",
        encoding="utf-8",
    )

    return tmp_path


@pytest.fixture
def repo_con_encoding(tmp_path: Path) -> Path:
    """Crea una repo con file in encoding diversi."""
    # UTF-8 standard
    (tmp_path / "utf8.txt").write_text("Héllo wörld àéìòù\n", encoding="utf-8")

    # Latin-1 (ISO-8859-1)
    (tmp_path / "latin1.txt").write_bytes("Café résumé naïve\n".encode("latin-1"))

    # File binario
    (tmp_path / "binary.dat").write_bytes(bytes(range(256)))

    return tmp_path


# --- Test Protocol ---


class TestAuditSourceProtocol:
    """Verifica che LocalRepoSource implementi il Protocol AuditSource."""

    def test_isinstance_check(self, repo_base: Path):
        """LocalRepoSource è un'istanza di AuditSource (runtime_checkable)."""
        source = LocalRepoSource(repo_base)
        assert isinstance(source, AuditSource)

    def test_ha_metodi_richiesti(self, repo_base: Path):
        """LocalRepoSource ha tutti i metodi del Protocol."""
        source = LocalRepoSource(repo_base)
        assert hasattr(source, "get_file_tree")
        assert hasattr(source, "read_file")
        assert hasattr(source, "get_metadata")
        assert callable(source.get_file_tree)
        assert callable(source.read_file)
        assert callable(source.get_metadata)


# --- Test Costruttore ---


class TestLocalRepoSourceInit:
    """Test per l'inizializzazione di LocalRepoSource."""

    def test_path_valido(self, repo_base: Path):
        """Si istanzia con un path valido."""
        source = LocalRepoSource(repo_base)
        assert source.root == repo_base

    def test_path_come_stringa(self, repo_base: Path):
        """Accetta anche una stringa come path."""
        source = LocalRepoSource(str(repo_base))
        assert source.root == repo_base

    def test_path_inesistente(self):
        """Solleva FileNotFoundError per path inesistente."""
        with pytest.raises(FileNotFoundError, match="non esiste"):
            LocalRepoSource("/path/che/non/esiste/assolutamente")

    def test_path_file_non_directory(self, tmp_path: Path):
        """Solleva NotADirectoryError se il path è un file."""
        file_path = tmp_path / "file.txt"
        file_path.touch()
        with pytest.raises(NotADirectoryError, match="non è una directory"):
            LocalRepoSource(file_path)


# --- Test File Tree ---


class TestGetFileTree:
    """Test per la costruzione del file tree."""

    def test_file_tree_base(self, repo_base: Path):
        """Restituisce tutti i file e directory della repo base."""
        source = LocalRepoSource(repo_base)
        tree = source.get_file_tree()

        assert tree.root == str(repo_base)

        # Estrai solo i file (non directory)
        file_paths = [e.path for e in tree.entries if not e.is_dir]
        dir_paths = [e.path for e in tree.entries if e.is_dir]

        # Verifica i file presenti
        assert ".env" in file_paths
        assert "Dockerfile" in file_paths
        assert "README.md" in file_paths
        assert "index.js" in file_paths
        assert "src/app.py" in file_paths
        assert "src/utils.py" in file_paths

        # Verifica la directory
        assert "src" in dir_paths

    def test_file_tree_dimensioni(self, repo_base: Path):
        """Le dimensioni dei file nel tree sono corrette."""
        source = LocalRepoSource(repo_base)
        tree = source.get_file_tree()

        for entry in tree.entries:
            if not entry.is_dir:
                full_path = repo_base / entry.path
                assert entry.size == full_path.stat().st_size

    def test_file_tree_ritorna_tipo_corretto(self, repo_base: Path):
        """get_file_tree ritorna un FileTree."""
        source = LocalRepoSource(repo_base)
        tree = source.get_file_tree()
        assert isinstance(tree, FileTree)

    def test_directory_vuota(self, tmp_path: Path):
        """Una directory vuota restituisce un tree senza entry."""
        source = LocalRepoSource(tmp_path)
        tree = source.get_file_tree()
        assert tree.entries == []

    def test_percorsi_normalizzati_con_slash(self, repo_base: Path):
        """I percorsi usano sempre / come separatore (anche su Windows)."""
        source = LocalRepoSource(repo_base)
        tree = source.get_file_tree()
        for entry in tree.entries:
            assert "\\" not in entry.path, f"Backslash trovato in: {entry.path}"


# --- Test .gitignore ---


class TestGitignore:
    """Test per il rispetto delle regole .gitignore."""

    def test_ignora_node_modules(self, repo_con_gitignore: Path):
        """node_modules/ è ignorata come da .gitignore."""
        source = LocalRepoSource(repo_con_gitignore)
        tree = source.get_file_tree()
        paths = [e.path for e in tree.entries]

        assert not any("node_modules" in p for p in paths)

    def test_ignora_pycache(self, repo_con_gitignore: Path):
        """__pycache__/ è ignorata come da .gitignore."""
        source = LocalRepoSource(repo_con_gitignore)
        tree = source.get_file_tree()
        paths = [e.path for e in tree.entries]

        assert not any("__pycache__" in p for p in paths)

    def test_ignora_dist(self, repo_con_gitignore: Path):
        """dist/ è ignorata come da .gitignore."""
        source = LocalRepoSource(repo_con_gitignore)
        tree = source.get_file_tree()
        paths = [e.path for e in tree.entries]

        assert not any(p.startswith("dist") for p in paths)

    def test_ignora_pattern_estensione(self, repo_con_gitignore: Path):
        """*.log è ignorato come da .gitignore."""
        source = LocalRepoSource(repo_con_gitignore)
        tree = source.get_file_tree()
        file_paths = [e.path for e in tree.entries if not e.is_dir]

        assert "notes.log" not in file_paths

    def test_ignora_sempre_git(self, repo_con_gitignore: Path):
        """.git/ è sempre ignorata anche senza .gitignore."""
        source = LocalRepoSource(repo_con_gitignore)
        tree = source.get_file_tree()
        paths = [e.path for e in tree.entries]

        assert not any(".git" == p or p.startswith(".git/") for p in paths)

    def test_mantiene_file_non_ignorati(self, repo_con_gitignore: Path):
        """I file non nel .gitignore sono presenti."""
        source = LocalRepoSource(repo_con_gitignore)
        tree = source.get_file_tree()
        file_paths = [e.path for e in tree.entries if not e.is_dir]

        assert "src/main.py" in file_paths
        assert "README.md" in file_paths
        assert ".gitignore" in file_paths

    def test_senza_gitignore(self, repo_base: Path):
        """Senza .gitignore, tutti i file sono inclusi (tranne .git/)."""
        source = LocalRepoSource(repo_base)
        tree = source.get_file_tree()
        file_paths = [e.path for e in tree.entries if not e.is_dir]

        # Tutti i file presenti
        assert len(file_paths) == 6  # .env, Dockerfile, README.md, index.js, src/app.py, src/utils.py


# --- Test read_file ---


class TestReadFile:
    """Test per la lettura dei file."""

    def test_legge_file_utf8(self, repo_base: Path):
        """Legge correttamente un file UTF-8."""
        source = LocalRepoSource(repo_base)
        content = source.read_file("src/app.py")
        assert "Flask" in content
        assert "app.run()" in content

    def test_legge_file_con_encoding_utf8(self, repo_con_encoding: Path):
        """Legge correttamente file UTF-8 con caratteri speciali."""
        source = LocalRepoSource(repo_con_encoding)
        content = source.read_file("utf8.txt")
        assert "Héllo" in content
        assert "àéìòù" in content

    def test_legge_file_con_encoding_latin1(self, repo_con_encoding: Path):
        """Legge file latin-1 con fallback."""
        source = LocalRepoSource(repo_con_encoding)
        content = source.read_file("latin1.txt")
        assert "sum" in content  # parte di "résumé"

    def test_rifiuta_file_binario(self, repo_con_encoding: Path):
        """Solleva ValueError per file binari (contiene byte null)."""
        source = LocalRepoSource(repo_con_encoding)
        with pytest.raises(ValueError, match="binario"):
            source.read_file("binary.dat")

    def test_file_inesistente(self, repo_base: Path):
        """Solleva FileNotFoundError per file che non esiste."""
        source = LocalRepoSource(repo_base)
        with pytest.raises(FileNotFoundError):
            source.read_file("non_esiste.py")

    def test_legge_file_vuoto(self, tmp_path: Path):
        """Legge correttamente un file vuoto."""
        (tmp_path / "vuoto.txt").write_text("", encoding="utf-8")
        source = LocalRepoSource(tmp_path)
        content = source.read_file("vuoto.txt")
        assert content == ""

    def test_path_non_file(self, repo_base: Path):
        """Solleva FileNotFoundError se il path è una directory."""
        source = LocalRepoSource(repo_base)
        with pytest.raises(FileNotFoundError, match="non è un file"):
            source.read_file("src")


# --- Test get_metadata ---


class TestGetMetadata:
    """Test per i metadati della sorgente."""

    def test_metadata_base(self, repo_base: Path):
        """Metadata contengono il nome directory e conteggio corretto."""
        source = LocalRepoSource(repo_base)
        meta = source.get_metadata()

        assert isinstance(meta, SourceMetadata)
        assert meta.name == repo_base.name
        assert meta.source_type == "local"
        assert meta.total_files == 6  # .env, Dockerfile, README.md, index.js, src/app.py, src/utils.py
        assert meta.total_loc > 0

    def test_metadata_directory_vuota(self, tmp_path: Path):
        """Metadata per directory vuota: 0 file, 0 LOC."""
        source = LocalRepoSource(tmp_path)
        meta = source.get_metadata()

        assert meta.total_files == 0
        assert meta.total_loc == 0

    def test_metadata_loc_count(self, tmp_path: Path):
        """LOC contate correttamente."""
        (tmp_path / "a.py").write_text("line1\nline2\nline3\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("line1\nline2\n", encoding="utf-8")

        source = LocalRepoSource(tmp_path)
        meta = source.get_metadata()

        assert meta.total_files == 2
        assert meta.total_loc == 5  # 3 + 2

    def test_metadata_ignora_binari_nel_loc(self, repo_con_encoding: Path):
        """I file binari non contribuiscono al conteggio LOC."""
        source = LocalRepoSource(repo_con_encoding)
        meta = source.get_metadata()

        # 2 file testuali, 1 binario — ma i file contati sono 3 (il binario conta come file)
        assert meta.total_files == 3
        # LOC solo dai file testuali
        assert meta.total_loc > 0

    def test_metadata_rispetta_gitignore(self, repo_con_gitignore: Path):
        """I file ignorati da .gitignore non sono contati nei metadata."""
        source = LocalRepoSource(repo_con_gitignore)
        meta = source.get_metadata()

        # Solo: .gitignore, README.md, src/main.py — i file ignorati non contano
        assert meta.total_files == 3


# --- Test caching file tree ---


class TestFileTreeCaching:
    """Verifica che get_file_tree() restituisca lo stesso oggetto dopo la prima chiamata."""

    def test_cached_returns_same_object(self, repo_base: Path):
        """Chiamate multiple restituiscono lo stesso oggetto FileTree."""
        source = LocalRepoSource(repo_base)
        tree1 = source.get_file_tree()
        tree2 = source.get_file_tree()
        assert tree1 is tree2

    def test_metadata_uses_cached_tree(self, repo_base: Path):
        """get_metadata() usa la stessa tree cached."""
        source = LocalRepoSource(repo_base)
        tree1 = source.get_file_tree()
        _ = source.get_metadata()
        tree2 = source.get_file_tree()
        assert tree1 is tree2

    def test_cache_content_correct(self, repo_base: Path):
        """La tree cached ha il contenuto corretto."""
        source = LocalRepoSource(repo_base)
        tree = source.get_file_tree()
        file_paths = {e.path for e in tree.entries if not e.is_dir}
        assert "src/app.py" in file_paths
        assert "README.md" in file_paths
        # Seconda chiamata, stessi risultati
        tree2 = source.get_file_tree()
        file_paths2 = {e.path for e in tree2.entries if not e.is_dir}
        assert file_paths == file_paths2
