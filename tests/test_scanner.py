"""
Test per il FileScanner (Blocco 3).

Verifica:
- Conta correttamente file e LOC
- Esclude directory che devono essere escluse
- Calcola estensioni corrette
- Gestisce file binari e non leggibili
- Funziona su repo vuota
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cto_audit.collectors.scanner import FileScanner, EXCLUDED_DIRECTORIES
from cto_audit.sources.local import LocalRepoSource


@pytest.fixture
def repo_mista(tmp_path: Path) -> Path:
    """
    Repo di test mista con linguaggi multipli e directory da escludere.
    """
    # Sorgenti Python
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text(
        "# Main\nimport os\nprint('hello')\n", encoding="utf-8"
    )
    (tmp_path / "src" / "utils.py").write_text(
        "def helper():\n    return True\n", encoding="utf-8"
    )

    # Sorgenti JavaScript
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend" / "app.js").write_text(
        "const x = 1;\nconsole.log(x);\n", encoding="utf-8"
    )
    (tmp_path / "frontend" / "style.css").write_text(
        "body { color: red; }\n", encoding="utf-8"
    )

    # File root
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11\nCOPY . /app\n", encoding="utf-8"
    )
    (tmp_path / "README.md").write_text("# Test\n", encoding="utf-8")

    # Directory che devono essere escluse
    (tmp_path / "node_modules" / "lodash").mkdir(parents=True)
    (tmp_path / "node_modules" / "lodash" / "index.js").write_text(
        "module.exports = {};\n", encoding="utf-8"
    )
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "main.cpython-311.pyc").write_bytes(b"\x00\x01\x02")
    (tmp_path / ".venv" / "lib").mkdir(parents=True)
    (tmp_path / ".venv" / "lib" / "site.py").write_text("# venv\n", encoding="utf-8")
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "output.js").write_text("// built\n", encoding="utf-8")

    # File binario nella root
    (tmp_path / "image.png").write_bytes(b"\x89PNG\x00\x00")

    return tmp_path


@pytest.fixture
def repo_vuota(tmp_path: Path) -> Path:
    """Repo completamente vuota."""
    return tmp_path


class TestFileScanner:
    """Test per il FileScanner."""

    def test_scan_conta_file_correttamente(self, repo_mista: Path):
        """Lo scanner conta solo i file non in directory escluse."""
        source = LocalRepoSource(repo_mista)
        scanner = FileScanner(source)
        files = scanner.scan()

        paths = [f.path for f in files]
        # File attesi: Dockerfile, README.md, image.png, frontend/app.js,
        # frontend/style.css, src/main.py, src/utils.py
        assert len(files) == 7
        assert "src/main.py" in paths
        assert "src/utils.py" in paths
        assert "frontend/app.js" in paths
        assert "frontend/style.css" in paths
        assert "Dockerfile" in paths
        assert "README.md" in paths
        assert "image.png" in paths

    def test_scan_esclude_node_modules(self, repo_mista: Path):
        """I file in node_modules/ sono esclusi."""
        source = LocalRepoSource(repo_mista)
        scanner = FileScanner(source)
        files = scanner.scan()
        paths = [f.path for f in files]

        assert not any("node_modules" in p for p in paths)

    def test_scan_esclude_pycache(self, repo_mista: Path):
        """I file in __pycache__/ sono esclusi."""
        source = LocalRepoSource(repo_mista)
        scanner = FileScanner(source)
        files = scanner.scan()
        paths = [f.path for f in files]

        assert not any("__pycache__" in p for p in paths)

    def test_scan_esclude_venv(self, repo_mista: Path):
        """I file in .venv/ sono esclusi."""
        source = LocalRepoSource(repo_mista)
        scanner = FileScanner(source)
        files = scanner.scan()
        paths = [f.path for f in files]

        assert not any(".venv" in p for p in paths)

    def test_scan_esclude_build(self, repo_mista: Path):
        """I file in build/ sono esclusi."""
        source = LocalRepoSource(repo_mista)
        scanner = FileScanner(source)
        files = scanner.scan()
        paths = [f.path for f in files]

        assert not any(p.startswith("build/") for p in paths)

    def test_scan_calcola_estensioni(self, repo_mista: Path):
        """Le estensioni sono calcolate correttamente."""
        source = LocalRepoSource(repo_mista)
        scanner = FileScanner(source)
        files = scanner.scan()

        ext_map = {f.path: f.extension for f in files}
        assert ext_map["src/main.py"] == ".py"
        assert ext_map["frontend/app.js"] == ".js"
        assert ext_map["frontend/style.css"] == ".css"
        assert ext_map["README.md"] == ".md"
        assert ext_map["image.png"] == ".png"
        # Dockerfile non ha estensione
        assert ext_map["Dockerfile"] == ""

    def test_scan_calcola_loc(self, repo_mista: Path):
        """Le LOC sono calcolate correttamente per i file leggibili."""
        source = LocalRepoSource(repo_mista)
        scanner = FileScanner(source)
        files = scanner.scan()

        loc_map = {f.path: f.lines_of_code for f in files}
        assert loc_map["src/main.py"] == 3  # 3 righe
        assert loc_map["src/utils.py"] == 2  # 2 righe
        assert loc_map["frontend/app.js"] == 2  # 2 righe
        assert loc_map["Dockerfile"] == 2  # 2 righe

    def test_scan_loc_zero_per_binari(self, repo_mista: Path):
        """I file binari hanno LOC = 0."""
        source = LocalRepoSource(repo_mista)
        scanner = FileScanner(source)
        files = scanner.scan()

        loc_map = {f.path: f.lines_of_code for f in files}
        assert loc_map["image.png"] == 0

    def test_scan_size_corretta(self, repo_mista: Path):
        """Le dimensioni dei file sono corrette."""
        source = LocalRepoSource(repo_mista)
        scanner = FileScanner(source)
        files = scanner.scan()

        for f in files:
            full_path = repo_mista / f.path
            assert f.size == full_path.stat().st_size

    def test_scan_repo_vuota(self, repo_vuota: Path):
        """Una repo vuota restituisce lista vuota."""
        source = LocalRepoSource(repo_vuota)
        scanner = FileScanner(source)
        files = scanner.scan()

        assert files == []

    def test_scan_risultati_ordinati(self, repo_mista: Path):
        """I risultati sono ordinati per path."""
        source = LocalRepoSource(repo_mista)
        scanner = FileScanner(source)
        files = scanner.scan()

        paths = [f.path for f in files]
        assert paths == sorted(paths)

    def test_excluded_directories_contiene_pattern_principali(self):
        """La lista di directory escluse contiene i pattern principali dal doc."""
        expected = {"node_modules", "vendor", ".git", "__pycache__", ".venv",
                    "venv", "dist", "build", "target"}
        assert expected.issubset(EXCLUDED_DIRECTORIES)
