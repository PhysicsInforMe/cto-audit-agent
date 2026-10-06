"""
Test .gitignore con pattern annidati e ancorati in LocalRepoSource.

Regressione: "benchmarks/repos/" non escludeva la directory perche il
pattern veniva confrontato con i singoli componenti del percorso.
"""

from __future__ import annotations

from pathlib import Path

from cto_audit.sources.local import LocalRepoSource


def _write(base: Path, rel: str, content: str = "x\n") -> None:
    p = base / Path(rel)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _paths(repo: Path) -> set[str]:
    return {e.path for e in LocalRepoSource(repo).get_file_tree().entries if not e.is_dir}


def test_pattern_directory_annidata(tmp_path):
    _write(tmp_path, ".gitignore", "benchmarks/repos/\n")
    _write(tmp_path, "benchmarks/repos/black/setup.py")
    _write(tmp_path, "benchmarks/run.py")
    _write(tmp_path, "src/app.py")
    paths = _paths(tmp_path)
    assert "benchmarks/run.py" in paths
    assert "src/app.py" in paths
    assert not any(p.startswith("benchmarks/repos/") for p in paths)


def test_pattern_ancorato_alla_root(tmp_path):
    _write(tmp_path, ".gitignore", "/dist\n")
    _write(tmp_path, "dist/bundle.js")
    _write(tmp_path, "src/dist/keep.js")
    paths = _paths(tmp_path)
    assert "dist/bundle.js" not in paths
    assert "src/dist/keep.js" in paths  # il pattern ancorato non vale in profondita


def test_pattern_file_con_path(tmp_path):
    _write(tmp_path, ".gitignore", "docs/*.tmp\n")
    _write(tmp_path, "docs/a.tmp")
    _write(tmp_path, "docs/a.md")
    paths = _paths(tmp_path)
    assert "docs/a.tmp" not in paths
    assert "docs/a.md" in paths


def test_pattern_semplice_resta_valido(tmp_path):
    _write(tmp_path, ".gitignore", "*.log\nnode_modules/\n")
    _write(tmp_path, "app.log")
    _write(tmp_path, "deep/node_modules/x/index.js")
    _write(tmp_path, "app.py")
    paths = _paths(tmp_path)
    assert paths == {".gitignore", "app.py"}
