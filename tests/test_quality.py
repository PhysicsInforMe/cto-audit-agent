"""
Test QualityAnalyzer — 6 check di qualita CTO-level.
"""

from __future__ import annotations

from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from cto_audit.analyzers.quality import QualityAnalyzer
from cto_audit.core.models import (
    Finding,
    Layer,
    Severity,
    StackInfo,
)
from cto_audit.sources.local import LocalRepoSource


def _write(base: Path, rel: str, content: str) -> None:
    p = base / Path(rel)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _run_quality(repo_path: Path, stack: StackInfo | None = None) -> list[Finding]:
    source = LocalRepoSource(repo_path)
    stack = stack or StackInfo(languages={"python": 1.0})
    analyzer = QualityAnalyzer()
    return analyzer.analyze(source, stack, [])


def _triggered_rules(findings: list[Finding]) -> set[str]:
    return {f.rule_id for f in findings if f.severity != Severity.INFO}


# ============================================================
# QUAL-DOC-001 — No README
# ============================================================

class TestReadme:
    def test_no_readme(self, tmp_path):
        _write(tmp_path, "app.py", "print('hello')\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-DOC-001" in _triggered_rules(findings)

    def test_readme_present(self, tmp_path):
        _write(tmp_path, "README.md", "# My Project\n")
        _write(tmp_path, "app.py", "print('hello')\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-DOC-001" not in _triggered_rules(findings)

    def test_readme_rst(self, tmp_path):
        _write(tmp_path, "README.rst", "My Project\n==========\n")
        _write(tmp_path, "app.py", "print('hello')\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-DOC-001" not in _triggered_rules(findings)


# ============================================================
# QUAL-DOC-002 — Inline Documentation
# ============================================================

class TestDocstrings:
    def test_no_docstrings(self, tmp_path):
        """Files with functions but no docstrings."""
        for i in range(5):
            _write(tmp_path, f"module{i}.py", (
                f"def func_a{i}():\n    pass\n\n"
                f"def func_b{i}():\n    pass\n\n"
                f"def func_c{i}():\n    pass\n"
            ))
        findings = _run_quality(tmp_path)
        assert "QUAL-DOC-002" in _triggered_rules(findings)

    def test_good_docstrings(self, tmp_path):
        """Files with good docstring coverage."""
        for i in range(5):
            _write(tmp_path, f"module{i}.py", (
                f'def func_a{i}():\n    """Does something."""\n    pass\n\n'
                f'def func_b{i}():\n    """Does another thing."""\n    pass\n\n'
                f"def func_c{i}():\n    pass\n"
            ))
        findings = _run_quality(tmp_path)
        assert "QUAL-DOC-002" not in _triggered_rules(findings)

    def test_too_few_files_skip(self, tmp_path):
        """With <3 qualifying files, check is skipped."""
        _write(tmp_path, "app.py", "def main():\n    pass\n\ndef run():\n    pass\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-DOC-002" not in _triggered_rules(findings)


# ============================================================
# QUAL-LINT-001 — No Linter
# ============================================================

class TestLinter:
    def test_no_linter(self, tmp_path):
        _write(tmp_path, "app.py", "print('hello')\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-LINT-001" in _triggered_rules(findings)

    def test_eslintrc(self, tmp_path):
        _write(tmp_path, ".eslintrc.json", '{"extends": "eslint:recommended"}\n')
        _write(tmp_path, "app.js", "console.log('hello');\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-LINT-001" not in _triggered_rules(findings)

    def test_ruff_toml(self, tmp_path):
        _write(tmp_path, "ruff.toml", "[lint]\nselect = ['E', 'F']\n")
        _write(tmp_path, "app.py", "print('hello')\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-LINT-001" not in _triggered_rules(findings)

    def test_pyproject_with_ruff(self, tmp_path):
        _write(tmp_path, "pyproject.toml", (
            "[project]\nname = 'test'\n\n"
            "[tool.ruff]\nselect = ['E', 'F']\n"
        ))
        _write(tmp_path, "app.py", "print('hello')\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-LINT-001" not in _triggered_rules(findings)

    def test_pyproject_without_linter(self, tmp_path):
        _write(tmp_path, "pyproject.toml", "[project]\nname = 'test'\n")
        _write(tmp_path, "app.py", "print('hello')\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-LINT-001" in _triggered_rules(findings)

    def test_prettier(self, tmp_path):
        _write(tmp_path, ".prettierrc", '{"semi": true}\n')
        _write(tmp_path, "app.js", "console.log('hello');\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-LINT-001" not in _triggered_rules(findings)

    def test_editorconfig(self, tmp_path):
        _write(tmp_path, ".editorconfig", "root = true\n[*]\nindent_style = space\n")
        _write(tmp_path, "app.py", "print('hello')\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-LINT-001" not in _triggered_rules(findings)


# ============================================================
# QUAL-TYPING-001 — No Type Checking
# ============================================================

class TestTyping:
    def test_no_typing_python(self, tmp_path):
        _write(tmp_path, "app.py", "print('hello')\n")
        stack = StackInfo(languages={"python": 1.0})
        findings = _run_quality(tmp_path, stack)
        assert "QUAL-TYPING-001" in _triggered_rules(findings)

    def test_mypy_ini(self, tmp_path):
        _write(tmp_path, "mypy.ini", "[mypy]\nstrict = True\n")
        _write(tmp_path, "app.py", "print('hello')\n")
        stack = StackInfo(languages={"python": 1.0})
        findings = _run_quality(tmp_path, stack)
        assert "QUAL-TYPING-001" not in _triggered_rules(findings)

    def test_tsconfig(self, tmp_path):
        _write(tmp_path, "tsconfig.json", '{"compilerOptions": {"strict": true}}\n')
        _write(tmp_path, "app.ts", "console.log('hello');\n")
        stack = StackInfo(languages={"typescript": 1.0})
        findings = _run_quality(tmp_path, stack)
        assert "QUAL-TYPING-001" not in _triggered_rules(findings)

    def test_pyproject_mypy(self, tmp_path):
        _write(tmp_path, "pyproject.toml", "[project]\nname='test'\n\n[tool.mypy]\nstrict = true\n")
        _write(tmp_path, "app.py", "print('hello')\n")
        stack = StackInfo(languages={"python": 1.0})
        findings = _run_quality(tmp_path, stack)
        assert "QUAL-TYPING-001" not in _triggered_rules(findings)

    def test_no_typing_go_skip(self, tmp_path):
        """Go doesn't need type checking config."""
        _write(tmp_path, "main.go", "package main\nfunc main() {}\n")
        stack = StackInfo(languages={"go": 1.0})
        findings = _run_quality(tmp_path, stack)
        assert "QUAL-TYPING-001" not in _triggered_rules(findings)


# ============================================================
# QUAL-COMPLEXITY-001 — Excessive Nesting
# ============================================================

class TestNesting:
    def test_deep_nesting_python(self, tmp_path):
        """Python file with >5 levels of nesting."""
        code = (
            "def deeply_nested():\n"
            "    if True:\n"
            "        for i in range(10):\n"
            "            if i > 5:\n"
            "                for j in range(10):\n"
            "                    if j > 3:\n"
            "                        while True:\n"
            "                            print('deep')\n"
            "                            break\n"
        )
        _write(tmp_path, "deep.py", code)
        findings = _run_quality(tmp_path)
        assert "QUAL-COMPLEXITY-001" in _triggered_rules(findings)

    def test_shallow_code(self, tmp_path):
        _write(tmp_path, "simple.py", (
            "def simple():\n"
            "    if True:\n"
            "        return 42\n"
            "    return 0\n"
        ))
        findings = _run_quality(tmp_path)
        assert "QUAL-COMPLEXITY-001" not in _triggered_rules(findings)


# ============================================================
# QUAL-DUP-001 — Duplicate Filenames
# ============================================================

class TestDuplicateFilenames:
    def test_duplicate_files(self, tmp_path):
        """Same filename in 3+ directories."""
        _write(tmp_path, "module_a/utils.py", "def a(): pass\n")
        _write(tmp_path, "module_b/utils.py", "def b(): pass\n")
        _write(tmp_path, "module_c/utils.py", "def c(): pass\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-DUP-001" in _triggered_rules(findings)

    def test_no_duplicates(self, tmp_path):
        _write(tmp_path, "module_a/helpers.py", "def a(): pass\n")
        _write(tmp_path, "module_b/utils.py", "def b(): pass\n")
        _write(tmp_path, "module_c/tools.py", "def c(): pass\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-DUP-001" not in _triggered_rules(findings)

    def test_init_excluded(self, tmp_path):
        """__init__.py is legitimately duplicated."""
        _write(tmp_path, "module_a/__init__.py", "")
        _write(tmp_path, "module_b/__init__.py", "")
        _write(tmp_path, "module_c/__init__.py", "")
        findings = _run_quality(tmp_path)
        assert "QUAL-DUP-001" not in _triggered_rules(findings)


# ============================================================
# Integration
# ============================================================

class TestQualityIntegration:
    def test_poor_quality_repo(self, tmp_path):
        """Repo with all quality issues."""
        for i in range(5):
            _write(tmp_path, f"module{i}.py", (
                f"def func_a{i}():\n    pass\n\n"
                f"def func_b{i}():\n    pass\n"
            ))
        # Duplicate filenames
        _write(tmp_path, "a/handler.py", "def handle(): pass\n")
        _write(tmp_path, "b/handler.py", "def handle(): pass\n")
        _write(tmp_path, "c/handler.py", "def handle(): pass\n")

        findings = _run_quality(tmp_path)
        rules = _triggered_rules(findings)

        assert "QUAL-DOC-001" in rules
        assert "QUAL-LINT-001" in rules
        assert "QUAL-DUP-001" in rules

    def test_all_findings_quality_layer(self, tmp_path):
        _write(tmp_path, "app.py", "print('hello')\n")
        findings = _run_quality(tmp_path)
        for f in findings:
            assert f.layer == Layer.QUALITY


# ============================================================
# QUAL-PRECOMMIT-001 — Pre-commit Hooks
# ============================================================

class TestPrecommit:
    def test_no_precommit(self, tmp_path):
        _write(tmp_path, "app.py", "print('hello')\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-PRECOMMIT-001" in _triggered_rules(findings)

    def test_precommit_yaml_present(self, tmp_path):
        _write(tmp_path, "app.py", "print('hello')\n")
        _write(tmp_path, ".pre-commit-config.yaml", "repos:\n  - repo: ...\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-PRECOMMIT-001" not in _triggered_rules(findings)

    def test_husky_in_package_json(self, tmp_path):
        import json
        _write(tmp_path, "app.js", "console.log('hello')\n")
        _write(tmp_path, "package.json", json.dumps({
            "devDependencies": {"husky": "^9.0.0"}
        }))
        findings = _run_quality(tmp_path)
        assert "QUAL-PRECOMMIT-001" not in _triggered_rules(findings)

    def test_husky_dir_present(self, tmp_path):
        _write(tmp_path, "app.py", "print('hello')\n")
        _write(tmp_path, ".husky/pre-commit", "#!/bin/sh\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-PRECOMMIT-001" not in _triggered_rules(findings)

    def test_lefthook_present(self, tmp_path):
        _write(tmp_path, "app.py", "print('hello')\n")
        _write(tmp_path, "lefthook.yml", "pre-commit:\n  commands:\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-PRECOMMIT-001" not in _triggered_rules(findings)


# ============================================================
# QUAL-EDITORCONFIG-001 — EditorConfig
# ============================================================

class TestEditorconfig:
    def test_no_editorconfig(self, tmp_path):
        _write(tmp_path, "app.py", "print('hello')\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-EDITORCONFIG-001" in _triggered_rules(findings)

    def test_editorconfig_present(self, tmp_path):
        _write(tmp_path, "app.py", "print('hello')\n")
        _write(tmp_path, ".editorconfig", "root = true\n[*]\nindent_style = space\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-EDITORCONFIG-001" not in _triggered_rules(findings)


# ============================================================
# QUAL-CONTRIBUTING-001 — CONTRIBUTING.md
# ============================================================

class TestContributing:
    def test_no_contributing(self, tmp_path):
        _write(tmp_path, "app.py", "print('hello')\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-CONTRIBUTING-001" in _triggered_rules(findings)

    def test_contributing_present(self, tmp_path):
        _write(tmp_path, "app.py", "print('hello')\n")
        _write(tmp_path, "CONTRIBUTING.md", "# How to Contribute\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-CONTRIBUTING-001" not in _triggered_rules(findings)

    def test_contributing_case_insensitive(self, tmp_path):
        _write(tmp_path, "app.py", "print('hello')\n")
        _write(tmp_path, "Contributing.md", "# How to Contribute\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-CONTRIBUTING-001" not in _triggered_rules(findings)


# ============================================================
# QUAL-CHANGELOG-001 — CHANGELOG
# ============================================================

class TestChangelog:
    def test_no_changelog(self, tmp_path):
        _write(tmp_path, "app.py", "print('hello')\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-CHANGELOG-001" in _triggered_rules(findings)

    def test_changelog_present(self, tmp_path):
        _write(tmp_path, "app.py", "print('hello')\n")
        _write(tmp_path, "CHANGELOG.md", "# Changelog\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-CHANGELOG-001" not in _triggered_rules(findings)

    def test_changes_md_accepted(self, tmp_path):
        _write(tmp_path, "app.py", "print('hello')\n")
        _write(tmp_path, "CHANGES.md", "# Changes\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-CHANGELOG-001" not in _triggered_rules(findings)

    def test_history_md_accepted(self, tmp_path):
        _write(tmp_path, "app.py", "print('hello')\n")
        _write(tmp_path, "HISTORY.md", "# History\n")
        findings = _run_quality(tmp_path)
        assert "QUAL-CHANGELOG-001" not in _triggered_rules(findings)
