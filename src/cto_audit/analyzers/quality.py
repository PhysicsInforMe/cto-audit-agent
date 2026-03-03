"""
Quality Analyzer — Layer 4: Qualita del Codice.

Indicatori di qualita a livello CTO: documentazione, linting, typing,
complessita, duplicazione. NON metriche da linter (non conta gli spazi).

10 check:
- QUAL-DOC-001: Nessun README.md/README.rst nella root
- QUAL-DOC-002: Documentazione inline insufficiente (<30% file con docstring)
- QUAL-LINT-001: Nessun linter/formatter configurato
- QUAL-TYPING-001: Nessun type checking (solo Python/JS/TS)
- QUAL-COMPLEXITY-001: Codice eccessivamente annidato (>5 livelli)
- QUAL-DUP-001: File con nome identico in directory diverse (3+ occorrenze)
- QUAL-PRECOMMIT-001: Nessun pre-commit hook configurato
- QUAL-EDITORCONFIG-001: Nessun .editorconfig presente
- QUAL-CONTRIBUTING-001: Nessun CONTRIBUTING.md presente
- QUAL-CHANGELOG-001: Nessun CHANGELOG.md presente
"""

from __future__ import annotations

import re
import uuid
from collections import defaultdict

from cto_audit.core.models import (
    FileClassification,
    Finding,
    Layer,
    PrivacyCategory,
    Severity,
    StackInfo,
)
from cto_audit.core.source import AuditSource


# --- Linter/Formatter markers ---

LINTER_MARKERS: dict[str, str] = {
    # Python
    ".flake8": "Flake8",
    "setup.cfg": "Flake8/Setuptools",
    "ruff.toml": "Ruff",
    ".ruff.toml": "Ruff",
    "pyproject.toml": "Ruff/Black/Mypy (config)",
    ".pylintrc": "Pylint",
    ".isort.cfg": "isort",
    # JavaScript/TypeScript
    ".eslintrc": "ESLint",
    ".eslintrc.js": "ESLint",
    ".eslintrc.cjs": "ESLint",
    ".eslintrc.json": "ESLint",
    ".eslintrc.yml": "ESLint",
    ".eslintrc.yaml": "ESLint",
    "eslint.config.js": "ESLint (flat)",
    "eslint.config.mjs": "ESLint (flat)",
    "eslint.config.cjs": "ESLint (flat)",
    ".prettierrc": "Prettier",
    ".prettierrc.json": "Prettier",
    ".prettierrc.yml": "Prettier",
    ".prettierrc.js": "Prettier",
    "prettier.config.js": "Prettier",
    "prettier.config.mjs": "Prettier",
    "biome.json": "Biome",
    # Ruby
    ".rubocop.yml": "RuboCop",
    ".rubocop.yaml": "RuboCop",
    # Go
    ".golangci.yml": "golangci-lint",
    ".golangci.yaml": "golangci-lint",
    # Rust
    "rustfmt.toml": "rustfmt",
    ".rustfmt.toml": "rustfmt",
    "clippy.toml": "Clippy",
    # Java
    "checkstyle.xml": "Checkstyle",
    ".editorconfig": "EditorConfig",
}

# Content markers in pyproject.toml for linter presence
PYPROJECT_LINTER_MARKERS: list[str] = [
    "[tool.ruff]", "[tool.black]", "[tool.flake8]",
    "[tool.pylint]", "[tool.isort]",
]

# --- Type checking markers ---

TYPING_MARKERS: dict[str, str] = {
    # Python
    "mypy.ini": "mypy",
    ".mypy.ini": "mypy",
    "pyrightconfig.json": "Pyright",
    "pytype.cfg": "pytype",
    # JS/TS
    "tsconfig.json": "TypeScript",
    "jsconfig.json": "JSConfig",
}

PYPROJECT_TYPING_MARKERS: list[str] = [
    "[tool.mypy]", "[tool.pyright]",
]

# --- Docstring detection ---

# Python docstring: triple quotes right after def/class
PYTHON_DOCSTRING_RE = re.compile(
    r'''(?:def\s+\w+\s*\([^)]*\)\s*(?:->[^:]*)?:\s*\n\s*(?:"{3}|'{3})|class\s+\w+[^:]*:\s*\n\s*(?:"{3}|'{3}))''',
    re.MULTILINE,
)

# Python function/class count
PYTHON_CALLABLE_RE = re.compile(
    r"^(?:def|class)\s+\w+",
    re.MULTILINE,
)

# JS/TS JSDoc: /** ... */
JSDOC_RE = re.compile(r"/\*\*[\s\S]*?\*/")

# JS/TS function count
JS_FUNCTION_RE = re.compile(
    r"(?:function\s+\w+|(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?\(|class\s+\w+|(?:export\s+)?(?:default\s+)?(?:async\s+)?function)",
    re.MULTILINE,
)

# Source code extensions to check for docstrings
DOCSTRING_CHECK_EXTENSIONS: set[str] = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
}

# --- Indentation/nesting ---

NESTING_THRESHOLD = 5  # Livelli di indentazione che indicano complessita eccessiva

# Directories to skip
SKIP_DIRS: set[str] = {
    "node_modules", "vendor", ".git", "__pycache__", "venv",
    ".venv", "env", "build", "dist", "target",
    ".tox", ".mypy_cache", ".pytest_cache", "site-packages",
    ".next", ".nuxt", "coverage",
}

SOURCE_EXTENSIONS: set[str] = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go",
    ".rb", ".rs", ".cs", ".php", ".kt", ".scala",
}


def _make_id() -> str:
    return str(uuid.uuid4())[:8]


def _should_scan_file(path: str) -> bool:
    """Determina se un file deve essere scansionato."""
    parts = path.replace("\\", "/").split("/")
    if any(part in SKIP_DIRS for part in parts):
        return False
    basename = parts[-1]
    ext = "." + basename.rsplit(".", 1)[-1] if "." in basename else ""
    return ext in SOURCE_EXTENSIONS


class QualityAnalyzer:
    """
    Analyzer per il layer Qualita del Codice.

    Verifica indicatori di qualita a livello CTO: documentazione,
    linting, typing, complessita, duplicazione.
    """

    def analyze(
        self,
        source: AuditSource,
        stack_info: StackInfo,
        classifications: list[FileClassification],
    ) -> list[Finding]:
        """Analizza la qualita del codebase."""
        file_tree = source.get_file_tree()
        all_paths: set[str] = set()
        dir_paths: set[str] = set()
        for entry in file_tree.entries:
            if entry.is_dir:
                dir_paths.add(entry.path)
            else:
                all_paths.add(entry.path)

        findings: list[Finding] = []

        findings.extend(self._check_readme(all_paths))
        findings.extend(self._check_docstrings(all_paths, source))
        findings.extend(self._check_linter(all_paths, source))
        findings.extend(self._check_typing(all_paths, stack_info, source))
        findings.extend(self._check_nesting(all_paths, source))
        findings.extend(self._check_duplicate_filenames(all_paths))
        findings.extend(self._check_precommit(all_paths, source))
        findings.extend(self._check_editorconfig(all_paths))
        findings.extend(self._check_contributing(all_paths))
        findings.extend(self._check_changelog(all_paths))

        return findings

    # --- Check 1: README ---

    def _check_readme(self, all_paths: set[str]) -> list[Finding]:
        """Verifica presenza di README nella root."""
        readme_names = {"README.md", "README.rst", "README.txt", "README", "readme.md"}
        basenames = {p for p in all_paths if "/" not in p}

        if any(name in basenames for name in readme_names):
            return []

        # Case-insensitive fallback
        basenames_lower = {p.lower() for p in basenames}
        if any(name.lower() in basenames_lower for name in readme_names):
            return []

        return [Finding(
            id=_make_id(),
            layer=Layer.QUALITY,
            severity=Severity.MEDIUM,
            rule_id="QUAL-DOC-001",
            title="Nessun README nella root del progetto",
            description=(
                "Non e stato trovato un file README.md o README.rst nella root. "
                "Il README e il primo punto di contatto per nuovi sviluppatori "
                "e dovrebbe contenere: descrizione, setup, architettura, come contribuire."
            ),
        )]

    # --- Check 2: Inline Documentation ---

    def _check_docstrings(
        self, all_paths: set[str], source: AuditSource
    ) -> list[Finding]:
        """Verifica percentuale di file con documentazione inline."""
        total_files = 0
        documented_files = 0

        for path in all_paths:
            if not _should_scan_file(path):
                continue

            basename = path.rsplit("/", 1)[-1]
            ext = "." + basename.rsplit(".", 1)[-1] if "." in basename else ""
            if ext not in DOCSTRING_CHECK_EXTENSIONS:
                continue

            try:
                content = source.read_file(path)
            except (ValueError, FileNotFoundError, PermissionError, UnicodeDecodeError):
                continue

            # Solo file con almeno 2 funzioni/classi
            if ext == ".py":
                callables = PYTHON_CALLABLE_RE.findall(content)
                if len(callables) < 2:
                    continue
                total_files += 1
                docstrings = PYTHON_DOCSTRING_RE.findall(content)
                if len(docstrings) >= len(callables) * 0.3:
                    documented_files += 1
            elif ext in (".js", ".jsx", ".ts", ".tsx"):
                functions = JS_FUNCTION_RE.findall(content)
                if len(functions) < 2:
                    continue
                total_files += 1
                jsdocs = JSDOC_RE.findall(content)
                if len(jsdocs) >= len(functions) * 0.3:
                    documented_files += 1

        if total_files < 3:
            return []  # Troppo pochi file per giudicare

        doc_ratio = documented_files / total_files
        if doc_ratio >= 0.30:
            return []

        return [Finding(
            id=_make_id(),
            layer=Layer.QUALITY,
            severity=Severity.LOW,
            rule_id="QUAL-DOC-002",
            title=f"Documentazione inline insufficiente ({doc_ratio:.0%} dei file)",
            description=(
                f"Solo {documented_files}/{total_files} file sorgente ({doc_ratio:.0%}) "
                "hanno documentazione inline (docstring/JSDoc). "
                "Una soglia minima del 30% e raccomandata per manutenibilita."
            ),
        )]

    # --- Check 3: Linter/Formatter ---

    def _check_linter(
        self, all_paths: set[str], source: AuditSource
    ) -> list[Finding]:
        """Verifica presenza di un linter/formatter configurato."""
        basenames = {p.rsplit("/", 1)[-1] for p in all_paths}

        # Check file markers
        for marker_file in LINTER_MARKERS:
            if marker_file in basenames:
                # pyproject.toml needs content check
                if marker_file == "pyproject.toml":
                    pyproject_paths = [p for p in all_paths if p.rsplit("/", 1)[-1] == "pyproject.toml"]
                    for pp in pyproject_paths:
                        try:
                            content = source.read_file(pp)
                            if any(m in content for m in PYPROJECT_LINTER_MARKERS):
                                return []
                        except (ValueError, FileNotFoundError, PermissionError, UnicodeDecodeError):
                            continue
                else:
                    return []

        return [Finding(
            id=_make_id(),
            layer=Layer.QUALITY,
            severity=Severity.MEDIUM,
            rule_id="QUAL-LINT-001",
            title="Nessun linter o formatter configurato",
            description=(
                "Non e stata trovata nessuna configurazione di linter/formatter "
                "(ESLint, Prettier, Ruff, Black, Flake8, RuboCop, golangci-lint). "
                "Un linter riduce bug, migliora la consistenza del codice "
                "e accelera le code review."
            ),
            framework_ref="NIS2 Art.21(2)(a)",
        )]

    # --- Check 4: Type Checking ---

    def _check_typing(
        self,
        all_paths: set[str],
        stack_info: StackInfo,
        source: AuditSource,
    ) -> list[Finding]:
        """Verifica presenza di type checking (solo Python/JS/TS)."""
        # Solo se il progetto usa Python o JavaScript/TypeScript
        has_python = "python" in stack_info.languages
        has_js = any(lang in stack_info.languages for lang in ("javascript", "typescript"))

        if not has_python and not has_js:
            return []

        basenames = {p.rsplit("/", 1)[-1] for p in all_paths}

        # Check file markers
        for marker_file in TYPING_MARKERS:
            if marker_file in basenames:
                return []

        # Check pyproject.toml content for mypy/pyright
        pyproject_paths = [p for p in all_paths if p.rsplit("/", 1)[-1] == "pyproject.toml"]
        for pp in pyproject_paths:
            try:
                content = source.read_file(pp)
                if any(m in content for m in PYPROJECT_TYPING_MARKERS):
                    return []
            except (ValueError, FileNotFoundError, PermissionError, UnicodeDecodeError):
                continue

        return [Finding(
            id=_make_id(),
            layer=Layer.QUALITY,
            severity=Severity.LOW,
            rule_id="QUAL-TYPING-001",
            title="Nessun type checking configurato",
            description=(
                "Il progetto non configura nessun type checker "
                "(mypy, Pyright per Python; TypeScript strict per JS). "
                "Il type checking riduce bug a runtime e migliora la documentazione implicita."
            ),
        )]

    # --- Check 5: Excessive Nesting ---

    def _check_nesting(
        self, all_paths: set[str], source: AuditSource
    ) -> list[Finding]:
        """Rileva file con annidamento eccessivo (>5 livelli)."""
        deeply_nested: list[tuple[str, int]] = []  # (path, max_depth)

        for path in all_paths:
            if not _should_scan_file(path):
                continue

            try:
                content = source.read_file(path)
            except (ValueError, FileNotFoundError, PermissionError, UnicodeDecodeError):
                continue

            max_depth = self._measure_max_nesting(content, path)
            if max_depth > NESTING_THRESHOLD:
                deeply_nested.append((path, max_depth))

        if not deeply_nested:
            return []

        # Ordina per profondita decrescente
        deeply_nested.sort(key=lambda x: x[1], reverse=True)

        # Cap per dimensione progetto
        total_scannable = sum(1 for p in all_paths if _should_scan_file(p))
        max_penalized = min(8, max(3, round(len(deeply_nested) / max(total_scannable, 1) * 40)))
        capped = deeply_nested[:max_penalized]

        display = capped[:5]
        more = f" (+{len(deeply_nested) - 5} file)" if len(deeply_nested) > 5 else ""

        return [Finding(
            id=_make_id(),
            layer=Layer.QUALITY,
            severity=Severity.MEDIUM,
            rule_id="QUAL-COMPLEXITY-001",
            title=f"Codice eccessivamente annidato ({len(deeply_nested)} file)",
            description=(
                f"Trovati file con annidamento >{NESTING_THRESHOLD} livelli:\n"
                + "\n".join(f"  - {p} (max {d} livelli)" for p, d in display)
                + more
                + "\nL'annidamento eccessivo riduce la leggibilita. "
                "Considerare early return, guard clause, o estrazione di funzioni."
            ),
        )]

    def _measure_max_nesting(self, content: str, path: str) -> int:
        """Misura il livello massimo di annidamento in un file."""
        basename = path.rsplit("/", 1)[-1]
        ext = "." + basename.rsplit(".", 1)[-1] if "." in basename else ""

        max_depth = 0

        if ext == ".py":
            # Python: conta livelli di indentazione (4 spazi = 1 livello)
            for line in content.splitlines():
                stripped = line.lstrip()
                if not stripped or stripped.startswith("#"):
                    continue
                indent = len(line) - len(stripped)
                depth = indent // 4
                if depth > max_depth:
                    max_depth = depth
        elif ext in (".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rs", ".cs", ".kt", ".scala", ".php"):
            # Brace-based: conta { e } per il nesting
            depth = 0
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                    continue
                depth += stripped.count("{")
                depth -= stripped.count("}")
                if depth > max_depth:
                    max_depth = depth

        return max_depth

    # --- Check 6: Duplicate Filenames ---

    def _check_duplicate_filenames(self, all_paths: set[str]) -> list[Finding]:
        """Rileva file con nome identico in directory diverse (3+ occorrenze)."""
        filename_map: dict[str, list[str]] = defaultdict(list)

        for path in all_paths:
            parts = path.replace("\\", "/").split("/")
            # Skip common directories
            if any(part in SKIP_DIRS for part in parts):
                continue

            basename = parts[-1]
            # Skip common files that are legitimately duplicated
            if basename in ("__init__.py", "index.js", "index.ts", "index.tsx",
                           "index.html", "conftest.py", ".gitkeep", ".gitignore",
                           "package.json", "Makefile", "README.md"):
                continue

            ext = "." + basename.rsplit(".", 1)[-1] if "." in basename else ""
            if ext not in SOURCE_EXTENSIONS:
                continue

            filename_map[basename].append(path)

        # Filtra: almeno 3 occorrenze
        duplicates = {name: paths for name, paths in filename_map.items() if len(paths) >= 3}

        if not duplicates:
            return []

        # Cap a 5 file names
        dup_list = sorted(duplicates.items(), key=lambda x: -len(x[1]))[:5]

        return [Finding(
            id=_make_id(),
            layer=Layer.QUALITY,
            severity=Severity.LOW,
            rule_id="QUAL-DUP-001",
            title=f"File con nome identico in directory diverse ({len(duplicates)} nomi)",
            description=(
                "Trovati file sorgente con lo stesso nome in directory diverse "
                "(segnale di copy-paste):\n"
                + "\n".join(
                    f"  - {name}: {len(paths)} copie"
                    for name, paths in dup_list
                )
                + "\nConsiderare refactoring per eliminare duplicazione."
            ),
        )]

    # --- Check 7: Pre-commit Hooks ---

    def _check_precommit(
        self, all_paths: set[str], source: AuditSource
    ) -> list[Finding]:
        """Verifica presenza di pre-commit hooks (.pre-commit-config.yaml, husky, .husky/)."""
        basenames = {p.rsplit("/", 1)[-1] for p in all_paths}

        # Check .pre-commit-config.yaml
        if ".pre-commit-config.yaml" in basenames:
            return []

        # Check .husky/ directory
        if any(p.startswith(".husky/") or p == ".husky" for p in all_paths):
            return []

        # Check husky in package.json
        if "package.json" in basenames:
            pkg_paths = [p for p in all_paths if p.rsplit("/", 1)[-1] == "package.json" and "/" not in p]
            if not pkg_paths:
                pkg_paths = [p for p in all_paths if p.rsplit("/", 1)[-1] == "package.json"]
            for pp in pkg_paths[:1]:
                try:
                    content = source.read_file(pp)
                    if '"husky"' in content or '"lint-staged"' in content:
                        return []
                except (ValueError, FileNotFoundError, UnicodeDecodeError):
                    continue

        # Check lefthook
        if "lefthook.yml" in basenames or "lefthook.yaml" in basenames:
            return []

        return [Finding(
            id=_make_id(),
            layer=Layer.QUALITY,
            severity=Severity.MEDIUM,
            rule_id="QUAL-PRECOMMIT-001",
            title="Nessun pre-commit hook configurato",
            description=(
                "Non e stato trovato nessun sistema di pre-commit hook "
                "(.pre-commit-config.yaml, Husky, lefthook). "
                "I pre-commit hook prevengono commit di codice non conforme, "
                "secrets accidentali e altri errori comuni."
            ),
        )]

    # --- Check 8: EditorConfig ---

    def _check_editorconfig(self, all_paths: set[str]) -> list[Finding]:
        """Verifica presenza di .editorconfig nella root."""
        basenames_root = {p for p in all_paths if "/" not in p}

        if ".editorconfig" in basenames_root:
            return []

        return [Finding(
            id=_make_id(),
            layer=Layer.QUALITY,
            severity=Severity.LOW,
            rule_id="QUAL-EDITORCONFIG-001",
            title="Nessun .editorconfig presente",
            description=(
                "Non e stato trovato un file .editorconfig nella root. "
                "EditorConfig garantisce impostazioni di formattazione consistenti "
                "(indentazione, fine riga, charset) tra editor e sviluppatori diversi."
            ),
        )]

    # --- Check 9: CONTRIBUTING.md ---

    def _check_contributing(self, all_paths: set[str]) -> list[Finding]:
        """Verifica presenza di CONTRIBUTING.md (case-insensitive)."""
        basenames_lower = {p.rsplit("/", 1)[-1].lower() for p in all_paths if "/" not in p}

        if "contributing.md" in basenames_lower:
            return []

        return [Finding(
            id=_make_id(),
            layer=Layer.QUALITY,
            severity=Severity.LOW,
            rule_id="QUAL-CONTRIBUTING-001",
            title="Nessun CONTRIBUTING.md presente",
            description=(
                "Non e stato trovato un file CONTRIBUTING.md. "
                "Le linee guida per i contributori accelerano l'onboarding "
                "e riducono il tempo di review delle pull request."
            ),
        )]

    # --- Check 10: CHANGELOG.md ---

    def _check_changelog(self, all_paths: set[str]) -> list[Finding]:
        """Verifica presenza di CHANGELOG.md, CHANGES.md o HISTORY.md (case-insensitive)."""
        basenames_lower = {p.rsplit("/", 1)[-1].lower() for p in all_paths if "/" not in p}

        changelog_names = {"changelog.md", "changes.md", "history.md"}
        if basenames_lower & changelog_names:
            return []

        return [Finding(
            id=_make_id(),
            layer=Layer.QUALITY,
            severity=Severity.LOW,
            rule_id="QUAL-CHANGELOG-001",
            title="Nessun CHANGELOG presente",
            description=(
                "Non e stato trovato un file CHANGELOG.md (o CHANGES.md, HISTORY.md). "
                "Un changelog strutturato facilita il tracking delle modifiche "
                "e la comunicazione con gli stakeholder."
            ),
        )]
