"""
Project Type Detector — Rilevazione automatica del tipo di progetto.

Architettura a 3 livelli:
  Livello 1: Rule-based (sempre attivo, 0 dipendenze)
  Livello 2: TF-IDF + cosine similarity su README (opzionale, stdlib only)
  Livello 3: Sentence-BERT embeddings (opzionale, sentence-transformers)

Il sistema funziona al 100% senza NLP. NLP migliora solo la confidence.
"""

from __future__ import annotations

import json
import re

from cto_audit.core.models import (
    FileTree,
    ProjectType,
    ProjectTypeResult,
    StackInfo,
)
from cto_audit.core.source import AuditSource


# --- Web framework names (proper names from StackDetector, lowercase) ---

WEB_FRAMEWORK_NAMES: set[str] = {
    # Python
    "fastapi", "django", "flask", "starlette", "tornado", "aiohttp", "sanic",
    # Java
    "spring boot", "spring", "quarkus", "micronaut",
    # JavaScript/TypeScript
    "express", "fastify", "nestjs", "koa", "hapi", "next.js", "nuxt.js",
    # Go
    "gin", "fiber", "echo",
    # Rust
    "actix web", "axum", "rocket", "warp",
    # Ruby
    "ruby on rails", "sinatra",
    # PHP
    "laravel", "symfony",
    # Elixir
    "phoenix",
}

FRONTEND_FRAMEWORK_NAMES: set[str] = {
    "react", "vue", "angular", "svelte", "solid",
}

# Package names in package.json dependencies that indicate frontend
FRONTEND_PACKAGES: set[str] = {
    "react", "react-dom", "vue", "@angular/core", "svelte",
    "solid-js", "preact", "next", "nuxt", "gatsby",
}

# Package names indicating CLI tool
CLI_PACKAGES: set[str] = {
    "commander", "yargs", "inquirer", "chalk", "ora",
    "meow", "oclif", "vorpal",
}

# Python packages indicating data pipeline
DATA_PACKAGES: set[str] = {
    "pandas", "numpy", "scikit-learn", "sklearn", "torch",
    "tensorflow", "keras", "xgboost", "lightgbm",
    "pyspark", "dask", "airflow", "luigi", "prefect",
    "mlflow", "wandb",
}

# Python packages indicating CLI tool
CLI_PYTHON_PACKAGES: set[str] = {
    "click", "typer", "argparse", "fire", "cement",
}

# Directories that indicate test infrastructure
TEST_DIRS: set[str] = {
    "tests", "test", "__tests__", "spec", "specs",
    "test_", "testing",
}

# CI config indicators
CI_FILES: set[str] = {
    ".github/workflows", ".gitlab-ci.yml", "Jenkinsfile",
    ".circleci", ".travis.yml", "azure-pipelines.yml",
}

# Source code extensions
SOURCE_EXTENSIONS: set[str] = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go",
    ".rb", ".rs", ".cs", ".php", ".kt", ".scala",
}


class ProjectTypeDetector:
    """
    Rilevatore del tipo di progetto basato su regole euristiche.

    Analizza stack info, file tree e contenuti per determinare se il
    progetto è una web app, frontend, libreria, CLI, data pipeline,
    prototipo, o sconosciuto.
    """

    def detect(
        self,
        stack_info: StackInfo,
        file_tree: FileTree,
        source: AuditSource,
    ) -> ProjectTypeResult:
        """
        Rileva il tipo di progetto.

        Priorità:
        1. Full-stack (web fw + frontend fw)
        2. Web app (web framework rilevato)
        3. Frontend (frontend framework senza backend)
        4. Data pipeline (heavy data/ML deps)
        5. CLI tool (CLI frameworks/patterns)
        6. Library (setup.py/pyproject.toml con build-system, no web fw)
        7. Prototype (pochi file, no CI, no test)
        8. Unknown (nessun segnale forte)

        Args:
            stack_info: Stack tecnologico rilevato
            file_tree: Albero dei file del progetto
            source: Sorgente dati per leggere contenuti

        Returns:
            ProjectTypeResult con tipo, confidence, metodo e segnali
        """
        # Raccogli path e directory
        all_paths: set[str] = set()
        dir_paths: set[str] = set()
        for entry in file_tree.entries:
            if entry.is_dir:
                dir_paths.add(entry.path)
            else:
                all_paths.add(entry.path)

        basenames = {p.rsplit("/", 1)[-1] for p in all_paths}
        frameworks_lower = {fw.lower() for fw in stack_info.frameworks}

        signals: list[str] = []

        # --- Detect web framework ---
        has_web_fw = bool(frameworks_lower & WEB_FRAMEWORK_NAMES)
        if has_web_fw:
            matched = frameworks_lower & WEB_FRAMEWORK_NAMES
            signals.append(f"Web framework: {', '.join(matched)}")

        # --- Detect frontend framework ---
        has_frontend_fw = bool(frameworks_lower & FRONTEND_FRAMEWORK_NAMES)
        has_frontend_pkg = False

        # Check package.json for frontend packages
        if "package.json" in basenames:
            pkg_deps = self._read_package_json_deps(all_paths, source)
            if pkg_deps & FRONTEND_PACKAGES:
                has_frontend_pkg = True
                matched_fe = pkg_deps & FRONTEND_PACKAGES
                signals.append(f"Frontend packages: {', '.join(matched_fe)}")

        if has_frontend_fw:
            signals.append(f"Frontend framework: {', '.join(frameworks_lower & FRONTEND_FRAMEWORK_NAMES)}")

        # --- 1. Full-stack ---
        if has_web_fw and (has_frontend_fw or has_frontend_pkg):
            signals.append("Full-stack: web framework + frontend")
            return ProjectTypeResult(
                detected_type=ProjectType.FULL_STACK,
                confidence=0.85,
                method="rule_based",
                signals=signals,
            )

        # --- 2. Web app ---
        if has_web_fw:
            return ProjectTypeResult(
                detected_type=ProjectType.WEB_APP,
                confidence=0.9,
                method="rule_based",
                signals=signals,
            )

        # --- 3. Frontend ---
        if has_frontend_fw or has_frontend_pkg:
            return ProjectTypeResult(
                detected_type=ProjectType.FRONTEND,
                confidence=0.85,
                method="rule_based",
                signals=signals,
            )

        # --- Check Python deps for data/CLI ---
        python_deps = self._read_python_deps(all_paths, source)

        # --- 4. Data pipeline ---
        data_deps = python_deps & DATA_PACKAGES
        if data_deps:
            signals.append(f"Data/ML packages: {', '.join(data_deps)}")
            return ProjectTypeResult(
                detected_type=ProjectType.DATA_PIPELINE,
                confidence=0.8,
                method="rule_based",
                signals=signals,
            )

        # --- 5. CLI tool ---
        cli_deps = python_deps & CLI_PYTHON_PACKAGES
        if cli_deps:
            signals.append(f"CLI packages: {', '.join(cli_deps)}")
            return ProjectTypeResult(
                detected_type=ProjectType.CLI_TOOL,
                confidence=0.75,
                method="rule_based",
                signals=signals,
            )

        # Check JS CLI packages
        if "package.json" in basenames:
            pkg_deps = self._read_package_json_deps(all_paths, source)
            cli_js = pkg_deps & CLI_PACKAGES
            if cli_js:
                signals.append(f"CLI packages (JS): {', '.join(cli_js)}")
                return ProjectTypeResult(
                    detected_type=ProjectType.CLI_TOOL,
                    confidence=0.75,
                    method="rule_based",
                    signals=signals,
                )

        # --- 6. Library ---
        is_library = self._check_library(all_paths, basenames, source)
        if is_library:
            signals.append("Library pattern: build-system/setup.py without web framework")
            return ProjectTypeResult(
                detected_type=ProjectType.LIBRARY,
                confidence=0.8,
                method="rule_based",
                signals=signals,
            )

        # --- 7. Prototype ---
        is_prototype = self._check_prototype(all_paths, dir_paths, basenames)
        if is_prototype:
            signals.append("Prototype: few source files, no CI, no tests")
            return ProjectTypeResult(
                detected_type=ProjectType.PROTOTYPE,
                confidence=0.7,
                method="rule_based",
                signals=signals,
            )

        # --- 8. Unknown ---
        signals.append("No strong signals detected")
        return ProjectTypeResult(
            detected_type=ProjectType.UNKNOWN,
            confidence=0.3,
            method="rule_based",
            signals=signals,
        )

    def _read_package_json_deps(
        self, all_paths: set[str], source: AuditSource,
    ) -> set[str]:
        """Legge i nomi delle dipendenze da package.json."""
        deps: set[str] = set()
        pkg_paths = [p for p in all_paths if p.rsplit("/", 1)[-1] == "package.json"]

        # Preferisci root package.json
        root_pkgs = [p for p in pkg_paths if "/" not in p]
        target = root_pkgs[0] if root_pkgs else (pkg_paths[0] if pkg_paths else None)

        if not target:
            return deps

        try:
            content = source.read_file(target)
            data = json.loads(content)
            for key in ("dependencies", "devDependencies"):
                if isinstance(data.get(key), dict):
                    deps.update(data[key].keys())
        except (ValueError, FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError):
            pass

        return deps

    def _read_python_deps(
        self, all_paths: set[str], source: AuditSource,
    ) -> set[str]:
        """Legge i nomi delle dipendenze Python da requirements.txt/pyproject.toml/setup.py."""
        deps: set[str] = set()

        # requirements.txt
        req_paths = [p for p in all_paths if p.rsplit("/", 1)[-1] == "requirements.txt"]
        for rp in req_paths:
            try:
                content = source.read_file(rp)
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and not line.startswith("-"):
                        # Extract package name (before ==, >=, <=, ~=, !=, [)
                        pkg = re.split(r"[=<>~!;\[\s]", line)[0].strip().lower()
                        if pkg:
                            deps.add(pkg)
            except (ValueError, FileNotFoundError, UnicodeDecodeError):
                continue

        # pyproject.toml — simple heuristic
        pyproject_paths = [p for p in all_paths if p.rsplit("/", 1)[-1] == "pyproject.toml"]
        for pp in pyproject_paths:
            try:
                content = source.read_file(pp)
                # Look for dependencies section
                for line in content.splitlines():
                    line = line.strip().strip('"').strip("'").strip(",")
                    pkg = re.split(r"[=<>~!;\[\s]", line)[0].strip().lower()
                    if pkg in DATA_PACKAGES or pkg in CLI_PYTHON_PACKAGES:
                        deps.add(pkg)
            except (ValueError, FileNotFoundError, UnicodeDecodeError):
                continue

        # setup.py — look for install_requires
        setup_paths = [p for p in all_paths if p.rsplit("/", 1)[-1] == "setup.py"]
        for sp in setup_paths:
            try:
                content = source.read_file(sp)
                for pkg in DATA_PACKAGES | CLI_PYTHON_PACKAGES:
                    if pkg in content.lower():
                        deps.add(pkg)
            except (ValueError, FileNotFoundError, UnicodeDecodeError):
                continue

        return deps

    def _check_library(
        self,
        all_paths: set[str],
        basenames: set[str],
        source: AuditSource,
    ) -> bool:
        """Verifica se il progetto è una libreria."""
        # setup.py presente → likely library
        if "setup.py" in basenames:
            return True

        # pyproject.toml con [build-system] → library
        if "pyproject.toml" in basenames:
            pyproject_paths = [p for p in all_paths if p.rsplit("/", 1)[-1] == "pyproject.toml"]
            for pp in pyproject_paths:
                try:
                    content = source.read_file(pp)
                    if "[build-system]" in content:
                        return True
                except (ValueError, FileNotFoundError, UnicodeDecodeError):
                    continue

        # Cargo.toml with [lib] → Rust library
        if "Cargo.toml" in basenames:
            cargo_paths = [p for p in all_paths if p.rsplit("/", 1)[-1] == "Cargo.toml"]
            for cp in cargo_paths:
                try:
                    content = source.read_file(cp)
                    if "[lib]" in content:
                        return True
                except (ValueError, FileNotFoundError, UnicodeDecodeError):
                    continue

        return False

    def _check_prototype(
        self,
        all_paths: set[str],
        dir_paths: set[str],
        basenames: set[str],
    ) -> bool:
        """Verifica se il progetto è un prototipo/esperimento."""
        # Count source files
        source_files = sum(
            1 for p in all_paths
            if "." in p.rsplit("/", 1)[-1]
            and "." + p.rsplit("/", 1)[-1].rsplit(".", 1)[-1] in SOURCE_EXTENSIONS
        )

        if source_files >= 20:
            return False

        # Check no CI
        has_ci = any(
            ci in basenames or any(
                p == ci.rstrip("/") or p.startswith(ci) for p in dir_paths
            )
            for ci in CI_FILES
        )
        if has_ci:
            return False

        # Check no tests
        has_tests = any(
            d.rsplit("/", 1)[-1].lower() in TEST_DIRS
            for d in dir_paths
        )
        if has_tests:
            return False

        return source_files > 0  # At least 1 source file, but fewer than 20
