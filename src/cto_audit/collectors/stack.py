"""
Stack detector — rileva linguaggi, framework e infrastruttura di un codebase.

Il StackDetector analizza i file scansionati per determinare:
1. Linguaggi presenti e le loro percentuali (per estensione + analisi marker)
2. Framework usati (da file marker: requirements.txt, package.json, pom.xml, etc.)
3. Tipo di infrastruttura (Docker, CI/CD, IaC, etc.)

È progettato per essere language-agnostic: supporta Python, JavaScript/TypeScript,
Java, Go, Rust, C#, Ruby, PHP, e altri.
"""

from __future__ import annotations

import json
import re
from typing import Any

from cto_audit.core.models import FileInfo, StackInfo
from cto_audit.core.source import AuditSource


# --- Mapping estensione → linguaggio ---

EXTENSION_TO_LANGUAGE: dict[str, str] = {
    # Python
    ".py": "python",
    ".pyw": "python",
    ".pyi": "python",
    # JavaScript / TypeScript
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    # Java
    ".java": "java",
    # Go
    ".go": "go",
    # Rust
    ".rs": "rust",
    # C#
    ".cs": "csharp",
    # Ruby
    ".rb": "ruby",
    # PHP
    ".php": "php",
    # C / C++
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    # Swift
    ".swift": "swift",
    # Kotlin
    ".kt": "kotlin",
    ".kts": "kotlin",
    # Scala
    ".scala": "scala",
    # Dart
    ".dart": "dart",
    # Shell
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    # HTML / CSS (non contati come linguaggi principali ma tracciati)
    ".html": "html",
    ".htm": "html",
    ".css": "css",
    ".scss": "css",
    ".sass": "css",
    ".less": "css",
    # SQL
    ".sql": "sql",
    # Elixir / Erlang
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    # Lua
    ".lua": "lua",
    # R
    ".r": "r",
    ".R": "r",
    # Zig
    ".zig": "zig",
}


# --- File marker per rilevamento framework ---
# Ogni entry: (file marker, callback per analisi contenuto)
# Il callback riceve il contenuto del file e restituisce i framework trovati

def _detect_python_frameworks(content: str) -> list[str]:
    """Rileva framework Python da requirements.txt o pyproject.toml."""
    frameworks: list[str] = []
    content_lower = content.lower()

    mapping = {
        "fastapi": "FastAPI",
        "django": "Django",
        "flask": "Flask",
        "starlette": "Starlette",
        "tornado": "Tornado",
        "aiohttp": "aiohttp",
        "sanic": "Sanic",
        "celery": "Celery",
        "sqlalchemy": "SQLAlchemy",
        "alembic": "Alembic",
        "pydantic": "Pydantic",
        "pytest": "pytest",
        "numpy": "NumPy",
        "pandas": "pandas",
        "scikit-learn": "scikit-learn",
        "tensorflow": "TensorFlow",
        "torch": "PyTorch",
        "pytorch": "PyTorch",
        "transformers": "Hugging Face Transformers",
    }

    for marker, name in mapping.items():
        if marker in content_lower:
            frameworks.append(name)

    return frameworks


def _detect_node_frameworks(content: str) -> list[str]:
    """Rileva framework Node.js da package.json."""
    frameworks: list[str] = []
    try:
        pkg = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return frameworks

    # Unisci dependencies e devDependencies
    all_deps: dict[str, Any] = {}
    all_deps.update(pkg.get("dependencies", {}))
    all_deps.update(pkg.get("devDependencies", {}))

    mapping = {
        "react": "React",
        "react-dom": "React",
        "next": "Next.js",
        "vue": "Vue.js",
        "nuxt": "Nuxt.js",
        "@angular/core": "Angular",
        "svelte": "Svelte",
        "express": "Express",
        "fastify": "Fastify",
        "nestjs": "NestJS",
        "@nestjs/core": "NestJS",
        "koa": "Koa",
        "hapi": "Hapi",
        "@hapi/hapi": "Hapi",
        "jest": "Jest",
        "mocha": "Mocha",
        "vitest": "Vitest",
        "cypress": "Cypress",
        "prisma": "Prisma",
        "@prisma/client": "Prisma",
        "sequelize": "Sequelize",
        "typeorm": "TypeORM",
        "mongoose": "Mongoose",
        "tailwindcss": "Tailwind CSS",
        "electron": "Electron",
    }

    for dep_name, framework_name in mapping.items():
        if dep_name in all_deps:
            frameworks.append(framework_name)

    return frameworks


def _detect_java_frameworks(content: str) -> list[str]:
    """Rileva framework Java da pom.xml o build.gradle."""
    frameworks: list[str] = []
    content_lower = content.lower()

    mapping = {
        "spring-boot": "Spring Boot",
        "spring-framework": "Spring",
        "spring-web": "Spring",
        "quarkus": "Quarkus",
        "micronaut": "Micronaut",
        "jakarta.ee": "Jakarta EE",
        "javax.servlet": "Java Servlet",
        "hibernate": "Hibernate",
        "junit": "JUnit",
        "mockito": "Mockito",
    }

    for marker, name in mapping.items():
        if marker in content_lower:
            frameworks.append(name)

    return frameworks


def _detect_go_frameworks(content: str) -> list[str]:
    """Rileva framework Go da go.mod."""
    frameworks: list[str] = []

    mapping = {
        "github.com/gin-gonic/gin": "Gin",
        "github.com/gofiber/fiber": "Fiber",
        "github.com/labstack/echo": "Echo",
        "github.com/gorilla/mux": "Gorilla Mux",
        "github.com/beego/beego": "Beego",
        "gorm.io/gorm": "GORM",
    }

    for marker, name in mapping.items():
        if marker in content:
            frameworks.append(name)

    return frameworks


def _detect_rust_frameworks(content: str) -> list[str]:
    """Rileva framework Rust da Cargo.toml."""
    frameworks: list[str] = []
    content_lower = content.lower()

    mapping = {
        "actix-web": "Actix Web",
        "axum": "Axum",
        "rocket": "Rocket",
        "warp": "Warp",
        "tokio": "Tokio",
        "diesel": "Diesel",
        "sqlx": "SQLx",
        "serde": "Serde",
    }

    for marker, name in mapping.items():
        if marker in content_lower:
            frameworks.append(name)

    return frameworks


def _detect_ruby_frameworks(content: str) -> list[str]:
    """Rileva framework Ruby da Gemfile."""
    frameworks: list[str] = []
    content_lower = content.lower()

    mapping = {
        "rails": "Ruby on Rails",
        "sinatra": "Sinatra",
        "hanami": "Hanami",
        "rspec": "RSpec",
        "sidekiq": "Sidekiq",
    }

    for marker, name in mapping.items():
        if marker in content_lower:
            frameworks.append(name)

    return frameworks


def _detect_php_frameworks(content: str) -> list[str]:
    """Rileva framework PHP da composer.json."""
    frameworks: list[str] = []
    try:
        pkg = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return frameworks

    all_deps: dict[str, Any] = {}
    all_deps.update(pkg.get("require", {}))
    all_deps.update(pkg.get("require-dev", {}))

    mapping = {
        "laravel/framework": "Laravel",
        "symfony/framework-bundle": "Symfony",
        "slim/slim": "Slim",
        "cakephp/cakephp": "CakePHP",
        "phpunit/phpunit": "PHPUnit",
    }

    for dep_name, name in mapping.items():
        if dep_name in all_deps:
            frameworks.append(name)

    return frameworks


def _detect_csharp_frameworks(content: str) -> list[str]:
    """Rileva framework C# da .csproj."""
    frameworks: list[str] = []
    content_lower = content.lower()

    if "microsoft.aspnetcore" in content_lower:
        frameworks.append("ASP.NET Core")
    if "microsoft.entityframeworkcore" in content_lower:
        frameworks.append("Entity Framework Core")
    if "xunit" in content_lower:
        frameworks.append("xUnit")
    if "nunit" in content_lower:
        frameworks.append("NUnit")
    if "blazor" in content_lower:
        frameworks.append("Blazor")

    return frameworks


# Mapping: filename → funzione di rilevamento framework
FRAMEWORK_MARKERS: dict[str, Any] = {
    "requirements.txt": _detect_python_frameworks,
    "Pipfile": _detect_python_frameworks,
    "pyproject.toml": _detect_python_frameworks,
    "setup.py": _detect_python_frameworks,
    "setup.cfg": _detect_python_frameworks,
    "package.json": _detect_node_frameworks,
    "pom.xml": _detect_java_frameworks,
    "build.gradle": _detect_java_frameworks,
    "build.gradle.kts": _detect_java_frameworks,
    "go.mod": _detect_go_frameworks,
    "Cargo.toml": _detect_rust_frameworks,
    "Gemfile": _detect_ruby_frameworks,
    "composer.json": _detect_php_frameworks,
}


# --- File marker per rilevamento infrastruttura ---

INFRA_MARKERS: dict[str, list[str]] = {
    # CI/CD
    ".github/workflows": ["GitHub Actions"],
    ".gitlab-ci.yml": ["GitLab CI"],
    "Jenkinsfile": ["Jenkins"],
    "azure-pipelines.yml": ["Azure DevOps"],
    ".circleci": ["CircleCI"],
    ".travis.yml": ["Travis CI"],
    "bitbucket-pipelines.yml": ["Bitbucket Pipelines"],
    # Container
    "Dockerfile": ["Docker"],
    "docker-compose.yml": ["Docker Compose"],
    "docker-compose.yaml": ["Docker Compose"],
    "docker-compose.prod.yml": ["Docker Compose"],
    "docker-compose.override.yml": ["Docker Compose"],
    # Kubernetes
    "k8s": ["Kubernetes"],
    "kubernetes": ["Kubernetes"],
    "helm": ["Helm"],
    "Chart.yaml": ["Helm"],
    # IaC
    "terraform": ["Terraform"],
    "main.tf": ["Terraform"],
    "cloudformation": ["CloudFormation"],
    "template.yaml": ["CloudFormation"],
    "ansible": ["Ansible"],
    "playbook.yml": ["Ansible"],
    "Pulumi.yaml": ["Pulumi"],
    # Serverless
    "serverless.yml": ["Serverless Framework"],
    "serverless.yaml": ["Serverless Framework"],
    "vercel.json": ["Vercel"],
    "netlify.toml": ["Netlify"],
    # Monitoring
    "prometheus.yml": ["Prometheus"],
    "grafana": ["Grafana"],
    "datadog.yaml": ["Datadog"],
    # Altro
    "Vagrantfile": ["Vagrant"],
    "Makefile": ["Make"],
}


class StackDetector:
    """
    Rileva stack tecnologico, framework e infrastruttura di un codebase.

    Analizza i file scansionati (lista FileInfo) e la sorgente (per leggere
    i file marker) per determinare l'intero stack del progetto.

    Attributes:
        source: La sorgente dati per leggere i contenuti dei file marker
    """

    def __init__(self, source: AuditSource) -> None:
        """
        Args:
            source: Implementazione di AuditSource per leggere i file
        """
        self.source = source

    def detect(self, files: list[FileInfo]) -> StackInfo:
        """
        Rileva lo stack tecnologico completo del progetto.

        Args:
            files: Lista di FileInfo prodotta dal FileScanner

        Returns:
            StackInfo con linguaggi, framework, e infrastruttura rilevati
        """
        languages = self._detect_languages(files)
        frameworks = self._detect_frameworks(files)
        infra = self._detect_infra(files)

        return StackInfo(
            languages=languages,
            frameworks=sorted(set(frameworks)),
            infra_type=sorted(set(infra)),
        )

    def _detect_languages(self, files: list[FileInfo]) -> dict[str, float]:
        """
        Rileva i linguaggi di programmazione e le loro percentuali.

        Le percentuali sono calcolate in base alle righe di codice (LOC)
        per linguaggio. Linguaggi con 0 LOC ma file presenti vengono
        comunque conteggiati con un minimo.

        Args:
            files: Lista di FileInfo

        Returns:
            Dict linguaggio → percentuale (0.0 - 1.0)
        """
        loc_per_language: dict[str, int] = {}

        for f in files:
            lang = EXTENSION_TO_LANGUAGE.get(f.extension)
            if lang is None:
                continue
            loc = max(f.lines_of_code, 1)  # almeno 1 per file presente
            loc_per_language[lang] = loc_per_language.get(lang, 0) + loc

        total_loc = sum(loc_per_language.values())
        if total_loc == 0:
            return {}

        # Calcola percentuali e arrotonda a 4 decimali
        percentages: dict[str, float] = {}
        for lang, loc in sorted(loc_per_language.items(), key=lambda x: -x[1]):
            percentages[lang] = round(loc / total_loc, 4)

        return percentages

    def _detect_frameworks(self, files: list[FileInfo]) -> list[str]:
        """
        Rileva i framework usati analizzando i file marker.

        Per ogni file marker trovato (requirements.txt, package.json, etc.),
        legge il contenuto e passa a un detector specifico per linguaggio.

        Args:
            files: Lista di FileInfo

        Returns:
            Lista di nomi framework rilevati
        """
        frameworks: list[str] = []
        file_paths = {f.path for f in files}

        for file_path in file_paths:
            # Prendi solo il nome del file (senza directory)
            basename = file_path.split("/")[-1]
            detector = FRAMEWORK_MARKERS.get(basename)
            if detector is None:
                continue

            try:
                content = self.source.read_file(file_path)
                detected = detector(content)
                frameworks.extend(detected)
            except (FileNotFoundError, ValueError, PermissionError):
                continue

        # Gestisci anche .csproj per C#
        for file_path in file_paths:
            if file_path.endswith(".csproj"):
                try:
                    content = self.source.read_file(file_path)
                    frameworks.extend(_detect_csharp_frameworks(content))
                except (FileNotFoundError, ValueError, PermissionError):
                    continue

        return frameworks

    def _detect_infra(self, files: list[FileInfo]) -> list[str]:
        """
        Rileva il tipo di infrastruttura del progetto.

        Controlla la presenza di file e directory marker specifici
        per CI/CD, container, IaC, serverless, monitoring, etc.

        Args:
            files: Lista di FileInfo

        Returns:
            Lista di tipi di infrastruttura rilevati
        """
        infra: list[str] = []
        file_paths = {f.path for f in files}
        # Raccogliamo anche le directory (componenti di percorso)
        all_path_parts: set[str] = set()
        for f in files:
            parts = f.path.split("/")
            for i, part in enumerate(parts):
                # Aggiungi il componente singolo
                all_path_parts.add(part)
                # Aggiungi anche percorsi parziali (es. ".github/workflows")
                if i > 0:
                    all_path_parts.add("/".join(parts[:i + 1]))

        for marker, infra_types in INFRA_MARKERS.items():
            # Controlla se il marker matcha un file o parte di un percorso
            if marker in file_paths or marker in all_path_parts:
                infra.extend(infra_types)

        return infra
