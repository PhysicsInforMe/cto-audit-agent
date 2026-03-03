"""
Test per lo StackDetector (Blocco 3).

Verifica:
- Rileva correttamente linguaggi e percentuali
- Rileva framework da file marker (requirements.txt, package.json, etc.)
- Rileva infrastruttura (Docker, CI/CD, IaC)
- Funziona su repo vuota, solo Python, solo JS, mista
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cto_audit.collectors.scanner import FileScanner
from cto_audit.collectors.stack import StackDetector
from cto_audit.sources.local import LocalRepoSource


# --- Fixture ---


@pytest.fixture
def repo_solo_python(tmp_path: Path) -> Path:
    """Repo con solo file Python e FastAPI."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "\n"
        "@app.get('/')\n"
        "def root():\n"
        "    return {'status': 'ok'}\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "models.py").write_text(
        "from pydantic import BaseModel\n"
        "\n"
        "class User(BaseModel):\n"
        "    name: str\n"
        "    email: str\n",
        encoding="utf-8",
    )
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_main.py").write_text(
        "def test_root():\n"
        "    assert True\n",
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text(
        "fastapi>=0.100\nuvicorn>=0.23\npydantic>=2.0\npytest>=8.0\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def repo_solo_js(tmp_path: Path) -> Path:
    """Repo con solo JavaScript/TypeScript e React + Express."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "App.tsx").write_text(
        "import React from 'react';\n"
        "export const App = () => <div>Hello</div>;\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "index.ts").write_text(
        "import { App } from './App';\n"
        "console.log(App);\n",
        encoding="utf-8",
    )
    (tmp_path / "server").mkdir()
    (tmp_path / "server" / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.listen(3000);\n",
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "test-app",
        "dependencies": {
            "react": "^18.0",
            "react-dom": "^18.0",
            "express": "^4.18",
        },
        "devDependencies": {
            "jest": "^29.0",
            "typescript": "^5.0",
        },
    }), encoding="utf-8")
    return tmp_path


@pytest.fixture
def repo_mista_con_infra(tmp_path: Path) -> Path:
    """
    Repo mista: Python + JS + Docker + GitHub Actions + Terraform.
    """
    # Python
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "app.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n"
        "# line 3\n# line 4\n# line 5\n# line 6\n# line 7\n# line 8\n",
        encoding="utf-8",
    )
    (tmp_path / "backend" / "requirements.txt").write_text(
        "flask>=3.0\nsqlalchemy>=2.0\nalembic>=1.12\n",
        encoding="utf-8",
    )

    # JavaScript
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend" / "app.jsx").write_text(
        "import React from 'react';\nexport default () => <h1>Hi</h1>;\n",
        encoding="utf-8",
    )
    (tmp_path / "frontend" / "package.json").write_text(json.dumps({
        "dependencies": {"react": "^18.0", "react-dom": "^18.0"},
    }), encoding="utf-8")

    # Go
    (tmp_path / "services" / "gateway").mkdir(parents=True)
    (tmp_path / "services" / "gateway" / "main.go").write_text(
        "package main\n\nimport \"fmt\"\n\nfunc main() {\n    fmt.Println(\"hello\")\n}\n",
        encoding="utf-8",
    )
    (tmp_path / "services" / "gateway" / "go.mod").write_text(
        "module gateway\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.9.1\n",
        encoding="utf-8",
    )

    # Docker
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11\nCOPY . /app\nCMD [\"python\", \"app.py\"]\n",
        encoding="utf-8",
    )
    (tmp_path / "docker-compose.yml").write_text(
        "version: '3'\nservices:\n  app:\n    build: .\n",
        encoding="utf-8",
    )

    # GitHub Actions
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
        encoding="utf-8",
    )

    # Terraform
    (tmp_path / "terraform").mkdir()
    (tmp_path / "terraform" / "main.tf").write_text(
        'resource "aws_instance" "web" {\n  ami = "ami-123"\n}\n',
        encoding="utf-8",
    )

    return tmp_path


@pytest.fixture
def repo_vuota(tmp_path: Path) -> Path:
    """Repo vuota — nessun file."""
    return tmp_path


@pytest.fixture
def repo_senza_framework(tmp_path: Path) -> Path:
    """Repo con file Python ma senza file marker framework."""
    (tmp_path / "script.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / "utils.py").write_text("def f(): pass\n", encoding="utf-8")
    return tmp_path


# --- Helper ---


def _scan_and_detect(repo_path: Path) -> tuple:
    """Helper: scansiona e rileva stack da una repo."""
    source = LocalRepoSource(repo_path)
    scanner = FileScanner(source)
    detector = StackDetector(source)
    files = scanner.scan()
    stack = detector.detect(files)
    return files, stack


# --- Test Linguaggi ---


class TestDetectLanguages:
    """Test per il rilevamento dei linguaggi."""

    def test_solo_python(self, repo_solo_python: Path):
        """Repo solo Python → 100% python."""
        _, stack = _scan_and_detect(repo_solo_python)
        assert "python" in stack.languages
        assert stack.languages["python"] == 1.0

    def test_solo_javascript(self, repo_solo_js: Path):
        """Repo JS/TS → sia javascript che typescript presenti."""
        _, stack = _scan_and_detect(repo_solo_js)
        assert "javascript" in stack.languages
        assert "typescript" in stack.languages
        # Insieme devono sommare a 1.0
        total = sum(stack.languages.values())
        assert abs(total - 1.0) < 0.01

    def test_repo_mista_linguaggi(self, repo_mista_con_infra: Path):
        """Repo mista → python, javascript, go presenti."""
        _, stack = _scan_and_detect(repo_mista_con_infra)
        assert "python" in stack.languages
        assert "javascript" in stack.languages
        assert "go" in stack.languages
        # Le percentuali sommano a ~1.0
        total = sum(stack.languages.values())
        assert abs(total - 1.0) < 0.01

    def test_repo_vuota_nessun_linguaggio(self, repo_vuota: Path):
        """Repo vuota → nessun linguaggio."""
        _, stack = _scan_and_detect(repo_vuota)
        assert stack.languages == {}

    def test_repo_senza_framework_ha_linguaggio(self, repo_senza_framework: Path):
        """Repo con file .py ma senza framework → python 100%."""
        _, stack = _scan_and_detect(repo_senza_framework)
        assert "python" in stack.languages
        assert stack.languages["python"] == 1.0


# --- Test Framework ---


class TestDetectFrameworks:
    """Test per il rilevamento dei framework."""

    def test_python_fastapi(self, repo_solo_python: Path):
        """Rileva FastAPI da requirements.txt."""
        _, stack = _scan_and_detect(repo_solo_python)
        assert "FastAPI" in stack.frameworks

    def test_python_pydantic_e_pytest(self, repo_solo_python: Path):
        """Rileva Pydantic e pytest da requirements.txt."""
        _, stack = _scan_and_detect(repo_solo_python)
        assert "Pydantic" in stack.frameworks
        assert "pytest" in stack.frameworks

    def test_js_react_express_jest(self, repo_solo_js: Path):
        """Rileva React, Express e Jest da package.json."""
        _, stack = _scan_and_detect(repo_solo_js)
        assert "React" in stack.frameworks
        assert "Express" in stack.frameworks
        assert "Jest" in stack.frameworks

    def test_mista_framework_multipli(self, repo_mista_con_infra: Path):
        """Repo mista rileva framework di linguaggi diversi."""
        _, stack = _scan_and_detect(repo_mista_con_infra)
        assert "Flask" in stack.frameworks
        assert "SQLAlchemy" in stack.frameworks
        assert "Alembic" in stack.frameworks
        assert "React" in stack.frameworks
        assert "Gin" in stack.frameworks

    def test_nessun_framework(self, repo_senza_framework: Path):
        """Repo senza file marker → nessun framework rilevato."""
        _, stack = _scan_and_detect(repo_senza_framework)
        assert stack.frameworks == []

    def test_repo_vuota_nessun_framework(self, repo_vuota: Path):
        """Repo vuota → nessun framework."""
        _, stack = _scan_and_detect(repo_vuota)
        assert stack.frameworks == []

    def test_framework_da_go_mod(self, tmp_path: Path):
        """Rileva Gin da go.mod."""
        (tmp_path / "main.go").write_text("package main\n", encoding="utf-8")
        (tmp_path / "go.mod").write_text(
            "module myapp\nrequire github.com/gin-gonic/gin v1.9.1\n",
            encoding="utf-8",
        )
        _, stack = _scan_and_detect(tmp_path)
        assert "Gin" in stack.frameworks

    def test_framework_da_cargo_toml(self, tmp_path: Path):
        """Rileva Actix Web e Serde da Cargo.toml."""
        (tmp_path / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
        (tmp_path / "Cargo.toml").write_text(
            "[dependencies]\nactix-web = \"4\"\nserde = \"1\"\ntokio = \"1\"\n",
            encoding="utf-8",
        )
        _, stack = _scan_and_detect(tmp_path)
        assert "Actix Web" in stack.frameworks
        assert "Serde" in stack.frameworks
        assert "Tokio" in stack.frameworks

    def test_framework_da_gemfile(self, tmp_path: Path):
        """Rileva Ruby on Rails da Gemfile."""
        (tmp_path / "app.rb").write_text("puts 'hello'\n", encoding="utf-8")
        (tmp_path / "Gemfile").write_text(
            "source 'https://rubygems.org'\ngem 'rails', '~> 7.0'\ngem 'rspec'\n",
            encoding="utf-8",
        )
        _, stack = _scan_and_detect(tmp_path)
        assert "Ruby on Rails" in stack.frameworks
        assert "RSpec" in stack.frameworks

    def test_framework_da_composer_json(self, tmp_path: Path):
        """Rileva Laravel da composer.json."""
        (tmp_path / "index.php").write_text("<?php echo 'hi'; ?>\n", encoding="utf-8")
        (tmp_path / "composer.json").write_text(json.dumps({
            "require": {"laravel/framework": "^10.0"},
            "require-dev": {"phpunit/phpunit": "^10.0"},
        }), encoding="utf-8")
        _, stack = _scan_and_detect(tmp_path)
        assert "Laravel" in stack.frameworks
        assert "PHPUnit" in stack.frameworks

    def test_framework_da_csproj(self, tmp_path: Path):
        """Rileva ASP.NET Core da .csproj."""
        (tmp_path / "Program.cs").write_text(
            "using System;\nConsole.WriteLine(\"Hello\");\n", encoding="utf-8"
        )
        (tmp_path / "MyApp.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk.Web">\n'
            "  <ItemGroup>\n"
            '    <PackageReference Include="Microsoft.AspNetCore.App" />\n'
            '    <PackageReference Include="Microsoft.EntityFrameworkCore" Version="8.0" />\n'
            "  </ItemGroup>\n"
            "</Project>\n",
            encoding="utf-8",
        )
        _, stack = _scan_and_detect(tmp_path)
        assert "ASP.NET Core" in stack.frameworks
        assert "Entity Framework Core" in stack.frameworks


# --- Test Infrastruttura ---


class TestDetectInfra:
    """Test per il rilevamento dell'infrastruttura."""

    def test_docker(self, repo_mista_con_infra: Path):
        """Rileva Docker da Dockerfile."""
        _, stack = _scan_and_detect(repo_mista_con_infra)
        assert "Docker" in stack.infra_type

    def test_docker_compose(self, repo_mista_con_infra: Path):
        """Rileva Docker Compose da docker-compose.yml."""
        _, stack = _scan_and_detect(repo_mista_con_infra)
        assert "Docker Compose" in stack.infra_type

    def test_github_actions(self, repo_mista_con_infra: Path):
        """Rileva GitHub Actions da .github/workflows."""
        _, stack = _scan_and_detect(repo_mista_con_infra)
        assert "GitHub Actions" in stack.infra_type

    def test_terraform(self, repo_mista_con_infra: Path):
        """Rileva Terraform dalla directory terraform/ e main.tf."""
        _, stack = _scan_and_detect(repo_mista_con_infra)
        assert "Terraform" in stack.infra_type

    def test_nessuna_infra(self, repo_senza_framework: Path):
        """Repo senza file infra → lista vuota."""
        _, stack = _scan_and_detect(repo_senza_framework)
        assert stack.infra_type == []

    def test_repo_vuota_nessuna_infra(self, repo_vuota: Path):
        """Repo vuota → nessuna infra."""
        _, stack = _scan_and_detect(repo_vuota)
        assert stack.infra_type == []

    def test_gitlab_ci(self, tmp_path: Path):
        """Rileva GitLab CI da .gitlab-ci.yml."""
        (tmp_path / "app.py").write_text("pass\n", encoding="utf-8")
        (tmp_path / ".gitlab-ci.yml").write_text(
            "stages:\n  - test\n", encoding="utf-8"
        )
        _, stack = _scan_and_detect(tmp_path)
        assert "GitLab CI" in stack.infra_type

    def test_jenkinsfile(self, tmp_path: Path):
        """Rileva Jenkins da Jenkinsfile."""
        (tmp_path / "app.py").write_text("pass\n", encoding="utf-8")
        (tmp_path / "Jenkinsfile").write_text(
            "pipeline { agent any }\n", encoding="utf-8"
        )
        _, stack = _scan_and_detect(tmp_path)
        assert "Jenkins" in stack.infra_type

    def test_kubernetes_e_helm(self, tmp_path: Path):
        """Rileva Kubernetes e Helm."""
        (tmp_path / "k8s").mkdir()
        (tmp_path / "k8s" / "deployment.yaml").write_text(
            "apiVersion: apps/v1\nkind: Deployment\n", encoding="utf-8"
        )
        (tmp_path / "Chart.yaml").write_text(
            "apiVersion: v2\nname: myapp\n", encoding="utf-8"
        )
        _, stack = _scan_and_detect(tmp_path)
        assert "Kubernetes" in stack.infra_type
        assert "Helm" in stack.infra_type

    def test_serverless_vercel(self, tmp_path: Path):
        """Rileva Vercel da vercel.json."""
        (tmp_path / "index.js").write_text("export default () => 'hi';\n", encoding="utf-8")
        (tmp_path / "vercel.json").write_text('{"version": 2}\n', encoding="utf-8")
        _, stack = _scan_and_detect(tmp_path)
        assert "Vercel" in stack.infra_type


# --- Test Integrazione Scanner + StackDetector ---


class TestIntegrazioneScanner:
    """Test che verificano l'integrazione tra FileScanner e StackDetector."""

    def test_pipeline_completa(self, repo_mista_con_infra: Path):
        """La pipeline Scanner → StackDetector produce risultati coerenti."""
        source = LocalRepoSource(repo_mista_con_infra)
        scanner = FileScanner(source)
        detector = StackDetector(source)

        files = scanner.scan()
        stack = detector.detect(files)

        # I file scansionati hanno le estensioni giuste
        extensions = {f.extension for f in files}
        assert ".py" in extensions
        assert ".jsx" in extensions
        assert ".go" in extensions

        # Lo stack ha rilevato tutto
        assert len(stack.languages) >= 3
        assert len(stack.frameworks) >= 3
        assert len(stack.infra_type) >= 3

    def test_scanner_non_include_excluded_in_stack(self, tmp_path: Path):
        """I file in directory escluse non influenzano lo stack rilevato."""
        # File Python nella root
        (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")

        # Enorme quantità di JS in node_modules (esclusa)
        (tmp_path / "node_modules" / "huge").mkdir(parents=True)
        for i in range(20):
            (tmp_path / "node_modules" / "huge" / f"file{i}.js").write_text(
                "// many lines\n" * 100, encoding="utf-8"
            )

        _, stack = _scan_and_detect(tmp_path)
        # Solo Python perché node_modules è escluso dallo scanner
        assert "python" in stack.languages
        assert "javascript" not in stack.languages
