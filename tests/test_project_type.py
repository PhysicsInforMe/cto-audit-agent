"""
Test ProjectTypeDetector + NLP Classifier.

Verifica:
- Rilevazione web_app con web framework
- Rilevazione frontend con React/Vue
- Rilevazione full_stack con web + frontend
- Rilevazione library con setup.py/pyproject.toml
- Rilevazione cli_tool con click/typer/argparse
- Rilevazione data_pipeline con pandas/sklearn
- Rilevazione prototype con pochi file e no CI
- Fallback unknown senza segnali
- TF-IDF classifier con README
- enhance_with_nlp fallback e miglioramento
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cto_audit.collectors.project_type import ProjectTypeDetector
from cto_audit.collectors.nlp_classifier import (
    TFIDFClassifier,
    enhance_with_nlp,
    _tokenize,
    _cosine_similarity,
    _compute_tf,
)
from cto_audit.core.models import (
    FileTree,
    FileTreeEntry,
    ProjectType,
    ProjectTypeResult,
    StackInfo,
)
from cto_audit.sources.local import LocalRepoSource


def _write(base: Path, rel: str, content: str) -> None:
    p = base / Path(rel)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _detect(tmp_path: Path, stack: StackInfo | None = None) -> ProjectTypeResult:
    source = LocalRepoSource(tmp_path)
    stack = stack or StackInfo()
    file_tree = source.get_file_tree()
    detector = ProjectTypeDetector()
    return detector.detect(stack, file_tree, source)


# ============================================================
# Rule-Based Detection
# ============================================================

class TestWebApp:
    def test_flask_detected(self, tmp_path):
        _write(tmp_path, "app.py", "from flask import Flask\n")
        _write(tmp_path, "requirements.txt", "flask>=3.0\n")
        stack = StackInfo(languages={"python": 1.0}, frameworks=["Flask"])
        result = _detect(tmp_path, stack)
        assert result.detected_type == ProjectType.WEB_APP
        assert result.confidence >= 0.9
        assert result.method == "rule_based"

    def test_fastapi_detected(self, tmp_path):
        _write(tmp_path, "main.py", "from fastapi import FastAPI\n")
        stack = StackInfo(languages={"python": 1.0}, frameworks=["FastAPI"])
        result = _detect(tmp_path, stack)
        assert result.detected_type == ProjectType.WEB_APP

    def test_express_detected(self, tmp_path):
        _write(tmp_path, "index.js", "const express = require('express')\n")
        _write(tmp_path, "package.json", json.dumps({
            "dependencies": {"express": "^4.18.0"}
        }))
        stack = StackInfo(languages={"javascript": 1.0}, frameworks=["Express"])
        result = _detect(tmp_path, stack)
        assert result.detected_type == ProjectType.WEB_APP

    def test_django_detected(self, tmp_path):
        _write(tmp_path, "manage.py", "import django\n")
        stack = StackInfo(languages={"python": 1.0}, frameworks=["Django"])
        result = _detect(tmp_path, stack)
        assert result.detected_type == ProjectType.WEB_APP


class TestFrontend:
    def test_react_detected(self, tmp_path):
        _write(tmp_path, "package.json", json.dumps({
            "dependencies": {"react": "^18.0.0", "react-dom": "^18.0.0"}
        }))
        _write(tmp_path, "src/App.tsx", "export default function App() {}\n")
        stack = StackInfo(languages={"javascript": 1.0}, frameworks=["React"])
        result = _detect(tmp_path, stack)
        assert result.detected_type == ProjectType.FRONTEND

    def test_vue_detected(self, tmp_path):
        _write(tmp_path, "package.json", json.dumps({
            "dependencies": {"vue": "^3.0.0"}
        }))
        stack = StackInfo(languages={"javascript": 1.0}, frameworks=["Vue"])
        result = _detect(tmp_path, stack)
        assert result.detected_type == ProjectType.FRONTEND


class TestFullStack:
    def test_flask_plus_react(self, tmp_path):
        _write(tmp_path, "app.py", "from flask import Flask\n")
        _write(tmp_path, "package.json", json.dumps({
            "dependencies": {"react": "^18.0.0", "react-dom": "^18.0.0"}
        }))
        stack = StackInfo(
            languages={"python": 0.6, "javascript": 0.4},
            frameworks=["Flask", "React"],
        )
        result = _detect(tmp_path, stack)
        assert result.detected_type == ProjectType.FULL_STACK
        assert result.confidence >= 0.85


class TestLibrary:
    def test_setup_py_detected(self, tmp_path):
        _write(tmp_path, "setup.py", "from setuptools import setup\nsetup(name='mylib')\n")
        _write(tmp_path, "mylib/__init__.py", "")
        _write(tmp_path, "mylib/core.py", "def hello(): pass\n")
        stack = StackInfo(languages={"python": 1.0})
        result = _detect(tmp_path, stack)
        assert result.detected_type == ProjectType.LIBRARY

    def test_pyproject_with_build_system(self, tmp_path):
        _write(tmp_path, "pyproject.toml", (
            "[build-system]\n"
            'requires = ["setuptools"]\n'
            'build-backend = "setuptools.build_meta"\n'
        ))
        _write(tmp_path, "src/mylib/__init__.py", "")
        stack = StackInfo(languages={"python": 1.0})
        result = _detect(tmp_path, stack)
        assert result.detected_type == ProjectType.LIBRARY


class TestCLITool:
    def test_click_detected(self, tmp_path):
        _write(tmp_path, "requirements.txt", "click>=8.0\n")
        _write(tmp_path, "cli.py", "import click\n")
        stack = StackInfo(languages={"python": 1.0})
        result = _detect(tmp_path, stack)
        assert result.detected_type == ProjectType.CLI_TOOL

    def test_typer_detected(self, tmp_path):
        _write(tmp_path, "requirements.txt", "typer>=0.9\n")
        _write(tmp_path, "main.py", "import typer\n")
        stack = StackInfo(languages={"python": 1.0})
        result = _detect(tmp_path, stack)
        assert result.detected_type == ProjectType.CLI_TOOL


class TestDataPipeline:
    def test_pandas_sklearn(self, tmp_path):
        _write(tmp_path, "requirements.txt", "pandas>=2.0\nscikit-learn>=1.0\n")
        _write(tmp_path, "pipeline.py", "import pandas as pd\n")
        stack = StackInfo(languages={"python": 1.0})
        result = _detect(tmp_path, stack)
        assert result.detected_type == ProjectType.DATA_PIPELINE

    def test_torch_detected(self, tmp_path):
        _write(tmp_path, "requirements.txt", "torch>=2.0\n")
        _write(tmp_path, "train.py", "import torch\n")
        stack = StackInfo(languages={"python": 1.0})
        result = _detect(tmp_path, stack)
        assert result.detected_type == ProjectType.DATA_PIPELINE


class TestPrototype:
    def test_few_files_no_ci_no_tests(self, tmp_path):
        _write(tmp_path, "main.py", "print('hello')\n")
        _write(tmp_path, "utils.py", "def helper(): pass\n")
        stack = StackInfo(languages={"python": 1.0})
        result = _detect(tmp_path, stack)
        assert result.detected_type == ProjectType.PROTOTYPE
        assert result.confidence >= 0.7

    def test_with_ci_not_prototype(self, tmp_path):
        _write(tmp_path, "main.py", "print('hello')\n")
        _write(tmp_path, ".github/workflows/ci.yml", "name: CI\n")
        stack = StackInfo(languages={"python": 1.0})
        result = _detect(tmp_path, stack)
        # Has CI, should not be classified as prototype
        assert result.detected_type != ProjectType.PROTOTYPE

    def test_with_tests_not_prototype(self, tmp_path):
        _write(tmp_path, "main.py", "print('hello')\n")
        _write(tmp_path, "tests/test_main.py", "def test_it(): pass\n")
        stack = StackInfo(languages={"python": 1.0})
        result = _detect(tmp_path, stack)
        assert result.detected_type != ProjectType.PROTOTYPE


class TestUnknown:
    def test_empty_repo(self, tmp_path):
        _write(tmp_path, "data.csv", "a,b,c\n1,2,3\n")
        stack = StackInfo()
        result = _detect(tmp_path, stack)
        assert result.detected_type == ProjectType.UNKNOWN
        assert result.confidence <= 0.3


# ============================================================
# ProjectTypeResult Model
# ============================================================

class TestProjectTypeResult:
    def test_valid_result(self):
        result = ProjectTypeResult(
            detected_type=ProjectType.WEB_APP,
            confidence=0.9,
            method="rule_based",
            signals=["Flask detected"],
        )
        assert result.detected_type == ProjectType.WEB_APP
        assert result.confidence == 0.9

    def test_confidence_bounds(self):
        with pytest.raises(Exception):
            ProjectTypeResult(
                detected_type=ProjectType.UNKNOWN,
                confidence=1.5,
                method="rule_based",
            )


# ============================================================
# TF-IDF Classifier
# ============================================================

class TestTFIDFClassifier:
    def test_web_app_readme(self):
        readme = (
            "# My API Server\n\n"
            "REST API web application built with Flask.\n"
            "Endpoints for authentication, user management.\n"
            "Database: PostgreSQL with SQLAlchemy ORM.\n"
            "Deploy with Docker and Kubernetes.\n"
            "Routes: /api/users, /api/auth/login\n"
        )
        classifier = TFIDFClassifier()
        result = classifier.classify(readme)
        assert result.method == "tfidf"
        assert result.confidence > 0.0
        # Should recognize as web-related
        assert result.detected_type in (
            ProjectType.WEB_APP, ProjectType.FULL_STACK
        )

    def test_too_short_readme(self):
        classifier = TFIDFClassifier()
        result = classifier.classify("Hello")
        assert result.detected_type == ProjectType.UNKNOWN
        assert result.confidence <= 0.3

    def test_data_pipeline_readme(self):
        readme = (
            "# Data Pipeline\n\n"
            "ETL pipeline for data processing and model training.\n"
            "Uses pandas for DataFrame operations, scikit-learn for ML.\n"
            "Batch processing of CSV datasets with feature engineering.\n"
            "Training pipeline produces prediction models.\n"
        )
        classifier = TFIDFClassifier()
        result = classifier.classify(readme)
        assert result.detected_type == ProjectType.DATA_PIPELINE


# ============================================================
# NLP Enhancement
# ============================================================

class TestEnhanceWithNLP:
    def test_high_confidence_skips_nlp(self):
        rule_result = ProjectTypeResult(
            detected_type=ProjectType.WEB_APP,
            confidence=0.9,
            method="rule_based",
            signals=["Flask detected"],
        )
        result = enhance_with_nlp(rule_result, "Some README content here for testing")
        # Should return original since confidence is high
        assert result.method == "rule_based"
        assert result.confidence == 0.9

    def test_no_readme_returns_original(self):
        rule_result = ProjectTypeResult(
            detected_type=ProjectType.UNKNOWN,
            confidence=0.3,
            method="rule_based",
            signals=[],
        )
        result = enhance_with_nlp(rule_result, None)
        assert result == rule_result

    def test_short_readme_returns_original(self):
        rule_result = ProjectTypeResult(
            detected_type=ProjectType.UNKNOWN,
            confidence=0.3,
            method="rule_based",
            signals=[],
        )
        result = enhance_with_nlp(rule_result, "Hi")
        assert result == rule_result


# ============================================================
# Tokenizer and helpers
# ============================================================

class TestTokenizer:
    def test_tokenize_basic(self):
        tokens = _tokenize("Hello World from Python REST API")
        assert "hello" in tokens
        assert "world" in tokens
        assert "python" in tokens
        # "from" is a stop word
        assert "from" not in tokens

    def test_empty_string(self):
        tokens = _tokenize("")
        assert tokens == []

    def test_cosine_similarity_identical(self):
        vec = {"a": 1.0, "b": 2.0}
        assert _cosine_similarity(vec, vec) == pytest.approx(1.0)

    def test_cosine_similarity_orthogonal(self):
        vec_a = {"a": 1.0}
        vec_b = {"b": 1.0}
        assert _cosine_similarity(vec_a, vec_b) == 0.0

    def test_compute_tf(self):
        tokens = ["hello", "world", "hello"]
        tf = _compute_tf(tokens)
        assert tf["hello"] == pytest.approx(2 / 3)
        assert tf["world"] == pytest.approx(1 / 3)
