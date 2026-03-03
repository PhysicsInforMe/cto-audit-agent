"""
Test SecurityAnalyzer — 8 check di sicurezza CTO-level.
"""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from cto_audit.analyzers.security import SecurityAnalyzer
from cto_audit.core.models import (
    FileClassification,
    Finding,
    Layer,
    Severity,
    StackInfo,
)
from cto_audit.core.orchestrator import AuditOrchestrator
from cto_audit.sources.local import LocalRepoSource


def _write(base: Path, rel: str, content: str) -> None:
    p = base / Path(rel)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _run_security(repo_path: Path) -> list[Finding]:
    source = LocalRepoSource(repo_path)
    stack = StackInfo(languages={"python": 1.0}, frameworks=["FastAPI"])
    analyzer = SecurityAnalyzer()
    return analyzer.analyze(source, stack, [])


def _triggered_rules(findings: list[Finding]) -> set[str]:
    return {f.rule_id for f in findings if f.severity != Severity.INFO}


# ============================================================
# SEC-DEPS-001 — Vulnerable Dependencies
# ============================================================

class TestVulnerableDeps:
    def test_old_django(self, tmp_path):
        _write(tmp_path, "requirements.txt", "django==1.11.29\n")
        findings = _run_security(tmp_path)
        assert "SEC-DEPS-001" in _triggered_rules(findings)

    def test_old_lodash(self, tmp_path):
        _write(tmp_path, "package.json", json.dumps({
            "dependencies": {"lodash": "4.17.15"}
        }))
        source = LocalRepoSource(tmp_path)
        stack = StackInfo(languages={"javascript": 1.0}, frameworks=["Express"])
        findings = SecurityAnalyzer().analyze(source, stack, [])
        assert "SEC-DEPS-001" in _triggered_rules(findings)

    def test_current_versions_ok(self, tmp_path):
        _write(tmp_path, "requirements.txt", "django==4.2.0\nflask==3.0.0\n")
        findings = _run_security(tmp_path)
        assert "SEC-DEPS-001" not in _triggered_rules(findings)


# ============================================================
# SEC-AUTH-001 — No Auth Framework
# ============================================================

class TestAuthCheck:
    def test_no_auth_with_routes(self, tmp_path):
        _write(tmp_path, "app.py", (
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/users')\n"
            "def get_users(): return []\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-AUTH-001" in _triggered_rules(findings)

    def test_has_auth(self, tmp_path):
        _write(tmp_path, "app.py", (
            "from fastapi import FastAPI\n"
            "from fastapi.security import OAuth2PasswordBearer\n"
            "app = FastAPI()\n"
            "oauth2 = OAuth2PasswordBearer(tokenUrl='token')\n"
            "@app.get('/users')\n"
            "def get_users(): return []\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-AUTH-001" not in _triggered_rules(findings)

    def test_no_auth_no_routes(self, tmp_path):
        _write(tmp_path, "utils.py", "def helper(): return 42\n")
        source = LocalRepoSource(tmp_path)
        stack = StackInfo(languages={"python": 1.0})
        findings = SecurityAnalyzer().analyze(source, stack, [])
        assert "SEC-AUTH-001" not in _triggered_rules(findings)


# ============================================================
# SEC-HTTPS-001 — HTTP URLs
# ============================================================

class TestHttpUrls:
    def test_http_url_found(self, tmp_path):
        _write(tmp_path, "config.py", (
            "API_URL = 'http://api.production.com/v1'\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-HTTPS-001" in _triggered_rules(findings)

    def test_localhost_ok(self, tmp_path):
        _write(tmp_path, "config.py", (
            "API_URL = 'http://localhost:8000/api'\n"
            "ALT_URL = 'http://127.0.0.1:3000'\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-HTTPS-001" not in _triggered_rules(findings)

    def test_https_ok(self, tmp_path):
        _write(tmp_path, "config.py", (
            "API_URL = 'https://api.production.com/v1'\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-HTTPS-001" not in _triggered_rules(findings)


# ============================================================
# SEC-CORS-001 — Permissive CORS
# ============================================================

class TestCors:
    def test_cors_star(self, tmp_path):
        _write(tmp_path, "app.py", (
            "from fastapi.middleware.cors import CORSMiddleware\n"
            "app.add_middleware(CORSMiddleware, allow_origins=['*'])\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-CORS-001" in _triggered_rules(findings)

    def test_cors_restricted(self, tmp_path):
        _write(tmp_path, "app.py", (
            "from fastapi.middleware.cors import CORSMiddleware\n"
            "app.add_middleware(CORSMiddleware, allow_origins=['https://app.example.com'])\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-CORS-001" not in _triggered_rules(findings)


# ============================================================
# SEC-SQL-001 — SQL Injection
# ============================================================

class TestSqlInjection:
    def test_fstring_sql(self, tmp_path):
        _write(tmp_path, "db.py", (
            "def get_user(name):\n"
            "    cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-SQL-001" in _triggered_rules(findings)

    def test_concat_sql(self, tmp_path):
        _write(tmp_path, "db.py", (
            "def get_user(name):\n"
            "    query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"\n"
            "    cursor.execute(query)\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-SQL-001" in _triggered_rules(findings)

    def test_parameterized_ok(self, tmp_path):
        _write(tmp_path, "db.py", (
            "def get_user(name):\n"
            "    cursor.execute('SELECT * FROM users WHERE name = %s', (name,))\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-SQL-001" not in _triggered_rules(findings)


# ============================================================
# SEC-SECRETS-CODE-001 — Hardcoded Secrets
# ============================================================

class TestHardcodedSecrets:
    def test_api_key_in_code(self, tmp_path):
        _write(tmp_path, "config.py", (
            "API_KEY = 'sk-proj-abc123def456ghi789jkl'\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-SECRETS-CODE-001" in _triggered_rules(findings)

    def test_aws_key_in_code(self, tmp_path):
        _write(tmp_path, "config.py", (
            "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n"
            "AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-SECRETS-CODE-001" in _triggered_rules(findings)

    def test_env_var_ok(self, tmp_path):
        _write(tmp_path, "config.py", (
            "import os\n"
            "API_KEY = os.environ.get('API_KEY')\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-SECRETS-CODE-001" not in _triggered_rules(findings)

    def test_placeholder_ok(self, tmp_path):
        _write(tmp_path, "config.py", (
            "API_KEY = 'your_api_key_here_replace_with_real_key'\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-SECRETS-CODE-001" not in _triggered_rules(findings)

    def test_test_files_skipped(self, tmp_path):
        _write(tmp_path, "test_config.py", (
            "API_KEY = 'sk-test-abc123def456ghi789jkl'\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-SECRETS-CODE-001" not in _triggered_rules(findings)

    # --- Config file secrets ---

    def test_properties_password(self, tmp_path):
        """Spring-style .properties con password hardcodata."""
        _write(tmp_path, "src/main/resources/application-mysql.properties", (
            "spring.datasource.url=jdbc:mysql://localhost:3306/petclinic\n"
            "spring.datasource.username=petclinic\n"
            "spring.datasource.password=petclinic\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-SECRETS-CODE-001" in _triggered_rules(findings)

    def test_yaml_password(self, tmp_path):
        """YAML config con password hardcodata."""
        _write(tmp_path, "config/application.yml", (
            "spring:\n"
            "  datasource:\n"
            "    password: mySuperSecret123\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-SECRETS-CODE-001" in _triggered_rules(findings)

    def test_ini_secret(self, tmp_path):
        """INI config con secret_key hardcodata."""
        _write(tmp_path, "config.ini", (
            "[database]\n"
            "host = localhost\n"
            "secret_key = abc123def456ghi789jkl012\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-SECRETS-CODE-001" in _triggered_rules(findings)

    def test_properties_env_placeholder_ok(self, tmp_path):
        """Spring ${} placeholder NON deve generare finding."""
        _write(tmp_path, "application.properties", (
            "spring.datasource.password=${DB_PASSWORD}\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-SECRETS-CODE-001" not in _triggered_rules(findings)

    def test_yaml_env_placeholder_ok(self, tmp_path):
        """YAML con ${} placeholder NON deve generare finding."""
        _write(tmp_path, "application.yml", (
            "spring:\n"
            "  datasource:\n"
            "    password: ${MYSQL_PASSWORD}\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-SECRETS-CODE-001" not in _triggered_rules(findings)

    def test_properties_enc_placeholder_ok(self, tmp_path):
        """Jasypt ENC() placeholder NON deve generare finding."""
        _write(tmp_path, "application.properties", (
            "spring.datasource.password=ENC(dGhpcyBpcyBhbiBlbmNyeXB0ZWQ=)\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-SECRETS-CODE-001" not in _triggered_rules(findings)

    def test_properties_empty_password_ok(self, tmp_path):
        """Password vuota NON deve generare finding."""
        _write(tmp_path, "application.properties", (
            "spring.datasource.password=\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-SECRETS-CODE-001" not in _triggered_rules(findings)

    def test_config_test_file_skipped(self, tmp_path):
        """File config di test NON deve generare finding."""
        _write(tmp_path, "test-config.properties", (
            "spring.datasource.password=testpassword123\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-SECRETS-CODE-001" not in _triggered_rules(findings)

    def test_conf_api_key(self, tmp_path):
        """.conf file con api_key hardcodata."""
        _write(tmp_path, "myapp.conf", (
            "[api]\n"
            "api_key = sk-live-abc123def456ghi789jkl012\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-SECRETS-CODE-001" in _triggered_rules(findings)

    def test_toml_password(self, tmp_path):
        """.toml file con password hardcodata."""
        _write(tmp_path, "config.toml", (
            '[database]\n'
            'password = "realPassword123!"\n'
        ))
        findings = _run_security(tmp_path)
        assert "SEC-SECRETS-CODE-001" in _triggered_rules(findings)


# ============================================================
# SEC-HEADERS-001 — Security Headers
# ============================================================

class TestSecurityHeaders:
    def test_no_headers_with_web(self, tmp_path):
        _write(tmp_path, "app.py", (
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n"
            "@app.get('/')\ndef root(): return {'ok': True}\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-HEADERS-001" in _triggered_rules(findings)

    def test_helmet_present(self, tmp_path):
        _write(tmp_path, "app.js", (
            "const express = require('express');\n"
            "const helmet = require('helmet');\n"
            "const app = express();\n"
            "app.use(helmet());\n"
        ))
        source = LocalRepoSource(tmp_path)
        stack = StackInfo(languages={"javascript": 1.0}, frameworks=["Express"])
        findings = SecurityAnalyzer().analyze(source, stack, [])
        assert "SEC-HEADERS-001" not in _triggered_rules(findings)

    def test_no_web_no_check(self, tmp_path):
        _write(tmp_path, "utils.py", "def helper(): return 42\n")
        source = LocalRepoSource(tmp_path)
        stack = StackInfo(languages={"python": 1.0})
        findings = SecurityAnalyzer().analyze(source, stack, [])
        assert "SEC-HEADERS-001" not in _triggered_rules(findings)


# ============================================================
# SEC-CRYPTO-001 — Weak Crypto
# ============================================================

class TestWeakCrypto:
    def test_md5_usage(self, tmp_path):
        _write(tmp_path, "auth.py", (
            "import hashlib\n"
            "def hash_password(pwd):\n"
            "    return hashlib.md5(pwd.encode()).hexdigest()\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-CRYPTO-001" in _triggered_rules(findings)

    def test_sha256_ok(self, tmp_path):
        _write(tmp_path, "auth.py", (
            "import hashlib\n"
            "def hash_data(data):\n"
            "    return hashlib.sha256(data.encode()).hexdigest()\n"
        ))
        findings = _run_security(tmp_path)
        assert "SEC-CRYPTO-001" not in _triggered_rules(findings)


# ============================================================
# Integration: All checks together
# ============================================================

class TestSecurityIntegration:
    def test_insecure_repo(self, tmp_path):
        """Repo con tutti i problemi di sicurezza."""
        _write(tmp_path, "requirements.txt", "django==1.11.29\nflask==0.12\n")
        _write(tmp_path, "app.py", (
            "from flask import Flask\n"
            "from flask_cors import CORS\n"
            "app = Flask(__name__)\n"
            "CORS(app)\n"
            "SECRET_KEY = 'sk-prod-abc123def456ghi789jkl'\n"
            "API_URL = 'http://api.production.com/v1'\n"
            "@app.route('/users')\n"
            "def get_users(): return []\n"
        ))
        _write(tmp_path, "db.py", (
            "import hashlib\n"
            "def get_user(name):\n"
            "    cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n"
            "def hash_pwd(pwd):\n"
            "    return hashlib.md5(pwd.encode()).hexdigest()\n"
        ))

        findings = _run_security(tmp_path)
        rules = _triggered_rules(findings)

        assert "SEC-DEPS-001" in rules
        assert "SEC-SECRETS-CODE-001" in rules
        assert "SEC-HTTPS-001" in rules
        assert "SEC-SQL-001" in rules
        assert "SEC-CRYPTO-001" in rules

    def test_secure_repo(self, tmp_path):
        """Repo con best practices di sicurezza."""
        _write(tmp_path, "requirements.txt", "django==4.2.0\nflask==3.0.0\n")
        _write(tmp_path, "app.py", (
            "import os\n"
            "from flask import Flask\n"
            "from flask_login import LoginManager\n"
            "from flask_talisman import Talisman\n"
            "app = Flask(__name__)\n"
            "Talisman(app)\n"
            "login_manager = LoginManager(app)\n"
            "SECRET_KEY = os.environ.get('SECRET_KEY')\n"
            "@app.route('/users')\n"
            "def get_users(): return []\n"
        ))
        findings = _run_security(tmp_path)
        rules = _triggered_rules(findings)

        assert "SEC-DEPS-001" not in rules
        assert "SEC-SECRETS-CODE-001" not in rules
        assert "SEC-AUTH-001" not in rules
        assert "SEC-HEADERS-001" not in rules

    def test_all_findings_are_security_layer(self, tmp_path):
        _write(tmp_path, "config.py", "API_KEY = 'sk-prod-abc123def456ghi789jkl'\n")
        findings = _run_security(tmp_path)
        for f in findings:
            assert f.layer == Layer.SECURITY

    def test_finding_has_uuid_id(self, tmp_path):
        _write(tmp_path, "config.py", "API_KEY = 'sk-prod-abc123def456ghi789jkl'\n")
        findings = _run_security(tmp_path)
        for f in findings:
            assert len(f.id) == 8
