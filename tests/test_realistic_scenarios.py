"""
Test scenari realistici end-to-end — 7 repository simulate.

Ogni scenario simula un codebase reale con problematiche iniettate,
per verificare che il sistema CTO Audit funzioni su repo concrete.

Scenari:
1. ShopFast     — Startup e-commerce Python/React, Docker mal configurato
2. CorpManager  — Monolite enterprise Java, Jenkins legacy, no Docker
3. PayGo        — Microservizio Go moderno, quasi perfetto
4. DataDump     — Prototipo abbandonato, zero infrastruttura
5. CloudAPI     — Servizio produzione ben architettato, quasi 100/100
6. RustCrate    — Libreria/CLI Rust, zero infra, no Docker (non deployable)
7. RailsStore   — E-commerce Ruby on Rails, Docker presente, secrets

Security e Quality analyzer ora producono finding reali.
"""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from cto_audit.core.models import AuditResult, Severity
from cto_audit.core.orchestrator import AuditOrchestrator
from cto_audit.reporters.markdown import MarkdownReporter
from cto_audit.sources.local import LocalRepoSource


# ============================================================
# Helper
# ============================================================


def _run_audit(repo_path: Path) -> AuditResult:
    """Esegue un audit completo e restituisce il risultato."""
    source = LocalRepoSource(repo_path)
    orchestrator = AuditOrchestrator(
        source=source,
        target_path=repo_path,
        auto_approve=True,
        console=Console(file=StringIO()),
    )
    return orchestrator.run()


def _triggered_rules(result: AuditResult) -> set[str]:
    """Restituisce i rule_id triggerati (esclusi INFO)."""
    rules: set[str] = set()
    for ls in result.health_score.layer_scores.values():
        for f in ls.findings:
            if f.severity != Severity.INFO:
                rules.add(f.rule_id)
    return rules


def _write(base: Path, rel: str, content: str) -> None:
    """Crea un file con directory parents."""
    p = base / Path(rel)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _make_large_java_controller(min_lines: int = 600) -> str:
    """Genera un controller Java realistico con >500 LOC."""
    lines = [
        "package com.corp.controllers;",
        "",
        "import org.springframework.web.bind.annotation.*;",
        "import org.springframework.http.ResponseEntity;",
        "import com.corp.services.UserService;",
        "import com.corp.models.User;",
        "import java.util.List;",
        "import java.util.Map;",
        "",
        "@RestController",
        "@RequestMapping(\"/api/users\")",
        "public class UserController {",
        "",
        "    private final UserService userService;",
        "",
        "    public UserController(UserService userService) {",
        "        this.userService = userService;",
        "    }",
        "",
    ]
    i = 0
    while len(lines) < min_lines:
        lines.extend([
            f"    @GetMapping(\"/action{i}\")",
            f"    public ResponseEntity<Object> action{i}(",
            f"            @RequestParam(required = false) String q,",
            f"            @RequestParam(defaultValue = \"0\") int page) {{",
            f"        if (q != null && q.length() > 255) {{",
            f"            return ResponseEntity.badRequest().build();",
            f"        }}",
            f"        Object result = userService.process(q, page);",
            f"        return ResponseEntity.ok(result);",
            f"    }}",
            "",
        ])
        i += 1
    lines.append("}")
    return "\n".join(lines)


# ============================================================
# Scenario 1 — ShopFast (Startup E-commerce)
# Score atteso: ~58-72  (infra ~46, arch ~78, sec ~63, qual ~93)
# ============================================================


@pytest.fixture(scope="module")
def shopfast_repo(tmp_path_factory) -> Path:
    """Startup Python/FastAPI + React, Docker mal configurato, secrets committati."""
    base = tmp_path_factory.mktemp("shopfast")

    # CI/CD presente
    _write(base, ".github/workflows/ci.yml", (
        "name: CI\non: [push]\njobs:\n  test:\n"
        "    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: pip install -r requirements.txt\n"
        "      - run: pytest\n"
    ))

    # Dockerfile single-stage, root, no healthcheck
    _write(base, "Dockerfile", (
        "FROM python:3.11-slim\nWORKDIR /app\nCOPY . .\n"
        "RUN pip install --no-cache-dir -r requirements.txt\n"
        "EXPOSE 8000\n"
        'CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0"]\n'
    ))
    # NO .dockerignore

    # .env con secrets
    _write(base, ".env", (
        "DB_PASSWORD=supersecret123\n"
        "DB_HOST=db.prod.internal\n"
        "REDIS_URL=redis://cache:6379\n"
    ))

    # Dipendenze senza lockfile
    _write(base, "requirements.txt", "flask>=3.0\nsqlalchemy>=2.0\nuvicorn>=0.24\n")
    _write(base, "package.json", json.dumps({
        "name": "shopfast-frontend",
        "dependencies": {"react": "^18.2.0", "react-dom": "^18.2.0"},
    }))

    # Codice API
    _write(base, "src/api/__init__.py", "")
    _write(base, "src/api/main.py", (
        "from fastapi import FastAPI\n\n"
        "app = FastAPI(title='ShopFast API')\n\n"
        "@app.get('/')\ndef root():\n    return {'message': 'ShopFast'}\n\n"
        "@app.get('/products')\ndef list_products():\n"
        "    return [{'id': 1, 'name': 'Widget', 'price': 9.99}]\n\n"
        "@app.post('/orders')\ndef create_order(product_id: int):\n"
        "    return {'order_id': 42, 'status': 'created'}\n"
    ))
    _write(base, "src/api/routes.py", (
        "from fastapi import APIRouter\n\n"
        "API_KEY = 'sk-proj-abc123def456ghi789jkl'\n\n"
        "router = APIRouter()\n\n"
        "@router.get('/payments')\ndef list_payments():\n"
        "    return [{'id': 1, 'amount': 100}]\n"
    ))
    _write(base, "src/api/database.py", (
        "from sqlalchemy import create_engine, Column, Integer, String\n"
        "from sqlalchemy.orm import declarative_base, sessionmaker\n\n"
        "DATABASE_URL = 'postgresql://shopfast:password@db:5432/shopfast'\n"
        "engine = create_engine(DATABASE_URL)\n"
        "SessionLocal = sessionmaker(bind=engine)\n"
        "Base = declarative_base()\n\n"
        "class Product(Base):\n"
        "    __tablename__ = 'products'\n"
        "    id = Column(Integer, primary_key=True)\n"
        "    name = Column(String(100))\n"
    ))

    # Frontend
    _write(base, "src/frontend/App.jsx", (
        "import React from 'react';\n\n"
        "function App() {\n"
        "  return <div><h1>ShopFast</h1></div>;\n"
        "}\n\nexport default App;\n"
    ))

    # Config con secrets
    _write(base, "config/settings.py", (
        "SECRET_KEY = 'django-insecure-k8s9d7f6g5h4j3k2l1'\n"
        "DATABASE_URL = 'postgresql://admin:s3cret_p4ss@prod-db:5432/shopfast'\n"
        "REDIS_URL = 'redis://cache.internal:6379/0'\n"
    ))

    _write(base, "README.md", "# ShopFast\nE-commerce startup.\n")
    return base


@pytest.fixture(scope="module")
def shopfast(shopfast_repo) -> AuditResult:
    return _run_audit(shopfast_repo)


class TestShopFast:
    """Scenario 1: Startup e-commerce con Docker mal configurato."""

    def test_score_range(self, shopfast):
        score = shopfast.health_score.overall_score
        assert 50 <= score <= 75, f"ShopFast score {score} fuori range 50-75"

    def test_rules_must_trigger(self, shopfast):
        rules = _triggered_rules(shopfast)
        expected = {
            "INFRA-DOCKER-002", "INFRA-DOCKER-003", "INFRA-DOCKER-004",
            "INFRA-DOCKER-005", "INFRA-IAC-001", "INFRA-DEPS-001",
            "INFRA-CONFIG-001", "INFRA-CONFIG-002", "INFRA-MON-001",
            "ARCH-TEST-001", "ARCH-DB-001",
            "SEC-SECRETS-CODE-001", "SEC-AUTH-001",
        }
        missing = expected - rules
        assert not missing, f"Regole attese non triggerate: {missing}"

    def test_rules_must_not_trigger(self, shopfast):
        rules = _triggered_rules(shopfast)
        forbidden = {"INFRA-CICD-001", "INFRA-DOCKER-001", "ARCH-STRUCT-001"}
        unexpected = forbidden & rules
        assert not unexpected, f"Regole che non dovevano triggerare: {unexpected}"

    def test_evidence_chain(self, shopfast):
        for ls in shopfast.health_score.layer_scores.values():
            for ev in ls.evidence_chain:
                assert ev.finding_id, "finding_id mancante in evidence"
                assert ev.rule_id, "rule_id mancante in evidence"
                assert ev.penalty <= 0, f"Penalita' positiva: {ev.penalty}"

    def test_markdown_report(self, shopfast):
        md = MarkdownReporter().report(shopfast)
        assert "# CTO Audit Report" in md
        assert "Health Score" in md
        assert "INFRA-" in md
        assert "ARCH-" in md


# ============================================================
# Scenario 2 — CorpManager (Monolite Enterprise Java)
# Score atteso: ~63-80  (infra ~49, arch ~95, sec ~63, qual ~94)
# Nota: ARCH-COUPLING-001 non scatta perche' il parser import
#       supporta solo Python e JS/TS, non Java.
# ============================================================


@pytest.fixture(scope="module")
def corpmanager_repo(tmp_path_factory) -> Path:
    """Monolite Spring Boot, Jenkins, no Docker, file enormi."""
    base = tmp_path_factory.mktemp("corpmanager")

    # CI presente (Jenkins)
    _write(base, "Jenkinsfile", (
        "pipeline {\n  agent any\n  stages {\n"
        "    stage('Build') { steps { sh 'mvn clean package' } }\n"
        "    stage('Test') { steps { sh 'mvn test' } }\n"
        "  }\n}\n"
    ))

    # pom.xml con Spring Boot + Hibernate
    _write(base, "pom.xml", (
        '<?xml version="1.0"?>\n<project>\n'
        "  <groupId>com.corp</groupId>\n"
        "  <artifactId>corpmanager</artifactId>\n"
        "  <parent>\n"
        "    <artifactId>spring-boot-starter-parent</artifactId>\n"
        "  </parent>\n"
        "  <dependencies>\n"
        "    <dependency><artifactId>spring-boot-starter-web</artifactId></dependency>\n"
        "    <dependency><artifactId>hibernate-core</artifactId></dependency>\n"
        "    <dependency><artifactId>junit</artifactId><scope>test</scope></dependency>\n"
        "  </dependencies>\n</project>\n"
    ))

    # Application.java
    _write(base, "src/main/java/com/corp/Application.java", (
        "package com.corp;\n\n"
        "import org.springframework.boot.SpringApplication;\n"
        "import org.springframework.boot.autoconfigure.SpringBootApplication;\n\n"
        "@SpringBootApplication\npublic class Application {\n"
        "    public static void main(String[] args) {\n"
        "        SpringApplication.run(Application.class, args);\n"
        "    }\n}\n"
    ))

    # Controller enorme (>500 LOC)
    _write(base, "src/main/java/com/corp/controllers/UserController.java",
           _make_large_java_controller(620))

    # Services (con import circolari, ma non rilevabili su Java)
    _write(base, "src/main/java/com/corp/services/UserService.java", (
        "package com.corp.services;\n\n"
        "import com.corp.services.OrderService;\n\n"
        "public class UserService {\n"
        "    private OrderService orderService;\n"
        "    public Object process(String q, int page) { return null; }\n"
        "}\n"
    ))
    _write(base, "src/main/java/com/corp/services/OrderService.java", (
        "package com.corp.services;\n\n"
        "import com.corp.services.UserService;\n\n"
        "public class OrderService {\n"
        "    private UserService userService;\n"
        "}\n"
    ))

    # Model
    _write(base, "src/main/java/com/corp/models/User.java", (
        "package com.corp.models;\n\npublic class User {\n"
        "    private Long id;\n    private String name;\n"
        "    private String email;\n}\n"
    ))

    # Config con password hardcoded
    _write(base, "src/main/java/com/corp/config/DatabaseConfig.java", (
        "package com.corp.config;\n\npublic class DatabaseConfig {\n"
        '    private static final String DB_URL = "jdbc:postgresql://db:5432/corp";\n'
        '    private static final String DB_PASSWORD = "corp_secret_2024";\n'
        "}\n"
    ))

    # Test presente
    _write(base, "src/test/java/com/corp/ApplicationTest.java", (
        "package com.corp;\n\nimport org.junit.jupiter.api.Test;\n\n"
        "public class ApplicationTest {\n"
        "    @Test\n    public void contextLoads() {}\n}\n"
    ))

    _write(base, "README.md", "# CorpManager\nEnterprise monolith.\n")
    return base


@pytest.fixture(scope="module")
def corpmanager(corpmanager_repo) -> AuditResult:
    return _run_audit(corpmanager_repo)


class TestCorpManager:
    """Scenario 2: Monolite enterprise Java senza container."""

    def test_score_range(self, corpmanager):
        score = corpmanager.health_score.overall_score
        assert 58 <= score <= 82, f"CorpManager score {score} fuori range 58-82"

    def test_rules_must_trigger(self, corpmanager):
        rules = _triggered_rules(corpmanager)
        expected = {
            "INFRA-DOCKER-001", "INFRA-IAC-001", "INFRA-DEPS-001",
            "INFRA-CONFIG-002", "INFRA-MON-001",
            "ARCH-SCALE-001", "ARCH-DB-001",
            "SEC-SECRETS-CODE-001", "SEC-AUTH-001",
        }
        missing = expected - rules
        assert not missing, f"Regole attese non triggerate: {missing}"

    def test_rules_must_not_trigger(self, corpmanager):
        rules = _triggered_rules(corpmanager)
        forbidden = {"INFRA-CICD-001", "ARCH-TEST-001"}
        unexpected = forbidden & rules
        assert not unexpected, f"Regole che non dovevano triggerare: {unexpected}"

    def test_context_aware_docker(self, corpmanager):
        """CorpManager (Spring Boot web app) deve ricevere INFRA-DOCKER-001, non INFRA-DOCKER-INFO."""
        infra = corpmanager.health_score.layer_scores["infra"]
        docker_findings = [f for f in infra.findings if "DOCKER" in f.rule_id]
        docker_rule_ids = {f.rule_id for f in docker_findings}
        assert "INFRA-DOCKER-001" in docker_rule_ids, (
            f"CorpManager doveva ricevere INFRA-DOCKER-001, ha: {docker_rule_ids}"
        )

    def test_evidence_chain(self, corpmanager):
        for ls in corpmanager.health_score.layer_scores.values():
            for ev in ls.evidence_chain:
                assert ev.finding_id
                assert ev.rule_id
                assert ev.penalty <= 0

    def test_markdown_report(self, corpmanager):
        md = MarkdownReporter().report(corpmanager)
        assert "# CTO Audit Report" in md
        assert "INFRA-DOCKER-001" in md


# ============================================================
# Scenario 3 — PayGo (Microservizio Go Moderno)
# Score atteso: ~75-88  (infra ~76, arch ~100, sec ~63, qual ~96)
# ============================================================


@pytest.fixture(scope="module")
def paygo_repo(tmp_path_factory) -> Path:
    """Go/Gin, Docker multi-stage best practices, K8s, Terraform, ma secrets."""
    base = tmp_path_factory.mktemp("paygo")

    # CI/CD
    _write(base, ".github/workflows/ci.yml", (
        "name: CI\non: [push]\njobs:\n  test:\n"
        "    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: actions/setup-go@v5\n"
        "      - run: go test ./...\n"
    ))

    # Dockerfile ottimale
    _write(base, "Dockerfile", (
        "FROM golang:1.22-alpine AS builder\nWORKDIR /app\n"
        "COPY go.mod go.sum ./\nRUN go mod download\n"
        "COPY . .\nRUN CGO_ENABLED=0 go build -o /server ./cmd/server\n\n"
        "FROM alpine:3.19\nRUN adduser -D appuser\n"
        "COPY --from=builder /server /server\n"
        "USER appuser\nEXPOSE 8080\n"
        "HEALTHCHECK --interval=30s CMD wget -qO- http://localhost:8080/health || exit 1\n"
        'CMD ["/server"]\n'
    ))
    _write(base, ".dockerignore", ".git\n.env\n*.md\n")

    # K8s + Terraform
    _write(base, "k8s/deployment.yaml", (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n"
        "  name: paygo\nspec:\n  replicas: 3\n"
        "  template:\n    spec:\n      containers:\n"
        "        - name: paygo\n          image: paygo:latest\n"
    ))
    _write(base, "terraform/main.tf", (
        'resource "aws_ecs_service" "api" {\n'
        '  name    = "paygo"\n  desired_count = 2\n}\n'
    ))

    # Go mod + lockfile
    _write(base, "go.mod", (
        "module github.com/paygo/paygo\n\ngo 1.22\n\nrequire (\n"
        "    github.com/gin-gonic/gin v1.9.1\n"
        "    gorm.io/gorm v1.25.5\n)\n"
    ))
    _write(base, "go.sum", (
        "github.com/gin-gonic/gin v1.9.1\n"
        "gorm.io/gorm v1.25.5\n"
    ))

    # Codice Go
    _write(base, "cmd/server/main.go", (
        "package main\n\nimport (\n"
        '    "github.com/gin-gonic/gin"\n)\n\n'
        "func main() {\n    r := gin.Default()\n"
        '    r.GET("/health", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })\n'
        '    r.Run(":8080")\n}\n'
    ))
    _write(base, "internal/handlers/payment.go", (
        "package handlers\n\n"
        'import "github.com/gin-gonic/gin"\n\n'
        "func CreatePayment(c *gin.Context) {\n"
        '    c.JSON(201, gin.H{"id": "pay_123"})\n}\n'
    ))
    _write(base, "internal/models/transaction.go", (
        "package models\n\nimport \"gorm.io/gorm\"\n\n"
        "type Transaction struct {\n    gorm.Model\n"
        "    Amount float64\n    Status string\n}\n"
    ))

    # Config con secrets hardcoded
    _write(base, "internal/config/config.go", (
        "package config\n\nconst (\n"
        '    API_KEY    = "sk_FAKE_paygo_abc123def456"\n'
        '    SECRET_KEY = "whsec_paygo_secret_key_2024"\n'
        ")\n"
    ))

    # Migrazioni
    _write(base, "migrations/001_init.sql", (
        "CREATE TABLE transactions (\n"
        "    id SERIAL PRIMARY KEY,\n"
        "    amount DECIMAL(10,2) NOT NULL,\n"
        "    status VARCHAR(20) DEFAULT 'pending'\n);\n"
    ))

    # Test
    _write(base, "tests/payment_test.go", (
        "package tests\n\nimport \"testing\"\n\n"
        "func TestCreatePayment(t *testing.T) {\n"
        '    t.Log("payment created")\n}\n'
    ))

    # Monitoring
    _write(base, "prometheus.yml", (
        "global:\n  scrape_interval: 15s\n"
        "scrape_configs:\n  - job_name: 'paygo'\n"
        "    static_configs:\n      - targets: ['localhost:8080']\n"
    ))

    # .env con secrets
    _write(base, ".env", (
        "STRIPE_SECRET_KEY=sk_FAKE_xxxxxxxxxxxxxxxxxxxxx\n"
        "DATABASE_URL=postgresql://paygo:password@db:5432/paygo\n"
    ))

    return base


@pytest.fixture(scope="module")
def paygo(paygo_repo) -> AuditResult:
    return _run_audit(paygo_repo)


class TestPayGo:
    """Scenario 3: Microservizio Go moderno, quasi perfetto."""

    def test_score_range(self, paygo):
        score = paygo.health_score.overall_score
        assert 72 <= score <= 90, f"PayGo score {score} fuori range 72-90"

    def test_rules_must_trigger(self, paygo):
        rules = _triggered_rules(paygo)
        expected = {"INFRA-CONFIG-001", "INFRA-CONFIG-002", "SEC-SECRETS-CODE-001"}
        missing = expected - rules
        assert not missing, f"Regole attese non triggerate: {missing}"

    def test_rules_must_not_trigger(self, paygo):
        rules = _triggered_rules(paygo)
        forbidden = {
            "INFRA-CICD-001", "INFRA-DOCKER-001", "INFRA-DOCKER-002",
            "INFRA-DOCKER-003", "INFRA-DOCKER-004", "INFRA-DOCKER-005",
            "INFRA-IAC-001", "INFRA-DEPS-001", "INFRA-MON-001",
            "ARCH-TEST-001", "ARCH-DB-001",
        }
        unexpected = forbidden & rules
        assert not unexpected, f"Regole che non dovevano triggerare: {unexpected}"

    def test_evidence_chain(self, paygo):
        infra_ev = paygo.health_score.layer_scores["infra"].evidence_chain
        non_info = [e for e in infra_ev if e.penalty < 0]
        assert len(non_info) >= 2, "Servono almeno 2 evidenze con penalita'"

    def test_markdown_report(self, paygo):
        md = MarkdownReporter().report(paygo)
        assert "Health Score" in md
        assert "INFRA-CONFIG" in md


# ============================================================
# Scenario 4 — DataDump (Prototipo Abbandonato)
# Score atteso: ~42-60  (infra ~12, arch ~78, sec ~62, qual ~89)
# ============================================================


@pytest.fixture(scope="module")
def datadump_repo(tmp_path_factory) -> Path:
    """Script Python buttati nella root, zero infrastruttura, secrets ovunque."""
    base = tmp_path_factory.mktemp("datadump")

    _write(base, "scraper.py", (
        "import requests\nfrom bs4 import BeautifulSoup\n\n"
        "def scrape_products(url):\n"
        "    response = requests.get(url, timeout=30)\n"
        "    response.raise_for_status()\n"
        "    soup = BeautifulSoup(response.text, 'html.parser')\n"
        "    products = []\n"
        "    for item in soup.select('.product-card'):\n"
        "        name = item.select_one('.name').text.strip()\n"
        "        price = item.select_one('.price').text.strip()\n"
        "        products.append({'name': name, 'price': price})\n"
        "    return products\n\n"
        "def scrape_reviews(url):\n"
        "    response = requests.get(url, timeout=30)\n"
        "    soup = BeautifulSoup(response.text, 'html.parser')\n"
        "    return [r.text for r in soup.select('.review')]\n"
    ))
    _write(base, "analyzer.py", (
        "from scraper import scrape_products\n\n"
        "def analyze_prices(url):\n"
        "    products = scrape_products(url)\n"
        "    prices = [float(p['price'].replace('$', '')) for p in products]\n"
        "    return {'mean': sum(prices) / max(len(prices), 1), 'count': len(prices)}\n"
    ))
    _write(base, "db.py", (
        "import sqlite3\n\n"
        "DB_PASSWORD = 'admin_secret_2024'\n\n"
        "def get_connection():\n"
        "    return sqlite3.connect('data.db')\n\n"
        "def save_products(products):\n"
        "    conn = get_connection()\n"
        "    cursor = conn.cursor()\n"
        "    cursor.execute('CREATE TABLE IF NOT EXISTS products (name TEXT, price REAL)')\n"
        "    for p in products:\n"
        "        cursor.execute('INSERT INTO products VALUES (?, ?)', "
        "(p['name'], p['price']))\n"
        "    conn.commit()\n    conn.close()\n"
    ))
    _write(base, "config.py", (
        "API_KEY = 'sk-datadump-abc123def456ghi789jkl'\n"
        "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n"
        "AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"
        "DATABASE_URL = 'postgresql://admin:password123@prod-db:5432/datadump'\n"
    ))
    _write(base, "utils.py", (
        "import os\nimport json\n\n"
        "def load_config():\n"
        "    return {'debug': os.environ.get('DEBUG', 'false')}\n\n"
        "def save_json(data, filename):\n"
        "    with open(filename, 'w') as f:\n"
        "        json.dump(data, f, indent=2)\n"
    ))
    _write(base, "main.py", (
        "from scraper import scrape_products, scrape_reviews\n"
        "from analyzer import analyze_prices\n"
        "from db import save_products\n"
        "from config import API_KEY, DATABASE_URL\n"
        "from utils import save_json\n\n"
        "def main():\n"
        "    products = scrape_products('https://example.com/products')\n"
        "    save_products(products)\n"
        "    analysis = analyze_prices('https://example.com/products')\n"
        "    save_json(analysis, 'output.json')\n\n"
        "if __name__ == '__main__':\n    main()\n"
    ))
    _write(base, ".env", (
        "API_KEY=sk-datadump-secret-env-key\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "STRIPE_SECRET_KEY=sk_FAKE_datadump_xxx\n"
    ))
    _write(base, "requirements.txt", "requests>=2.31\nbeautifulsoup4>=4.12\n")
    _write(base, "credentials.json", json.dumps({
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "region": "eu-west-1",
    }, indent=2))
    _write(base, "id_rsa", (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA1234567890abcdef\n"
        "-----END RSA PRIVATE KEY-----\n"
    ))

    return base


@pytest.fixture(scope="module")
def datadump(datadump_repo) -> AuditResult:
    return _run_audit(datadump_repo)


class TestDataDump:
    """Scenario 4: Prototipo abbandonato senza infrastruttura."""

    def test_score_range(self, datadump):
        score = datadump.health_score.overall_score
        assert 42 <= score <= 68, f"DataDump score {score} fuori range 42-68"

    def test_rules_must_trigger(self, datadump):
        rules = _triggered_rules(datadump)
        expected = {
            "INFRA-CICD-001", "INFRA-IAC-001",
            "INFRA-DEPS-001", "INFRA-CONFIG-001", "INFRA-CONFIG-002",
            "INFRA-MON-001", "ARCH-STRUCT-001", "ARCH-TEST-001",
            "SEC-SECRETS-CODE-001",
        }
        missing = expected - rules
        assert not missing, f"Regole attese non triggerate: {missing}"

    def test_rules_must_not_trigger(self, datadump):
        rules = _triggered_rules(datadump)
        # Niente ORM → ARCH-DB-001 non deve triggerare
        assert "ARCH-DB-001" not in rules, "ARCH-DB-001 non doveva triggerare (no ORM)"
        # DataDump non è deployable → INFRA-DOCKER-001 non deve triggerare
        assert "INFRA-DOCKER-001" not in rules, (
            "INFRA-DOCKER-001 non doveva triggerare (progetto non deployable)"
        )

    def test_context_aware_docker(self, datadump):
        """DataDump (scraper/CLI) deve ricevere INFRA-DOCKER-INFO, non INFRA-DOCKER-001."""
        infra = datadump.health_score.layer_scores["infra"]
        docker_findings = [f for f in infra.findings if "DOCKER" in f.rule_id]
        docker_rule_ids = {f.rule_id for f in docker_findings}
        assert "INFRA-DOCKER-INFO" in docker_rule_ids, (
            f"DataDump doveva ricevere INFRA-DOCKER-INFO, ha: {docker_rule_ids}"
        )
        assert "INFRA-DOCKER-001" not in docker_rule_ids, (
            "DataDump non doveva ricevere INFRA-DOCKER-001 (non è deployable)"
        )

    def test_evidence_chain(self, datadump):
        infra = datadump.health_score.layer_scores["infra"]
        arch = datadump.health_score.layer_scores["architecture"]
        assert len(infra.evidence_chain) >= 5, "DataDump deve avere molte evidenze infra"
        assert len(arch.evidence_chain) >= 2, "DataDump deve avere evidenze arch"

    def test_markdown_report(self, datadump):
        md = MarkdownReporter().report(datadump)
        assert "# CTO Audit Report" in md
        assert "INFRA-CICD-001" in md
        assert "ARCH-STRUCT-001" in md

    def test_infra_score_very_low(self, datadump):
        infra_score = datadump.health_score.layer_scores["infra"].score
        assert infra_score < 45, f"Infra score {infra_score} troppo alto per DataDump"


# ============================================================
# Scenario 5 — CloudAPI (Servizio Produzione Ben Architettato)
# Score atteso: ~95-100  (tutti i layer ~100)
# Con auth (OAuth2), security headers, linter (ruff), typing (mypy).
# ============================================================


@pytest.fixture(scope="module")
def cloudapi_repo(tmp_path_factory) -> Path:
    """FastAPI Clean Architecture, Docker multi-stage, CI/CD, Terraform, test, monitoring."""
    base = tmp_path_factory.mktemp("cloudapi")

    # CI/CD completo
    _write(base, ".github/workflows/ci.yml", (
        "name: CI\non: [push, pull_request]\njobs:\n"
        "  lint:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: pip install ruff && ruff check .\n"
        "  test:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: pip install -e '.[dev]' && pytest\n"
    ))
    _write(base, ".github/workflows/deploy.yml", (
        "name: Deploy\non:\n  push:\n    branches: [main]\njobs:\n"
        "  deploy:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: echo 'deploying'\n"
    ))

    # Dockerfile con best practices
    _write(base, "Dockerfile", (
        "FROM python:3.12-slim AS builder\nWORKDIR /app\n"
        "COPY pyproject.toml poetry.lock ./\n"
        "RUN pip install poetry && poetry install --no-dev\n\n"
        "FROM python:3.12-slim\nRUN useradd -m appuser\n"
        "WORKDIR /app\nCOPY --from=builder /app /app\n"
        "COPY src/ ./src/\nUSER appuser\nEXPOSE 8000\n"
        "HEALTHCHECK --interval=30s CMD curl -f http://localhost:8000/health || exit 1\n"
        'CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0"]\n'
    ))
    _write(base, ".dockerignore", ".git\n__pycache__\n*.pyc\ntests/\n")
    _write(base, "docker-compose.yml", (
        "version: '3.8'\nservices:\n  api:\n    build: .\n"
        "    ports:\n      - '8000:8000'\n    environment:\n"
        "      - DB_URL=${DB_URL}\n"
        "  db:\n    image: postgres:16-alpine\n"
    ))

    # IaC
    _write(base, "terraform/main.tf", (
        'resource "aws_ecs_service" "api" {\n'
        '  name    = "cloudapi"\n  desired_count = 2\n}\n'
    ))

    # Dipendenze con lockfile + linter + typing
    _write(base, "pyproject.toml", (
        "[project]\nname = 'cloudapi'\nversion = '1.0.0'\n"
        "dependencies = [\n"
        "    'fastapi>=0.104',\n    'uvicorn>=0.24',\n"
        "    'sqlalchemy>=2.0',\n    'pydantic>=2.5',\n"
        "    'alembic>=1.13',\n]\n\n"
        "[project.optional-dependencies]\n"
        "dev = ['pytest>=8.0', 'httpx>=0.25']\n\n"
        "[tool.ruff]\nselect = ['E', 'F', 'W']\n\n"
        "[tool.mypy]\nstrict = true\n"
    ))
    _write(base, "poetry.lock", "# Generated by Poetry\n[[package]]\nname = 'fastapi'\n")

    # Codice Clean Architecture — con docstring (QUAL-DOC-002)
    _write(base, "src/domain/models.py", (
        '"""Domain models for CloudAPI."""\n\n'
        "from pydantic import BaseModel\n\n"
        "class User(BaseModel):\n"
        '    """User domain model."""\n'
        "    id: int\n    name: str\n    email: str\n\n"
        "class Product(BaseModel):\n"
        '    """Product domain model."""\n'
        "    id: int\n    name: str\n    price: float\n"
    ))
    _write(base, "src/application/services.py", (
        '"""Application services layer."""\n\n'
        "from src.domain.models import User, Product\n\n"
        "class UserService:\n"
        '    """Service for user operations."""\n\n'
        "    def get_user(self, user_id: int) -> User:\n"
        '        """Get user by ID."""\n'
        "        return User(id=user_id, name='John', email='j@example.com')\n\n"
        "class ProductService:\n"
        '    """Service for product operations."""\n\n'
        "    def list_products(self) -> list[Product]:\n"
        '        """List all products."""\n'
        "        return [Product(id=1, name='Widget', price=9.99)]\n"
    ))
    _write(base, "src/infrastructure/database.py", (
        '"""Database infrastructure setup."""\n\n'
        "import os\nfrom sqlalchemy import create_engine\n"
        "from sqlalchemy.orm import sessionmaker\n\n"
        "engine = create_engine(os.environ['DB_URL'])\n"
        "SessionLocal = sessionmaker(bind=engine)\n"
    ))
    _write(base, "src/api/routes.py", (
        "from fastapi import APIRouter, Depends\n"
        "from fastapi.security import OAuth2PasswordBearer\n\n"
        "router = APIRouter()\n"
        "oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')\n\n"
        "@router.get('/health')\ndef health():\n    return {'status': 'ok'}\n\n"
        "@router.get('/users/{user_id}')\ndef get_user(user_id: int, token: str = Depends(oauth2_scheme)):\n"
        "    return {'id': user_id, 'name': 'John'}\n"
    ))
    _write(base, "src/main.py", (
        "from fastapi import FastAPI\nfrom src.api.routes import router\n\n"
        "app = FastAPI(title='CloudAPI', version='1.0.0')\n"
        "app.include_router(router)\n"
        "# Security headers: content-security-policy configured via middleware\n"
    ))

    # Test
    _write(base, "tests/__init__.py", "")
    _write(base, "tests/test_services.py", (
        "from src.application.services import UserService\n\n"
        "def test_get_user():\n"
        "    service = UserService()\n"
        "    user = service.get_user(1)\n"
        "    assert user.name == 'John'\n"
    ))
    _write(base, "tests/test_routes.py", (
        "def test_health():\n    assert True\n\n"
        "def test_get_user():\n    assert True\n"
    ))

    # Migrazioni
    _write(base, "migrations/001_initial.py", (
        '"""Initial migration."""\n\n'
        "def upgrade():\n    pass\n\ndef downgrade():\n    pass\n"
    ))

    # Monitoring
    _write(base, "prometheus.yml", (
        "global:\n  scrape_interval: 15s\n"
        "scrape_configs:\n  - job_name: 'cloudapi'\n"
        "    static_configs:\n      - targets: ['localhost:8000']\n"
    ))

    _write(base, "README.md", "# CloudAPI\nProduction-ready API.\n")

    # Quality best practices
    _write(base, ".pre-commit-config.yaml", (
        "repos:\n  - repo: https://github.com/astral-sh/ruff-pre-commit\n"
        "    rev: v0.4.0\n    hooks:\n      - id: ruff\n"
    ))
    _write(base, ".editorconfig", (
        "root = true\n\n[*]\nindent_style = space\nindent_size = 4\n"
        "end_of_line = lf\ncharset = utf-8\ntrim_trailing_whitespace = true\n"
    ))
    _write(base, "CONTRIBUTING.md", (
        "# Contributing\n\n## Setup\n1. Clone repo\n2. pip install -e '.[dev]'\n"
    ))
    _write(base, "CHANGELOG.md", (
        "# Changelog\n\n## 1.0.0\n- Initial release\n"
    ))

    return base


@pytest.fixture(scope="module")
def cloudapi(cloudapi_repo) -> AuditResult:
    return _run_audit(cloudapi_repo)


class TestCloudAPI:
    """Scenario 5: Repo quasi perfetta, score ~100."""

    def test_score_range(self, cloudapi):
        score = cloudapi.health_score.overall_score
        assert 95 <= score <= 100, f"CloudAPI score {score} fuori range 95-100"

    def test_no_non_info_rules(self, cloudapi):
        rules = _triggered_rules(cloudapi)
        # CloudAPI con best practices complete: nessuna regola penalizzante
        assert not rules, f"CloudAPI non doveva triggerare regole: {rules}"

    def test_all_layers_high(self, cloudapi):
        for name, ls in cloudapi.health_score.layer_scores.items():
            assert ls.score >= 90, f"Layer {name} score {ls.score} troppo basso"

    def test_evidence_chain_clean(self, cloudapi):
        for ls in cloudapi.health_score.layer_scores.values():
            for ev in ls.evidence_chain:
                # Solo evidenze INFO (penalty effettiva 0)
                assert ev.penalty >= -0.01, (
                    f"CloudAPI ha penalita' non-zero: {ev.rule_id} = {ev.penalty}"
                )

    def test_markdown_report(self, cloudapi):
        md = MarkdownReporter().report(cloudapi)
        assert "# CTO Audit Report" in md
        assert "Health Score" in md
        # Non deve contenere regole di penalita'
        assert "INFRA-CICD-001" not in md
        assert "INFRA-DOCKER-001" not in md


# ============================================================
# Scenario 6 — RustCrate (Libreria/CLI Rust)
# Score atteso: ~55-72  (infra ~15, arch ~80, sec ~80, qual ~95)
# Nota: non deployable → INFRA-DOCKER-INFO non INFRA-DOCKER-001
# ============================================================


@pytest.fixture(scope="module")
def rustcrate_repo(tmp_path_factory) -> Path:
    """Libreria Rust con CLI, nessuna infra, test presenti, no secrets."""
    base = tmp_path_factory.mktemp("rustcrate")

    # Cargo.toml (con serde, clap, tokio — no web framework)
    _write(base, "Cargo.toml", (
        "[package]\nname = \"rustcrate\"\nversion = \"0.1.0\"\n"
        "edition = \"2021\"\n\n"
        "[dependencies]\nserde = { version = \"1.0\", features = [\"derive\"] }\n"
        "clap = { version = \"4.4\", features = [\"derive\"] }\n"
        "tokio = { version = \"1\", features = [\"full\"] }\n"
        "anyhow = \"1.0\"\n"
        "tracing = \"0.1\"\n\n"
        "[dev-dependencies]\nassert_cmd = \"2.0\"\nprediates = \"3.0\"\n"
    ))
    # Lockfile
    _write(base, "Cargo.lock", (
        "# This file is automatically generated by Cargo.\n"
        "[[package]]\nname = \"rustcrate\"\nversion = \"0.1.0\"\n"
    ))

    # Source code — CLI tool per analisi file
    _write(base, "src/main.rs", (
        "use clap::Parser;\nuse rustcrate::analyzer;\n\n"
        "#[derive(Parser, Debug)]\n"
        "#[command(name = \"rustcrate\", version, about = \"File analyzer CLI\")]\n"
        "struct Args {\n"
        "    /// Path to analyze\n"
        "    #[arg(short, long)]\n"
        "    path: String,\n\n"
        "    /// Output format\n"
        "    #[arg(short, long, default_value = \"text\")]\n"
        "    format: String,\n}\n\n"
        "#[tokio::main]\nasync fn main() -> anyhow::Result<()> {\n"
        "    let args = Args::parse();\n"
        "    let result = analyzer::analyze(&args.path).await?;\n"
        "    println!(\"{:?}\", result);\n"
        "    Ok(())\n}\n"
    ))
    _write(base, "src/lib.rs", (
        "pub mod analyzer;\npub mod models;\npub mod utils;\n"
    ))
    _write(base, "src/analyzer.rs", (
        "use crate::models::FileStats;\nuse std::path::Path;\n\n"
        "pub async fn analyze(path: &str) -> anyhow::Result<FileStats> {\n"
        "    let path = Path::new(path);\n"
        "    let mut stats = FileStats::default();\n"
        "    if path.is_dir() {\n"
        "        for entry in std::fs::read_dir(path)? {\n"
        "            let entry = entry?;\n"
        "            stats.file_count += 1;\n"
        "            stats.total_size += entry.metadata()?.len();\n"
        "        }\n"
        "    }\n"
        "    Ok(stats)\n}\n"
    ))
    _write(base, "src/models.rs", (
        "use serde::{Serialize, Deserialize};\n\n"
        "#[derive(Debug, Default, Serialize, Deserialize)]\n"
        "pub struct FileStats {\n"
        "    pub file_count: usize,\n"
        "    pub total_size: u64,\n"
        "    pub extensions: Vec<String>,\n}\n"
    ))
    _write(base, "src/utils.rs", (
        "use std::path::Path;\n\n"
        "pub fn is_hidden(path: &Path) -> bool {\n"
        "    path.file_name()\n"
        "        .and_then(|n| n.to_str())\n"
        "        .map(|s| s.starts_with('.'))\n"
        "        .unwrap_or(false)\n}\n"
    ))

    # Test presenti
    _write(base, "tests/integration_test.rs", (
        "use assert_cmd::Command;\n\n"
        "#[test]\nfn test_help() {\n"
        "    let mut cmd = Command::cargo_bin(\"rustcrate\").unwrap();\n"
        "    cmd.arg(\"--help\").assert().success();\n}\n\n"
        "#[test]\nfn test_version() {\n"
        "    let mut cmd = Command::cargo_bin(\"rustcrate\").unwrap();\n"
        "    cmd.arg(\"--version\").assert().success();\n}\n"
    ))

    _write(base, "README.md", "# RustCrate\nFile analyzer CLI written in Rust.\n")
    return base


@pytest.fixture(scope="module")
def rustcrate(rustcrate_repo) -> AuditResult:
    return _run_audit(rustcrate_repo)


class TestRustCrate:
    """Scenario 6: Libreria/CLI Rust senza infra."""

    def test_score_range(self, rustcrate):
        score = rustcrate.health_score.overall_score
        assert 85 <= score <= 98, f"RustCrate score {score} fuori range 85-98"

    def test_stack_detected(self, rustcrate):
        """Il detector deve riconoscere Rust e Serde."""
        assert "rust" in rustcrate.stack_info.languages
        assert rustcrate.stack_info.languages["rust"] > 0.5
        assert any("Serde" in fw for fw in rustcrate.stack_info.frameworks)

    def test_rules_must_trigger(self, rustcrate):
        rules = _triggered_rules(rustcrate)
        expected = {
            "INFRA-CICD-001", "INFRA-IAC-001",
            "INFRA-MON-001",
        }
        missing = expected - rules
        assert not missing, f"Regole attese non triggerate: {missing}"

    def test_context_aware_docker(self, rustcrate):
        """RustCrate (CLI tool) deve ricevere INFRA-DOCKER-INFO, non INFRA-DOCKER-001."""
        infra = rustcrate.health_score.layer_scores["infra"]
        docker_findings = [f for f in infra.findings if "DOCKER" in f.rule_id]
        docker_rule_ids = {f.rule_id for f in docker_findings}
        assert "INFRA-DOCKER-INFO" in docker_rule_ids, (
            f"RustCrate doveva ricevere INFRA-DOCKER-INFO, ha: {docker_rule_ids}"
        )
        assert "INFRA-DOCKER-001" not in docker_rule_ids, (
            "RustCrate non doveva ricevere INFRA-DOCKER-001 (CLI non deployable)"
        )

    def test_no_secret_findings(self, rustcrate):
        """Nessun secret nel codice Rust."""
        rules = _triggered_rules(rustcrate)
        assert "SEC-SECRETS-CODE-001" not in rules

    def test_test_present(self, rustcrate):
        """Test presenti → ARCH-TEST-001 non deve triggerare."""
        rules = _triggered_rules(rustcrate)
        assert "ARCH-TEST-001" not in rules

    def test_evidence_chain(self, rustcrate):
        for ls in rustcrate.health_score.layer_scores.values():
            for ev in ls.evidence_chain:
                assert ev.finding_id
                assert ev.rule_id
                assert ev.penalty <= 0


# ============================================================
# Scenario 7 — RailsStore (E-commerce Ruby on Rails)
# Score atteso: ~58-75  (infra ~60, arch ~80, sec ~50, qual ~85)
# ============================================================


@pytest.fixture(scope="module")
def railsstore_repo(tmp_path_factory) -> Path:
    """Ruby on Rails e-commerce, Docker presente, CI/CD, secrets in config."""
    base = tmp_path_factory.mktemp("railsstore")

    # CI/CD
    _write(base, ".github/workflows/ci.yml", (
        "name: CI\non: [push]\njobs:\n  test:\n"
        "    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: ruby/setup-ruby@v1\n"
        "        with:\n          ruby-version: '3.2'\n"
        "      - run: bundle install\n"
        "      - run: bundle exec rspec\n"
    ))

    # Dockerfile (single-stage, root user — non ottimale)
    _write(base, "Dockerfile", (
        "FROM ruby:3.2-slim\nWORKDIR /app\n"
        "COPY Gemfile Gemfile.lock ./\n"
        "RUN bundle install\nCOPY . .\n"
        "EXPOSE 3000\n"
        'CMD ["rails", "server", "-b", "0.0.0.0"]\n'
    ))
    _write(base, "docker-compose.yml", (
        "version: '3.8'\nservices:\n  web:\n    build: .\n"
        "    ports:\n      - '3000:3000'\n    depends_on:\n      - db\n"
        "  db:\n    image: postgres:16-alpine\n"
        "    environment:\n      POSTGRES_PASSWORD: password\n"
    ))

    # Gemfile + lockfile
    _write(base, "Gemfile", (
        "source 'https://rubygems.org'\n\n"
        "gem 'rails', '~> 7.1'\n"
        "gem 'pg', '~> 1.5'\n"
        "gem 'puma', '~> 6.4'\n"
        "gem 'devise', '~> 4.9'\n"
        "gem 'sidekiq', '~> 7.2'\n"
        "gem 'redis', '~> 5.0'\n\n"
        "group :development, :test do\n"
        "  gem 'rspec-rails', '~> 6.1'\n"
        "  gem 'factory_bot_rails'\n"
        "end\n"
    ))
    _write(base, "Gemfile.lock", (
        "GEM\n  remote: https://rubygems.org/\n  specs:\n"
        "    rails (7.1.2)\n    pg (1.5.4)\n"
        "    devise (4.9.3)\n    rspec-rails (6.1.0)\n\n"
        "PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails (~> 7.1)\n"
    ))

    # Config con secrets hardcoded
    _write(base, "config/database.yml", (
        "default: &default\n  adapter: postgresql\n  encoding: unicode\n"
        "  pool: 5\n\nproduction:\n  <<: *default\n"
        "  database: railsstore_prod\n"
        "  username: railsstore\n"
        "  password: db_secret_password_2024\n"
        "  host: db.production.internal\n"
    ))
    _write(base, "config/secrets.yml", (
        "production:\n"
        "  secret_key_base: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6\n"
    ))
    _write(base, "config/application.rb", (
        "require_relative 'boot'\n"
        "require 'rails/all'\n\n"
        "module RailsStore\n"
        "  class Application < Rails::Application\n"
        "    config.load_defaults 7.1\n"
        "    config.api_only = false\n"
        "  end\n"
        "end\n"
    ))
    # Initializer con API key hardcoded nel codice Ruby
    _write(base, "config/initializers/stripe.rb", (
        "Stripe.api_key = 'sk_FAKE_railsstore_abc123def456ghi789'\n"
        "SENDGRID_API_KEY = 'SG.xxxxxxxxxxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyy'\n"
    ))
    _write(base, "config/routes.rb", (
        "Rails.application.routes.draw do\n"
        "  root 'products#index'\n"
        "  resources :products\n"
        "  resources :orders\n"
        "  devise_for :users\n"
        "end\n"
    ))

    # Controllers
    _write(base, "app/controllers/application_controller.rb", (
        "class ApplicationController < ActionController::Base\n"
        "  before_action :authenticate_user!\n"
        "end\n"
    ))
    _write(base, "app/controllers/products_controller.rb", (
        "class ProductsController < ApplicationController\n"
        "  skip_before_action :authenticate_user!, only: [:index, :show]\n\n"
        "  def index\n"
        "    @products = Product.all\n"
        "  end\n\n"
        "  def show\n"
        "    @product = Product.find(params[:id])\n"
        "  end\n\n"
        "  def create\n"
        "    @product = Product.new(product_params)\n"
        "    if @product.save\n"
        "      redirect_to @product\n"
        "    else\n"
        "      render :new\n"
        "    end\n"
        "  end\n\n"
        "  private\n\n"
        "  def product_params\n"
        "    params.require(:product).permit(:name, :price, :description)\n"
        "  end\n"
        "end\n"
    ))
    _write(base, "app/controllers/orders_controller.rb", (
        "class OrdersController < ApplicationController\n"
        "  def index\n    @orders = current_user.orders\n  end\n\n"
        "  def create\n"
        "    @order = current_user.orders.build(order_params)\n"
        "    @order.save\n"
        "    redirect_to @order\n"
        "  end\n\n"
        "  private\n\n"
        "  def order_params\n"
        "    params.require(:order).permit(:product_id, :quantity)\n"
        "  end\n"
        "end\n"
    ))

    # Models
    _write(base, "app/models/product.rb", (
        "class Product < ApplicationRecord\n"
        "  has_many :order_items\n"
        "  validates :name, presence: true\n"
        "  validates :price, numericality: { greater_than: 0 }\n"
        "end\n"
    ))
    _write(base, "app/models/order.rb", (
        "class Order < ApplicationRecord\n"
        "  belongs_to :user\n"
        "  has_many :order_items\n"
        "  validates :status, inclusion: { in: %w[pending paid shipped] }\n"
        "end\n"
    ))
    _write(base, "app/models/user.rb", (
        "class User < ApplicationRecord\n"
        "  devise :database_authenticatable, :registerable,\n"
        "         :recoverable, :rememberable, :validatable\n"
        "  has_many :orders\n"
        "end\n"
    ))

    # DB Migrations
    _write(base, "db/migrate/001_create_products.rb", (
        "class CreateProducts < ActiveRecord::Migration[7.1]\n"
        "  def change\n"
        "    create_table :products do |t|\n"
        "      t.string :name, null: false\n"
        "      t.decimal :price, precision: 10, scale: 2\n"
        "      t.text :description\n"
        "      t.timestamps\n"
        "    end\n"
        "  end\n"
        "end\n"
    ))

    # Test presenti
    _write(base, "spec/models/product_spec.rb", (
        "require 'rails_helper'\n\n"
        "RSpec.describe Product, type: :model do\n"
        "  it 'validates name presence' do\n"
        "    product = Product.new(name: nil)\n"
        "    expect(product).not_to be_valid\n"
        "  end\n\n"
        "  it 'validates price positivity' do\n"
        "    product = Product.new(name: 'Widget', price: -1)\n"
        "    expect(product).not_to be_valid\n"
        "  end\n"
        "end\n"
    ))
    _write(base, "spec/controllers/products_controller_spec.rb", (
        "require 'rails_helper'\n\n"
        "RSpec.describe ProductsController, type: :controller do\n"
        "  describe 'GET #index' do\n"
        "    it 'returns success' do\n"
        "      get :index\n"
        "      expect(response).to have_http_status(:success)\n"
        "    end\n"
        "  end\n"
        "end\n"
    ))

    # .env con secrets
    _write(base, ".env", (
        "RAILS_MASTER_KEY=abc123def456ghi789jkl012mno345pq\n"
        "DATABASE_URL=postgresql://railsstore:password@db:5432/railsstore\n"
        "REDIS_URL=redis://cache:6379/0\n"
        "STRIPE_SECRET_KEY=sk_FAKE_rails_xxxxxxxxxxxx\n"
    ))

    _write(base, "README.md", "# RailsStore\nE-commerce built with Ruby on Rails.\n")
    return base


@pytest.fixture(scope="module")
def railsstore(railsstore_repo) -> AuditResult:
    return _run_audit(railsstore_repo)


class TestRailsStore:
    """Scenario 7: E-commerce Ruby on Rails con Docker e secrets."""

    def test_score_range(self, railsstore):
        score = railsstore.health_score.overall_score
        assert 60 <= score <= 88, f"RailsStore score {score} fuori range 60-88"

    def test_stack_detected(self, railsstore):
        """Il detector deve riconoscere Ruby e Rails."""
        assert "ruby" in railsstore.stack_info.languages
        assert any("Rails" in fw for fw in railsstore.stack_info.frameworks)

    def test_rules_must_trigger(self, railsstore):
        rules = _triggered_rules(railsstore)
        expected = {
            "INFRA-DOCKER-002",    # Single-stage Docker
            "INFRA-DOCKER-004",    # Root user
            "INFRA-DOCKER-005",    # No healthcheck
            "INFRA-IAC-001",       # No IaC
            "INFRA-CONFIG-001",    # .env presente
            "INFRA-CONFIG-002",    # No .env.example
            "INFRA-MON-001",       # No monitoring
            "SEC-SECRETS-CODE-001",  # Secrets in config files
        }
        missing = expected - rules
        assert not missing, f"Regole attese non triggerate: {missing}"

    def test_rules_must_not_trigger(self, railsstore):
        rules = _triggered_rules(railsstore)
        forbidden = {
            "INFRA-CICD-001",   # CI presente
            "INFRA-DOCKER-001", # Docker presente
            "INFRA-DEPS-001",   # Lockfile presente (Gemfile.lock)
            "ARCH-TEST-001",    # Test presenti (spec/)
        }
        unexpected = forbidden & rules
        assert not unexpected, f"Regole che non dovevano triggerare: {unexpected}"

    def test_docker_penalized(self, railsstore):
        """Docker presente ma mal configurato — DOCKER-001 non deve scattare."""
        infra = railsstore.health_score.layer_scores["infra"]
        docker_rules = {f.rule_id for f in infra.findings if "DOCKER" in f.rule_id}
        assert "INFRA-DOCKER-001" not in docker_rules

    def test_secrets_detected(self, railsstore):
        """Secrets in config/database.yml e .env devono essere rilevati."""
        rules = _triggered_rules(railsstore)
        assert "SEC-SECRETS-CODE-001" in rules

    def test_evidence_chain(self, railsstore):
        for ls in railsstore.health_score.layer_scores.values():
            for ev in ls.evidence_chain:
                assert ev.finding_id
                assert ev.rule_id
                assert ev.penalty <= 0

    def test_markdown_report(self, railsstore):
        md = MarkdownReporter().report(railsstore)
        assert "# CTO Audit Report" in md
        assert "Ruby" in md


# ============================================================
# Test Comparativi — Ranking tra scenari
# ============================================================


class TestComparativo:
    """Verifica il ranking relativo degli score tra scenari."""

    def test_cloudapi_gt_paygo(self, cloudapi, paygo):
        assert cloudapi.health_score.overall_score > paygo.health_score.overall_score

    def test_paygo_gt_shopfast(self, paygo, shopfast):
        assert paygo.health_score.overall_score > shopfast.health_score.overall_score

    def test_shopfast_gt_datadump(self, shopfast, datadump):
        assert shopfast.health_score.overall_score > datadump.health_score.overall_score

    def test_corpmanager_gt_datadump(self, corpmanager, datadump):
        assert corpmanager.health_score.overall_score > datadump.health_score.overall_score

    def test_rustcrate_gt_datadump(self, rustcrate, datadump):
        """RustCrate (libreria con test) > DataDump (prototipo zero infra)."""
        assert rustcrate.health_score.overall_score > datadump.health_score.overall_score

    def test_railsstore_gt_datadump(self, railsstore, datadump):
        """RailsStore (Rails con Docker/CI) > DataDump."""
        assert railsstore.health_score.overall_score > datadump.health_score.overall_score

    def test_full_ranking_top5(self, cloudapi, paygo, corpmanager, shopfast, datadump):
        """CloudAPI > PayGo > CorpManager > ShopFast > DataDump."""
        scores = {
            "CloudAPI": cloudapi.health_score.overall_score,
            "PayGo": paygo.health_score.overall_score,
            "CorpManager": corpmanager.health_score.overall_score,
            "ShopFast": shopfast.health_score.overall_score,
            "DataDump": datadump.health_score.overall_score,
        }
        ranked = sorted(scores.items(), key=lambda x: -x[1])
        order = [name for name, _ in ranked]
        assert order == ["CloudAPI", "PayGo", "CorpManager", "ShopFast", "DataDump"], (
            f"Ranking inatteso: {order} (scores: {scores})"
        )
