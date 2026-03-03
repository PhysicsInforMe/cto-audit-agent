"""
Genera i report Markdown per tutti e 5 gli scenari realistici.

Crea la cartella reports/ con:
- Un report CTO Audit per ogni scenario
- Un riepilogo comparativo finale
"""

from __future__ import annotations

import json
import sys
import tempfile
from io import StringIO
from pathlib import Path

from rich.console import Console

# Assicura che src/ sia nel path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from cto_audit.core.models import AuditResult, Severity
from cto_audit.core.orchestrator import AuditOrchestrator
from cto_audit.reporters.markdown import MarkdownReporter
from cto_audit.sources.local import LocalRepoSource


# ============================================================
# Helper
# ============================================================

def _run_audit(repo_path: Path) -> AuditResult:
    source = LocalRepoSource(repo_path)
    orchestrator = AuditOrchestrator(
        source=source,
        target_path=repo_path,
        auto_approve=True,
        console=Console(file=StringIO()),
    )
    return orchestrator.run()


def _write(base: Path, rel: str, content: str) -> None:
    p = base / Path(rel)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _triggered_rules(result: AuditResult) -> set[str]:
    rules: set[str] = set()
    for ls in result.health_score.layer_scores.values():
        for f in ls.findings:
            if f.severity != Severity.INFO:
                rules.add(f.rule_id)
    return rules


def _make_large_java_controller(min_lines: int = 600) -> str:
    lines = [
        "package com.corp.controllers;", "",
        "import org.springframework.web.bind.annotation.*;",
        "import org.springframework.http.ResponseEntity;",
        "import com.corp.services.UserService;",
        "import com.corp.models.User;",
        "import java.util.List;", "import java.util.Map;", "",
        "@RestController", "@RequestMapping(\"/api/users\")",
        "public class UserController {", "",
        "    private final UserService userService;", "",
        "    public UserController(UserService userService) {",
        "        this.userService = userService;", "    }", "",
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
            f"    }}", "",
        ])
        i += 1
    lines.append("}")
    return "\n".join(lines)


# ============================================================
# Costruzione Scenari
# ============================================================

def build_shopfast(base: Path) -> Path:
    _write(base, ".github/workflows/ci.yml",
           "name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
           "    steps:\n      - uses: actions/checkout@v4\n"
           "      - run: pip install -r requirements.txt\n      - run: pytest\n")
    _write(base, "Dockerfile",
           "FROM python:3.11-slim\nWORKDIR /app\nCOPY . .\n"
           "RUN pip install --no-cache-dir -r requirements.txt\nEXPOSE 8000\n"
           'CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0"]\n')
    _write(base, ".env",
           "DB_PASSWORD=supersecret123\nDB_HOST=db.prod.internal\n"
           "REDIS_URL=redis://cache:6379\n")
    _write(base, "requirements.txt", "flask>=3.0\nsqlalchemy>=2.0\nuvicorn>=0.24\n")
    _write(base, "package.json", json.dumps({
        "name": "shopfast-frontend",
        "dependencies": {"react": "^18.2.0", "react-dom": "^18.2.0"},
    }))
    _write(base, "src/api/__init__.py", "")
    _write(base, "src/api/main.py",
           "from fastapi import FastAPI\n\napp = FastAPI(title='ShopFast API')\n\n"
           "@app.get('/')\ndef root():\n    return {'message': 'ShopFast'}\n\n"
           "@app.get('/products')\ndef list_products():\n"
           "    return [{'id': 1, 'name': 'Widget', 'price': 9.99}]\n\n"
           "@app.post('/orders')\ndef create_order(product_id: int):\n"
           "    return {'order_id': 42, 'status': 'created'}\n")
    _write(base, "src/api/routes.py",
           "from fastapi import APIRouter\n\n"
           "API_KEY = 'sk-proj-abc123def456ghi789jkl'\n\nrouter = APIRouter()\n\n"
           "@router.get('/payments')\ndef list_payments():\n"
           "    return [{'id': 1, 'amount': 100}]\n")
    _write(base, "src/api/database.py",
           "from sqlalchemy import create_engine, Column, Integer, String\n"
           "from sqlalchemy.orm import declarative_base, sessionmaker\n\n"
           "DATABASE_URL = 'postgresql://shopfast:password@db:5432/shopfast'\n"
           "engine = create_engine(DATABASE_URL)\nSessionLocal = sessionmaker(bind=engine)\n"
           "Base = declarative_base()\n\nclass Product(Base):\n"
           "    __tablename__ = 'products'\n    id = Column(Integer, primary_key=True)\n"
           "    name = Column(String(100))\n")
    _write(base, "src/frontend/App.jsx",
           "import React from 'react';\n\nfunction App() {\n"
           "  return <div><h1>ShopFast</h1></div>;\n}\n\nexport default App;\n")
    _write(base, "config/settings.py",
           "SECRET_KEY = 'django-insecure-k8s9d7f6g5h4j3k2l1'\n"
           "DATABASE_URL = 'postgresql://admin:s3cret_p4ss@prod-db:5432/shopfast'\n"
           "REDIS_URL = 'redis://cache.internal:6379/0'\n")
    _write(base, "README.md", "# ShopFast\nE-commerce startup.\n")
    return base


def build_corpmanager(base: Path) -> Path:
    _write(base, "Jenkinsfile",
           "pipeline {\n  agent any\n  stages {\n"
           "    stage('Build') { steps { sh 'mvn clean package' } }\n"
           "    stage('Test') { steps { sh 'mvn test' } }\n  }\n}\n")
    _write(base, "pom.xml",
           '<?xml version="1.0"?>\n<project>\n  <groupId>com.corp</groupId>\n'
           "  <artifactId>corpmanager</artifactId>\n  <parent>\n"
           "    <artifactId>spring-boot-starter-parent</artifactId>\n  </parent>\n"
           "  <dependencies>\n"
           "    <dependency><artifactId>spring-boot-starter-web</artifactId></dependency>\n"
           "    <dependency><artifactId>hibernate-core</artifactId></dependency>\n"
           "    <dependency><artifactId>junit</artifactId><scope>test</scope></dependency>\n"
           "  </dependencies>\n</project>\n")
    _write(base, "src/main/java/com/corp/Application.java",
           "package com.corp;\n\nimport org.springframework.boot.SpringApplication;\n"
           "import org.springframework.boot.autoconfigure.SpringBootApplication;\n\n"
           "@SpringBootApplication\npublic class Application {\n"
           "    public static void main(String[] args) {\n"
           "        SpringApplication.run(Application.class, args);\n    }\n}\n")
    _write(base, "src/main/java/com/corp/controllers/UserController.java",
           _make_large_java_controller(620))
    _write(base, "src/main/java/com/corp/services/UserService.java",
           "package com.corp.services;\n\nimport com.corp.services.OrderService;\n\n"
           "public class UserService {\n    private OrderService orderService;\n"
           "    public Object process(String q, int page) { return null; }\n}\n")
    _write(base, "src/main/java/com/corp/services/OrderService.java",
           "package com.corp.services;\n\nimport com.corp.services.UserService;\n\n"
           "public class OrderService {\n    private UserService userService;\n}\n")
    _write(base, "src/main/java/com/corp/models/User.java",
           "package com.corp.models;\n\npublic class User {\n"
           "    private Long id;\n    private String name;\n    private String email;\n}\n")
    _write(base, "src/main/java/com/corp/config/DatabaseConfig.java",
           "package com.corp.config;\n\npublic class DatabaseConfig {\n"
           '    private static final String DB_URL = "jdbc:postgresql://db:5432/corp";\n'
           '    private static final String DB_PASSWORD = "corp_secret_2024";\n}\n')
    _write(base, "src/test/java/com/corp/ApplicationTest.java",
           "package com.corp;\n\nimport org.junit.jupiter.api.Test;\n\n"
           "public class ApplicationTest {\n    @Test\n    public void contextLoads() {}\n}\n")
    _write(base, "README.md", "# CorpManager\nEnterprise monolith.\n")
    return base


def build_paygo(base: Path) -> Path:
    _write(base, ".github/workflows/ci.yml",
           "name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
           "    steps:\n      - uses: actions/checkout@v4\n"
           "      - uses: actions/setup-go@v5\n      - run: go test ./...\n")
    _write(base, "Dockerfile",
           "FROM golang:1.22-alpine AS builder\nWORKDIR /app\n"
           "COPY go.mod go.sum ./\nRUN go mod download\nCOPY . .\n"
           "RUN CGO_ENABLED=0 go build -o /server ./cmd/server\n\n"
           "FROM alpine:3.19\nRUN adduser -D appuser\n"
           "COPY --from=builder /server /server\nUSER appuser\nEXPOSE 8080\n"
           "HEALTHCHECK --interval=30s CMD wget -qO- http://localhost:8080/health || exit 1\n"
           'CMD ["/server"]\n')
    _write(base, ".dockerignore", ".git\n.env\n*.md\n")
    _write(base, "k8s/deployment.yaml",
           "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: paygo\n"
           "spec:\n  replicas: 3\n  template:\n    spec:\n      containers:\n"
           "        - name: paygo\n          image: paygo:latest\n")
    _write(base, "terraform/main.tf",
           'resource "aws_ecs_service" "api" {\n  name    = "paygo"\n  desired_count = 2\n}\n')
    _write(base, "go.mod",
           "module github.com/paygo/paygo\n\ngo 1.22\n\nrequire (\n"
           "    github.com/gin-gonic/gin v1.9.1\n    gorm.io/gorm v1.25.5\n)\n")
    _write(base, "go.sum",
           "github.com/gin-gonic/gin v1.9.1\ngorm.io/gorm v1.25.5\n")
    _write(base, "cmd/server/main.go",
           "package main\n\nimport (\n    \"github.com/gin-gonic/gin\"\n)\n\n"
           "func main() {\n    r := gin.Default()\n"
           '    r.GET("/health", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })\n'
           '    r.Run(":8080")\n}\n')
    _write(base, "internal/handlers/payment.go",
           "package handlers\n\nimport \"github.com/gin-gonic/gin\"\n\n"
           "func CreatePayment(c *gin.Context) {\n"
           '    c.JSON(201, gin.H{"id": "pay_123"})\n}\n')
    _write(base, "internal/models/transaction.go",
           "package models\n\nimport \"gorm.io/gorm\"\n\n"
           "type Transaction struct {\n    gorm.Model\n"
           "    Amount float64\n    Status string\n}\n")
    _write(base, "internal/config/config.go",
           "package config\n\nconst (\n"
           '    API_KEY    = "sk_FAKE_paygo_abc123def456"\n'
           '    SECRET_KEY = "whsec_paygo_secret_key_2024"\n)\n')
    _write(base, "migrations/001_init.sql",
           "CREATE TABLE transactions (\n    id SERIAL PRIMARY KEY,\n"
           "    amount DECIMAL(10,2) NOT NULL,\n"
           "    status VARCHAR(20) DEFAULT 'pending'\n);\n")
    _write(base, "tests/payment_test.go",
           "package tests\n\nimport \"testing\"\n\n"
           "func TestCreatePayment(t *testing.T) {\n"
           '    t.Log("payment created")\n}\n')
    _write(base, "prometheus.yml",
           "global:\n  scrape_interval: 15s\nscrape_configs:\n"
           "  - job_name: 'paygo'\n    static_configs:\n"
           "      - targets: ['localhost:8080']\n")
    _write(base, ".env",
           "STRIPE_SECRET_KEY=sk_FAKE_xxxxxxxxxxxxxxxxxxxxx\n"
           "DATABASE_URL=postgresql://paygo:password@db:5432/paygo\n")
    return base


def build_datadump(base: Path) -> Path:
    _write(base, "scraper.py",
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
           "    return [r.text for r in soup.select('.review')]\n")
    _write(base, "analyzer.py",
           "from scraper import scrape_products\n\n"
           "def analyze_prices(url):\n    products = scrape_products(url)\n"
           "    prices = [float(p['price'].replace('$', '')) for p in products]\n"
           "    return {'mean': sum(prices) / max(len(prices), 1), 'count': len(prices)}\n")
    _write(base, "db.py",
           "import sqlite3\n\nDB_PASSWORD = 'admin_secret_2024'\n\n"
           "def get_connection():\n    return sqlite3.connect('data.db')\n\n"
           "def save_products(products):\n    conn = get_connection()\n"
           "    cursor = conn.cursor()\n"
           "    cursor.execute('CREATE TABLE IF NOT EXISTS products (name TEXT, price REAL)')\n"
           "    for p in products:\n"
           "        cursor.execute('INSERT INTO products VALUES (?, ?)', "
           "(p['name'], p['price']))\n"
           "    conn.commit()\n    conn.close()\n")
    _write(base, "config.py",
           "API_KEY = 'sk-datadump-abc123def456ghi789jkl'\n"
           "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n"
           "AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"
           "DATABASE_URL = 'postgresql://admin:password123@prod-db:5432/datadump'\n")
    _write(base, "utils.py",
           "import os\nimport json\n\ndef load_config():\n"
           "    return {'debug': os.environ.get('DEBUG', 'false')}\n\n"
           "def save_json(data, filename):\n    with open(filename, 'w') as f:\n"
           "        json.dump(data, f, indent=2)\n")
    _write(base, "main.py",
           "from scraper import scrape_products, scrape_reviews\n"
           "from analyzer import analyze_prices\nfrom db import save_products\n"
           "from config import API_KEY, DATABASE_URL\nfrom utils import save_json\n\n"
           "def main():\n"
           "    products = scrape_products('https://example.com/products')\n"
           "    save_products(products)\n"
           "    analysis = analyze_prices('https://example.com/products')\n"
           "    save_json(analysis, 'output.json')\n\n"
           "if __name__ == '__main__':\n    main()\n")
    _write(base, ".env",
           "API_KEY=sk-datadump-secret-env-key\n"
           "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
           "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
           "STRIPE_SECRET_KEY=sk_FAKE_datadump_xxx\n")
    _write(base, "requirements.txt", "requests>=2.31\nbeautifulsoup4>=4.12\n")
    _write(base, "credentials.json", json.dumps({
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "region": "eu-west-1",
    }, indent=2))
    _write(base, "id_rsa",
           "-----BEGIN RSA PRIVATE KEY-----\n"
           "MIIEowIBAAKCAQEA1234567890abcdef\n"
           "-----END RSA PRIVATE KEY-----\n")
    return base


def build_cloudapi(base: Path) -> Path:
    _write(base, ".github/workflows/ci.yml",
           "name: CI\non: [push, pull_request]\njobs:\n"
           "  lint:\n    runs-on: ubuntu-latest\n    steps:\n"
           "      - uses: actions/checkout@v4\n"
           "      - run: pip install ruff && ruff check .\n"
           "  test:\n    runs-on: ubuntu-latest\n    steps:\n"
           "      - uses: actions/checkout@v4\n"
           "      - run: pip install -e '.[dev]' && pytest\n")
    _write(base, ".github/workflows/deploy.yml",
           "name: Deploy\non:\n  push:\n    branches: [main]\njobs:\n"
           "  deploy:\n    runs-on: ubuntu-latest\n    steps:\n"
           "      - uses: actions/checkout@v4\n      - run: echo 'deploying'\n")
    _write(base, "Dockerfile",
           "FROM python:3.12-slim AS builder\nWORKDIR /app\n"
           "COPY pyproject.toml poetry.lock ./\n"
           "RUN pip install poetry && poetry install --no-dev\n\n"
           "FROM python:3.12-slim\nRUN useradd -m appuser\nWORKDIR /app\n"
           "COPY --from=builder /app /app\nCOPY src/ ./src/\nUSER appuser\nEXPOSE 8000\n"
           "HEALTHCHECK --interval=30s CMD curl -f http://localhost:8000/health || exit 1\n"
           'CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0"]\n')
    _write(base, ".dockerignore", ".git\n__pycache__\n*.pyc\ntests/\n")
    _write(base, "docker-compose.yml",
           "version: '3.8'\nservices:\n  api:\n    build: .\n"
           "    ports:\n      - '8000:8000'\n    environment:\n"
           "      - DB_URL=${DB_URL}\n  db:\n    image: postgres:16-alpine\n")
    _write(base, "terraform/main.tf",
           'resource "aws_ecs_service" "api" {\n  name    = "cloudapi"\n  desired_count = 2\n}\n')
    _write(base, "pyproject.toml",
           "[project]\nname = 'cloudapi'\nversion = '1.0.0'\n"
           "dependencies = [\n    'fastapi>=0.104',\n    'uvicorn>=0.24',\n"
           "    'sqlalchemy>=2.0',\n    'pydantic>=2.5',\n    'alembic>=1.13',\n]\n\n"
           "[project.optional-dependencies]\ndev = ['pytest>=8.0', 'httpx>=0.25']\n")
    _write(base, "poetry.lock", "# Generated by Poetry\n[[package]]\nname = 'fastapi'\n")
    _write(base, "src/domain/models.py",
           "from pydantic import BaseModel\n\n"
           "class User(BaseModel):\n    id: int\n    name: str\n    email: str\n\n"
           "class Product(BaseModel):\n    id: int\n    name: str\n    price: float\n")
    _write(base, "src/application/services.py",
           "from src.domain.models import User, Product\n\n"
           "class UserService:\n    def get_user(self, user_id: int) -> User:\n"
           "        return User(id=user_id, name='John', email='j@example.com')\n\n"
           "class ProductService:\n    def list_products(self) -> list[Product]:\n"
           "        return [Product(id=1, name='Widget', price=9.99)]\n")
    _write(base, "src/infrastructure/database.py",
           "import os\nfrom sqlalchemy import create_engine\n"
           "from sqlalchemy.orm import sessionmaker\n\n"
           "engine = create_engine(os.environ['DB_URL'])\n"
           "SessionLocal = sessionmaker(bind=engine)\n")
    _write(base, "src/api/routes.py",
           "from fastapi import APIRouter\n\nrouter = APIRouter()\n\n"
           "@router.get('/health')\ndef health():\n    return {'status': 'ok'}\n\n"
           "@router.get('/users/{user_id}')\ndef get_user(user_id: int):\n"
           "    return {'id': user_id, 'name': 'John'}\n")
    _write(base, "src/main.py",
           "from fastapi import FastAPI\nfrom src.api.routes import router\n\n"
           "app = FastAPI(title='CloudAPI', version='1.0.0')\n"
           "app.include_router(router)\n")
    _write(base, "tests/__init__.py", "")
    _write(base, "tests/test_services.py",
           "from src.application.services import UserService\n\n"
           "def test_get_user():\n    service = UserService()\n"
           "    user = service.get_user(1)\n    assert user.name == 'John'\n")
    _write(base, "tests/test_routes.py",
           "def test_health():\n    assert True\n\n"
           "def test_get_user():\n    assert True\n")
    _write(base, "migrations/001_initial.py",
           '"""Initial migration."""\n\ndef upgrade():\n    pass\n\n'
           "def downgrade():\n    pass\n")
    _write(base, "prometheus.yml",
           "global:\n  scrape_interval: 15s\nscrape_configs:\n"
           "  - job_name: 'cloudapi'\n    static_configs:\n"
           "      - targets: ['localhost:8000']\n")
    _write(base, "README.md", "# CloudAPI\nProduction-ready API.\n")
    return base


# ============================================================
# Descrizioni scenari
# ============================================================

SCENARIO_DESC = {
    "shopfast": (
        "## Scenario 1: ShopFast — Startup E-commerce\n\n"
        "**Contesto**: Startup Python/FastAPI + React. Docker presente ma single-stage, "
        "esegue come root, senza HEALTHCHECK e .dockerignore. CI/CD presente (GitHub Actions). "
        "Secrets committati (.env e hardcoded nel codice). Nessun IaC, nessun lockfile, "
        "nessun monitoring, nessun test. SQLAlchemy senza migrazioni.\n\n"
        "**Stack**: Python, JavaScript (React), FastAPI, Flask, SQLAlchemy\n\n"
        "**Criticita' iniettate**: 11 regole attese\n"
        "- INFRA-DOCKER-002/003/004/005 (Dockerfile di bassa qualita')\n"
        "- INFRA-IAC-001 (no IaC)\n"
        "- INFRA-DEPS-001 (no lockfile)\n"
        "- INFRA-CONFIG-001 (.env con secrets)\n"
        "- INFRA-CONFIG-002 (API_KEY e SECRET_KEY hardcoded)\n"
        "- INFRA-MON-001 (no monitoring)\n"
        "- ARCH-TEST-001 (no test)\n"
        "- ARCH-DB-001 (SQLAlchemy senza migrazioni)\n"
    ),
    "corpmanager": (
        "## Scenario 2: CorpManager — Monolite Enterprise Java\n\n"
        "**Contesto**: Monolite Spring Boot con Jenkins CI. Nessun Docker, nessun IaC. "
        "File controller da 620+ LOC. Password hardcoded in DatabaseConfig.java. "
        "Maven senza lockfile. Hibernate senza migrazioni. Directory test presente.\n\n"
        "**Stack**: Java, Spring Boot, Hibernate, JUnit\n\n"
        "**Criticita' iniettate**: 7 regole attese\n"
        "- INFRA-DOCKER-001 (no container)\n"
        "- INFRA-IAC-001 (no IaC)\n"
        "- INFRA-DEPS-001 (Maven senza lockfile)\n"
        "- INFRA-CONFIG-002 (DB_PASSWORD hardcoded)\n"
        "- INFRA-MON-001 (no monitoring)\n"
        "- ARCH-SCALE-001 (UserController.java >500 LOC)\n"
        "- ARCH-DB-001 (Hibernate senza migrazioni)\n\n"
        "**Nota**: Import circolari Java (UserService <-> OrderService) presenti "
        "ma non rilevati — l'analyzer supporta solo Python e JS/TS.\n"
    ),
    "paygo": (
        "## Scenario 3: PayGo — Microservizio Go Moderno\n\n"
        "**Contesto**: Go/Gin con Docker multi-stage, USER non-root, HEALTHCHECK. "
        "CI/CD GitHub Actions, Kubernetes manifest, Terraform, go.sum lockfile, "
        "Prometheus monitoring, directory test, migrazioni SQL. "
        "Unico problema: .env con STRIPE_SECRET_KEY e API_KEY hardcoded in config.go.\n\n"
        "**Stack**: Go, Gin, GORM\n\n"
        "**Criticita' iniettate**: 2 sole regole attese\n"
        "- INFRA-CONFIG-001 (.env con secrets)\n"
        "- INFRA-CONFIG-002 (API_KEY hardcoded in config.go)\n"
    ),
    "datadump": (
        "## Scenario 4: DataDump — Prototipo Abbandonato\n\n"
        "**Contesto**: Script Python buttati nella root senza organizzazione. "
        "Zero infrastruttura: no CI/CD, no Docker, no IaC, no lockfile, no monitoring, "
        "no test. Secrets ovunque: .env, config.py con AWS credentials, "
        "credentials.json, chiave privata SSH (id_rsa). Struttura completamente flat.\n\n"
        "**Stack**: Python (requests, beautifulsoup4)\n\n"
        "**Criticita' iniettate**: 9 regole attese (il massimo)\n"
        "- INFRA-CICD-001 (no CI/CD)\n"
        "- INFRA-DOCKER-001 (no container)\n"
        "- INFRA-IAC-001 (no IaC)\n"
        "- INFRA-DEPS-001 (no lockfile)\n"
        "- INFRA-CONFIG-001 (.env con secrets)\n"
        "- INFRA-CONFIG-002 (API keys, AWS credentials hardcoded)\n"
        "- INFRA-MON-001 (no monitoring)\n"
        "- ARCH-STRUCT-001 (struttura flat)\n"
        "- ARCH-TEST-001 (no test)\n"
    ),
    "cloudapi": (
        "## Scenario 5: CloudAPI — Servizio Produzione Ben Architettato\n\n"
        "**Contesto**: FastAPI con Clean Architecture (domain/application/infrastructure). "
        "Docker multi-stage con USER non-root e HEALTHCHECK. CI/CD completo (lint + test + deploy). "
        "Terraform IaC. poetry.lock. Prometheus + health endpoint. Directory test. "
        "Migrazioni Alembic. Zero secrets committati.\n\n"
        "**Stack**: Python, FastAPI, SQLAlchemy, Alembic, Pydantic, pytest\n\n"
        "**Criticita' iniettate**: Nessuna — repo perfetta\n"
        "- Attese 0 regole di penalita'\n"
    ),
}

# ============================================================
# Main
# ============================================================

def main():
    project_root = Path(__file__).parent
    reports_dir = project_root / "reports"
    reports_dir.mkdir(exist_ok=True)

    scenarios = [
        ("shopfast", "ShopFast", build_shopfast),
        ("corpmanager", "CorpManager", build_corpmanager),
        ("paygo", "PayGo", build_paygo),
        ("datadump", "DataDump", build_datadump),
        ("cloudapi", "CloudAPI", build_cloudapi),
    ]

    results: dict[str, AuditResult] = {}
    reporter = MarkdownReporter()

    print("=" * 60)
    print("  GENERAZIONE REPORT SCENARI REALISTICI")
    print("=" * 60)

    for key, name, builder in scenarios:
        print(f"\n{'-' * 50}")
        print(f"  Scenario: {name}")
        print(f"{'-' * 50}")

        with tempfile.TemporaryDirectory(prefix=f"{key}_") as tmpdir:
            repo_path = Path(tmpdir)
            builder(repo_path)

            result = _run_audit(repo_path)
            results[key] = result

            rules = _triggered_rules(result)
            score = result.health_score.overall_score

            print(f"  Overall Score: {score}/100")
            print(f"  Regole triggerate: {len(rules)}")
            for r in sorted(rules):
                print(f"    - {r}")

            # Salva report CTO Audit
            report_path = reports_dir / f"audit_{key}.md"
            reporter.save(result, report_path)
            print(f"  Report salvato: {report_path.relative_to(project_root)}")

    # ============================================================
    # Genera riepilogo comparativo
    # ============================================================

    summary_lines = [
        "# Riepilogo Scenari Realistici — CTO Audit Agent\n",
        "Report generato automaticamente dai 5 scenari di test end-to-end.\n",
        "Ogni scenario simula un codebase reale con criticita' iniettate.\n\n",
        "---\n\n",
        "## Ranking Complessivo\n\n",
        "| # | Scenario | Overall Score | Infra | Architettura | Security | Quality | Regole |\n",
        "|---|----------|--------------|-------|-------------|----------|---------|--------|\n",
    ]

    ranked = sorted(results.items(), key=lambda x: -x[1].health_score.overall_score)
    for i, (key, result) in enumerate(ranked, 1):
        hs = result.health_score
        ls = hs.layer_scores
        n_rules = len(_triggered_rules(result))
        name = key.replace("shopfast", "ShopFast").replace("corpmanager", "CorpManager") \
                   .replace("paygo", "PayGo").replace("datadump", "DataDump") \
                   .replace("cloudapi", "CloudAPI")
        summary_lines.append(
            f"| {i} | **{name}** | **{hs.overall_score}/100** "
            f"| {ls['infra'].score} | {ls['architecture'].score} "
            f"| {ls['security'].score} | {ls['quality'].score} "
            f"| {n_rules} |\n"
        )

    summary_lines.append("\n---\n\n")

    # Dettaglio per scenario
    for key, result in results.items():
        desc = SCENARIO_DESC.get(key, "")
        summary_lines.append(desc)
        summary_lines.append("\n")

        hs = result.health_score
        summary_lines.append(f"### Risultato Audit: {hs.overall_score}/100\n\n")
        summary_lines.append("| Layer | Score |\n|-------|-------|\n")
        for layer_name, ls in hs.layer_scores.items():
            summary_lines.append(f"| {layer_name.capitalize()} | {ls.score}/100 |\n")
        summary_lines.append("\n")

        rules = _triggered_rules(result)
        if rules:
            summary_lines.append("**Regole triggerate:**\n\n")
            for r in sorted(rules):
                # Trova la descrizione del finding
                desc_text = ""
                for ls in hs.layer_scores.values():
                    for f in ls.findings:
                        if f.rule_id == r:
                            desc_text = f.title
                            break
                summary_lines.append(f"- `{r}` — {desc_text}\n")
        else:
            summary_lines.append("**Nessuna regola di penalita' triggerata.** Repo perfetta.\n")

        summary_lines.append("\n---\n\n")

    # Nota test
    summary_lines.append("## Risultati Test\n\n")
    summary_lines.append("Per eseguire la batteria di test:\n\n")
    summary_lines.append("```bash\n")
    summary_lines.append("python -m pytest tests/test_realistic_scenarios.py -v\n")
    summary_lines.append("```\n\n")
    summary_lines.append("I test verificano per ogni scenario:\n\n")
    summary_lines.append("1. **Score range** — lo score complessivo e' nel range atteso\n")
    summary_lines.append("2. **Regole attese** — ogni criticita' iniettata viene rilevata\n")
    summary_lines.append("3. **Regole non attese** — nessun falso positivo sulle best practice\n")
    summary_lines.append("4. **Catena evidenze** — ogni penalita' ha tracciabilita' completa\n")
    summary_lines.append("5. **Report Markdown** — il report contiene tutte le sezioni\n")
    summary_lines.append("6. **Ranking comparativo** — CloudAPI > PayGo > CorpManager > ShopFast > DataDump\n")

    summary_path = reports_dir / "riepilogo_scenari.md"
    summary_path.write_text("".join(summary_lines), encoding="utf-8")
    print(f"\n{'=' * 60}")
    print(f"  Riepilogo salvato: {summary_path.relative_to(project_root)}")
    print(f"  Report individuali: reports/audit_*.md")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
