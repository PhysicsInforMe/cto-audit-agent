"""
Benchmark Sintetico con Ground Truth — CTO Audit Agent

Genera repo sintetiche con errori iniettati in modo controllato.
Ogni repo ha un manifest di ground truth: quali regole DEVONO scattare.
Esegue audit e calcola precision/recall per ogni regola.

Uso:
    python benchmarks/synthetic_benchmark.py
"""

from __future__ import annotations

import json
import os
import random
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cto_audit.core.orchestrator import AuditOrchestrator
from cto_audit.sources.local import LocalRepoSource


# ============================================================
# Generatore di repo sintetiche
# ============================================================

@dataclass
class SyntheticRepo:
    """Definizione di una repo sintetica con ground truth."""
    name: str
    language: str
    description: str
    # Regole che DEVONO scattare (ground truth positives)
    expected_rules: set[str] = field(default_factory=set)
    # Regole che NON devono scattare (ground truth negatives)
    expected_absent: set[str] = field(default_factory=set)


def _write(root: Path, path: str, content: str) -> None:
    """Scrive un file creando le directory necessarie."""
    full = root / path
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(content, encoding="utf-8")


# --- Generatori per linguaggio ---

def gen_python_web_no_security(root: Path) -> SyntheticRepo:
    """Python web app con problemi di security ma buona infra."""
    # CI/CD presente
    _write(root, ".github/workflows/ci.yml", "name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: pytest\n")
    # Docker presente ma con problemi
    _write(root, "Dockerfile", "FROM python:3.12\nWORKDIR /app\nCOPY . .\nRUN pip install -r requirements.txt\nCMD [\"python\", \"app.py\"]\n")
    _write(root, "docker-compose.yml", "version: '3'\nservices:\n  web:\n    build: .\n    ports:\n      - '8000:8000'\n")
    # Dipendenze con lockfile
    _write(root, "requirements.txt", "fastapi==0.104.0\nuvicorn==0.24.0\nsqlalchemy==2.0.23\npydantic==2.5.0\n")
    _write(root, "requirements-lock.txt", "fastapi==0.104.0\nuvicorn==0.24.0\n")
    # README
    _write(root, "README.md", "# SecureApp\n\nA totally secure web application.\n\n## Install\n\n```bash\npip install -r requirements.txt\n```\n")
    # Test presenti
    _write(root, "tests/__init__.py", "")
    _write(root, "tests/test_api.py", "import pytest\n\ndef test_hello():\n    assert True\n\ndef test_api():\n    assert 1 + 1 == 2\n")
    # App con SQL injection
    _write(root, "app.py", """from fastapi import FastAPI, Request
from sqlalchemy import create_engine, text

app = FastAPI()
engine = create_engine("sqlite:///db.sqlite3")

@app.get("/users")
def get_users(name: str):
    # SQL Injection!
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    with engine.connect() as conn:
        result = conn.execute(text(query))
    return list(result)

@app.get("/search")
def search(q: str):
    # Altro SQL injection
    sql = f"SELECT * FROM items WHERE title LIKE '%{q}%'"
    with engine.connect() as conn:
        return list(conn.execute(text(sql)))
""")
    # Secrets hardcodati
    _write(root, "config.py", """
DATABASE_URL = "postgresql://user:password123@db.example.com/mydb"
SECRET_KEY = "sk-proj-ABC123DEF456GHI789"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
STRIPE_KEY = "sk_FAKE_4eC39HqLyjWDarjtT1zdp7dc"
""")
    # CORS permissivo
    _write(root, "middleware.py", """from fastapi.middleware.cors import CORSMiddleware

def setup_cors(app):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
""")
    # HTTP URLs
    _write(root, "utils.py", """import requests

def fetch_data():
    resp = requests.get("http://api.example.com/data")
    return resp.json()

def notify():
    requests.post("http://webhook.example.com/notify", json={"msg": "done"})
""")
    # .env con secrets
    _write(root, ".env", "DB_PASSWORD=supersecret123\nAPI_KEY=sk-live-abc123\n")
    # Monitoring assente
    # IaC assente

    return SyntheticRepo(
        name="python-web-insecure",
        language="python",
        description="Python FastAPI app con SQL injection, secrets esposti, CORS aperto",
        expected_rules={
            "SEC-SQL-001",           # SQL injection via string concat
            "SEC-SECRETS-CODE-001",  # Secrets hardcodati in config.py
            "SEC-CORS-001",          # CORS allow_origins=["*"]
            "SEC-HTTPS-001",         # URL http:// in utils.py
            "INFRA-CONFIG-001",      # .env con secrets
            "INFRA-IAC-001",         # Nessun IaC
            "INFRA-MON-001",         # Nessun monitoring
            "INFRA-DOCKER-004",      # Dockerfile senza USER (root)
            "INFRA-DOCKER-003",      # No multi-stage
            "INFRA-DOCKER-005",      # No HEALTHCHECK
        },
        expected_absent={
            "INFRA-CICD-001",     # CI/CD presente
            "ARCH-TEST-001",      # Test presenti
            "QUAL-DOC-001",       # README presente
            "INFRA-DEPS-001",     # Lockfile presente
        },
    )


def gen_go_microservice_clean(root: Path) -> SyntheticRepo:
    """Go microservice ben strutturato, pochi problemi."""
    _write(root, ".github/workflows/ci.yml", "name: CI\non: [push, pull_request]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-go@v4\n      - run: go test ./...\n      - run: golangci-lint run\n")
    _write(root, "Dockerfile", "FROM golang:1.22-alpine AS builder\nWORKDIR /app\nCOPY go.* ./\nRUN go mod download\nCOPY . .\nRUN CGO_ENABLED=0 go build -o server ./cmd/server\n\nFROM alpine:3.19\nRUN adduser -D appuser\nUSER appuser\nCOPY --from=builder /app/server /server\nHEALTHCHECK CMD wget -q --spider http://localhost:8080/health || exit 1\nCMD [\"/server\"]\n")
    _write(root, ".dockerignore", "*.md\n.git\n.github\n")
    _write(root, "go.mod", "module github.com/example/svc\n\ngo 1.22\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n\tgorm.io/gorm v1.25.5\n\tgorm.io/driver/postgres v1.5.4\n)\n")
    _write(root, "go.sum", "github.com/gin-gonic/gin v1.9.1 h1:abc123==\n")
    _write(root, "README.md", "# Go Microservice\n\nClean microservice with Gin and GORM.\n\n## Run\n\n```bash\ngo run ./cmd/server\n```\n")
    _write(root, "cmd/server/main.go", """package main

import (
    "github.com/gin-gonic/gin"
    "net/http"
)

func main() {
    r := gin.Default()
    r.GET("/health", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{"status": "ok"})
    })
    r.GET("/users", getUsers)
    r.Run(":8080")
}

func getUsers(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"users": []string{}})
}
""")
    _write(root, "internal/db/db.go", "package db\n\nimport \"gorm.io/gorm\"\n\ntype DB struct {\n\t*gorm.DB\n}\n")
    _write(root, "internal/handler/user.go", "package handler\n\ntype UserHandler struct{}\n")
    _write(root, "internal/handler/user_test.go", "package handler\n\nimport \"testing\"\n\nfunc TestUserHandler(t *testing.T) {\n\t// test\n}\n")
    _write(root, "migrations/001_init.sql", "CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT);\n")

    return SyntheticRepo(
        name="go-microservice-clean",
        language="go",
        description="Go microservice pulito con CI/CD, Docker multi-stage, test, lockfile",
        expected_rules={
            "INFRA-IAC-001",  # Nessun Terraform/CloudFormation
        },
        expected_absent={
            "INFRA-CICD-001",
            "INFRA-DOCKER-001",
            "INFRA-DOCKER-003",  # Ha multi-stage
            "INFRA-DOCKER-004",  # Ha USER
            "INFRA-DOCKER-005",  # Ha HEALTHCHECK
            "INFRA-DEPS-001",    # Ha go.sum
            "ARCH-TEST-001",     # Ha test
            "QUAL-DOC-001",      # Ha README
            "SEC-SQL-001",       # No SQL injection
        },
    )


def gen_js_spa_messy(root: Path) -> SyntheticRepo:
    """JavaScript SPA con architettura caotica e problemi di qualita."""
    # No CI/CD
    # No Docker
    _write(root, "package.json", json.dumps({
        "name": "messy-spa",
        "version": "1.0.0",
        "dependencies": {
            "react": "^18.2.0",
            "express": "^4.18.2",
            "mysql": "^2.18.1",
            "cors": "^2.8.5",
        },
        "devDependencies": {
            "webpack": "^5.89.0",
        },
    }, indent=2))
    # No lockfile
    _write(root, "README.md", "# Messy SPA\n\nA messy single page application.\n")
    # No test
    # File giganti e flat
    big_code = "function handler(req, res) {\n" + "  // logic\n" * 300 + "}\n"
    _write(root, "server.js", f"""const express = require('express');
const mysql = require('mysql');
const cors = require('cors');

const app = express();
app.use(cors());  // CORS aperto

const db = mysql.createConnection({{
    host: 'localhost',
    user: 'root',
    password: 'root123',
    database: 'myapp'
}});

app.get('/users', (req, res) => {{
    const name = req.query.name;
    // SQL Injection
    db.query("SELECT * FROM users WHERE name = '" + name + "'", (err, results) => {{
        res.json(results);
    }});
}});

app.get('/search', (req, res) => {{
    const q = req.query.q;
    db.query(`SELECT * FROM items WHERE title LIKE '%${{q}}%'`, (err, results) => {{
        res.json(results);
    }});
}});

{big_code}

app.listen(3000);
""")
    _write(root, "index.html", "<html><body><div id='root'></div><script src='bundle.js'></script></body></html>\n")
    _write(root, "app.js", "import React from 'react';\n\nfunction App() { return <div>Hello</div>; }\n\nexport default App;\n")
    # Config con secrets
    _write(root, "config.js", """module.exports = {
    DB_PASSWORD: 'root123',
    API_KEY: 'sk-proj-ABC123DEF456GHI789JKL',
    JWT_SECRET: 'mysupersecretjwtkey123456',
    STRIPE_KEY: 'sk_FAKE_4eC39HqLyjWDarjtT1zdp7dc',
};
""")
    # HTTP URLs
    _write(root, "api.js", """const axios = require('axios');

async function fetchData() {
    const resp = await axios.get('http://api.example.com/v1/data');
    return resp.data;
}

async function webhook() {
    await axios.post('http://hooks.example.com/notify');
}

module.exports = { fetchData, webhook };
""")
    # File con nesting profondo
    _write(root, "utils.js", """function process(data) {
    if (data) {
        if (data.items) {
            for (let i = 0; i < data.items.length; i++) {
                if (data.items[i].active) {
                    if (data.items[i].type === 'A') {
                        if (data.items[i].value > 0) {
                            if (data.items[i].valid) {
                                console.log('deep');
                            }
                        }
                    }
                }
            }
        }
    }
}
module.exports = { process };
""")
    # .env con secrets
    _write(root, ".env", "DB_HOST=localhost\nDB_PASS=root123\nSECRET=mysecretkey\n")
    # File duplicati (3 copie per superare soglia DUP)
    _write(root, "helpers/utils.js", "function process(data) { return data; }\nmodule.exports = { process };\n")
    _write(root, "lib/utils.js", "function process(data) { return data; }\nmodule.exports = { process };\n")

    return SyntheticRepo(
        name="js-spa-messy",
        language="javascript",
        description="JavaScript SPA caotica: no CI/CD, no Docker, no test, SQL injection, secrets",
        expected_rules={
            "INFRA-CICD-001",        # No CI/CD
            "INFRA-DOCKER-001",      # No Docker (ha express = web framework)
            "INFRA-IAC-001",         # No IaC
            "INFRA-DEPS-001",        # No lockfile
            "INFRA-CONFIG-001",      # .env con secrets
            "INFRA-MON-001",         # No monitoring
            "ARCH-TEST-001",         # No test directory
            "ARCH-STRUCT-001",       # Struttura flat
            "SEC-SQL-001",           # SQL injection
            "SEC-SECRETS-CODE-001",  # Secrets in config.js
            "SEC-CORS-001",          # app.use(cors())
            "SEC-HTTPS-001",         # URL http://
            "QUAL-COMPLEXITY-001",   # Nesting profondo
            "QUAL-DUP-001",          # utils.js duplicato
        },
        expected_absent=set(),
    )


def gen_java_spring_enterprise(root: Path) -> SyntheticRepo:
    """Java Spring Boot enterprise app con buona struttura."""
    _write(root, ".github/workflows/ci.yml", "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-java@v4\n        with:\n          java-version: 21\n      - run: mvn test\n")
    _write(root, "Dockerfile", "FROM eclipse-temurin:21-jre-alpine AS builder\nWORKDIR /app\nCOPY target/*.jar app.jar\n\nFROM eclipse-temurin:21-jre-alpine\nRUN addgroup -S app && adduser -S app -G app\nUSER app\nCOPY --from=builder /app/app.jar /app.jar\nHEALTHCHECK CMD wget -q --spider http://localhost:8080/actuator/health || exit 1\nENTRYPOINT [\"java\", \"-jar\", \"/app.jar\"]\n")
    _write(root, ".dockerignore", "*.md\n.git\ntarget\n")
    _write(root, "pom.xml", """<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>enterprise-app</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
            <version>3.2.1</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
            <version>3.2.1</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
            <version>3.2.1</version>
        </dependency>
        <dependency>
            <groupId>org.flywaydb</groupId>
            <artifactId>flyway-core</artifactId>
            <version>9.22.3</version>
        </dependency>
    </dependencies>
</project>
""")
    _write(root, "README.md", "# Enterprise App\n\nSpring Boot enterprise application.\n\n## Build\n\n```bash\nmvn clean package\n```\n")
    _write(root, "src/main/java/com/example/App.java", "package com.example;\n\nimport org.springframework.boot.SpringApplication;\n\npublic class App {\n    public static void main(String[] args) {\n        SpringApplication.run(App.class, args);\n    }\n}\n")
    _write(root, "src/main/java/com/example/controller/UserController.java", "package com.example.controller;\n\nimport org.springframework.web.bind.annotation.*;\n\n@RestController\n@RequestMapping(\"/api/users\")\npublic class UserController {\n    @GetMapping\n    public String getUsers() {\n        return \"users\";\n    }\n}\n")
    _write(root, "src/main/java/com/example/service/UserService.java", "package com.example.service;\n\npublic class UserService {\n    public String findAll() { return \"all\"; }\n}\n")
    _write(root, "src/main/java/com/example/repository/UserRepository.java", "package com.example.repository;\n\npublic interface UserRepository {}\n")
    _write(root, "src/test/java/com/example/AppTest.java", "package com.example;\n\nimport org.junit.jupiter.api.Test;\n\nclass AppTest {\n    @Test\n    void contextLoads() {}\n}\n")
    _write(root, "src/main/resources/application.yml", "spring:\n  datasource:\n    url: jdbc:postgresql://localhost:5432/mydb\n")
    _write(root, "src/main/resources/db/migration/V1__init.sql", "CREATE TABLE users (id SERIAL PRIMARY KEY, name VARCHAR(255));\n")
    # Monitoring config
    _write(root, "src/main/resources/application-prod.yml", "management:\n  endpoints:\n    web:\n      exposure:\n        include: health,metrics,prometheus\n")
    # Prometheus config
    _write(root, "prometheus.yml", "scrape_configs:\n  - job_name: 'app'\n    static_configs:\n      - targets: ['localhost:8080']\n")

    return SyntheticRepo(
        name="java-spring-enterprise",
        language="java",
        description="Java Spring Boot enterprise: CI/CD, Docker, test, auth, migrations, monitoring",
        expected_rules={
            "INFRA-IAC-001",  # No Terraform
        },
        expected_absent={
            "INFRA-CICD-001",
            "INFRA-DOCKER-001",
            "INFRA-DOCKER-003",
            "INFRA-DOCKER-004",
            "INFRA-DOCKER-005",
            "INFRA-DEPS-001",
            "ARCH-TEST-001",
            "QUAL-DOC-001",
            "SEC-AUTH-001",
            "ARCH-DB-001",
            "INFRA-MON-001",
        },
    )


def gen_rust_cli_minimal(root: Path) -> SyntheticRepo:
    """Rust CLI tool minimale ma pulito."""
    _write(root, "Cargo.toml", """[package]
name = "mytool"
version = "0.1.0"
edition = "2021"

[dependencies]
clap = { version = "4.4", features = ["derive"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
""")
    _write(root, "Cargo.lock", "# This file is generated\n[[package]]\nname = \"mytool\"\nversion = \"0.1.0\"\n")
    _write(root, "README.md", "# MyTool\n\nA Rust CLI tool.\n\n## Install\n\n```bash\ncargo install --path .\n```\n")
    _write(root, "src/main.rs", """use clap::Parser;

#[derive(Parser)]
#[command(name = "mytool")]
struct Cli {
    /// Input file
    input: String,
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

fn main() {
    let cli = Cli::parse();
    println!("Processing: {}", cli.input);
}
""")
    _write(root, "src/lib.rs", "pub fn process(input: &str) -> String {\n    input.to_uppercase()\n}\n\n#[cfg(test)]\nmod tests {\n    use super::*;\n\n    #[test]\n    fn test_process() {\n        assert_eq!(process(\"hello\"), \"HELLO\");\n    }\n}\n")
    # No CI/CD, no Docker (ma e un CLI, non un server)

    return SyntheticRepo(
        name="rust-cli-minimal",
        language="rust",
        description="Rust CLI minimale: no CI/CD, no Docker (OK per CLI), ha test e lockfile",
        expected_rules={
            "INFRA-CICD-001",   # No CI/CD
            "INFRA-IAC-001",    # No IaC
            "INFRA-MON-001",    # No monitoring
        },
        expected_absent={
            "INFRA-DEPS-001",   # Ha Cargo.lock
            "ARCH-TEST-001",    # Ha test in lib.rs
            "QUAL-DOC-001",     # Ha README
            "SEC-SQL-001",      # No SQL
        },
    )


def gen_php_laravel_vulnerable(root: Path) -> SyntheticRepo:
    """PHP Laravel app con vulnerabilita di security."""
    _write(root, "composer.json", json.dumps({
        "require": {
            "php": "^8.1",
            "laravel/framework": "^10.0",
            "guzzlehttp/guzzle": "^7.0",
        },
        "require-dev": {
            "phpunit/phpunit": "^10.0",
        },
    }, indent=4))
    _write(root, "composer.lock", json.dumps({"packages": []}, indent=4))
    _write(root, "README.md", "# Laravel App\n\nA Laravel application.\n")
    _write(root, ".env", "APP_KEY=base64:abc123\nDB_PASSWORD=root\nMAIL_PASSWORD=secret123\n")
    _write(root, "Dockerfile", "FROM php:8.2-fpm\nWORKDIR /var/www\nCOPY . .\nRUN composer install\nCMD [\"php-fpm\"]\n")
    # File PHP con problemi
    _write(root, "app/Http/Controllers/UserController.php", """<?php
namespace App\\Http\\Controllers;

use Illuminate\\Http\\Request;
use Illuminate\\Support\\Facades\\DB;

class UserController extends Controller
{
    public function search(Request $request)
    {
        $name = $request->input('name');
        // SQL Injection
        $users = DB::select("SELECT * FROM users WHERE name = '" . $name . "'");
        return response()->json($users);
    }

    public function fetch()
    {
        // HTTP URL
        $data = file_get_contents('http://api.example.com/data');
        return response()->json(json_decode($data));
    }
}
""")
    _write(root, "app/Http/Controllers/AuthController.php", """<?php
namespace App\\Http\\Controllers;

class AuthController extends Controller
{
    private $apiKey = 'sk_FAKE_4eC39HqLyjWDarjtT1zdp7dc';

    public function login()
    {
        // Using MD5 for password hashing
        $hash = md5($password);
        return $hash;
    }
}
""")
    _write(root, "config/cors.php", """<?php
return [
    'paths' => ['api/*'],
    'allowed_origins' => ['*'],
    'allowed_methods' => ['*'],
    'allowed_headers' => ['*'],
];
""")
    _write(root, "tests/Feature/ExampleTest.php", "<?php\n\nnamespace Tests\\Feature;\n\nuse Tests\\TestCase;\n\nclass ExampleTest extends TestCase\n{\n    public function test_example(): void\n    {\n        \\$this->assertTrue(true);\n    }\n}\n")
    _write(root, "database/migrations/2024_01_01_create_users.php", "<?php\n// migration\n")

    return SyntheticRepo(
        name="php-laravel-vulnerable",
        language="php",
        description="PHP Laravel con SQL injection, secrets hardcodati, MD5, CORS aperto",
        expected_rules={
            "INFRA-CICD-001",        # No CI/CD
            "INFRA-IAC-001",         # No IaC
            "INFRA-CONFIG-001",      # .env con secrets
            "INFRA-MON-001",         # No monitoring
            "INFRA-DOCKER-004",      # Dockerfile root
            "INFRA-DOCKER-003",      # No multi-stage
            "INFRA-DOCKER-005",      # No healthcheck
            "SEC-SQL-001",           # SQL injection
            "SEC-SECRETS-CODE-001",  # sk_live in AuthController
            "SEC-CRYPTO-001",        # md5()
            "SEC-HTTPS-001",         # http:// URL
            "SEC-CORS-001",          # allowed_origins = ['*']
        },
        expected_absent={
            "INFRA-DEPS-001",  # Ha composer.lock
            "ARCH-TEST-001",   # Ha tests/
            "QUAL-DOC-001",    # Ha README
        },
    )


def gen_ruby_rails_mature(root: Path) -> SyntheticRepo:
    """Ruby on Rails app matura con pochi problemi."""
    _write(root, ".github/workflows/ci.yml", "name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ruby/setup-ruby@v1\n      - run: bundle exec rspec\n")
    _write(root, "Dockerfile", "FROM ruby:3.2-alpine AS builder\nWORKDIR /app\nCOPY Gemfile* ./\nRUN bundle install\n\nFROM ruby:3.2-alpine\nRUN adduser -D rails\nUSER rails\nWORKDIR /app\nCOPY --from=builder /app .\nCOPY . .\nHEALTHCHECK CMD wget -q --spider http://localhost:3000/health || exit 1\nCMD [\"rails\", \"server\"]\n")
    _write(root, ".dockerignore", "*.md\n.git\ntmp\nlog\n")
    _write(root, "Gemfile", "source 'https://rubygems.org'\ngem 'rails', '~> 7.1'\ngem 'pg', '~> 1.5'\ngem 'devise', '~> 4.9'\ngem 'puma', '~> 6.4'\n")
    _write(root, "Gemfile.lock", "GEM\n  specs:\n    rails (7.1.0)\n")
    _write(root, "README.md", "# Rails App\n\nA mature Rails application with Devise auth.\n\n## Setup\n\n```bash\nbundle install\nrails db:setup\n```\n")
    _write(root, "app/controllers/application_controller.rb", "class ApplicationController < ActionController::Base\n  before_action :authenticate_user!\nend\n")
    _write(root, "app/controllers/users_controller.rb", "class UsersController < ApplicationController\n  def index\n    @users = User.all\n  end\nend\n")
    _write(root, "app/models/user.rb", "class User < ApplicationRecord\n  devise :database_authenticatable, :registerable\nend\n")
    _write(root, "config/routes.rb", "Rails.application.routes.draw do\n  devise_for :users\n  resources :users\nend\n")
    _write(root, "spec/models/user_spec.rb", "require 'rails_helper'\n\nRSpec.describe User do\n  it 'is valid' do\n    expect(User.new).to be_valid\n  end\nend\n")
    _write(root, "spec/rails_helper.rb", "require 'rspec'\n")
    _write(root, "db/migrate/001_create_users.rb", "class CreateUsers < ActiveRecord::Migration[7.1]\n  def change\n    create_table :users do |t|\n      t.string :email\n      t.timestamps\n    end\n  end\nend\n")
    _write(root, "config/initializers/sentry.rb", "# Sentry.init do |config|\n#   config.dsn = ENV['SENTRY_DSN']\n# end\n")
    # Monitoring tramite Sentry (commentato ma presente)

    return SyntheticRepo(
        name="ruby-rails-mature",
        language="ruby",
        description="Ruby on Rails matura: CI/CD, Docker, Devise auth, test, migrations",
        expected_rules={
            "INFRA-IAC-001",   # No IaC
            "INFRA-MON-001",   # Sentry commentato
        },
        expected_absent={
            "INFRA-CICD-001",
            "INFRA-DOCKER-001",
            "INFRA-DOCKER-003",
            "INFRA-DOCKER-004",
            "INFRA-DOCKER-005",
            "INFRA-DEPS-001",
            "ARCH-TEST-001",
            "QUAL-DOC-001",
            "SEC-AUTH-001",
            "ARCH-DB-001",
        },
    )


def gen_csharp_api_no_tests(root: Path) -> SyntheticRepo:
    """C# .NET API senza test e con problemi di qualita."""
    _write(root, "App.sln", "# Solution file\n")
    _write(root, "App/App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk.Web\">\n  <PropertyGroup>\n    <TargetFramework>net8.0</TargetFramework>\n  </PropertyGroup>\n  <ItemGroup>\n    <PackageReference Include=\"Microsoft.EntityFrameworkCore\" Version=\"8.0.0\" />\n  </ItemGroup>\n</Project>\n")
    _write(root, "Dockerfile", "FROM mcr.microsoft.com/dotnet/aspnet:8.0\nWORKDIR /app\nCOPY . .\nCMD [\"dotnet\", \"App.dll\"]\n")
    _write(root, "README.md", "# .NET API\n\nA .NET 8 API.\n")
    _write(root, ".env", "ConnectionString=Server=db;Database=mydb;User=sa;Password=P@ssw0rd!\n")
    big_controller = "using Microsoft.AspNetCore.Mvc;\n\nnamespace App.Controllers {\n    [ApiController]\n    [Route(\"api/[controller]\")]\n    public class DataController : ControllerBase {\n" + "        [HttpGet]\n        public IActionResult Get() { return Ok(); }\n" * 260 + "    }\n}\n"
    _write(root, "App/Controllers/DataController.cs", big_controller)
    _write(root, "App/Controllers/AuthController.cs", """using Microsoft.AspNetCore.Mvc;

namespace App.Controllers {
    [ApiController]
    public class AuthController : ControllerBase {
        private string secret_key = "SuperSecretKey123456789";

        [HttpPost("/login")]
        public IActionResult Login(string user, string pass) {
            // Using SHA1
            var hash = System.Security.Cryptography.SHA1.Create().ComputeHash(
                System.Text.Encoding.UTF8.GetBytes(pass));
            return Ok();
        }
    }
}
""")

    return SyntheticRepo(
        name="csharp-api-no-tests",
        language="csharp",
        description="C# .NET API senza test, secrets esposti, SHA1, file giganti",
        expected_rules={
            "INFRA-CICD-001",        # No CI/CD
            "INFRA-IAC-001",         # No IaC
            "INFRA-CONFIG-001",      # .env con password
            "INFRA-MON-001",         # No monitoring
            "INFRA-DOCKER-004",      # Dockerfile root
            "INFRA-DOCKER-003",      # No multi-stage
            "INFRA-DOCKER-005",      # No healthcheck
            "ARCH-TEST-001",         # No test
            "ARCH-SCALE-001",        # DataController.cs >500 LOC
            "SEC-SECRETS-CODE-001",  # Secret in AuthController
            "SEC-CRYPTO-001",        # SHA1
        },
        expected_absent={
            "QUAL-DOC-001",  # Ha README
        },
    )


def gen_python_data_pipeline(root: Path) -> SyntheticRepo:
    """Python data pipeline (non web) con problemi misti."""
    _write(root, "requirements.txt", "pandas==2.1.4\nscikit-learn==1.3.2\nsqlalchemy==2.0.23\nrequests==2.31.0\n")
    _write(root, "README.md", "# Data Pipeline\n\nETL pipeline for data processing.\n")
    _write(root, "Makefile", "run:\n\tpython main.py\n\ntest:\n\tpytest tests/\n")
    _write(root, "tests/test_pipeline.py", "def test_transform():\n    assert True\n")
    _write(root, "main.py", """import pandas as pd
from sqlalchemy import create_engine, text

DB_URL = "postgresql://admin:password123@db.example.com/warehouse"
engine = create_engine(DB_URL)

def extract():
    data = pd.read_sql("SELECT * FROM raw_data", engine)
    return data

def transform(df):
    # Deeply nested logic
    for i, row in df.iterrows():
        if row['type'] == 'A':
            if row['status'] == 'active':
                if row['value'] > 100:
                    if row['category'] in ['X', 'Y']:
                        if row['flag']:
                            if row['score'] > 0.5:
                                df.at[i, 'result'] = 'matched'
    return df

def load(df):
    df.to_sql('processed', engine, if_exists='replace')

if __name__ == '__main__':
    data = extract()
    data = transform(data)
    load(data)
""")
    _write(root, "utils.py", """import hashlib

def hash_email(email):
    # Weak hash
    return hashlib.md5(email.encode()).hexdigest()

def fetch_external():
    import requests
    return requests.get("http://data-api.example.com/v1/feed").json()
""")

    return SyntheticRepo(
        name="python-data-pipeline",
        language="python",
        description="Python ETL: no CI/CD, no Docker, secrets in code, MD5, nesting",
        expected_rules={
            "INFRA-CICD-001",
            "INFRA-IAC-001",
            "INFRA-MON-001",
            "SEC-SECRETS-CODE-001",   # DB password in code
            "SEC-CRYPTO-001",         # MD5
            "SEC-HTTPS-001",          # http:// URL
            "QUAL-COMPLEXITY-001",    # Deep nesting
        },
        expected_absent={
            "INFRA-DEPS-001",  # Has pinned requirements.txt (==)
            "ARCH-TEST-001",   # Ha tests/
            "QUAL-DOC-001",    # Ha README
        },
    )


# Lista completa dei generatori
GENERATORS = [
    gen_python_web_no_security,
    gen_go_microservice_clean,
    gen_js_spa_messy,
    gen_java_spring_enterprise,
    gen_rust_cli_minimal,
    gen_php_laravel_vulnerable,
    gen_ruby_rails_mature,
    gen_csharp_api_no_tests,
    gen_python_data_pipeline,
]


# ============================================================
# Audit e confronto
# ============================================================

def run_audit(repo_path: Path) -> set[str]:
    """Esegue audit e restituisce set di rule_id triggered."""
    source = LocalRepoSource(repo_path)
    orchestrator = AuditOrchestrator(
        source=source,
        target_path=repo_path,
        offline=True,
        auto_approve=True,
        no_llm=True,
    )
    result = orchestrator.run()

    triggered = set()
    for layer_name, layer_score in result.health_score.layer_scores.items():
        for f in layer_score.findings:
            triggered.add(f.rule_id)

    return triggered


def evaluate(repo: SyntheticRepo, triggered: set[str]) -> dict:
    """Calcola precision/recall per una repo."""
    # True positives: regole attese che sono scattate
    tp = repo.expected_rules & triggered
    # False negatives: regole attese che NON sono scattate
    fn = repo.expected_rules - triggered
    # False positives (rispetto a expected_absent): regole che non dovevano scattare ma sono scattate
    fp_strict = repo.expected_absent & triggered

    # Calcola metriche
    recall = len(tp) / len(repo.expected_rules) if repo.expected_rules else 1.0
    # Precision calcolata solo su expected_rules + expected_absent
    relevant_triggered = triggered & (repo.expected_rules | repo.expected_absent)
    precision = len(tp) / len(relevant_triggered) if relevant_triggered else 1.0

    return {
        "true_positives": sorted(tp),
        "false_negatives": sorted(fn),
        "false_positives_strict": sorted(fp_strict),
        "all_triggered": sorted(triggered),
        "recall": round(recall * 100, 1),
        "precision": round(precision * 100, 1),
    }


# ============================================================
# Main
# ============================================================

def main():
    base_dir = Path(__file__).parent
    results_dir = base_dir / "results"
    results_dir.mkdir(exist_ok=True)

    all_results = {}
    all_tp = 0
    all_fn = 0
    all_fp = 0
    rule_tp = {}
    rule_fn = {}

    print("=" * 60)
    print("BENCHMARK SINTETICO CON GROUND TRUTH")
    print("=" * 60)

    for gen_func in GENERATORS:
        # Crea repo in tmpdir
        tmpdir = Path(tempfile.mkdtemp(prefix="synth_"))
        try:
            repo = gen_func(tmpdir)
            print(f"\n--- {repo.name} ({repo.language}) ---")
            print(f"  {repo.description}")
            print(f"  Expected rules: {len(repo.expected_rules)}")

            # Audit
            triggered = run_audit(tmpdir)
            eval_result = evaluate(repo, triggered)

            print(f"  Triggered: {len(triggered)} rules")
            print(f"  Recall: {eval_result['recall']}% | Precision: {eval_result['precision']}%")

            if eval_result["false_negatives"]:
                print(f"  FALSE NEGATIVES: {eval_result['false_negatives']}")
            if eval_result["false_positives_strict"]:
                print(f"  FALSE POSITIVES: {eval_result['false_positives_strict']}")

            # Accumula statistiche
            tp_count = len(eval_result["true_positives"])
            fn_count = len(eval_result["false_negatives"])
            fp_count = len(eval_result["false_positives_strict"])
            all_tp += tp_count
            all_fn += fn_count
            all_fp += fp_count

            for rule in eval_result["true_positives"]:
                rule_tp[rule] = rule_tp.get(rule, 0) + 1
            for rule in eval_result["false_negatives"]:
                rule_fn[rule] = rule_fn.get(rule, 0) + 1

            all_results[repo.name] = {
                "language": repo.language,
                "description": repo.description,
                "expected_rules": sorted(repo.expected_rules),
                "expected_absent": sorted(repo.expected_absent),
                "evaluation": eval_result,
            }

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    # Statistiche aggregate
    total_checks = all_tp + all_fn
    overall_recall = round(all_tp / total_checks * 100, 1) if total_checks else 0
    overall_precision = round(all_tp / (all_tp + all_fp) * 100, 1) if (all_tp + all_fp) else 0

    print("\n" + "=" * 60)
    print("RISULTATI AGGREGATI")
    print("=" * 60)
    print(f"\nRepo sintetiche: {len(all_results)}")
    print(f"Check totali: {total_checks}")
    print(f"True Positives: {all_tp}")
    print(f"False Negatives: {all_fn}")
    print(f"False Positives (strict): {all_fp}")
    print(f"\nOVERALL RECALL: {overall_recall}%")
    print(f"OVERALL PRECISION: {overall_precision}%")

    # Per-rule breakdown
    all_rules = sorted(set(rule_tp.keys()) | set(rule_fn.keys()))
    print("\n--- Detection Rate per Regola ---")
    print(f"{'Regola':30s} {'TP':>4s} {'FN':>4s} {'Rate':>7s}")
    for rule in all_rules:
        tp = rule_tp.get(rule, 0)
        fn = rule_fn.get(rule, 0)
        rate = round(tp / (tp + fn) * 100, 1) if (tp + fn) else 0
        status = "OK" if rate == 100 else "MISS" if rate == 0 else "PARTIAL"
        print(f"  {rule:28s} {tp:4d} {fn:4d} {rate:6.1f}% {status}")

    # Salva risultati
    output = results_dir / "synthetic_benchmark.json"
    with open(output, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "repos": all_results,
            "aggregate": {
                "total_repos": len(all_results),
                "total_checks": total_checks,
                "true_positives": all_tp,
                "false_negatives": all_fn,
                "false_positives_strict": all_fp,
                "overall_recall": overall_recall,
                "overall_precision": overall_precision,
                "per_rule": {
                    rule: {
                        "tp": rule_tp.get(rule, 0),
                        "fn": rule_fn.get(rule, 0),
                        "rate": round(rule_tp.get(rule, 0) / (rule_tp.get(rule, 0) + rule_fn.get(rule, 0)) * 100, 1)
                        if (rule_tp.get(rule, 0) + rule_fn.get(rule, 0)) else 0,
                    }
                    for rule in all_rules
                },
            },
        }, f, indent=2, ensure_ascii=False)

    print(f"\nRisultati salvati in {output}")


if __name__ == "__main__":
    main()
