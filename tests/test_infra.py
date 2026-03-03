"""
Test per InfraAnalyzer (Blocco 7).

Verifica:
- BaseAnalyzer è un Protocol runtime_checkable
- InfraAnalyzer rispetta l'interfaccia BaseAnalyzer
- Repo senza CI/CD → Finding critico INFRA-CICD-001
- Repo con GitHub Actions → finding info (nessun critico CI/CD)
- Repo con Dockerfile senza multi-stage → Finding medium INFRA-DOCKER-003
- Repo senza Dockerfile → Finding critico INFRA-DOCKER-001
- Repo senza lockfile → Finding high INFRA-DEPS-001
- Repo con .env con secrets → Finding INFRA-CONFIG-001
- Repo totalmente vuota di infra → finding critici multipli
- Repo ben strutturata → pochi finding, severità bassa
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cto_audit.analyzers.base import BaseAnalyzer
from cto_audit.analyzers.infra import InfraAnalyzer
from cto_audit.collectors.privacy import PrivacyClassifier
from cto_audit.collectors.scanner import FileScanner
from cto_audit.collectors.stack import StackDetector
from cto_audit.core.models import (
    Finding,
    Layer,
    PrivacyCategory,
    Severity,
    StackInfo,
)
from cto_audit.sources.local import LocalRepoSource


# --- Helpers ---


def _run_infra_analysis(tmp_path: Path) -> list[Finding]:
    """Helper: esegue la pipeline completa fino all'InfraAnalyzer."""
    source = LocalRepoSource(tmp_path)
    scanner = FileScanner(source)
    files = scanner.scan()
    detector = StackDetector(source)
    stack_info = detector.detect(files)
    classifier = PrivacyClassifier(source)
    classifications = classifier.classify(files)

    analyzer = InfraAnalyzer()
    return analyzer.analyze(source, stack_info, classifications)


def _find_by_rule(findings: list[Finding], rule_id: str) -> list[Finding]:
    """Filtra i finding per rule_id."""
    return [f for f in findings if f.rule_id == rule_id]


def _has_rule(findings: list[Finding], rule_id: str) -> bool:
    """Verifica se un finding con un certo rule_id è presente."""
    return any(f.rule_id == rule_id for f in findings)


# --- Fixture ---


@pytest.fixture
def repo_vuota(tmp_path: Path) -> Path:
    """Repository con solo un file Python, nessuna infrastruttura."""
    (tmp_path / "app.py").write_text(
        "def main():\n    print('hello')\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def repo_minima(tmp_path: Path) -> Path:
    """Repository minima: Python + requirements.txt, niente altro."""
    (tmp_path / "app.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n",
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text(
        "flask>=3.0\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def repo_con_github_actions(tmp_path: Path) -> Path:
    """Repository con GitHub Actions CI/CD."""
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def repo_con_dockerfile_base(tmp_path: Path) -> Path:
    """Repository con Dockerfile base (singolo stage, root)."""
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11\nCOPY . /app\nCMD [\"python\", \"app.py\"]\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def repo_con_dockerfile_multistage(tmp_path: Path) -> Path:
    """Repository con Dockerfile multi-stage e best practices."""
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11-slim AS builder\n"
        "WORKDIR /build\n"
        "COPY requirements.txt .\n"
        "RUN pip install -r requirements.txt\n\n"
        "FROM python:3.11-slim\n"
        "WORKDIR /app\n"
        "COPY --from=builder /build .\n"
        "COPY . .\n"
        "USER appuser\n"
        "HEALTHCHECK CMD curl -f http://localhost:8080/health || exit 1\n"
        "CMD [\"python\", \"app.py\"]\n",
        encoding="utf-8",
    )
    (tmp_path / ".dockerignore").write_text(
        "node_modules\n.git\n.env\n",
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("flask>=3.0\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("flask>=3.0\n", encoding="utf-8")
    return tmp_path


@pytest.fixture
def repo_con_env(tmp_path: Path) -> Path:
    """Repository con file .env contenente secrets."""
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / ".env").write_text(
        "DB_PASSWORD=secret123\nAPI_KEY=sk-abc123xyz\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def repo_ben_strutturata(tmp_path: Path) -> Path:
    """Repository ben strutturata con infra completa."""
    # Codice sorgente
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n\n"
        "@app.get('/health')\n"
        "def health():\n"
        "    return {'status': 'ok'}\n",
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("flask>=3.0\n", encoding="utf-8")
    (tmp_path / "poetry.lock").write_text("# poetry lock\n", encoding="utf-8")

    # CI/CD
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
        encoding="utf-8",
    )

    # Docker multi-stage con best practices
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11-slim AS builder\n"
        "WORKDIR /build\n"
        "COPY requirements.txt .\n"
        "RUN pip install -r requirements.txt\n\n"
        "FROM python:3.11-slim\n"
        "WORKDIR /app\n"
        "COPY --from=builder /build .\n"
        "USER appuser\n"
        "HEALTHCHECK CMD curl -f http://localhost:8080/health || exit 1\n"
        "CMD [\"python\", \"app.py\"]\n",
        encoding="utf-8",
    )
    (tmp_path / ".dockerignore").write_text(
        "node_modules\n.git\n.env\n__pycache__\n",
        encoding="utf-8",
    )

    # IaC
    (tmp_path / "terraform").mkdir()
    (tmp_path / "terraform" / "main.tf").write_text(
        'resource "aws_instance" "app" {\n  ami = "ami-123"\n}\n',
        encoding="utf-8",
    )

    # Monitoraggio
    (tmp_path / "sentry.properties").write_text(
        "defaults.org=myorg\n",
        encoding="utf-8",
    )

    return tmp_path


# --- Test BaseAnalyzer Protocol ---


class TestBaseAnalyzer:
    """Test per l'interfaccia BaseAnalyzer."""

    def test_protocol_runtime_checkable(self):
        """BaseAnalyzer è un Protocol runtime_checkable."""
        analyzer = InfraAnalyzer()
        assert isinstance(analyzer, BaseAnalyzer)

    def test_analyze_restituisce_lista_finding(self, repo_vuota: Path):
        """analyze() restituisce una lista di Finding."""
        findings = _run_infra_analysis(repo_vuota)
        assert isinstance(findings, list)
        assert all(isinstance(f, Finding) for f in findings)

    def test_tutti_i_finding_sono_layer_infra(self, repo_vuota: Path):
        """Tutti i finding prodotti hanno layer=infra."""
        findings = _run_infra_analysis(repo_vuota)
        assert all(f.layer == Layer.INFRA for f in findings)


# --- Test CI/CD ---


class TestCICD:
    """Test per i check CI/CD."""

    def test_repo_senza_cicd_finding_high(self, repo_vuota: Path):
        """Repo senza CI/CD → Finding high INFRA-CICD-001."""
        findings = _run_infra_analysis(repo_vuota)
        assert _has_rule(findings, "INFRA-CICD-001")
        cicd_finding = _find_by_rule(findings, "INFRA-CICD-001")[0]
        assert cicd_finding.severity == Severity.HIGH

    def test_repo_con_github_actions_no_finding_critico(
        self, repo_con_github_actions: Path
    ):
        """Repo con GitHub Actions → nessun finding critico CI/CD."""
        findings = _run_infra_analysis(repo_con_github_actions)
        assert not _has_rule(findings, "INFRA-CICD-001")

    def test_repo_con_github_actions_finding_info(
        self, repo_con_github_actions: Path
    ):
        """Repo con GitHub Actions → finding info INFRA-CICD-INFO."""
        findings = _run_infra_analysis(repo_con_github_actions)
        assert _has_rule(findings, "INFRA-CICD-INFO")
        info_finding = _find_by_rule(findings, "INFRA-CICD-INFO")[0]
        assert info_finding.severity == Severity.INFO
        assert "GitHub Actions" in info_finding.title

    def test_cicd_finding_ha_framework_ref(self, repo_vuota: Path):
        """Il finding INFRA-CICD-001 ha framework_ref NIST."""
        findings = _run_infra_analysis(repo_vuota)
        cicd_finding = _find_by_rule(findings, "INFRA-CICD-001")[0]
        assert cicd_finding.framework_ref is not None
        assert "NIST" in cicd_finding.framework_ref

    def test_gitlab_ci_rilevato(self, tmp_path: Path):
        """GitLab CI rilevato correttamente."""
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / ".gitlab-ci.yml").write_text(
            "stages:\n  - test\n", encoding="utf-8"
        )
        findings = _run_infra_analysis(tmp_path)
        assert not _has_rule(findings, "INFRA-CICD-001")
        info = _find_by_rule(findings, "INFRA-CICD-INFO")[0]
        assert "GitLab CI" in info.title


# --- Test Container ---


class TestContainer:
    """Test per i check containerizzazione."""

    def test_repo_non_deployable_senza_container_finding_info(self, repo_vuota: Path):
        """Repo non-deployable senza Dockerfile → Finding info INFRA-DOCKER-INFO."""
        findings = _run_infra_analysis(repo_vuota)
        assert _has_rule(findings, "INFRA-DOCKER-INFO")
        docker_finding = _find_by_rule(findings, "INFRA-DOCKER-INFO")[0]
        assert docker_finding.severity == Severity.INFO

    def test_repo_deployable_senza_container_finding_medium(self, repo_minima: Path):
        """Repo deployable (Flask) senza Dockerfile → Finding medium INFRA-DOCKER-001."""
        findings = _run_infra_analysis(repo_minima)
        assert _has_rule(findings, "INFRA-DOCKER-001")
        docker_finding = _find_by_rule(findings, "INFRA-DOCKER-001")[0]
        assert docker_finding.severity == Severity.MEDIUM

    def test_dockerfile_senza_multistage_finding_medium(
        self, repo_con_dockerfile_base: Path
    ):
        """Dockerfile senza multi-stage → Finding medium INFRA-DOCKER-003."""
        findings = _run_infra_analysis(repo_con_dockerfile_base)
        assert _has_rule(findings, "INFRA-DOCKER-003")
        finding = _find_by_rule(findings, "INFRA-DOCKER-003")[0]
        assert finding.severity == Severity.MEDIUM

    def test_dockerfile_senza_user_finding_medium(
        self, repo_con_dockerfile_base: Path
    ):
        """Dockerfile senza USER non-root → Finding medium INFRA-DOCKER-004."""
        findings = _run_infra_analysis(repo_con_dockerfile_base)
        assert _has_rule(findings, "INFRA-DOCKER-004")
        finding = _find_by_rule(findings, "INFRA-DOCKER-004")[0]
        assert finding.severity == Severity.MEDIUM

    def test_dockerfile_senza_dockerignore_finding_low(
        self, repo_con_dockerfile_base: Path
    ):
        """Dockerfile senza .dockerignore → Finding low INFRA-DOCKER-002."""
        findings = _run_infra_analysis(repo_con_dockerfile_base)
        assert _has_rule(findings, "INFRA-DOCKER-002")
        finding = _find_by_rule(findings, "INFRA-DOCKER-002")[0]
        assert finding.severity == Severity.LOW

    def test_dockerfile_multistage_nessun_finding_003(
        self, repo_con_dockerfile_multistage: Path
    ):
        """Dockerfile multi-stage → nessun finding INFRA-DOCKER-003."""
        findings = _run_infra_analysis(repo_con_dockerfile_multistage)
        assert not _has_rule(findings, "INFRA-DOCKER-003")

    def test_dockerfile_con_user_nessun_finding_004(
        self, repo_con_dockerfile_multistage: Path
    ):
        """Dockerfile con USER non-root → nessun finding INFRA-DOCKER-004."""
        findings = _run_infra_analysis(repo_con_dockerfile_multistage)
        assert not _has_rule(findings, "INFRA-DOCKER-004")

    def test_dockerfile_con_dockerignore_nessun_finding_002(
        self, repo_con_dockerfile_multistage: Path
    ):
        """Dockerfile con .dockerignore → nessun finding INFRA-DOCKER-002."""
        findings = _run_infra_analysis(repo_con_dockerfile_multistage)
        assert not _has_rule(findings, "INFRA-DOCKER-002")

    def test_dockerfile_con_healthcheck_nessun_finding_005(
        self, repo_con_dockerfile_multistage: Path
    ):
        """Dockerfile con HEALTHCHECK → nessun finding INFRA-DOCKER-005."""
        findings = _run_infra_analysis(repo_con_dockerfile_multistage)
        assert not _has_rule(findings, "INFRA-DOCKER-005")

    def test_repo_con_container_nessun_finding_001(
        self, repo_con_dockerfile_base: Path
    ):
        """Repo con Dockerfile → nessun finding INFRA-DOCKER-001."""
        findings = _run_infra_analysis(repo_con_dockerfile_base)
        assert not _has_rule(findings, "INFRA-DOCKER-001")


# --- Test IaC ---


class TestIaC:
    """Test per i check Infrastructure as Code."""

    def test_repo_senza_iac_finding_high(self, repo_vuota: Path):
        """Repo senza IaC → Finding high INFRA-IAC-001."""
        findings = _run_infra_analysis(repo_vuota)
        assert _has_rule(findings, "INFRA-IAC-001")
        finding = _find_by_rule(findings, "INFRA-IAC-001")[0]
        assert finding.severity == Severity.HIGH

    def test_repo_con_terraform_nessun_finding(self, tmp_path: Path):
        """Repo con Terraform → nessun finding INFRA-IAC-001."""
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "main.tf").write_text(
            'resource "aws_instance" "app" {}\n', encoding="utf-8"
        )
        findings = _run_infra_analysis(tmp_path)
        assert not _has_rule(findings, "INFRA-IAC-001")

    def test_repo_con_ansible_nessun_finding(self, tmp_path: Path):
        """Repo con Ansible → nessun finding INFRA-IAC-001."""
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "ansible").mkdir()
        (tmp_path / "ansible" / "playbook.yml").write_text(
            "- hosts: all\n", encoding="utf-8"
        )
        findings = _run_infra_analysis(tmp_path)
        assert not _has_rule(findings, "INFRA-IAC-001")


# --- Test Dipendenze ---


class TestDipendenze:
    """Test per i check gestione dipendenze."""

    def test_repo_con_manifest_senza_lockfile_finding_high(
        self, repo_minima: Path
    ):
        """Repo con requirements.txt ma senza lockfile → Finding high."""
        findings = _run_infra_analysis(repo_minima)
        assert _has_rule(findings, "INFRA-DEPS-001")
        finding = _find_by_rule(findings, "INFRA-DEPS-001")[0]
        assert finding.severity == Severity.HIGH

    def test_repo_con_lockfile_nessun_finding(self, tmp_path: Path):
        """Repo con lockfile presente → nessun finding INFRA-DEPS-001."""
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": {"express": "^4.0"}}),
            encoding="utf-8",
        )
        (tmp_path / "package-lock.json").write_text(
            json.dumps({"lockfileVersion": 3}),
            encoding="utf-8",
        )
        findings = _run_infra_analysis(tmp_path)
        assert not _has_rule(findings, "INFRA-DEPS-001")

    def test_repo_senza_manifest_nessun_finding_deps(self, repo_vuota: Path):
        """Repo senza file di dipendenze → nessun finding INFRA-DEPS-001."""
        findings = _run_infra_analysis(repo_vuota)
        assert not _has_rule(findings, "INFRA-DEPS-001")

    def test_deps_finding_ha_framework_ref(self, repo_minima: Path):
        """Il finding INFRA-DEPS-001 ha framework_ref NIS2."""
        findings = _run_infra_analysis(repo_minima)
        deps_finding = _find_by_rule(findings, "INFRA-DEPS-001")[0]
        assert deps_finding.framework_ref is not None
        assert "NIS2" in deps_finding.framework_ref


# --- Test Config / Secrets ---


class TestConfig:
    """Test per i check configurazione e secrets."""

    def test_repo_con_env_finding_config(self, repo_con_env: Path):
        """Repo con .env sensibile → Finding INFRA-CONFIG-001."""
        findings = _run_infra_analysis(repo_con_env)
        assert _has_rule(findings, "INFRA-CONFIG-001")
        finding = _find_by_rule(findings, "INFRA-CONFIG-001")[0]
        assert finding.severity == Severity.HIGH

    def test_repo_senza_env_nessun_finding_config(self, repo_vuota: Path):
        """Repo senza .env → nessun finding INFRA-CONFIG-001."""
        findings = _run_infra_analysis(repo_vuota)
        assert not _has_rule(findings, "INFRA-CONFIG-001")

    def test_secrets_in_config_file(self, tmp_path: Path):
        """File con password in chiaro → Finding INFRA-CONFIG-002."""
        (tmp_path / "config.yml").write_text(
            "database:\n  password: super_secret_123\n  host: localhost\n",
            encoding="utf-8",
        )
        findings = _run_infra_analysis(tmp_path)
        assert _has_rule(findings, "INFRA-CONFIG-002")


# --- Test Monitoraggio ---


class TestMonitoraggio:
    """Test per i check monitoraggio e health check."""

    def test_repo_senza_monitoring_finding_medium(self, repo_vuota: Path):
        """Repo senza monitoraggio → Finding medium INFRA-MON-001."""
        findings = _run_infra_analysis(repo_vuota)
        assert _has_rule(findings, "INFRA-MON-001")
        finding = _find_by_rule(findings, "INFRA-MON-001")[0]
        assert finding.severity == Severity.MEDIUM

    def test_repo_con_health_check_nessun_finding(self, tmp_path: Path):
        """Repo con endpoint /health → nessun finding INFRA-MON-001."""
        (tmp_path / "app.py").write_text(
            "from flask import Flask\n"
            "app = Flask(__name__)\n\n"
            "@app.get('/health')\n"
            "def health():\n"
            "    return {'status': 'ok'}\n",
            encoding="utf-8",
        )
        findings = _run_infra_analysis(tmp_path)
        assert not _has_rule(findings, "INFRA-MON-001")

    def test_repo_con_sentry_nessun_finding(self, tmp_path: Path):
        """Repo con Sentry → nessun finding INFRA-MON-001."""
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "sentry.properties").write_text(
            "defaults.org=myorg\n", encoding="utf-8"
        )
        findings = _run_infra_analysis(tmp_path)
        assert not _has_rule(findings, "INFRA-MON-001")

    def test_monitoring_finding_ha_framework_ref(self, repo_vuota: Path):
        """Il finding INFRA-MON-001 ha framework_ref NIS2."""
        findings = _run_infra_analysis(repo_vuota)
        mon_finding = _find_by_rule(findings, "INFRA-MON-001")[0]
        assert mon_finding.framework_ref is not None
        assert "NIS2" in mon_finding.framework_ref


# --- Test Integrazione / Scenari ---


class TestIntegrazione:
    """Test di integrazione su scenari complessi."""

    def test_repo_vuota_multipli_finding_penalizzanti(self, repo_vuota: Path):
        """Repo senza infra → finding penalizzanti per CI/CD e container/IaC."""
        findings = _run_infra_analysis(repo_vuota)
        non_info = [f for f in findings if f.severity != Severity.INFO]
        assert len(non_info) >= 1
        # CI/CD deve triggerare come HIGH
        rule_ids = {f.rule_id for f in non_info}
        assert "INFRA-CICD-001" in rule_ids

    def test_repo_ben_strutturata_pochi_finding(
        self, repo_ben_strutturata: Path
    ):
        """Repo ben strutturata → nessun finding critico o high."""
        findings = _run_infra_analysis(repo_ben_strutturata)
        critical_or_high = [
            f for f in findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        assert len(critical_or_high) == 0

    def test_repo_ben_strutturata_ha_finding_info(
        self, repo_ben_strutturata: Path
    ):
        """Repo ben strutturata → ha finding informativi."""
        findings = _run_infra_analysis(repo_ben_strutturata)
        info_findings = [f for f in findings if f.severity == Severity.INFO]
        assert len(info_findings) >= 1

    def test_tutti_i_finding_hanno_id_univoco(self, repo_vuota: Path):
        """Ogni finding ha un ID univoco."""
        findings = _run_infra_analysis(repo_vuota)
        ids = [f.id for f in findings]
        assert len(ids) == len(set(ids))

    def test_tutti_i_finding_hanno_rule_id(self, repo_vuota: Path):
        """Ogni finding ha un rule_id che inizia con INFRA-."""
        findings = _run_infra_analysis(repo_vuota)
        for f in findings:
            assert f.rule_id.startswith("INFRA-")

    def test_conteggio_finding_repo_minima(self, repo_minima: Path):
        """Repo minima ha finding attesi: CI/CD, container, IaC, deps, monitoring."""
        findings = _run_infra_analysis(repo_minima)
        rule_ids = {f.rule_id for f in findings}
        # Deve avere almeno questi finding
        assert "INFRA-CICD-001" in rule_ids    # Niente CI/CD
        assert "INFRA-DOCKER-001" in rule_ids  # Niente container
        assert "INFRA-IAC-001" in rule_ids     # Niente IaC
        assert "INFRA-DEPS-001" in rule_ids    # Niente lockfile
        assert "INFRA-MON-001" in rule_ids     # Niente monitoring


# --- Test .env.example ---


def _write(base: Path, rel: str, content: str) -> None:
    p = base / Path(rel)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


class TestEnvExample:
    """Test per il check INFRA-ENVEXAMPLE-001."""

    def test_gitignore_with_env_no_example(self, tmp_path: Path):
        """Gitignore ha .env ma nessun .env.example → finding."""
        _write(tmp_path, "app.py", "print('hello')\n")
        _write(tmp_path, ".gitignore", ".env\nnode_modules/\n")
        findings = _run_infra_analysis(tmp_path)
        assert _has_rule(findings, "INFRA-ENVEXAMPLE-001")
        finding = _find_by_rule(findings, "INFRA-ENVEXAMPLE-001")[0]
        assert finding.severity == Severity.MEDIUM

    def test_gitignore_with_env_and_example(self, tmp_path: Path):
        """Gitignore ha .env e .env.example presente → nessun finding."""
        _write(tmp_path, "app.py", "print('hello')\n")
        _write(tmp_path, ".gitignore", ".env\n")
        _write(tmp_path, ".env.example", "DB_HOST=localhost\nDB_PORT=5432\n")
        findings = _run_infra_analysis(tmp_path)
        assert not _has_rule(findings, "INFRA-ENVEXAMPLE-001")

    def test_gitignore_with_env_and_sample(self, tmp_path: Path):
        """Gitignore ha .env e .env.sample presente → nessun finding."""
        _write(tmp_path, "app.py", "print('hello')\n")
        _write(tmp_path, ".gitignore", ".env\n")
        _write(tmp_path, ".env.sample", "DB_HOST=localhost\n")
        findings = _run_infra_analysis(tmp_path)
        assert not _has_rule(findings, "INFRA-ENVEXAMPLE-001")

    def test_no_gitignore_no_finding(self, tmp_path: Path):
        """Nessun .gitignore → nessun finding."""
        _write(tmp_path, "app.py", "print('hello')\n")
        findings = _run_infra_analysis(tmp_path)
        assert not _has_rule(findings, "INFRA-ENVEXAMPLE-001")

    def test_gitignore_without_env_no_finding(self, tmp_path: Path):
        """Gitignore presente ma senza .env → nessun finding."""
        _write(tmp_path, "app.py", "print('hello')\n")
        _write(tmp_path, ".gitignore", "node_modules/\n*.pyc\n")
        findings = _run_infra_analysis(tmp_path)
        assert not _has_rule(findings, "INFRA-ENVEXAMPLE-001")
