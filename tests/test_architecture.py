"""
Test per ArchitectureAnalyzer (Blocco 8).

Verifica:
- ArchitectureAnalyzer rispetta l'interfaccia BaseAnalyzer
- Repo con import circolari → Finding ARCH-COUPLING-001
- Repo flat (tutto in root) → Finding ARCH-STRUCT-001
- Repo con pattern MVC chiaro → finding info, nessun finding struttura
- Repo con file >500 LOC → Finding ARCH-SCALE-001
- Repo senza test directory → Finding ARCH-TEST-001
- Repo con migrazioni DB → nessun finding ARCH-DB-001
- Repo con ORM senza migrazioni → Finding ARCH-DB-001
- Fan-out eccessivo → Finding ARCH-COUPLING-002
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cto_audit.analyzers.architecture import ArchitectureAnalyzer
from cto_audit.analyzers.base import BaseAnalyzer
from cto_audit.collectors.privacy import PrivacyClassifier
from cto_audit.collectors.scanner import FileScanner
from cto_audit.collectors.stack import StackDetector
from cto_audit.core.models import (
    Finding,
    Layer,
    Severity,
    StackInfo,
)
from cto_audit.sources.local import LocalRepoSource


# --- Helpers ---


def _run_arch_analysis(tmp_path: Path) -> list[Finding]:
    """Helper: esegue la pipeline completa fino all'ArchitectureAnalyzer."""
    source = LocalRepoSource(tmp_path)
    scanner = FileScanner(source)
    files = scanner.scan()
    detector = StackDetector(source)
    stack_info = detector.detect(files)
    classifier = PrivacyClassifier(source)
    classifications = classifier.classify(files)

    analyzer = ArchitectureAnalyzer()
    return analyzer.analyze(source, stack_info, classifications)


def _find_by_rule(findings: list[Finding], rule_id: str) -> list[Finding]:
    """Filtra i finding per rule_id."""
    return [f for f in findings if f.rule_id == rule_id]


def _has_rule(findings: list[Finding], rule_id: str) -> bool:
    """Verifica se un finding con un certo rule_id è presente."""
    return any(f.rule_id == rule_id for f in findings)


# --- Fixture ---


@pytest.fixture
def repo_flat(tmp_path: Path) -> Path:
    """Repository con struttura flat: tutti i file nella root."""
    for name in ["app.py", "models.py", "utils.py", "config.py", "db.py", "api.py"]:
        (tmp_path / name).write_text(
            f"# {name}\ndef func():\n    pass\n",
            encoding="utf-8",
        )
    return tmp_path


@pytest.fixture
def repo_mvc(tmp_path: Path) -> Path:
    """Repository con pattern MVC chiaro."""
    for d in ["models", "views", "controllers", "templates", "tests"]:
        (tmp_path / d).mkdir()

    (tmp_path / "models" / "user.py").write_text(
        "class User:\n    pass\n", encoding="utf-8",
    )
    (tmp_path / "views" / "home.py").write_text(
        "def home():\n    return 'home'\n", encoding="utf-8",
    )
    (tmp_path / "controllers" / "auth.py").write_text(
        "def login():\n    pass\n", encoding="utf-8",
    )
    (tmp_path / "tests" / "test_user.py").write_text(
        "def test_user():\n    assert True\n", encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "from models.user import User\n", encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def repo_circular_imports(tmp_path: Path) -> Path:
    """Repository con import circolari tra moduli Python."""
    (tmp_path / "src").mkdir()

    # Ciclo: a → b → c → a
    (tmp_path / "src" / "a.py").write_text(
        "from src.b import func_b\n\ndef func_a():\n    return func_b()\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "b.py").write_text(
        "from src.c import func_c\n\ndef func_b():\n    return func_c()\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "c.py").write_text(
        "from src.a import func_a\n\ndef func_c():\n    return func_a()\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def repo_file_grande(tmp_path: Path) -> Path:
    """Repository con un file Python molto grande (>500 LOC)."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text(
        "def test_ok():\n    assert True\n", encoding="utf-8",
    )

    # Crea un file con 600 righe
    lines = ["# File grande\n"]
    for i in range(600):
        lines.append(f"def func_{i}():\n    return {i}\n\n")
    (tmp_path / "big_module.py").write_text("".join(lines), encoding="utf-8")

    return tmp_path


@pytest.fixture
def repo_senza_test(tmp_path: Path) -> Path:
    """Repository senza directory o file di test."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "def main():\n    print('hello')\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "utils.py").write_text(
        "def helper():\n    return True\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def repo_con_test(tmp_path: Path) -> Path:
    """Repository con directory tests."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "def main():\n    print('hello')\n", encoding="utf-8",
    )
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text(
        "def test_main():\n    assert True\n", encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def repo_orm_senza_migrazioni(tmp_path: Path) -> Path:
    """Repository con ORM (SQLAlchemy) ma senza migrazioni."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "from sqlalchemy import create_engine\n"
        "engine = create_engine('sqlite:///db.sqlite')\n",
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text(
        "sqlalchemy>=2.0\nflask>=3.0\n",
        encoding="utf-8",
    )
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_db.py").write_text(
        "def test_db():\n    assert True\n", encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def repo_orm_con_migrazioni(tmp_path: Path) -> Path:
    """Repository con ORM e directory migrazioni."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "from sqlalchemy import create_engine\n",
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text(
        "sqlalchemy>=2.0\nalembic>=1.0\n",
        encoding="utf-8",
    )
    (tmp_path / "alembic").mkdir()
    (tmp_path / "alembic" / "env.py").write_text(
        "# alembic config\n", encoding="utf-8",
    )
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_db.py").write_text(
        "def test_db():\n    assert True\n", encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def repo_layered(tmp_path: Path) -> Path:
    """Repository con pattern layered / Clean Architecture."""
    for d in ["domain", "application", "infrastructure", "tests"]:
        (tmp_path / d).mkdir()

    (tmp_path / "domain" / "entities.py").write_text(
        "class User:\n    pass\n", encoding="utf-8",
    )
    (tmp_path / "application" / "services.py").write_text(
        "class UserService:\n    pass\n", encoding="utf-8",
    )
    (tmp_path / "infrastructure" / "db.py").write_text(
        "class Database:\n    pass\n", encoding="utf-8",
    )
    (tmp_path / "tests" / "test_domain.py").write_text(
        "def test_user():\n    assert True\n", encoding="utf-8",
    )
    return tmp_path


# --- Test BaseAnalyzer ---


class TestBaseAnalyzer:
    """Test per l'interfaccia BaseAnalyzer."""

    def test_protocol_runtime_checkable(self):
        """ArchitectureAnalyzer implementa BaseAnalyzer."""
        analyzer = ArchitectureAnalyzer()
        assert isinstance(analyzer, BaseAnalyzer)

    def test_tutti_i_finding_sono_layer_architecture(self, repo_flat: Path):
        """Tutti i finding prodotti hanno layer=architecture."""
        findings = _run_arch_analysis(repo_flat)
        assert all(f.layer == Layer.ARCHITECTURE for f in findings)

    def test_finding_hanno_id_univoco(self, repo_flat: Path):
        """Ogni finding ha un ID univoco."""
        findings = _run_arch_analysis(repo_flat)
        ids = [f.id for f in findings]
        assert len(ids) == len(set(ids))

    def test_finding_hanno_rule_id_arch(self, repo_flat: Path):
        """Ogni finding ha un rule_id che inizia con ARCH-."""
        findings = _run_arch_analysis(repo_flat)
        for f in findings:
            assert f.rule_id.startswith("ARCH-")


# --- Test Struttura Directory ---


class TestStruttura:
    """Test per il rilevamento del pattern architetturale."""

    def test_repo_flat_finding_struct(self, repo_flat: Path):
        """Repo flat → Finding ARCH-STRUCT-001."""
        findings = _run_arch_analysis(repo_flat)
        assert _has_rule(findings, "ARCH-STRUCT-001")
        finding = _find_by_rule(findings, "ARCH-STRUCT-001")[0]
        assert finding.severity == Severity.MEDIUM

    def test_repo_mvc_no_finding_struct(self, repo_mvc: Path):
        """Repo MVC → nessun finding ARCH-STRUCT-001."""
        findings = _run_arch_analysis(repo_mvc)
        assert not _has_rule(findings, "ARCH-STRUCT-001")

    def test_repo_mvc_finding_info(self, repo_mvc: Path):
        """Repo MVC → finding info ARCH-STRUCT-INFO."""
        findings = _run_arch_analysis(repo_mvc)
        assert _has_rule(findings, "ARCH-STRUCT-INFO")
        info = _find_by_rule(findings, "ARCH-STRUCT-INFO")[0]
        assert info.severity == Severity.INFO
        assert "MVC" in info.title

    def test_repo_layered_finding_info(self, repo_layered: Path):
        """Repo layered → finding info ARCH-STRUCT-INFO."""
        findings = _run_arch_analysis(repo_layered)
        assert _has_rule(findings, "ARCH-STRUCT-INFO")
        info = _find_by_rule(findings, "ARCH-STRUCT-INFO")[0]
        assert info.severity == Severity.INFO
        assert "layered" in info.title.lower() or "clean" in info.title.lower()


# --- Test Coupling ---


class TestCoupling:
    """Test per il rilevamento di import circolari e fan-out."""

    def test_import_circolari_finding(self, repo_circular_imports: Path):
        """Repo con import circolari → Finding ARCH-COUPLING-001."""
        findings = _run_arch_analysis(repo_circular_imports)
        assert _has_rule(findings, "ARCH-COUPLING-001")
        finding = _find_by_rule(findings, "ARCH-COUPLING-001")[0]
        assert finding.severity == Severity.HIGH

    def test_import_circolari_contiene_cicli(self, repo_circular_imports: Path):
        """Il finding per import circolari descrive i cicli."""
        findings = _run_arch_analysis(repo_circular_imports)
        finding = _find_by_rule(findings, "ARCH-COUPLING-001")[0]
        # La descrizione deve menzionare i moduli coinvolti
        assert "src.a" in finding.description or "src.b" in finding.description

    def test_repo_senza_cicli_no_finding_coupling(self, repo_mvc: Path):
        """Repo senza import circolari → nessun finding ARCH-COUPLING-001."""
        findings = _run_arch_analysis(repo_mvc)
        assert not _has_rule(findings, "ARCH-COUPLING-001")

    def test_fan_out_eccessivo(self, tmp_path: Path):
        """Modulo con troppi import interni → Finding ARCH-COUPLING-002."""
        (tmp_path / "src").mkdir()
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_x.py").write_text(
            "def test_ok():\n    assert True\n", encoding="utf-8",
        )

        # Crea 12 moduli piccoli
        for i in range(12):
            (tmp_path / "src" / f"mod_{i}.py").write_text(
                f"def func_{i}():\n    return {i}\n", encoding="utf-8",
            )

        # Un modulo che importa tutti
        imports = "\n".join(f"from src.mod_{i} import func_{i}" for i in range(12))
        (tmp_path / "src" / "orchestrator.py").write_text(
            f"{imports}\n\ndef run_all():\n    pass\n",
            encoding="utf-8",
        )

        findings = _run_arch_analysis(tmp_path)
        assert _has_rule(findings, "ARCH-COUPLING-002")
        finding = _find_by_rule(findings, "ARCH-COUPLING-002")[0]
        assert finding.severity == Severity.MEDIUM


# --- Test File Grandi ---


class TestFileGrandi:
    """Test per il rilevamento di file troppo grandi."""

    def test_file_grande_finding(self, repo_file_grande: Path):
        """File >500 LOC → Finding ARCH-SCALE-001."""
        findings = _run_arch_analysis(repo_file_grande)
        assert _has_rule(findings, "ARCH-SCALE-001")
        finding = _find_by_rule(findings, "ARCH-SCALE-001")[0]
        assert finding.severity == Severity.MEDIUM
        assert "big_module.py" in finding.title

    def test_file_piccolo_nessun_finding(self, repo_mvc: Path):
        """File piccoli → nessun finding ARCH-SCALE-001."""
        findings = _run_arch_analysis(repo_mvc)
        assert not _has_rule(findings, "ARCH-SCALE-001")

    def test_file_grande_ha_file_path(self, repo_file_grande: Path):
        """Il finding per file grande ha file_path impostato."""
        findings = _run_arch_analysis(repo_file_grande)
        finding = _find_by_rule(findings, "ARCH-SCALE-001")[0]
        assert finding.file_path == "big_module.py"


# --- Test Directory Test ---


class TestDirectoryTest:
    """Test per la verifica della directory test."""

    def test_repo_senza_test_finding(self, repo_senza_test: Path):
        """Repo senza test → Finding ARCH-TEST-001."""
        findings = _run_arch_analysis(repo_senza_test)
        assert _has_rule(findings, "ARCH-TEST-001")
        finding = _find_by_rule(findings, "ARCH-TEST-001")[0]
        assert finding.severity == Severity.CRITICAL

    def test_repo_con_test_dir_nessun_finding(self, repo_con_test: Path):
        """Repo con directory tests/ → nessun finding ARCH-TEST-001."""
        findings = _run_arch_analysis(repo_con_test)
        assert not _has_rule(findings, "ARCH-TEST-001")

    def test_repo_con_file_test_nessun_finding(self, tmp_path: Path):
        """Repo con file test_*.py in root → nessun finding ARCH-TEST-001."""
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "test_app.py").write_text(
            "def test_ok():\n    assert True\n", encoding="utf-8",
        )
        findings = _run_arch_analysis(tmp_path)
        assert not _has_rule(findings, "ARCH-TEST-001")


# --- Test Database / Migrazioni ---


class TestDatabase:
    """Test per il rilevamento ORM e migrazioni."""

    def test_orm_senza_migrazioni_finding(self, repo_orm_senza_migrazioni: Path):
        """ORM presente senza migrazioni → Finding ARCH-DB-001."""
        findings = _run_arch_analysis(repo_orm_senza_migrazioni)
        assert _has_rule(findings, "ARCH-DB-001")
        finding = _find_by_rule(findings, "ARCH-DB-001")[0]
        assert finding.severity == Severity.MEDIUM
        assert "SQLAlchemy" in finding.description

    def test_orm_con_migrazioni_nessun_finding(self, repo_orm_con_migrazioni: Path):
        """ORM con migrazioni → nessun finding ARCH-DB-001."""
        findings = _run_arch_analysis(repo_orm_con_migrazioni)
        assert not _has_rule(findings, "ARCH-DB-001")

    def test_repo_senza_orm_nessun_finding_db(self, repo_mvc: Path):
        """Repo senza ORM → nessun finding ARCH-DB-001."""
        findings = _run_arch_analysis(repo_mvc)
        assert not _has_rule(findings, "ARCH-DB-001")


# --- Test Integrazione ---


class TestIntegrazione:
    """Test di integrazione su scenari complessi."""

    def test_repo_ben_organizzata(self, repo_mvc: Path):
        """Repo MVC con test → nessun finding critico."""
        findings = _run_arch_analysis(repo_mvc)
        critical_or_high = [
            f for f in findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        assert len(critical_or_high) == 0

    def test_repo_problematica_multipli_finding(self, tmp_path: Path):
        """Repo con problemi multipli → finding attesi presenti."""
        # Struttura flat, niente test, file grande
        for name in ["a.py", "b.py", "c.py", "d.py", "e.py"]:
            (tmp_path / name).write_text(
                f"# {name}\ndef func():\n    pass\n", encoding="utf-8",
            )
        # File grande
        lines = [f"def f{i}():\n    return {i}\n\n" for i in range(600)]
        (tmp_path / "big.py").write_text("".join(lines), encoding="utf-8")

        findings = _run_arch_analysis(tmp_path)

        # Deve avere almeno: flat structure, no test, file grande
        rule_ids = {f.rule_id for f in findings}
        assert "ARCH-STRUCT-001" in rule_ids
        assert "ARCH-TEST-001" in rule_ids
        assert "ARCH-SCALE-001" in rule_ids

    def test_conteggio_finding_repo_layered(self, repo_layered: Path):
        """Repo layered ben organizzata → finding informativi."""
        findings = _run_arch_analysis(repo_layered)
        # Deve avere un finding info per la struttura
        info_findings = [f for f in findings if f.severity == Severity.INFO]
        assert len(info_findings) >= 1
        # Non deve avere finding di test (ha directory tests)
        assert not _has_rule(findings, "ARCH-TEST-001")
