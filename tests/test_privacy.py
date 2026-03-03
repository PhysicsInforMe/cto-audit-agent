"""
Test per il PrivacyClassifier (Blocco 4).

Verifica tutte le regole di classificazione dal doc 03-hitl-flow.md:
- SENSITIVE: .env, .pem, private key, alta entropia, password in file
- EXCLUDED: node_modules, lockfile, .png, file > 1MB
- SAFE: file normali di codice sorgente
- Motivo sempre presente e leggibile
"""

from __future__ import annotations

import string
from pathlib import Path

import pytest

from cto_audit.collectors.privacy import (
    ENTROPY_THRESHOLD,
    PrivacyClassifier,
    _shannon_entropy,
)
from cto_audit.collectors.scanner import FileScanner
from cto_audit.core.models import FileInfo, PrivacyCategory
from cto_audit.sources.local import LocalRepoSource


# --- Helper per creare FileInfo e classificare singoli file ---


def _classify_single(tmp_path: Path, filename: str, content: str | bytes = "") -> tuple:
    """
    Helper: crea un file, scansiona e classifica, restituisce (category, reason).

    Per file di testo passa content come str, per binari come bytes.
    Supporta anche path con sottodirectory (es. "config/prod/db.yml").
    """
    file_path = tmp_path / filename
    file_path.parent.mkdir(parents=True, exist_ok=True)

    if isinstance(content, bytes):
        file_path.write_bytes(content)
    else:
        file_path.write_text(content, encoding="utf-8")

    source = LocalRepoSource(tmp_path)
    scanner = FileScanner(source)
    classifier = PrivacyClassifier(source)

    files = scanner.scan()
    classifications = classifier.classify(files)

    # Trova la classificazione del file che ci interessa
    # (normalizza percorso per confronto)
    target = filename.replace("\\", "/")
    for c in classifications:
        if c.file_info.path == target:
            return (c.category, c.reason, c.confidence)

    # Se non trovato (potrebbe essere escluso dallo scanner)
    # classifica direttamente il FileInfo
    fi = FileInfo(
        path=target,
        size=file_path.stat().st_size,
        extension="." + target.rsplit(".", 1)[1] if "." in target.split("/")[-1] else "",
        lines_of_code=0,
    )
    result = classifier.classify([fi])
    return (result[0].category, result[0].reason, result[0].confidence)


# ===== Test SENSITIVE =====


class TestSensitiveFilename:
    """Test per file classificati come SENSITIVE per nome file."""

    def test_env_file(self, tmp_path: Path):
        """File .env con PASSWORD → 🔴 SENSITIVE."""
        cat, reason, _ = _classify_single(
            tmp_path, ".env", "DB_PASSWORD=secret123\nAPI_KEY=abc\n"
        )
        assert cat == PrivacyCategory.SENSITIVE
        assert "sensibile" in reason.lower() or "pattern" in reason.lower()

    def test_env_production(self, tmp_path: Path):
        """File .env.production → 🔴 SENSITIVE (pattern .env.*)."""
        cat, reason, _ = _classify_single(
            tmp_path, ".env.production", "SECRET=xyz\n"
        )
        assert cat == PrivacyCategory.SENSITIVE

    def test_server_pem(self, tmp_path: Path):
        """File server.pem → 🔴 SENSITIVE."""
        cat, reason, _ = _classify_single(
            tmp_path, "server.pem", "--- cert data ---\n"
        )
        assert cat == PrivacyCategory.SENSITIVE
        assert "pem" in reason.lower() or "pattern" in reason.lower()

    def test_private_key_file(self, tmp_path: Path):
        """File private.key → 🔴 SENSITIVE."""
        cat, reason, _ = _classify_single(
            tmp_path, "private.key", "key data\n"
        )
        assert cat == PrivacyCategory.SENSITIVE

    def test_id_rsa(self, tmp_path: Path):
        """File id_rsa → 🔴 SENSITIVE."""
        cat, reason, _ = _classify_single(
            tmp_path, "id_rsa", "ssh key data\n"
        )
        assert cat == PrivacyCategory.SENSITIVE

    def test_secrets_yml(self, tmp_path: Path):
        """File secrets.yml → 🔴 SENSITIVE (pattern secrets.*)."""
        cat, reason, _ = _classify_single(
            tmp_path, "secrets.yml", "db_password: secret\n"
        )
        assert cat == PrivacyCategory.SENSITIVE

    def test_credentials_json(self, tmp_path: Path):
        """File credentials.json → 🔴 SENSITIVE (pattern credentials.*)."""
        cat, reason, _ = _classify_single(
            tmp_path, "credentials.json", '{"key": "value"}\n'
        )
        assert cat == PrivacyCategory.SENSITIVE

    def test_htpasswd(self, tmp_path: Path):
        """File .htpasswd → 🔴 SENSITIVE."""
        cat, reason, _ = _classify_single(
            tmp_path, ".htpasswd", "user:$apr1$...\n"
        )
        assert cat == PrivacyCategory.SENSITIVE

    def test_keystore(self, tmp_path: Path):
        """File app.keystore → 🔴 SENSITIVE."""
        cat, reason, _ = _classify_single(
            tmp_path, "app.keystore", "keystore data\n"
        )
        assert cat == PrivacyCategory.SENSITIVE


class TestSensitiveContent:
    """Test per file classificati come SENSITIVE per contenuto."""

    def test_private_key_pem_nel_contenuto(self, tmp_path: Path):
        """File con -----BEGIN PRIVATE KEY----- → 🔴 SENSITIVE."""
        cat, reason, _ = _classify_single(
            tmp_path, "config.txt",
            "some config\n-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANB...\n-----END PRIVATE KEY-----\n"
        )
        assert cat == PrivacyCategory.SENSITIVE
        assert "chiave privata" in reason.lower() or "private" in reason.lower()

    def test_rsa_private_key_nel_contenuto(self, tmp_path: Path):
        """File con -----BEGIN RSA PRIVATE KEY----- → 🔴 SENSITIVE."""
        cat, reason, _ = _classify_single(
            tmp_path, "key.conf",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ...\n-----END RSA PRIVATE KEY-----\n"
        )
        assert cat == PrivacyCategory.SENSITIVE

    def test_password_nel_contenuto(self, tmp_path: Path):
        """File con password=xxx nel contenuto → 🔴 SENSITIVE."""
        cat, reason, _ = _classify_single(
            tmp_path, "config.ini",
            "[database]\nhost=localhost\npassword=mysecretpassword\nport=5432\n"
        )
        assert cat == PrivacyCategory.SENSITIVE
        assert "password" in reason.lower()

    def test_api_key_nel_contenuto(self, tmp_path: Path):
        """File con api_key=xxx nel contenuto → 🔴 SENSITIVE."""
        cat, reason, _ = _classify_single(
            tmp_path, "settings.py",
            "DEBUG = True\nAPI_KEY = 'sk-1234567890abcdef'\nHOST = 'localhost'\n"
        )
        assert cat == PrivacyCategory.SENSITIVE
        assert "api" in reason.lower() or "key" in reason.lower()

    def test_aws_credentials_nel_contenuto(self, tmp_path: Path):
        """File con aws_access_key_id → 🔴 SENSITIVE."""
        cat, reason, _ = _classify_single(
            tmp_path, "aws.conf",
            "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtn...\n"
        )
        assert cat == PrivacyCategory.SENSITIVE
        assert "aws" in reason.lower()

    def test_database_url_nel_contenuto(self, tmp_path: Path):
        """File con database_url → 🔴 SENSITIVE."""
        cat, reason, _ = _classify_single(
            tmp_path, "app_config.py",
            "DATABASE_URL = 'postgresql://user:pass@host:5432/db'\n"
        )
        assert cat == PrivacyCategory.SENSITIVE
        assert "database" in reason.lower()

    def test_connection_string_nel_contenuto(self, tmp_path: Path):
        """File con connection_string → 🔴 SENSITIVE."""
        cat, reason, _ = _classify_single(
            tmp_path, "db.yml",
            "connection_string: Server=host;Database=mydb;User=sa;Password=secret\n"
        )
        assert cat == PrivacyCategory.SENSITIVE

    def test_docker_compose_prod_con_password(self, tmp_path: Path):
        """docker-compose.prod.yml CON password → 🔴 SENSITIVE."""
        cat, reason, _ = _classify_single(
            tmp_path, "docker-compose.prod.yml",
            "version: '3'\nservices:\n  db:\n    environment:\n"
            "      POSTGRES_PASSWORD=mysecretpassword123\n"
        )
        assert cat == PrivacyCategory.SENSITIVE
        assert "password" in reason.lower()


class TestSensitiveEntropy:
    """Test per file classificati come SENSITIVE per alta entropia."""

    def test_alta_entropia_api_key(self, tmp_path: Path):
        """File con stringa ad alta entropia (API key) → 🔴 SENSITIVE."""
        # Genera una stringa ad alta entropia (simula una API key reale)
        high_entropy_value = "sk_FAKE_aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5"
        cat, reason, _ = _classify_single(
            tmp_path, "config.env.example",
            f"# Config example\nSTRIPE_KEY={high_entropy_value}\n"
        )
        assert cat == PrivacyCategory.SENSITIVE
        assert "entropia" in reason.lower()

    def test_bassa_entropia_non_sensibile(self, tmp_path: Path):
        """File con valore a bassa entropia → NON sensitive per entropia."""
        cat, reason, _ = _classify_single(
            tmp_path, "config.txt",
            "setting = aaaaaaaaaaaaaaaaaaaaaa\nname = test-project-name-here\n"
        )
        # Potrebbe essere SAFE (bassa entropia, nessun pattern)
        assert cat == PrivacyCategory.SAFE


class TestSensitivePath:
    """Test per file classificati come SENSITIVE per pattern di percorso."""

    def test_config_prod(self, tmp_path: Path):
        """File in config/prod/ → 🔴 SENSITIVE."""
        cat, reason, _ = _classify_single(
            tmp_path, "config/prod/database.yml",
            "host: prod-db.example.com\nport: 5432\n"
        )
        assert cat == PrivacyCategory.SENSITIVE
        assert "percorso" in reason.lower() or "path" in reason.lower() or "prod" in reason.lower()

    def test_deploy_prod(self, tmp_path: Path):
        """File in deploy/prod/ → 🔴 SENSITIVE."""
        cat, reason, _ = _classify_single(
            tmp_path, "deploy/prod/vars.yml",
            "region: eu-west-1\n"
        )
        assert cat == PrivacyCategory.SENSITIVE


# ===== Test EXCLUDED =====


class TestExcludedExtension:
    """Test per file classificati come EXCLUDED per estensione."""

    def test_png(self, tmp_path: Path):
        """File .png → ⚫ EXCLUDED."""
        cat, reason, _ = _classify_single(
            tmp_path, "logo.png", b"\x89PNG\x00\x00"
        )
        assert cat == PrivacyCategory.EXCLUDED
        assert "estensione" in reason.lower() or ".png" in reason.lower()

    def test_jpg(self, tmp_path: Path):
        """File .jpg → ⚫ EXCLUDED."""
        cat, reason, _ = _classify_single(tmp_path, "photo.jpg", b"\xff\xd8\xff")
        assert cat == PrivacyCategory.EXCLUDED

    def test_exe(self, tmp_path: Path):
        """File .exe → ⚫ EXCLUDED."""
        cat, reason, _ = _classify_single(tmp_path, "app.exe", b"MZ\x00\x00")
        assert cat == PrivacyCategory.EXCLUDED

    def test_pyc(self, tmp_path: Path):
        """File .pyc → ⚫ EXCLUDED."""
        cat, reason, _ = _classify_single(tmp_path, "module.pyc", b"\x00\x00\x00")
        assert cat == PrivacyCategory.EXCLUDED

    def test_sqlite(self, tmp_path: Path):
        """File .sqlite → ⚫ EXCLUDED."""
        cat, reason, _ = _classify_single(tmp_path, "data.sqlite", b"SQLite format")
        assert cat == PrivacyCategory.EXCLUDED


class TestExcludedLockfile:
    """Test per file classificati come EXCLUDED perché lockfile."""

    def test_package_lock(self, tmp_path: Path):
        """package-lock.json → ⚫ EXCLUDED."""
        cat, reason, _ = _classify_single(
            tmp_path, "package-lock.json", '{"lockfileVersion": 3}\n'
        )
        assert cat == PrivacyCategory.EXCLUDED
        assert "lockfile" in reason.lower()

    def test_yarn_lock(self, tmp_path: Path):
        """yarn.lock → ⚫ EXCLUDED."""
        cat, reason, _ = _classify_single(
            tmp_path, "yarn.lock", "# yarn lockfile v1\n"
        )
        assert cat == PrivacyCategory.EXCLUDED

    def test_poetry_lock(self, tmp_path: Path):
        """poetry.lock → ⚫ EXCLUDED."""
        cat, reason, _ = _classify_single(
            tmp_path, "poetry.lock", "[[package]]\n"
        )
        assert cat == PrivacyCategory.EXCLUDED

    def test_cargo_lock(self, tmp_path: Path):
        """Cargo.lock → ⚫ EXCLUDED."""
        cat, reason, _ = _classify_single(
            tmp_path, "Cargo.lock", "[[package]]\nname = \"serde\"\n"
        )
        assert cat == PrivacyCategory.EXCLUDED

    def test_pipfile_lock(self, tmp_path: Path):
        """Pipfile.lock → ⚫ EXCLUDED."""
        cat, reason, _ = _classify_single(
            tmp_path, "Pipfile.lock", '{"_meta": {}}\n'
        )
        assert cat == PrivacyCategory.EXCLUDED

    def test_gemfile_lock(self, tmp_path: Path):
        """Gemfile.lock → ⚫ EXCLUDED."""
        cat, reason, _ = _classify_single(
            tmp_path, "Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n"
        )
        assert cat == PrivacyCategory.EXCLUDED


class TestExcludedSize:
    """Test per file classificati come EXCLUDED per dimensione."""

    def test_file_grande(self, tmp_path: Path):
        """File > 1MB → ⚫ EXCLUDED."""
        # Crea file da 1.5 MB
        big_content = "x" * (1_048_576 + 500_000)
        cat, reason, _ = _classify_single(tmp_path, "big_data.csv", big_content)
        assert cat == PrivacyCategory.EXCLUDED
        assert "grande" in reason.lower() or "mb" in reason.lower()

    def test_file_esattamente_1mb_non_escluso(self, tmp_path: Path):
        """File esattamente 1MB → NON escluso per dimensione (limite è >1MB)."""
        content = "x" * 1_048_576
        cat, reason, _ = _classify_single(tmp_path, "exact.csv", content)
        # Non dovrebbe essere EXCLUDED per dimensione (= non >)
        assert cat != PrivacyCategory.EXCLUDED or "grande" not in reason.lower()


class TestExcludedDirectory:
    """Test per file classificati come EXCLUDED per directory."""

    def test_node_modules(self, tmp_path: Path):
        """File in node_modules/ → ⚫ EXCLUDED."""
        fi = FileInfo(
            path="node_modules/lodash/index.js",
            size=100,
            extension=".js",
            lines_of_code=5,
        )
        source = LocalRepoSource(tmp_path)
        classifier = PrivacyClassifier(source)
        result = classifier.classify([fi])
        assert result[0].category == PrivacyCategory.EXCLUDED
        assert "node_modules" in result[0].reason

    def test_vendor(self, tmp_path: Path):
        """File in vendor/ → ⚫ EXCLUDED."""
        fi = FileInfo(
            path="vendor/autoload.php",
            size=50,
            extension=".php",
            lines_of_code=2,
        )
        source = LocalRepoSource(tmp_path)
        classifier = PrivacyClassifier(source)
        result = classifier.classify([fi])
        assert result[0].category == PrivacyCategory.EXCLUDED


# ===== Test SAFE =====


class TestSafe:
    """Test per file classificati come SAFE."""

    def test_routes_py_normale(self, tmp_path: Path):
        """File src/api/routes.py normale → 🟢 SAFE."""
        cat, reason, _ = _classify_single(
            tmp_path, "src/api/routes.py",
            "from fastapi import APIRouter\n\nrouter = APIRouter()\n\n"
            "@router.get('/health')\ndef health():\n    return {'status': 'ok'}\n"
        )
        assert cat == PrivacyCategory.SAFE
        assert "nessun pattern" in reason.lower()

    def test_dockerfile_senza_secrets(self, tmp_path: Path):
        """Dockerfile senza secrets → 🟢 SAFE."""
        cat, reason, _ = _classify_single(
            tmp_path, "Dockerfile",
            "FROM python:3.11-slim\nWORKDIR /app\nCOPY . .\nCMD [\"python\", \"main.py\"]\n"
        )
        assert cat == PrivacyCategory.SAFE

    def test_docker_compose_senza_password(self, tmp_path: Path):
        """docker-compose.yml SENZA password → 🟢 SAFE."""
        cat, reason, _ = _classify_single(
            tmp_path, "docker-compose.yml",
            "version: '3'\nservices:\n  web:\n    build: .\n    ports:\n      - '8000:8000'\n"
        )
        assert cat == PrivacyCategory.SAFE

    def test_readme(self, tmp_path: Path):
        """README.md → 🟢 SAFE."""
        cat, reason, _ = _classify_single(
            tmp_path, "README.md", "# My Project\n\nA cool project.\n"
        )
        assert cat == PrivacyCategory.SAFE

    def test_python_source(self, tmp_path: Path):
        """File Python normale → 🟢 SAFE."""
        cat, reason, _ = _classify_single(
            tmp_path, "app.py",
            "import os\nfrom pathlib import Path\n\ndef main():\n    print('hello')\n"
        )
        assert cat == PrivacyCategory.SAFE

    def test_github_actions(self, tmp_path: Path):
        """File CI/CD senza secrets → 🟢 SAFE."""
        cat, reason, _ = _classify_single(
            tmp_path, "ci.yml",
            "name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - uses: actions/checkout@v4\n"
        )
        assert cat == PrivacyCategory.SAFE


# ===== Test motivo sempre presente e leggibile =====


class TestReasonPresente:
    """Verifica che il motivo sia sempre presente e leggibile."""

    def test_reason_non_vuota_per_ogni_classificazione(self, tmp_path: Path):
        """Ogni classificazione ha un motivo non vuoto."""
        # Crea repo con mix di file
        (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
        (tmp_path / ".env").write_text("SECRET=abc\n", encoding="utf-8")
        (tmp_path / "logo.png").write_bytes(b"\x89PNG\x00")
        (tmp_path / "package-lock.json").write_text("{}\n", encoding="utf-8")

        source = LocalRepoSource(tmp_path)
        scanner = FileScanner(source)
        classifier = PrivacyClassifier(source)
        files = scanner.scan()
        classifications = classifier.classify(files)

        for c in classifications:
            assert c.reason, f"Motivo vuoto per {c.file_info.path}"
            assert len(c.reason) > 5, f"Motivo troppo corto per {c.file_info.path}: {c.reason}"

    def test_confidence_sempre_valida(self, tmp_path: Path):
        """La confidenza è sempre tra 0.0 e 1.0."""
        (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
        (tmp_path / ".env").write_text("PASSWORD=secret123abc\n", encoding="utf-8")

        source = LocalRepoSource(tmp_path)
        scanner = FileScanner(source)
        classifier = PrivacyClassifier(source)
        files = scanner.scan()
        classifications = classifier.classify(files)

        for c in classifications:
            assert 0.0 <= c.confidence <= 1.0, (
                f"Confidenza fuori range per {c.file_info.path}: {c.confidence}"
            )


# ===== Test funzione entropia Shannon =====


class TestShannonEntropy:
    """Test per la funzione di calcolo entropia."""

    def test_stringa_vuota(self):
        """Stringa vuota → entropia 0."""
        assert _shannon_entropy("") == 0.0

    def test_stringa_costante(self):
        """Stringa con un solo carattere ripetuto → entropia 0."""
        assert _shannon_entropy("aaaaaaaaaa") == 0.0

    def test_stringa_due_caratteri_bilanciata(self):
        """Stringa con 2 caratteri equamente distribuiti → entropia 1.0."""
        entropy = _shannon_entropy("abababababababab")
        assert abs(entropy - 1.0) < 0.01

    def test_api_key_alta_entropia(self):
        """Una API key tipica ha entropia > 4.5."""
        api_key = "sk_FAKE_aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5"
        entropy = _shannon_entropy(api_key)
        assert entropy > ENTROPY_THRESHOLD

    def test_parola_normale_bassa_entropia(self):
        """Una parola normale ha entropia bassa."""
        entropy = _shannon_entropy("hello world")
        assert entropy < ENTROPY_THRESHOLD

    def test_codice_python_entropia_media(self):
        """Codice Python ha entropia media (< soglia)."""
        code = "def calculate_total(items):\n    return sum(item.price for item in items)\n"
        entropy = _shannon_entropy(code)
        assert entropy < ENTROPY_THRESHOLD


# ===== Test integrazione pipeline completa =====


class TestIntegrazionePipeline:
    """Test che verificano la pipeline Scanner → PrivacyClassifier."""

    def test_pipeline_completa(self, tmp_path: Path):
        """Pipeline completa produce classificazioni per tutti i file scansionati."""
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("print('hello')\n", encoding="utf-8")
        (tmp_path / "src" / "models.py").write_text("class User: pass\n", encoding="utf-8")
        (tmp_path / ".env").write_text("SECRET=abc123\n", encoding="utf-8")
        (tmp_path / "logo.png").write_bytes(b"\x89PNG\x00")
        (tmp_path / "package-lock.json").write_text("{}\n", encoding="utf-8")

        source = LocalRepoSource(tmp_path)
        scanner = FileScanner(source)
        classifier = PrivacyClassifier(source)

        files = scanner.scan()
        classifications = classifier.classify(files)

        # Una classificazione per ogni file scansionato
        assert len(classifications) == len(files)

        # Verifica categorie
        cat_map = {c.file_info.path: c.category for c in classifications}
        assert cat_map["src/app.py"] == PrivacyCategory.SAFE
        assert cat_map["src/models.py"] == PrivacyCategory.SAFE
        assert cat_map[".env"] == PrivacyCategory.SENSITIVE
        assert cat_map["logo.png"] == PrivacyCategory.EXCLUDED
        assert cat_map["package-lock.json"] == PrivacyCategory.EXCLUDED

    def test_conteggio_per_categoria(self, tmp_path: Path):
        """I conteggi per categoria sono coerenti."""
        # Crea un mix ragionevole
        (tmp_path / "a.py").write_text("pass\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("pass\n", encoding="utf-8")
        (tmp_path / "c.js").write_text("// ok\n", encoding="utf-8")
        (tmp_path / ".env").write_text("KEY=val\n", encoding="utf-8")
        (tmp_path / "icon.svg").write_text("<svg></svg>", encoding="utf-8")

        source = LocalRepoSource(tmp_path)
        scanner = FileScanner(source)
        classifier = PrivacyClassifier(source)

        files = scanner.scan()
        classifications = classifier.classify(files)

        by_category = {}
        for c in classifications:
            by_category.setdefault(c.category, []).append(c)

        safe_count = len(by_category.get(PrivacyCategory.SAFE, []))
        sensitive_count = len(by_category.get(PrivacyCategory.SENSITIVE, []))
        excluded_count = len(by_category.get(PrivacyCategory.EXCLUDED, []))

        assert safe_count == 3  # a.py, b.py, c.js
        assert sensitive_count == 1  # .env
        assert excluded_count == 1  # icon.svg
