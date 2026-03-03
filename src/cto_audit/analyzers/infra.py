"""
Infra Analyzer — Layer 1: Infrastruttura.

Primo layer di analisi, il più importante per un CTO.
Verifica la presenza e qualità di:
- CI/CD pipeline (GitHub Actions, GitLab CI, Jenkins, etc.)
- Containerizzazione (Dockerfile, docker-compose, Kubernetes)
- Infrastructure as Code (Terraform, CloudFormation, Ansible, Pulumi)
- Gestione dipendenze (lockfile, versioni pinned)
- Configurazione (secrets in chiaro, .env pattern)
- Monitoraggio (health checks, logging, error tracking)

Analisi deterministica (pattern matching, file existence, contenuto).
Infra-agnostico: non assume quale tipo di infra troverà.
"""

from __future__ import annotations

import re
import uuid

from cto_audit.core.models import (
    FileClassification,
    Finding,
    Layer,
    PrivacyCategory,
    Severity,
    StackInfo,
)
from cto_audit.core.source import AuditSource


# --- Marker CI/CD ---

CICD_MARKERS: dict[str, str] = {
    ".github/workflows": "GitHub Actions",
    ".gitlab-ci.yml": "GitLab CI",
    "Jenkinsfile": "Jenkins",
    "azure-pipelines.yml": "Azure DevOps",
    ".circleci": "CircleCI",
    ".travis.yml": "Travis CI",
    "bitbucket-pipelines.yml": "Bitbucket Pipelines",
}

# --- Marker Container ---

CONTAINER_MARKERS: dict[str, str] = {
    "Dockerfile": "Docker",
    "docker-compose.yml": "Docker Compose",
    "docker-compose.yaml": "Docker Compose",
    "compose.yml": "Docker Compose",
    "compose.yaml": "Docker Compose",
}

KUBERNETES_MARKERS: list[str] = [
    "k8s/",
    "kubernetes/",
    "Chart.yaml",
    "kustomization.yaml",
    "kustomization.yml",
]

# --- Marker IaC ---

IAC_MARKERS: dict[str, str] = {
    "terraform/": "Terraform",
    "main.tf": "Terraform",
    "cloudformation/": "CloudFormation",
    "template.yaml": "CloudFormation",
    "ansible/": "Ansible",
    "playbook.yml": "Ansible",
    "Pulumi.yaml": "Pulumi",
    "Pulumi.yml": "Pulumi",
}

# --- Lockfile per linguaggio ---

LOCKFILES: dict[str, str] = {
    # JavaScript / TypeScript
    "package-lock.json": "npm",
    "yarn.lock": "Yarn",
    "pnpm-lock.yaml": "pnpm",
    "bun.lock": "Bun",
    "bun.lockb": "Bun",
    "deno.lock": "Deno",
    # Python
    "poetry.lock": "Poetry",
    "Pipfile.lock": "Pipenv",
    "uv.lock": "uv",
    "pdm.lock": "PDM",
    # Rust
    "Cargo.lock": "Cargo",
    # Ruby
    "Gemfile.lock": "Bundler",
    # PHP
    "composer.lock": "Composer",
    # Go
    "go.sum": "Go",
    # Dart / Flutter
    "pubspec.lock": "Pub",
    # Swift
    "Package.resolved": "SwiftPM",
    # Elixir
    "mix.lock": "Mix",
    # Java / Kotlin (Gradle)
    "gradle.lockfile": "Gradle",
    # iOS / macOS
    "Podfile.lock": "CocoaPods",
}

# --- Marker dipendenze (file manifesto) ---

DEPENDENCY_MANIFESTS: list[str] = [
    # Python
    "requirements.txt",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    # JavaScript / TypeScript
    "package.json",
    "deno.json",
    "deno.jsonc",
    # Java / Kotlin
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    # Go
    "go.mod",
    # Rust
    "Cargo.toml",
    # Ruby
    "Gemfile",
    # PHP
    "composer.json",
    # Dart / Flutter
    "pubspec.yaml",
    # Swift
    "Package.swift",
    # Elixir
    "mix.exs",
    # iOS / macOS
    "Podfile",
]

# --- Marker monitoraggio ---

MONITORING_MARKERS: dict[str, str] = {
    "prometheus.yml": "Prometheus",
    "prometheus.yaml": "Prometheus",
    "grafana/": "Grafana",
    "datadog.yaml": "Datadog",
    "datadog.yml": "Datadog",
    "newrelic.yml": "New Relic",
    "sentry.properties": "Sentry",
    ".sentryclirc": "Sentry",
}

# --- Nomi web framework (per euristica "is deployable") ---
# Questi sono i nomi "proper" come restituiti dal StackDetector
# (es. "Spring Boot", "FastAPI", "Express"), non i nomi package.

DEPLOYABLE_FRAMEWORK_NAMES: set[str] = {
    # Python
    "fastapi", "django", "flask", "starlette", "tornado", "aiohttp", "sanic",
    # Java
    "spring boot", "spring", "quarkus", "micronaut", "jakarta ee", "java servlet",
    # JavaScript/TypeScript
    "express", "fastify", "nestjs", "koa", "hapi", "next.js", "nuxt.js",
    # Go
    "gin", "fiber", "echo", "gorilla mux", "beego",
    # Rust
    "actix web", "axum", "rocket", "warp",
    # Ruby
    "ruby on rails", "sinatra", "hanami",
    # PHP
    "laravel", "symfony",
    # Elixir
    "phoenix",
    # Electron (desktop app, deployable)
    "electron",
}

# --- Pattern health check nel codice ---

HEALTH_CHECK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"/health", re.IGNORECASE),
    re.compile(r"/healthz", re.IGNORECASE),
    re.compile(r"/readyz?", re.IGNORECASE),
    re.compile(r"/livez?", re.IGNORECASE),
    re.compile(r"health[-_]?check", re.IGNORECASE),
    re.compile(r"HEALTHCHECK", re.IGNORECASE),
]


def _make_id() -> str:
    """Genera un ID univoco per un finding."""
    return str(uuid.uuid4())[:8]


class InfraAnalyzer:
    """
    Analyzer per il layer Infrastruttura.

    Esegue check deterministici su CI/CD, container, IaC, dipendenze,
    configurazione e monitoraggio. Ogni check produce Finding con
    rule_id coerente (INFRA-*).
    """

    def analyze(
        self,
        source: AuditSource,
        stack_info: StackInfo,
        classifications: list[FileClassification],
    ) -> list[Finding]:
        """Analizza l'infrastruttura del codebase."""
        # Raccoglie tutti i path dal file tree
        file_tree = source.get_file_tree()
        all_paths: set[str] = set()
        dir_paths: set[str] = set()
        for entry in file_tree.entries:
            if entry.is_dir:
                dir_paths.add(entry.path)
            else:
                all_paths.add(entry.path)

        findings: list[Finding] = []

        # Esegui tutti i check
        findings.extend(self._check_cicd(all_paths, dir_paths))
        findings.extend(self._check_containers(all_paths, dir_paths, source, stack_info))
        findings.extend(self._check_iac(all_paths, dir_paths))
        findings.extend(self._check_dependencies(all_paths, source))
        findings.extend(self._check_secrets(classifications))
        findings.extend(self._check_monitoring(all_paths, dir_paths, source))
        findings.extend(self._check_env_example(all_paths, source))

        return findings

    # --- Check CI/CD ---

    def _check_cicd(
        self, all_paths: set[str], dir_paths: set[str]
    ) -> list[Finding]:
        """Verifica presenza e configurazione CI/CD."""
        findings: list[Finding] = []

        # Cerca marker CI/CD
        detected_cicd: list[str] = []
        for marker, name in CICD_MARKERS.items():
            if marker.endswith("/"):
                # Directory marker
                if any(p == marker.rstrip("/") or p.startswith(marker) for p in dir_paths):
                    detected_cicd.append(name)
            else:
                # File marker — cerca sia come file esatto che come prefisso di path
                if marker in all_paths or any(
                    p == marker or p.startswith(marker + "/") for p in all_paths | dir_paths
                ):
                    detected_cicd.append(name)

        if not detected_cicd:
            findings.append(Finding(
                id=_make_id(),
                layer=Layer.INFRA,
                severity=Severity.HIGH,
                rule_id="INFRA-CICD-001",
                title="Nessun CI/CD pipeline rilevato",
                description=(
                    "Non è stata trovata nessuna configurazione CI/CD "
                    "(GitHub Actions, GitLab CI, Jenkins, Azure DevOps, CircleCI, Travis CI). "
                    "Una pipeline CI/CD è essenziale per garantire build, test e deploy automatizzati."
                ),
                framework_ref="NIST PR.DS-6",
            ))
        else:
            # CI/CD trovato — finding informativo
            findings.append(Finding(
                id=_make_id(),
                layer=Layer.INFRA,
                severity=Severity.INFO,
                rule_id="INFRA-CICD-INFO",
                title=f"CI/CD rilevato: {', '.join(detected_cicd)}",
                description=(
                    f"Pipeline CI/CD configurata con: {', '.join(detected_cicd)}."
                ),
            ))

        return findings

    # --- Check Container ---

    def _check_containers(
        self,
        all_paths: set[str],
        dir_paths: set[str],
        source: AuditSource,
        stack_info: StackInfo,
    ) -> list[Finding]:
        """Verifica containerizzazione e qualità Dockerfile."""
        findings: list[Finding] = []

        # Cerca Dockerfile
        dockerfile_paths: list[str] = [
            p for p in all_paths if p == "Dockerfile" or p.endswith("/Dockerfile")
        ]

        # Cerca docker-compose
        compose_paths: list[str] = [
            p for p in all_paths
            if any(p == m or p.endswith("/" + m) for m in (
                "docker-compose.yml", "docker-compose.yaml",
                "compose.yml", "compose.yaml",
            ))
        ]

        # Cerca Kubernetes
        has_k8s = any(
            any(p == m.rstrip("/") or p.startswith(m) for p in dir_paths | all_paths)
            for m in KUBERNETES_MARKERS
        )

        if not dockerfile_paths and not compose_paths and not has_k8s:
            if self._is_deployable(stack_info):
                findings.append(Finding(
                    id=_make_id(),
                    layer=Layer.INFRA,
                    severity=Severity.MEDIUM,
                    rule_id="INFRA-DOCKER-001",
                    title="Nessuna containerizzazione rilevata",
                    description=(
                        "Non sono stati trovati Dockerfile, docker-compose, né manifest Kubernetes. "
                        "La containerizzazione è fondamentale per ambienti di deploy riproducibili."
                    ),
                ))
            else:
                findings.append(Finding(
                    id=_make_id(),
                    layer=Layer.INFRA,
                    severity=Severity.INFO,
                    rule_id="INFRA-DOCKER-INFO",
                    title="Nessuna containerizzazione (non richiesta per questo tipo di progetto)",
                    description=(
                        "Non sono stati trovati Dockerfile, docker-compose, né manifest Kubernetes. "
                        "Questo progetto non sembra essere un'applicazione web/servizio deployabile, "
                        "quindi la containerizzazione non è un requisito."
                    ),
                ))
            return findings

        # Analizza qualità Dockerfile
        for df_path in dockerfile_paths:
            findings.extend(self._analyze_dockerfile(df_path, all_paths, source))

        return findings

    def _analyze_dockerfile(
        self, path: str, all_paths: set[str], source: AuditSource
    ) -> list[Finding]:
        """Analizza la qualità di un Dockerfile."""
        findings: list[Finding] = []

        try:
            content = source.read_file(path)
        except (ValueError, FileNotFoundError):
            return findings

        content_upper = content.upper()

        # Check multi-stage build
        from_count = len(re.findall(r"^FROM\s+", content, re.MULTILINE | re.IGNORECASE))
        if from_count < 2:
            findings.append(Finding(
                id=_make_id(),
                layer=Layer.INFRA,
                severity=Severity.MEDIUM,
                rule_id="INFRA-DOCKER-003",
                title="Dockerfile senza multi-stage build",
                description=(
                    f"Il Dockerfile '{path}' usa un singolo stage. "
                    "Un multi-stage build riduce la dimensione dell'immagine finale "
                    "e migliora la sicurezza separando build e runtime."
                ),
                file_path=path,
            ))

        # Check USER non-root
        has_user = bool(re.search(r"^USER\s+(?!root)", content, re.MULTILINE | re.IGNORECASE))
        if not has_user:
            findings.append(Finding(
                id=_make_id(),
                layer=Layer.INFRA,
                severity=Severity.MEDIUM,
                rule_id="INFRA-DOCKER-004",
                title="Dockerfile esegue come root",
                description=(
                    f"Il Dockerfile '{path}' non imposta un utente non-root con USER. "
                    "Eseguire container come root è un rischio di sicurezza."
                ),
                file_path=path,
            ))

        # Check .dockerignore
        has_dockerignore = ".dockerignore" in all_paths
        if not has_dockerignore:
            findings.append(Finding(
                id=_make_id(),
                layer=Layer.INFRA,
                severity=Severity.LOW,
                rule_id="INFRA-DOCKER-002",
                title=".dockerignore non presente",
                description=(
                    "Non è stato trovato un file .dockerignore. "
                    "Senza .dockerignore, file non necessari (node_modules, .git, .env) "
                    "potrebbero finire nell'immagine Docker."
                ),
            ))

        # Check HEALTHCHECK
        has_healthcheck = "HEALTHCHECK" in content_upper
        if not has_healthcheck:
            findings.append(Finding(
                id=_make_id(),
                layer=Layer.INFRA,
                severity=Severity.LOW,
                rule_id="INFRA-DOCKER-005",
                title="Dockerfile senza HEALTHCHECK",
                description=(
                    f"Il Dockerfile '{path}' non definisce un HEALTHCHECK. "
                    "Un HEALTHCHECK permette a Docker/orchestratori di verificare "
                    "lo stato del container."
                ),
                file_path=path,
            ))

        return findings

    # --- Euristica "is deployable" ---

    def _is_deployable(self, stack_info: StackInfo) -> bool:
        """Determina se il progetto è un'applicazione deployabile (web/servizio).

        Librerie, CLI tool, scraper e simili non hanno bisogno di Docker.
        Default per ambigui: deployable (conservativo — meglio penalizzare in più).
        """
        # Check framework names (proper names from StackDetector, case-insensitive)
        for fw in stack_info.frameworks:
            if fw.lower() in DEPLOYABLE_FRAMEWORK_NAMES:
                return True
        # No frameworks at all → likely script/prototype, not deployable
        if not stack_info.frameworks:
            return False
        # Has frameworks but none is web: probably library/CLI/data
        return False

    # --- Check IaC ---

    def _check_iac(
        self, all_paths: set[str], dir_paths: set[str]
    ) -> list[Finding]:
        """Verifica presenza di Infrastructure as Code."""
        findings: list[Finding] = []

        detected_iac: list[str] = []
        for marker, name in IAC_MARKERS.items():
            if marker.endswith("/"):
                if any(p == marker.rstrip("/") or p.startswith(marker) for p in dir_paths):
                    if name not in detected_iac:
                        detected_iac.append(name)
            else:
                if marker in all_paths:
                    if name not in detected_iac:
                        detected_iac.append(name)

        if not detected_iac:
            findings.append(Finding(
                id=_make_id(),
                layer=Layer.INFRA,
                severity=Severity.HIGH,
                rule_id="INFRA-IAC-001",
                title="Nessun Infrastructure as Code rilevato",
                description=(
                    "Non è stato trovato nessun tool IaC (Terraform, CloudFormation, Ansible, Pulumi). "
                    "L'infrastruttura non codificata è difficile da replicare, auditare e versionare."
                ),
            ))

        return findings

    # --- Check Dipendenze ---

    def _check_dependencies(self, all_paths: set[str], source: AuditSource) -> list[Finding]:
        """Verifica lockfile e gestione dipendenze."""
        findings: list[Finding] = []

        # Controlla se ci sono file di dipendenze
        # Cerca sia path esatti che basename (per manifest in sottodirectory,
        # es. web/requirements.txt, backend/package.json)
        all_basenames = {p.rsplit("/", 1)[-1] for p in all_paths}
        has_manifests = any(m in all_basenames for m in DEPENDENCY_MANIFESTS)

        if not has_manifests:
            # Nessun manifesto → non serve lockfile
            return findings

        # Controlla lockfile (cerca anche in sottodirectory)
        detected_lockfiles: list[str] = []
        for lockfile, manager in LOCKFILES.items():
            if lockfile in all_basenames:
                detected_lockfiles.append(f"{lockfile} ({manager})")

        # Check if requirements.txt has pinned versions (==) — acts as lockfile
        if not detected_lockfiles and "requirements.txt" in all_basenames:
            for p in all_paths:
                if p.rsplit("/", 1)[-1] == "requirements.txt":
                    try:
                        content = source.read_file(p)
                        if content:
                            lines = [l.strip() for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]
                            pinned = sum(1 for l in lines if "==" in l)
                            if lines and pinned / len(lines) >= 0.5:
                                detected_lockfiles.append("requirements.txt (pinned versions)")
                                break
                    except Exception:
                        continue

        # Maven pom.xml pins versions directly (no separate lockfile needed)
        if not detected_lockfiles and "pom.xml" in all_basenames:
            for p in all_paths:
                if p.rsplit("/", 1)[-1] == "pom.xml":
                    try:
                        content = source.read_file(p)
                        if content and "<version>" in content:
                            detected_lockfiles.append("pom.xml (Maven pinned versions)")
                            break
                    except Exception:
                        continue

        if not detected_lockfiles:
            findings.append(Finding(
                id=_make_id(),
                layer=Layer.INFRA,
                severity=Severity.HIGH,
                rule_id="INFRA-DEPS-001",
                title="Nessun lockfile presente",
                description=(
                    "Il progetto ha file di dipendenze ma nessun lockfile "
                    "(package-lock.json, yarn.lock, poetry.lock, Cargo.lock, etc.). "
                    "Senza lockfile le build non sono riproducibili e si rischiano "
                    "aggiornamenti non controllati."
                ),
                framework_ref="NIS2 Art.21(2)(d)",
            ))

        return findings

    # --- Check Secrets / Config ---

    def _check_secrets(
        self, classifications: list[FileClassification]
    ) -> list[Finding]:
        """Correlazione con privacy classifier: segnala file sensibili nel repo."""
        findings: list[Finding] = []

        sensitive_files = [
            c for c in classifications
            if c.category == PrivacyCategory.SENSITIVE
        ]

        # Filtra solo i file .env e file di configurazione con secrets
        env_files = [
            c for c in sensitive_files
            if c.file_info.path.endswith(".env")
            or c.file_info.path.split("/")[-1].startswith(".env")
        ]

        secret_config_files = [
            c for c in sensitive_files
            if c not in env_files
            and any(kw in c.reason.lower() for kw in (
                "password", "api_key", "secret", "credential", "private key",
                "token", "chiave privata",
            ))
            # Escludi file di documentazione e CI/CD (contengono placeholder, non secrets)
            and not self._is_documentation_or_ci(c.file_info.path)
        ]

        if env_files:
            env_paths = ", ".join(c.file_info.path for c in env_files[:5])
            findings.append(Finding(
                id=_make_id(),
                layer=Layer.INFRA,
                severity=Severity.HIGH,
                rule_id="INFRA-CONFIG-001",
                title="File .env con dati sensibili nel repository",
                description=(
                    f"Trovati file .env con dati sensibili: {env_paths}. "
                    "I file .env non dovrebbero essere inclusi nel repository. "
                    "Usare .env.example con valori placeholder e aggiungere .env a .gitignore."
                ),
            ))

        if secret_config_files:
            secret_paths = ", ".join(c.file_info.path for c in secret_config_files[:5])
            findings.append(Finding(
                id=_make_id(),
                layer=Layer.INFRA,
                severity=Severity.HIGH,
                rule_id="INFRA-CONFIG-002",
                title="Secrets rilevati in file di configurazione",
                description=(
                    f"Trovati secrets in chiaro nei file: {secret_paths}. "
                    "I secrets dovrebbero essere gestiti tramite variabili d'ambiente, "
                    "vault (HashiCorp Vault, AWS Secrets Manager) o file cifrati."
                ),
            ))

        return findings

    def _is_documentation_or_ci(self, path: str) -> bool:
        """Verifica se un file è documentazione, CI/CD config, o traduzione (non un vero config file)."""
        basename = path.split("/")[-1].lower()
        path_lower = path.lower()
        # README, CONTRIBUTING, CHANGELOG, etc.
        if basename.startswith(("readme", "contributing", "changelog", "authors")):
            return True
        # File markdown/rst di documentazione
        if basename.endswith((".md", ".rst")) and not basename.startswith("."):
            return True
        # CI/CD workflow files (contengono ${{ secrets.* }}, non secrets reali)
        if ".github/workflows/" in path or ".gitlab-ci" in path:
            return True
        # Translation/i18n files (.po, .pot contengono keyword "password" come stringhe da tradurre)
        if basename.endswith((".po", ".pot")):
            return True
        if any(seg in path_lower for seg in ("/locale/", "/locales/", "/i18n/", "/translations/")):
            return True
        return False

    # --- Check Monitoraggio ---

    def _check_monitoring(
        self,
        all_paths: set[str],
        dir_paths: set[str],
        source: AuditSource,
    ) -> list[Finding]:
        """Verifica presenza di monitoraggio e health check."""
        findings: list[Finding] = []

        # Cerca marker di monitoraggio
        detected_monitoring: list[str] = []
        for marker, name in MONITORING_MARKERS.items():
            if marker.endswith("/"):
                if any(p == marker.rstrip("/") or p.startswith(marker) for p in dir_paths):
                    if name not in detected_monitoring:
                        detected_monitoring.append(name)
            else:
                if marker in all_paths:
                    if name not in detected_monitoring:
                        detected_monitoring.append(name)

        # Cerca health check nel codice sorgente
        has_health_check = False
        source_extensions = {".py", ".js", ".ts", ".go", ".java", ".rb", ".rs", ".yml", ".yaml"}
        for path in all_paths:
            ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
            if ext not in source_extensions:
                continue
            try:
                content = source.read_file(path)
            except (ValueError, FileNotFoundError, PermissionError):
                continue
            if any(p.search(content) for p in HEALTH_CHECK_PATTERNS):
                has_health_check = True
                break

        if not detected_monitoring and not has_health_check:
            findings.append(Finding(
                id=_make_id(),
                layer=Layer.INFRA,
                severity=Severity.MEDIUM,
                rule_id="INFRA-MON-001",
                title="Nessun monitoraggio rilevato",
                description=(
                    "Non sono stati trovati strumenti di monitoraggio "
                    "(Prometheus, Grafana, Datadog, Sentry, New Relic) "
                    "né endpoint di health check nel codice. "
                    "Il monitoraggio è essenziale per la gestione operativa."
                ),
                framework_ref="NIS2 Art.21(2)(c)",
            ))

        return findings

    # --- Check .env.example ---

    def _check_env_example(
        self, all_paths: set[str], source: AuditSource
    ) -> list[Finding]:
        """Verifica presenza di .env.example quando .gitignore ha .env."""
        basenames = {p.rsplit("/", 1)[-1] for p in all_paths}

        # Solo se .gitignore esiste
        if ".gitignore" not in basenames:
            return []

        # Leggi .gitignore e cerca ".env"
        gitignore_paths = [p for p in all_paths if p.rsplit("/", 1)[-1] == ".gitignore" and "/" not in p]
        if not gitignore_paths:
            gitignore_paths = [p for p in all_paths if p.rsplit("/", 1)[-1] == ".gitignore"]

        has_env_in_gitignore = False
        for gp in gitignore_paths[:1]:
            try:
                content = source.read_file(gp)
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped == ".env" or stripped == ".env*" or stripped == "*.env":
                        has_env_in_gitignore = True
                        break
            except (ValueError, FileNotFoundError, UnicodeDecodeError):
                continue

        if not has_env_in_gitignore:
            return []

        # Verifica se esiste .env.example o .env.sample
        if ".env.example" in basenames or ".env.sample" in basenames:
            return []

        return [Finding(
            id=_make_id(),
            layer=Layer.INFRA,
            severity=Severity.MEDIUM,
            rule_id="INFRA-ENVEXAMPLE-001",
            title=".env.example mancante",
            description=(
                "Il .gitignore esclude file .env ma non esiste un file "
                ".env.example o .env.sample. Un file di esempio documenta "
                "le variabili d'ambiente necessarie e facilita l'onboarding "
                "di nuovi sviluppatori."
            ),
        )]
