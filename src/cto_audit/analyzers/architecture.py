"""
Architecture Analyzer — Layer 2: Architettura.

Analizza la struttura del progetto per rilevare:
- Pattern architetturale (MVC, Clean Arch, feature-based, flat/caotico)
- Coupling: import circolari, fan-out eccessivo
- Separazione dei concern: business logic mescolata con infra
- Database: ORM, migrazioni, raw SQL
- Scalabilità: file enormi (>500 LOC), stato globale
- Presenza directory test

Analisi deterministica con import extraction basata su regex
per Python e JavaScript/TypeScript.
"""

from __future__ import annotations

import re
import uuid
from collections import defaultdict

from cto_audit.core.models import (
    FileClassification,
    FileInfo,
    Finding,
    Layer,
    PrivacyCategory,
    Severity,
    StackInfo,
)
from cto_audit.core.source import AuditSource


# --- Soglie ---

LOC_THRESHOLD = 500  # File con più di 500 LOC → finding
FAN_OUT_THRESHOLD = 10  # Modulo che importa > 10 moduli interni → finding

# Estensioni escluse dal check "file grandi" (dati, traduzioni, generati)
LARGE_FILE_SKIP_EXTENSIONS: set[str] = {
    ".po", ".mo", ".pot",       # Traduzioni gettext
    ".csv", ".tsv",             # Dati tabulari
    ".map",                     # Source maps
    ".lock",                    # Lock files (uv.lock, etc.)
    ".svg",                     # Grafica vettoriale (testo ma non codice)
    ".min.js", ".min.css",      # File minificati
    ".xml", ".xsd", ".xslt",   # XML data/config/schema
    ".resx", ".resw",          # .NET resource files (localizzazione)
    ".json",                    # JSON data/config
    ".yaml", ".yml",           # YAML data/config
    ".sql",                     # SQL scripts/migrations
    ".proto",                   # Protocol Buffer definitions
    ".graphql", ".gql",        # GraphQL schema
    ".wsdl",                    # SOAP service definitions
    ".xaml",                    # WPF/UWP markup
    ".csproj", ".fsproj",      # .NET project files
    ".sln",                     # .NET solution files
    ".plist",                   # Apple property lists
    ".pbxproj",                # Xcode project files
}

# Nomi file (lowercase) esclusi dal check "file grandi"
LARGE_FILE_SKIP_NAMES: set[str] = {
    "license", "licence", "license.md", "licence.md",
    "license.txt", "licence.txt",
    "changelog", "changelog.md", "changelog.txt", "changelog.rst",
    "changes", "changes.md",
    "contributors", "contributors.md",
    "authors", "authors.md", "authors.txt",
    ".cto-audit-classification.yml",
}

# Segmenti di path (directory) che indicano codice vendored/third-party
# Se un segmento del path (case-insensitive) matcha, il file e' escluso
LARGE_FILE_SKIP_DIRS: set[str] = {
    "vendor", "vendors",
    "third_party", "third-party", "thirdparty",
    "bower_components",
    "wwwroot",
    "lib_npm",
    "external", "extern",
    "bundled",
    "packages",             # NuGet/monorepo vendored
    "migrations", "migrate",  # DB migrations
}

# --- Pattern struttura directory ---

# Directory che indicano organizzazione MVC/layered
MVC_MARKERS: list[str] = [
    "models", "views", "controllers",
    "templates", "static",
]

# Directory che indicano Clean Architecture / layered
LAYERED_MARKERS: list[str] = [
    "domain", "application", "infrastructure",
    "core", "services", "repositories",
    "usecases", "entities", "adapters",
    "interfaces", "ports",
]

# Directory che indicano organizzazione per feature
FEATURE_MARKERS: list[str] = [
    "features", "modules", "apps",
]

# Directory note per test
TEST_DIRECTORIES: list[str] = [
    "tests", "test", "__tests__", "spec", "specs",
    "test_", "testing",
]

# --- Marker database/migrazioni ---

MIGRATION_MARKERS: list[str] = [
    "migrations/",
    "alembic/",
    "db/migrate/",
    "prisma/migrations/",
    "sequelize/migrations/",
    "flyway/",
    "liquibase/",
]

ORM_DEPENDENCIES: dict[str, str] = {
    "sqlalchemy": "SQLAlchemy",
    "django": "Django ORM",
    "tortoise-orm": "Tortoise ORM",
    "peewee": "Peewee",
    "prisma": "Prisma",
    "sequelize": "Sequelize",
    "typeorm": "TypeORM",
    "hibernate": "Hibernate",
    "entity-framework": "Entity Framework",
    "activerecord": "ActiveRecord",
    "gorm": "GORM",
    "diesel": "Diesel",
    "mongoose": "Mongoose",
}

# --- Regex import extraction ---

# Python: import X / from X import Y
_PY_IMPORT_RE = re.compile(
    r"^(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))",
    re.MULTILINE,
)

# JavaScript/TypeScript: import ... from 'X' / require('X')
_JS_IMPORT_RE = re.compile(
    r"""(?:import\s+.*?\s+from\s+['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\))""",
    re.MULTILINE,
)


def _make_id() -> str:
    """Genera un ID univoco per un finding."""
    return str(uuid.uuid4())[:8]


class ArchitectureAnalyzer:
    """
    Analyzer per il layer Architettura.

    Verifica struttura directory, coupling tra moduli, separazione dei concern,
    gestione database/migrazioni, scalabilità (file grandi, stato globale),
    e presenza di test.
    """

    def analyze(
        self,
        source: AuditSource,
        stack_info: StackInfo,
        classifications: list[FileClassification],
    ) -> list[Finding]:
        """Analizza l'architettura del codebase."""
        file_tree = source.get_file_tree()

        # Raccogli path e directory
        all_paths: list[str] = []
        dir_paths: set[str] = set()
        for entry in file_tree.entries:
            if entry.is_dir:
                dir_paths.add(entry.path)
            else:
                all_paths.append(entry.path)

        # Raccogli FileInfo solo per file non-EXCLUDED (privacy classifier)
        non_excluded = [
            c for c in classifications
            if c.category != PrivacyCategory.EXCLUDED
        ]
        file_infos = [c.file_info for c in non_excluded]

        findings: list[Finding] = []

        findings.extend(self._check_structure(all_paths, dir_paths))
        findings.extend(self._check_coupling(all_paths, source))
        findings.extend(self._check_large_files(file_infos))
        findings.extend(self._check_test_directory(dir_paths, all_paths, source))
        findings.extend(self._check_database(all_paths, dir_paths, stack_info))

        return findings

    # --- Check struttura directory ---

    def _check_structure(
        self, all_paths: list[str], dir_paths: set[str]
    ) -> list[Finding]:
        """Rileva il pattern architetturale dalla struttura directory."""
        findings: list[Finding] = []

        # Tutti i nomi di directory nel progetto (qualsiasi livello)
        all_dir_names: set[str] = set()
        for d in dir_paths:
            for part in d.split("/"):
                if not part.startswith("."):
                    all_dir_names.add(part.lower())

        # Rileva pattern
        mvc_matches = [m for m in MVC_MARKERS if m in all_dir_names]
        layered_matches = [m for m in LAYERED_MARKERS if m in all_dir_names]
        feature_matches = [m for m in FEATURE_MARKERS if m in all_dir_names]

        # Conta file nella root vs subdirectory
        root_files = [p for p in all_paths if "/" not in p and not p.startswith(".")]
        subdir_files = [p for p in all_paths if "/" in p]

        # Struttura flat: > 70% dei file nella root (e almeno 5 file)
        total_source = len(root_files) + len(subdir_files)
        is_flat = (
            total_source >= 5
            and len(root_files) > 0
            and (len(root_files) / total_source) > 0.7
        )

        if is_flat:
            findings.append(Finding(
                id=_make_id(),
                layer=Layer.ARCHITECTURE,
                severity=Severity.MEDIUM,
                rule_id="ARCH-STRUCT-001",
                title="Struttura directory flat/caotica",
                description=(
                    f"La maggior parte dei file ({len(root_files)}/{total_source}) "
                    "si trova nella directory root senza organizzazione in sotto-directory. "
                    "Una struttura organizzata (MVC, layered, feature-based) migliora "
                    "manutenibilità e navigazione."
                ),
            ))
        elif mvc_matches and len(mvc_matches) >= 2:
            findings.append(Finding(
                id=_make_id(),
                layer=Layer.ARCHITECTURE,
                severity=Severity.INFO,
                rule_id="ARCH-STRUCT-INFO",
                title=f"Pattern MVC rilevato ({', '.join(mvc_matches)})",
                description=(
                    f"La struttura directory suggerisce un pattern MVC/MTV "
                    f"con directory: {', '.join(mvc_matches)}."
                ),
            ))
        elif layered_matches and len(layered_matches) >= 2:
            findings.append(Finding(
                id=_make_id(),
                layer=Layer.ARCHITECTURE,
                severity=Severity.INFO,
                rule_id="ARCH-STRUCT-INFO",
                title=f"Pattern layered/Clean Architecture rilevato ({', '.join(layered_matches)})",
                description=(
                    f"La struttura directory suggerisce un'architettura a layer "
                    f"con directory: {', '.join(layered_matches)}."
                ),
            ))
        elif feature_matches:
            findings.append(Finding(
                id=_make_id(),
                layer=Layer.ARCHITECTURE,
                severity=Severity.INFO,
                rule_id="ARCH-STRUCT-INFO",
                title="Pattern feature-based rilevato",
                description=(
                    "La struttura directory suggerisce un'organizzazione per feature/moduli."
                ),
            ))

        return findings

    # --- Check coupling (import circolari) ---

    def _check_coupling(
        self, all_paths: list[str], source: AuditSource
    ) -> list[Finding]:
        """Rileva import circolari e fan-out eccessivo."""
        findings: list[Finding] = []

        # Costruisci grafo delle dipendenze
        dep_graph: dict[str, set[str]] = defaultdict(set)

        # Mappa path → modulo per matching
        module_set: set[str] = set()
        for path in all_paths:
            if path.endswith(".py"):
                module = self._path_to_module(path)
                module_set.add(module)

        # Estrai import Python
        for path in all_paths:
            if not path.endswith(".py"):
                continue
            try:
                content = source.read_file(path)
            except (ValueError, FileNotFoundError, PermissionError):
                continue

            module = self._path_to_module(path)
            imports = self._extract_python_imports(content)

            for imp in imports:
                resolved = self._resolve_import(imp, module_set)
                if resolved and resolved != module:
                    dep_graph[module].add(resolved)

        # Estrai import JS/TS
        for path in all_paths:
            if not any(path.endswith(ext) for ext in (".js", ".jsx", ".ts", ".tsx")):
                continue
            try:
                content = source.read_file(path)
            except (ValueError, FileNotFoundError, PermissionError):
                continue

            module = self._path_to_module(path)
            js_imports = self._extract_js_imports(content, path)

            for imp in js_imports:
                if imp and imp != module:
                    dep_graph[module].add(imp)

        # Rileva cicli
        cycles = self._detect_cycles(dep_graph)
        if cycles:
            cycle_descriptions = []
            for cycle in cycles[:5]:
                cycle_descriptions.append(" → ".join(cycle))

            findings.append(Finding(
                id=_make_id(),
                layer=Layer.ARCHITECTURE,
                severity=Severity.HIGH,
                rule_id="ARCH-COUPLING-001",
                title=f"Import circolari rilevati ({len(cycles)} cicli)",
                description=(
                    "Rilevati import circolari tra moduli del progetto. "
                    "Le dipendenze circolari rendono il codice difficile da testare, "
                    "rifattorizzare e mantenere.\n"
                    "Cicli trovati:\n" +
                    "\n".join(f"  - {c}" for c in cycle_descriptions)
                ),
            ))

        # Rileva fan-out eccessivo — normalizzato per dimensione progetto
        fanout_modules: list[tuple[str, int]] = []
        for module, deps in dep_graph.items():
            if len(deps) > FAN_OUT_THRESHOLD:
                fanout_modules.append((module, len(deps)))

        if fanout_modules:
            # Ordina per fan-out decrescente (peggiori prima)
            fanout_modules.sort(key=lambda x: x[1], reverse=True)

            total_modules = max(len(dep_graph), 1)
            fanout_ratio = len(fanout_modules) / total_modules
            max_penalized = min(8, max(3, round(fanout_ratio * 40)))

            for i, (module, dep_count) in enumerate(fanout_modules):
                if i < max_penalized:
                    findings.append(Finding(
                        id=_make_id(),
                        layer=Layer.ARCHITECTURE,
                        severity=Severity.MEDIUM,
                        rule_id="ARCH-COUPLING-002",
                        title=f"Fan-out eccessivo: {module}",
                        description=(
                            f"Il modulo '{module}' importa {dep_count} moduli interni "
                            f"(soglia: {FAN_OUT_THRESHOLD}). Un fan-out elevato indica "
                            "un modulo con troppe responsabilità che andrebbe suddiviso."
                        ),
                        file_path=module.replace(".", "/") + ".py",
                    ))
                else:
                    findings.append(Finding(
                        id=_make_id(),
                        layer=Layer.ARCHITECTURE,
                        severity=Severity.INFO,
                        rule_id="ARCH-COUPLING-INFO",
                        title=f"Fan-out elevato: {module} ({dep_count} import)",
                        description=(
                            f"Il modulo '{module}' importa {dep_count} moduli interni "
                            f"(soglia: {FAN_OUT_THRESHOLD}). Riportato come informativo; "
                            f"i {max_penalized} moduli peggiori sono già conteggiati."
                        ),
                        file_path=module.replace(".", "/") + ".py",
                    ))

        return findings

    def _path_to_module(self, path: str) -> str:
        """Converte un path file in nome modulo (senza estensione)."""
        for ext in (".py", ".js", ".jsx", ".ts", ".tsx"):
            if path.endswith(ext):
                path = path[:-len(ext)]
                break
        if path.endswith("/index"):
            path = path[:-6]
        return path.replace("/", ".")

    def _extract_python_imports(self, content: str) -> list[str]:
        """Estrai nomi di moduli importati da codice Python."""
        imports: list[str] = []
        for match in _PY_IMPORT_RE.finditer(content):
            module = match.group(1) or match.group(2)
            if module:
                imports.append(module)
        return imports

    def _extract_js_imports(self, content: str, current_path: str) -> list[str]:
        """Estrai path di moduli importati da codice JS/TS (solo relativi)."""
        imports: list[str] = []
        for match in _JS_IMPORT_RE.finditer(content):
            imp_path = match.group(1) or match.group(2)
            if imp_path and imp_path.startswith("."):
                resolved = self._resolve_js_import(imp_path, current_path)
                if resolved:
                    imports.append(resolved)
        return imports

    def _resolve_js_import(self, import_path: str, current_file: str) -> str | None:
        """Risolvi un import JS relativo rispetto al file corrente."""
        parts = current_file.split("/")
        base_dir = "/".join(parts[:-1]) if len(parts) > 1 else ""

        imp_parts = import_path.split("/")
        result_parts = base_dir.split("/") if base_dir else []

        for part in imp_parts:
            if part == ".":
                continue
            elif part == "..":
                if result_parts:
                    result_parts.pop()
            else:
                result_parts.append(part)

        resolved = "/".join(result_parts)
        return self._path_to_module(resolved) if resolved else None

    def _resolve_import(self, import_name: str, module_set: set[str]) -> str | None:
        """Risolvi un import Python: controlla se è un modulo interno al progetto."""
        if import_name in module_set:
            return import_name

        # Match parziale (es. 'app.models' come prefisso)
        parts = import_name.split(".")
        for i in range(len(parts), 0, -1):
            prefix = ".".join(parts[:i])
            if prefix in module_set:
                return prefix

        return None

    def _detect_cycles(self, graph: dict[str, set[str]]) -> list[list[str]]:
        """Rileva cicli nel grafo delle dipendenze tramite DFS."""
        cycles: list[list[str]] = []
        visited: set[str] = set()
        rec_stack: set[str] = set()
        path: list[str] = []

        def dfs(node: str) -> None:
            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            for neighbor in graph.get(node, set()):
                if neighbor not in visited:
                    dfs(neighbor)
                elif neighbor in rec_stack:
                    cycle_start = path.index(neighbor)
                    cycle = path[cycle_start:] + [neighbor]
                    if cycle not in cycles:
                        cycles.append(cycle)

            path.pop()
            rec_stack.discard(node)

        for node in list(graph.keys()):
            if node not in visited:
                dfs(node)

        return cycles

    # --- Check file grandi ---

    def _check_large_files(self, file_infos: list[FileInfo]) -> list[Finding]:
        """Rileva file sorgente con più di 500 LOC.

        Filtra file non-sorgente (traduzioni .po, LICENSE, changelog, etc.)
        che sono legittimamente grandi senza indicare problemi architetturali.

        Normalizzazione per dimensione progetto: penalizza la percentuale di
        file grandi, non il numero assoluto. In un progetto con 1000+ file,
        avere 70 file grandi (7%) è meno grave che in un progetto con 20 file
        averne 10 (50%). I file peggiori (per LOC) vengono penalizzati per
        primi; gli altri sono riportati come INFO (visibili ma senza penalità).
        """
        # Raccogli tutti i file grandi
        large_files: list[FileInfo] = []
        for fi in file_infos:
            if fi.lines_of_code <= LOC_THRESHOLD:
                continue

            # Salta file con estensioni non-sorgente
            ext = fi.extension.lower()
            if ext in LARGE_FILE_SKIP_EXTENSIONS:
                continue

            # Salta file con nomi noti non-sorgente
            basename = fi.path.split("/")[-1].lower()
            if basename in LARGE_FILE_SKIP_NAMES:
                continue

            # Salta file in directory vendored/third-party/migrations
            path_parts = fi.path.replace("\\", "/").lower().split("/")
            if any(part in LARGE_FILE_SKIP_DIRS for part in path_parts[:-1]):
                continue

            large_files.append(fi)

        if not large_files:
            return []

        # Ordina per LOC decrescente (peggiori prima)
        large_files.sort(key=lambda f: f.lines_of_code, reverse=True)

        # Calcola cap basato su percentuale di file grandi
        total_files = max(len(file_infos), 1)
        large_ratio = len(large_files) / total_files
        # Formula: ratio × 50, con min 3 e max 10
        # 4% ratio → 3, 10% → 5, 20% → 10, >20% → 10
        max_penalized = min(10, max(3, round(large_ratio * 50)))

        findings: list[Finding] = []

        for i, fi in enumerate(large_files):
            if i < max_penalized:
                # Finding con penalità (MEDIUM)
                findings.append(Finding(
                    id=_make_id(),
                    layer=Layer.ARCHITECTURE,
                    severity=Severity.MEDIUM,
                    rule_id="ARCH-SCALE-001",
                    title=f"File molto grande: {fi.path} ({fi.lines_of_code} LOC)",
                    description=(
                        f"Il file '{fi.path}' ha {fi.lines_of_code} righe di codice "
                        f"(soglia: {LOC_THRESHOLD}). File troppo grandi sono difficili "
                        "da comprendere, testare e manutenere. Considerare lo split "
                        "in moduli più piccoli con responsabilità singola."
                    ),
                    file_path=fi.path,
                ))
            else:
                # Finding informativo (nessuna penalità)
                findings.append(Finding(
                    id=_make_id(),
                    layer=Layer.ARCHITECTURE,
                    severity=Severity.INFO,
                    rule_id="ARCH-SCALE-INFO",
                    title=f"File grande: {fi.path} ({fi.lines_of_code} LOC)",
                    description=(
                        f"Il file '{fi.path}' ha {fi.lines_of_code} righe di codice "
                        f"(soglia: {LOC_THRESHOLD}). Riportato come informativo; "
                        f"i {max_penalized} file più grandi sono già conteggiati "
                        "nella penalità."
                    ),
                    file_path=fi.path,
                ))

        return findings

    # --- Check test directory ---

    def _check_test_directory(
        self, dir_paths: set[str], all_paths: list[str], source: AuditSource
    ) -> list[Finding]:
        """Verifica la presenza di directory/file di test."""
        findings: list[Finding] = []

        all_dir_names: set[str] = set()
        for d in dir_paths:
            for part in d.split("/"):
                all_dir_names.add(part.lower())

        has_test_dir = any(td in all_dir_names for td in TEST_DIRECTORIES)

        has_test_files = any(
            self._is_test_file(p) for p in all_paths
        )

        # Rust inline tests: #[cfg(test)] / #[test] inside .rs files
        has_rust_inline_tests = False
        if not has_test_dir and not has_test_files:
            rs_files = [p for p in all_paths if p.endswith(".rs")]
            for rs_path in rs_files[:20]:  # Sample max 20 files
                try:
                    content = source.read_file(rs_path)
                    if content and ("#[cfg(test)]" in content or "#[test]" in content):
                        has_rust_inline_tests = True
                        break
                except Exception:
                    continue

        if not has_test_dir and not has_test_files and not has_rust_inline_tests:
            findings.append(Finding(
                id=_make_id(),
                layer=Layer.ARCHITECTURE,
                severity=Severity.CRITICAL,
                rule_id="ARCH-TEST-001",
                title="Nessuna directory o file di test rilevati",
                description=(
                    "Non sono state trovate directory di test (tests/, test/, __tests__, spec/) "
                    "né file di test (test_*.py, *.test.js, *.spec.ts). "
                    "I test sono fondamentali per la qualità e la manutenibilità del software."
                ),
            ))

        return findings

    def _is_test_file(self, path: str) -> bool:
        """Verifica se un file è un file di test."""
        name = path.split("/")[-1].lower()
        return (
            name.startswith("test_")
            or name.endswith("_test.py")
            or name.endswith("_test.go")       # Go convention
            or name.endswith("test.java")       # Java: FooTest.java
            or name.endswith("test.cs")         # C#: FooTest.cs
            or name.endswith("_spec.rb")        # Ruby RSpec
            or ".test." in name                 # JS/TS: foo.test.js
            or ".spec." in name                 # JS/TS: foo.spec.ts
            or name == "conftest.py"
        )

    # --- Check database / migrazioni ---

    def _check_database(
        self,
        all_paths: list[str],
        dir_paths: set[str],
        stack_info: StackInfo,
    ) -> list[Finding]:
        """Verifica gestione database: ORM, migrazioni."""
        findings: list[Finding] = []

        # Rileva se il progetto usa un database
        uses_db = False
        detected_orm: list[str] = []
        for fw in stack_info.frameworks:
            fw_lower = fw.lower()
            for key, name in ORM_DEPENDENCIES.items():
                if key in fw_lower:
                    uses_db = True
                    if name not in detected_orm:
                        detected_orm.append(name)

        if not uses_db:
            return findings

        # Controlla migrazioni (cerca in qualsiasi sottodirectory)
        has_migrations = False
        for marker in MIGRATION_MARKERS:
            if marker.endswith("/"):
                marker_name = marker.rstrip("/")
                for p in dir_paths | set(all_paths):
                    # Matcha il marker come componente di directory a qualsiasi livello
                    # es. "migrations" matcha "cms/migrations" o "web/app/migrations/0001.py"
                    parts = p.replace("\\", "/").split("/")
                    if marker_name in parts:
                        has_migrations = True
                        break
                if has_migrations:
                    break

        if not has_migrations:
            findings.append(Finding(
                id=_make_id(),
                layer=Layer.ARCHITECTURE,
                severity=Severity.MEDIUM,
                rule_id="ARCH-DB-001",
                title="ORM rilevato ma nessuna gestione migrazioni",
                description=(
                    f"Il progetto usa {', '.join(detected_orm)} ma non sono state trovate "
                    "directory di migrazioni (migrations/, alembic/, db/migrate/). "
                    "Le migrazioni sono essenziali per gestire l'evoluzione dello schema "
                    "in modo riproducibile e versionato."
                ),
            ))

        return findings
