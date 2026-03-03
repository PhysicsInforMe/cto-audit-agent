"""
Security Analyzer — Layer 3: Sicurezza.

Scansione CTO-level, NON SonarQube. Cerca assenza di best practice
e presenza di pattern pericolosi noti. Deterministico (regex + file existence).

8 check:
- SEC-DEPS-001: Dipendenze con versioni notoriamente vulnerabili
- SEC-AUTH-001: Nessun framework auth rilevato (se ha route API)
- SEC-HTTPS-001: URL http:// hardcodati nel codice
- SEC-CORS-001: CORS permissivo (* origins)
- SEC-SQL-001: SQL injection via string concat/f-string
- SEC-SECRETS-CODE-001: Secrets/API key hardcodati in file sorgente e config
- SEC-HEADERS-001: Nessun middleware security headers (se web framework)
- SEC-CRYPTO-001: Pattern crittografici deboli (MD5, SHA1, DES, RC4)
"""

from __future__ import annotations

import re
import uuid
from collections import defaultdict

from cto_audit.core.models import (
    FileClassification,
    Finding,
    Layer,
    PrivacyCategory,
    Severity,
    StackInfo,
)
from cto_audit.core.source import AuditSource


# --- Known Vulnerable Dependencies (top CVE storiche) ---

VULNERABLE_DEPS: dict[str, dict] = {
    # Python
    "django": {"below": "2.0", "cve": "CVE-2019-14232+", "lang": "python"},
    "flask": {"below": "1.0", "cve": "CVE-2018-1000656", "lang": "python"},
    "requests": {"below": "2.20.0", "cve": "CVE-2018-18074", "lang": "python"},
    "pyyaml": {"below": "5.1", "cve": "CVE-2020-1747", "lang": "python"},
    "urllib3": {"below": "1.26.5", "cve": "CVE-2021-33503", "lang": "python"},
    "jinja2": {"below": "2.11.3", "cve": "CVE-2020-28493", "lang": "python"},
    "pillow": {"below": "8.3.2", "cve": "CVE-2021-34552", "lang": "python"},
    "cryptography": {"below": "3.3.2", "cve": "CVE-2021-3449", "lang": "python"},
    # JavaScript
    "lodash": {"below": "4.17.21", "cve": "CVE-2021-23337", "lang": "javascript"},
    "minimist": {"below": "1.2.6", "cve": "CVE-2021-44906", "lang": "javascript"},
    "node-fetch": {"below": "2.6.7", "cve": "CVE-2022-0235", "lang": "javascript"},
    "axios": {"below": "0.21.1", "cve": "CVE-2021-3749", "lang": "javascript"},
    "express": {"below": "4.17.3", "cve": "CVE-2022-24999", "lang": "javascript"},
    # Java
    "log4j": {"below": "2.17.0", "cve": "CVE-2021-44228 (Log4Shell)", "lang": "java"},
    "spring-boot": {"below": "2.5.12", "cve": "CVE-2022-22965 (Spring4Shell)", "lang": "java"},
    "jackson-databind": {"below": "2.12.6", "cve": "CVE-2020-36518", "lang": "java"},
    "commons-collections": {"below": "3.2.2", "cve": "CVE-2015-7501", "lang": "java"},
    # Go
    "golang.org/x/crypto": {"below": "0.0.0-20220314234659", "cve": "CVE-2022-27191", "lang": "go"},
    "golang.org/x/text": {"below": "0.3.8", "cve": "CVE-2022-32149", "lang": "go"},
}

# --- Auth framework markers ---

AUTH_MARKERS: dict[str, list[str]] = {
    "python": [
        "django.contrib.auth", "flask-login", "flask-jwt", "flask-security",
        "fastapi.security", "python-jose", "pyjwt", "authlib", "django-allauth",
        "django-rest-framework", "rest_framework.authentication",
        "passlib", "itsdangerous",
    ],
    "javascript": [
        "passport", "jsonwebtoken", "express-jwt", "next-auth", "auth0",
        "firebase/auth", "supabase", "@auth/", "lucia", "clerk",
        "bcryptjs", "bcrypt",
    ],
    "java": [
        "spring-security", "spring.security", "spring-boot-starter-security",
        "SecurityConfig", "WebSecurityConfigurerAdapter", "@EnableWebSecurity",
        "shiro", "keycloak",
    ],
    "go": [
        "golang.org/x/oauth2", "github.com/dgrijalva/jwt-go",
        "github.com/golang-jwt/jwt", "github.com/casbin",
        "github.com/coreos/go-oidc",
    ],
    "ruby": [
        "devise", "omniauth", "sorcery", "rodauth", "warden",
        "bcrypt", "jwt", "doorkeeper", "pundit", "cancancan",
    ],
    "php": [
        "laravel/sanctum", "tymon/jwt-auth", "laravel/passport",
        "auth0/login", "league/oauth2", "firebase/php-jwt",
        "Auth::routes", "auth.php",
    ],
    "csharp": [
        "Microsoft.AspNetCore.Identity", "Microsoft.AspNetCore.Authentication",
        "IdentityServer", "AspNet.Security.OAuth", "Microsoft.Identity",
        "[Authorize]", "AddAuthentication", "AddIdentity",
    ],
}

# --- Web framework markers (per condizionare check) ---

WEB_FRAMEWORK_MARKERS: list[str] = [
    "fastapi", "flask", "django", "express", "koa", "hapi", "nestjs",
    "spring-boot", "spring-web", "gin-gonic", "fiber", "echo",
    "rails", "sinatra", "laravel", "symfony", "actix-web", "rocket",
    "nextjs", "nuxt", "sveltekit",
]

API_ROUTE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"@app\.(get|post|put|delete|patch|route)\s*\(", re.IGNORECASE),
    re.compile(r"@router\.(get|post|put|delete|patch)\s*\(", re.IGNORECASE),
    re.compile(r"app\.(get|post|put|delete|patch|use)\s*\(", re.IGNORECASE),
    re.compile(r"router\.(get|post|put|delete|patch)\s*\(", re.IGNORECASE),
    re.compile(r"@(Get|Post|Put|Delete|Patch)Mapping", re.IGNORECASE),
    re.compile(r"@RequestMapping", re.IGNORECASE),
    re.compile(r"@RestController", re.IGNORECASE),
    re.compile(r"r\.GET\(|r\.POST\(|r\.PUT\(", re.IGNORECASE),
]

# --- CORS patterns ---

CORS_PERMISSIVE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"""allow_origins\s*=\s*\[\s*["']\*["']\s*\]"""),
    re.compile(r"""AllowAllOrigins\s*:\s*true""", re.IGNORECASE),
    re.compile(r"""cors\(\s*\)""", re.IGNORECASE),
    re.compile(r"""origin\s*:\s*["']\*["']""", re.IGNORECASE),
    re.compile(r"""Access-Control-Allow-Origin['":\s]+\*""", re.IGNORECASE),
    re.compile(r"""allowedOrigins\s*\(\s*["']\*["']\s*\)""", re.IGNORECASE),
    re.compile(r"""CorsRegistry.*allowedOrigins\s*\(\s*["']\*["']\s*\)""", re.IGNORECASE),
    # PHP: 'allowed_origins' => ['*'] or "allowed_origins" => ["*"]
    re.compile(r"""allowed_origins['"]\s*=>\s*\[\s*["']\*["']\s*\]""", re.IGNORECASE),
]

# --- SQL injection patterns ---

SQL_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    # Python f-string/format in SQL
    re.compile(r"""(?:execute|cursor\.execute|query)\s*\(\s*f["'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP)""", re.IGNORECASE),
    re.compile(r"""(?:execute|cursor\.execute|query)\s*\(\s*["'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*%s.*["']\s*%""", re.IGNORECASE),
    re.compile(r"""(?:execute|cursor\.execute|query)\s*\(\s*["'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP).*\{""", re.IGNORECASE),
    # String concatenation in SQL
    re.compile(r"""["'](?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*["']\s*\+\s*""", re.IGNORECASE),
    re.compile(r"""\+\s*["'].*(?:WHERE|AND|OR|SET)\s+""", re.IGNORECASE),
    # Java PreparedStatement bypass
    re.compile(r"""Statement.*execute(?:Query|Update)\s*\(\s*["'].*\+""", re.IGNORECASE),
    # PHP: "SELECT ... " . $var (dot concatenation)
    re.compile(r"""["'](?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*["']\s*\.\s*\$""", re.IGNORECASE),
]

# --- Secrets patterns in source code ---

SECRETS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"""(?:api[_-]?key|apikey)\s*[:=]\s*["'][A-Za-z0-9_\-]{20,}["']""", re.IGNORECASE), "API Key"),
    (re.compile(r"""(?:secret[_-]?key|secretkey)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']""", re.IGNORECASE), "Secret Key"),
    (re.compile(r"""(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}["']""", re.IGNORECASE), "Password"),
    (re.compile(r"""(?:aws_access_key_id)\s*[:=]\s*["']AKIA[A-Z0-9]{16}["']""", re.IGNORECASE), "AWS Access Key"),
    (re.compile(r"""(?:aws_secret_access_key)\s*[:=]\s*["'][A-Za-z0-9/+=]{30,}["']""", re.IGNORECASE), "AWS Secret Key"),
    (re.compile(r"""sk[_-](?:live|test)[_-][A-Za-z0-9]{20,}"""), "Stripe Key"),
    (re.compile(r"""sk-[A-Za-z0-9]{20,}"""), "OpenAI/API Key"),
    (re.compile(r"""ghp_[A-Za-z0-9]{36}"""), "GitHub Token"),
    (re.compile(r"""gho_[A-Za-z0-9]{36}"""), "GitHub OAuth Token"),
    (re.compile(r"""(?:private[_-]?key|PRIVATE[_-]?KEY)\s*[:=]\s*["'][^"']{20,}["']""", re.IGNORECASE), "Private Key"),
    (re.compile(r"""(?:token|TOKEN)\s*[:=]\s*["'][A-Za-z0-9_\-]{20,}["']"""), "Token"),
    (re.compile(r"""(?:DATABASE_URL|DB_URL)\s*[:=]\s*["'](?:postgres(?:ql)?|mysql|mongodb)://[^"']*:[^"']*@""", re.IGNORECASE), "Database URL with credentials"),
]

# Placeholder values to exclude from secret detection
SECRET_PLACEHOLDERS: set[str] = {
    "xxx", "yyy", "zzz", "test", "example", "placeholder", "changeme",
    "your_", "my_", "sample", "dummy", "fake", "mock", "todo",
    "none", "null", "empty", "undefined", "replace",
}

# --- Config file secret detection ---

# Config file extensions to scan for secrets
CONFIG_EXTENSIONS: set[str] = {
    ".properties", ".yml", ".yaml", ".ini", ".cfg", ".conf", ".toml",
}

# Patterns for secrets in config files (no quotes required)
# Format: (regex, secret_type)
CONFIG_SECRETS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # password=value, password: value (YAML/properties)
    (re.compile(
        r"""(?:^|[\s.])(?:password|passwd|pwd)\s*[:=]\s*(.+)""",
        re.IGNORECASE | re.MULTILINE,
    ), "Password"),
    # secret_key=value, secret=value
    (re.compile(
        r"""(?:^|[\s.])(?:secret[_-]?key|secret)\s*[:=]\s*(.+)""",
        re.IGNORECASE | re.MULTILINE,
    ), "Secret Key"),
    # api_key=value, apikey=value
    (re.compile(
        r"""(?:^|[\s.])(?:api[_-]?key|apikey)\s*[:=]\s*(.+)""",
        re.IGNORECASE | re.MULTILINE,
    ), "API Key"),
    # token=value (standalone, not as part of other words)
    (re.compile(
        r"""(?:^|[\s.])(?:auth[_-]?token|access[_-]?token)\s*[:=]\s*(.+)""",
        re.IGNORECASE | re.MULTILINE,
    ), "Token"),
    # private_key=value
    (re.compile(
        r"""(?:^|[\s.])(?:private[_-]?key)\s*[:=]\s*(.+)""",
        re.IGNORECASE | re.MULTILINE,
    ), "Private Key"),
]

# --- Security headers middleware markers ---

SECURITY_HEADERS_MARKERS: list[str] = [
    "helmet", "secure-headers", "django-csp", "django.middleware.security",
    "SecurityMiddleware", "flask-talisman", "secure", "content-security-policy",
    "x-content-type-options", "x-frame-options", "strict-transport-security",
    "SecurityHeadersMiddleware", "csp_middleware",
]

# --- Weak crypto patterns ---

WEAK_CRYPTO_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"""\bmd5\s*\(""", re.IGNORECASE), "MD5"),
    (re.compile(r"""\bMD5\b(?!.*hmac)"""), "MD5"),
    (re.compile(r"""hashlib\.md5\b"""), "MD5 (hashlib)"),
    (re.compile(r"""hashlib\.sha1\b"""), "SHA1 (hashlib)"),
    (re.compile(r"""MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-1)["']\s*\)""", re.IGNORECASE), "MD5/SHA1 (Java)"),
    (re.compile(r"""crypto\.createHash\s*\(\s*["'](?:md5|sha1)["']\s*\)""", re.IGNORECASE), "MD5/SHA1 (Node.js)"),
    (re.compile(r"""\bDES\b(?:\.|\s*\()"""), "DES"),
    (re.compile(r"""\bRC4\b(?:\.|\s*\()"""), "RC4"),
    (re.compile(r"""DESede|TripleDES"""), "3DES"),
    (re.compile(r"""Blowfish""", re.IGNORECASE), "Blowfish"),
    # C# / .NET
    (re.compile(r"""SHA1\.Create\s*\("""), "SHA1 (.NET)"),
    (re.compile(r"""MD5\.Create\s*\("""), "MD5 (.NET)"),
    (re.compile(r"""SHA1CryptoServiceProvider"""), "SHA1 (.NET legacy)"),
    (re.compile(r"""MD5CryptoServiceProvider"""), "MD5 (.NET legacy)"),
]

# Source code extensions to scan
SOURCE_EXTENSIONS: set[str] = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go",
    ".rb", ".rs", ".cs", ".php", ".kt", ".scala", ".swift",
}

# Extensions excluded from scanning (data/config/generated)
SKIP_EXTENSIONS: set[str] = {
    ".min.js", ".min.css", ".map", ".lock",
    ".po", ".mo", ".pot",
    ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".woff", ".woff2", ".ttf", ".eot",
    ".pyc", ".pyo", ".class",
}

# Directories to skip when scanning
SKIP_DIRS: set[str] = {
    "node_modules", "vendor", ".git", "__pycache__", "venv",
    ".venv", "env", ".env", "build", "dist", "target",
    ".tox", ".mypy_cache", ".pytest_cache", "site-packages",
    ".next", ".nuxt", "coverage",
}


def _make_id() -> str:
    """Genera un ID univoco per un finding."""
    return str(uuid.uuid4())[:8]


def _is_placeholder(value: str) -> bool:
    """Controlla se un valore e un placeholder, non un secret reale.

    Controlla solo la parte valore (dopo = o :), non il nome della variabile.
    """
    # Estrai solo la parte valore (dopo = o :)
    for sep in ("=", ":"):
        if sep in value:
            value = value.split(sep, 1)[1]
            break
    val_lower = value.lower().strip("\"' \t")

    # Se il valore e troppo corto dopo stripping, potrebbe essere un placeholder
    if len(val_lower) < 8:
        return True

    # Verifica se contiene parole tipiche dei placeholder
    # Ma solo se la parola placeholder e il contenuto principale, non parte di un token
    placeholder_only = {"xxx", "yyy", "zzz", "changeme", "none", "null", "empty", "undefined"}
    if val_lower in placeholder_only:
        return True

    # Prefix-based placeholders (your_xxx, my_key, sample_key etc.)
    prefix_placeholders = ("your_", "my_", "sample_", "dummy_", "fake_", "mock_", "todo_",
                           "test_", "example_", "placeholder", "replace_me")
    return any(val_lower.startswith(ph) for ph in prefix_placeholders)


def _is_config_placeholder(value: str) -> bool:
    """Controlla se un valore in un file di configurazione è un placeholder.

    Gestisce pattern tipici di config files: ${VAR}, %(var)s, ENC(...),
    <PLACEHOLDER>, variabili d'ambiente, valori vuoti, commenti.
    """
    val = value.strip().strip("\"'")

    # Valore vuoto o solo whitespace
    if not val or val.isspace():
        return True

    # Troppo corto per essere un secret reale (meno di 3 char utili)
    if len(val) < 3:
        return True

    # ${ENV_VAR} or ${env.VAR} — Spring/shell variable interpolation
    if re.match(r"^\$\{.*\}$", val):
        return True

    # $ENV_VAR — shell variable
    if re.match(r"^\$[A-Z_][A-Z0-9_]*$", val):
        return True

    # %(var)s — Python ConfigParser interpolation
    if re.match(r"^%\(.*\)s$", val):
        return True

    # ENC(...) — Jasypt encrypted values
    if re.match(r"^ENC\(.*\)$", val):
        return True

    # <PLACEHOLDER> — XML-style placeholder
    if re.match(r"^<[A-Z_]+>$", val):
        return True

    # {{VAR}} — template engines (Jinja2, Mustache, etc.)
    if re.match(r"^\{\{.*\}\}$", val):
        return True

    # Comment lines (# or !)
    if val.startswith("#") or val.startswith("!"):
        return True

    # Standard placeholder words
    return _is_placeholder(f"x={val}")


def _should_scan_file(path: str) -> bool:
    """Determina se un file deve essere scansionato per security check."""
    # Skip dirs
    parts = path.replace("\\", "/").split("/")
    if any(part in SKIP_DIRS for part in parts):
        return False

    # Check extension
    basename = parts[-1]
    for skip_ext in SKIP_EXTENSIONS:
        if basename.endswith(skip_ext):
            return False

    ext = "." + basename.rsplit(".", 1)[-1] if "." in basename else ""
    return ext in SOURCE_EXTENSIONS


def _version_less_than(version_str: str, threshold: str) -> bool:
    """Confronto semplificato tra versioni (major.minor.patch)."""
    def parse(v: str) -> list[int]:
        parts = []
        for p in v.split("."):
            # Prendi solo la parte numerica
            num = ""
            for ch in p:
                if ch.isdigit():
                    num += ch
                else:
                    break
            parts.append(int(num) if num else 0)
        return parts

    try:
        v_parts = parse(version_str)
        t_parts = parse(threshold)
        # Pad to same length
        max_len = max(len(v_parts), len(t_parts))
        v_parts.extend([0] * (max_len - len(v_parts)))
        t_parts.extend([0] * (max_len - len(t_parts)))
        return v_parts < t_parts
    except (ValueError, IndexError):
        return False


class SecurityAnalyzer:
    """
    Analyzer per il layer Sicurezza.

    Scansione CTO-level: cerca assenza di best practice e presenza
    di pattern pericolosi noti. Deterministico (regex + file existence).
    Quando online, interroga anche l'API OSV per CVE note nelle dipendenze.
    """

    def __init__(self, offline: bool = False) -> None:
        self.offline = offline

    def analyze(
        self,
        source: AuditSource,
        stack_info: StackInfo,
        classifications: list[FileClassification],
    ) -> list[Finding]:
        """Analizza la sicurezza del codebase."""
        file_tree = source.get_file_tree()
        all_paths: set[str] = set()
        dir_paths: set[str] = set()
        for entry in file_tree.entries:
            if entry.is_dir:
                dir_paths.add(entry.path)
            else:
                all_paths.add(entry.path)

        # Determina se il progetto ha un web framework / API routes
        has_web_framework = self._detect_web_framework(stack_info, all_paths)
        has_api_routes = False

        # Leggi file sorgente una sola volta e riusa per tutti i check
        file_contents: dict[str, str] = {}
        for path in all_paths:
            if not _should_scan_file(path):
                continue
            try:
                content = source.read_file(path)
                file_contents[path] = content
                # Detect API routes while reading
                if not has_api_routes:
                    for pattern in API_ROUTE_PATTERNS:
                        if pattern.search(content):
                            has_api_routes = True
                            break
            except (ValueError, FileNotFoundError, PermissionError, UnicodeDecodeError):
                continue

        findings: list[Finding] = []

        findings.extend(self._check_vulnerable_deps(all_paths, source))
        findings.extend(self._check_cve_online(all_paths, source))
        findings.extend(self._check_auth(has_web_framework, has_api_routes, file_contents, all_paths, source))
        findings.extend(self._check_http_urls(file_contents))
        findings.extend(self._check_cors(file_contents))
        findings.extend(self._check_sql_injection(file_contents))
        findings.extend(self._check_hardcoded_secrets(file_contents, all_paths, source))
        findings.extend(self._check_security_headers(has_web_framework, file_contents, all_paths))
        findings.extend(self._check_weak_crypto(file_contents))

        return findings

    def _detect_web_framework(self, stack_info: StackInfo, all_paths: set[str]) -> bool:
        """Rileva se il progetto usa un web framework."""
        for fw in stack_info.frameworks:
            if any(marker in fw.lower() for marker in WEB_FRAMEWORK_MARKERS):
                return True
        # Fallback: check file patterns
        web_markers = {"app.py", "server.py", "main.py", "index.js", "server.js", "app.js"}
        basenames = {p.rsplit("/", 1)[-1] for p in all_paths}
        return bool(web_markers & basenames)

    # --- Check 1: Vulnerable Dependencies ---

    def _check_vulnerable_deps(
        self, all_paths: set[str], source: AuditSource
    ) -> list[Finding]:
        """Cerca dipendenze con versioni notoriamente vulnerabili."""
        findings: list[Finding] = []
        vulnerable_found: list[str] = []

        # Scan dependency manifests
        dep_files: dict[str, str] = {
            "requirements.txt": "python",
            "Pipfile": "python",
            "pyproject.toml": "python",
            "package.json": "javascript",
            "pom.xml": "java",
            "build.gradle": "java",
            "build.gradle.kts": "java",
            "go.mod": "go",
        }

        for path in all_paths:
            basename = path.rsplit("/", 1)[-1]
            lang = dep_files.get(basename)
            if not lang:
                continue

            try:
                content = source.read_file(path)
            except (ValueError, FileNotFoundError, PermissionError, UnicodeDecodeError):
                continue

            for dep_name, dep_info in VULNERABLE_DEPS.items():
                if dep_info["lang"] != lang:
                    continue

                # Check if dependency is present and extract version
                version = self._extract_dep_version(content, dep_name, lang)
                if version and _version_less_than(version, dep_info["below"]):
                    vulnerable_found.append(
                        f"{dep_name} {version} (< {dep_info['below']}, {dep_info['cve']})"
                    )

        if vulnerable_found:
            # Cap a 5 per leggibilita
            display = vulnerable_found[:5]
            more = f" (+{len(vulnerable_found) - 5} altre)" if len(vulnerable_found) > 5 else ""
            findings.append(Finding(
                id=_make_id(),
                layer=Layer.SECURITY,
                severity=Severity.HIGH,
                rule_id="SEC-DEPS-001",
                title=f"Dipendenze con versioni vulnerabili ({len(vulnerable_found)} trovate)",
                description=(
                    "Trovate dipendenze con versioni associate a CVE note:\n"
                    + "\n".join(f"  - {v}" for v in display)
                    + more
                    + "\nAggiornare immediatamente queste dipendenze."
                ),
                framework_ref="NIS2 Art.21(2)(d)",
            ))

        return findings

    def _extract_dep_version(self, content: str, dep_name: str, lang: str) -> str | None:
        """Estrae la versione di una dipendenza dal file manifest."""
        if lang == "python":
            # requirements.txt: dep==1.0.0 o dep>=1.0.0
            pattern = re.compile(
                rf"^{re.escape(dep_name)}\s*[=<>~!]=?\s*([0-9][0-9.]*)",
                re.MULTILINE | re.IGNORECASE,
            )
            match = pattern.search(content)
            if match:
                return match.group(1)

        elif lang == "javascript":
            # package.json: "dep": "^1.0.0" o "dep": "1.0.0"
            pattern = re.compile(
                rf'"{re.escape(dep_name)}"\s*:\s*"[~^]?([0-9][0-9.]*)"',
                re.IGNORECASE,
            )
            match = pattern.search(content)
            if match:
                return match.group(1)

        elif lang == "java":
            # pom.xml / build.gradle: version tag or version string
            # Simplified: look for artifact + version nearby
            dep_lower = dep_name.lower()
            if dep_lower in content.lower():
                pattern = re.compile(
                    rf"{re.escape(dep_name)}.*?(?:version|:)\s*['\"]?([0-9][0-9.]*)",
                    re.IGNORECASE | re.DOTALL,
                )
                match = pattern.search(content[:content.lower().find(dep_lower) + 500])
                if match:
                    return match.group(1)

        elif lang == "go":
            # go.mod: dep v1.0.0
            pattern = re.compile(
                rf"{re.escape(dep_name)}\s+v([0-9][0-9.]*)",
                re.IGNORECASE,
            )
            match = pattern.search(content)
            if match:
                return match.group(1)

        return None

    # --- Check 1b: CVE Online (OSV API) ---

    def _check_cve_online(
        self, all_paths: set[str], source: AuditSource
    ) -> list[Finding]:
        """Interroga l'API OSV per CVE note nelle dipendenze (solo se online)."""
        if self.offline:
            return []

        try:
            from cto_audit.collectors.cve_checker import parse_dependencies, query_osv
        except ImportError:
            return []

        deps = parse_dependencies(all_paths, source)
        if not deps:
            return []

        cve_results = query_osv(deps)
        if not cve_results:
            return []

        # Costruisci finding
        total_cves = sum(len(r.cve_ids) for r in cve_results)
        display_lines: list[str] = []
        for r in cve_results[:10]:
            cves = ", ".join(r.cve_ids[:3])
            more = f" +{len(r.cve_ids) - 3}" if len(r.cve_ids) > 3 else ""
            display_lines.append(
                f"  - {r.dependency.name} {r.dependency.version} "
                f"({r.dependency.ecosystem}): {cves}{more}"
            )

        more_deps = f"\n  (+{len(cve_results) - 10} altre dipendenze)" if len(cve_results) > 10 else ""

        # Severity basata sul numero di CVE e se ci sono critiche
        severity = Severity.HIGH if total_cves >= 5 else Severity.MEDIUM

        return [Finding(
            id=_make_id(),
            layer=Layer.SECURITY,
            severity=severity,
            rule_id="SEC-DEPS-CVE-001",
            title=f"CVE note nelle dipendenze ({total_cves} vulnerabilita in {len(cve_results)} pacchetti)",
            description=(
                "Trovate vulnerabilita note (CVE) nelle dipendenze del progetto "
                "(fonte: Google OSV database):\n"
                + "\n".join(display_lines)
                + more_deps
                + "\n\nAggiornare le dipendenze alle versioni patchate."
            ),
            framework_ref="NIS2 Art.21(2)(d)",
        )]

    # --- Check 2: Auth Framework ---

    # Manifest files to scan for auth markers (not in SOURCE_EXTENSIONS)
    _AUTH_MANIFEST_NAMES: set[str] = {
        "pom.xml", "build.gradle", "build.gradle.kts",
        "Gemfile", "composer.json", "Package.swift",
    }

    def _check_auth(
        self,
        has_web_framework: bool,
        has_api_routes: bool,
        file_contents: dict[str, str],
        all_paths: set[str],
        source: AuditSource,
    ) -> list[Finding]:
        """Verifica presenza di framework auth (solo se web/API)."""
        if not has_web_framework and not has_api_routes:
            return []

        # Cerca marker auth nel codice
        all_auth_markers: list[str] = []
        for markers in AUTH_MARKERS.values():
            all_auth_markers.extend(markers)

        for content in file_contents.values():
            content_lower = content.lower().replace("-", "_")
            if any(marker.lower().replace("-", "_") in content_lower for marker in all_auth_markers):
                return []

        # Also check manifest/config files (pom.xml, Gemfile, etc.)
        for path in all_paths:
            basename = path.rsplit("/", 1)[-1] if "/" in path else path
            if basename in self._AUTH_MANIFEST_NAMES:
                try:
                    content = source.read_file(path)
                    content_lower = content.lower().replace("-", "_")
                    if any(marker.lower().replace("-", "_") in content_lower for marker in all_auth_markers):
                        return []
                except (ValueError, FileNotFoundError, PermissionError, UnicodeDecodeError):
                    continue

        return [Finding(
            id=_make_id(),
            layer=Layer.SECURITY,
            severity=Severity.HIGH,
            rule_id="SEC-AUTH-001",
            title="Nessun framework di autenticazione rilevato",
            description=(
                "Il progetto espone route API ma non utilizza nessun framework "
                "di autenticazione noto (JWT, OAuth, session-based, API key auth). "
                "Le API esposte senza autenticazione sono vulnerabili ad accesso non autorizzato."
            ),
            framework_ref="NIST PR.AC-1",
        )]

    # --- Check 3: HTTP URLs ---

    def _check_http_urls(self, file_contents: dict[str, str]) -> list[Finding]:
        """Cerca URL http:// hardcodati (esclusi localhost/127.0.0.1)."""
        http_pattern = re.compile(
            r"""http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|example\.com|example\.org)([a-zA-Z0-9._-]+)"""
        )

        http_urls: list[tuple[str, str]] = []  # (path, url)
        for path, content in file_contents.items():
            for match in http_pattern.finditer(content):
                url = match.group(0)
                # Skip comments and documentation
                if url not in ("http://",):
                    http_urls.append((path, url))

        if not http_urls:
            return []

        # Cap a 5
        display = http_urls[:5]
        more = f" (+{len(http_urls) - 5} altre)" if len(http_urls) > 5 else ""

        return [Finding(
            id=_make_id(),
            layer=Layer.SECURITY,
            severity=Severity.MEDIUM,
            rule_id="SEC-HTTPS-001",
            title=f"URL HTTP non cifrati nel codice ({len(http_urls)} trovati)",
            description=(
                "Trovati URL con protocollo HTTP (non cifrato) hardcodati:\n"
                + "\n".join(f"  - {p}: {u}" for p, u in display)
                + more
                + "\nTutte le comunicazioni dovrebbero usare HTTPS."
            ),
            file_path=http_urls[0][0] if http_urls else None,
            framework_ref="NIST PR.DS-2",
        )]

    # --- Check 4: CORS Permissive ---

    def _check_cors(self, file_contents: dict[str, str]) -> list[Finding]:
        """Cerca configurazioni CORS permissive (* origins)."""
        cors_findings: list[str] = []

        for path, content in file_contents.items():
            for pattern in CORS_PERMISSIVE_PATTERNS:
                if pattern.search(content):
                    cors_findings.append(path)
                    break

        if not cors_findings:
            return []

        return [Finding(
            id=_make_id(),
            layer=Layer.SECURITY,
            severity=Severity.MEDIUM,
            rule_id="SEC-CORS-001",
            title=f"CORS permissivo rilevato ({len(cors_findings)} file)",
            description=(
                "Trovata configurazione CORS che permette qualsiasi origine (*):\n"
                + "\n".join(f"  - {p}" for p in cors_findings[:5])
                + "\nUn CORS permissivo espone le API a richieste cross-origin non autorizzate."
            ),
            file_path=cors_findings[0],
            framework_ref="OWASP A01:2021",
        )]

    # --- Check 5: SQL Injection ---

    def _check_sql_injection(self, file_contents: dict[str, str]) -> list[Finding]:
        """Cerca pattern di SQL injection via string concat/f-string."""
        sql_findings: list[tuple[str, str]] = []

        for path, content in file_contents.items():
            for pattern in SQL_INJECTION_PATTERNS:
                match = pattern.search(content)
                if match:
                    # Estrai snippet
                    snippet = match.group(0)[:80]
                    sql_findings.append((path, snippet))
                    break  # 1 finding per file

        if not sql_findings:
            return []

        # Cap a 5
        display = sql_findings[:5]
        more = f" (+{len(sql_findings) - 5})" if len(sql_findings) > 5 else ""

        return [Finding(
            id=_make_id(),
            layer=Layer.SECURITY,
            severity=Severity.HIGH,
            rule_id="SEC-SQL-001",
            title=f"Possibile SQL Injection ({len(sql_findings)} file)",
            description=(
                "Trovata costruzione di query SQL con concatenazione di stringhe/f-string:\n"
                + "\n".join(f"  - {p}" for p, _ in display)
                + more
                + "\nUsare query parametrizzate (? o %s con parametri separati) o un ORM."
            ),
            file_path=sql_findings[0][0],
            framework_ref="OWASP A03:2021",
        )]

    # --- Check 6: Hardcoded Secrets ---

    def _check_hardcoded_secrets(
        self,
        file_contents: dict[str, str],
        all_paths: set[str] | None = None,
        source: AuditSource | None = None,
    ) -> list[Finding]:
        """Cerca secrets/API key hardcodati in file sorgente e config."""
        secrets_found: list[tuple[str, str]] = []  # (path, type)

        # 1) Scan source code files (existing logic)
        for path, content in file_contents.items():
            # Skip test files
            basename = path.rsplit("/", 1)[-1].lower()
            if basename.startswith("test_") or ".test." in basename or ".spec." in basename:
                continue
            # Skip CI/CD files
            if ".github/workflows/" in path or ".gitlab-ci" in path:
                continue

            for pattern, secret_type in SECRETS_PATTERNS:
                match = pattern.search(content)
                if match:
                    matched_text = match.group(0)
                    if not _is_placeholder(matched_text):
                        secrets_found.append((path, secret_type))
                        break  # 1 per file

        # 2) Scan config files (.properties, .yml, .ini, .conf, etc.)
        if all_paths and source:
            secrets_found.extend(
                self._scan_config_files_for_secrets(all_paths, source)
            )

        if not secrets_found:
            return []

        # Cap a 5
        display = secrets_found[:5]
        more = f" (+{len(secrets_found) - 5})" if len(secrets_found) > 5 else ""

        return [Finding(
            id=_make_id(),
            layer=Layer.SECURITY,
            severity=Severity.CRITICAL,
            rule_id="SEC-SECRETS-CODE-001",
            title=f"Secrets hardcodati nel codice/config ({len(secrets_found)} file)",
            description=(
                "Trovati secrets/credenziali hardcodati direttamente nel codice o config:\n"
                + "\n".join(f"  - {p} ({t})" for p, t in display)
                + more
                + "\nI secrets devono essere gestiti via variabili d'ambiente o secret manager."
            ),
            file_path=secrets_found[0][0],
            framework_ref="NIST PR.DS-5",
        )]

    def _scan_config_files_for_secrets(
        self,
        all_paths: set[str],
        source: AuditSource,
    ) -> list[tuple[str, str]]:
        """Scansiona file di configurazione per secrets hardcodati."""
        secrets_found: list[tuple[str, str]] = []

        for path in sorted(all_paths):
            basename = path.rsplit("/", 1)[-1].lower()

            # Solo file config
            ext = "." + basename.rsplit(".", 1)[-1] if "." in basename else ""
            if ext not in CONFIG_EXTENSIONS:
                continue

            # Skip dirs problematiche
            parts = path.replace("\\", "/").split("/")
            if any(part in SKIP_DIRS for part in parts):
                continue

            # Skip test/example config files
            if "test" in basename or "example" in basename or "sample" in basename:
                continue

            try:
                content = source.read_file(path)
            except (ValueError, FileNotFoundError, PermissionError, UnicodeDecodeError):
                continue

            for pattern, secret_type in CONFIG_SECRETS_PATTERNS:
                match = pattern.search(content)
                if match:
                    raw_value = match.group(1).strip()
                    if not _is_config_placeholder(raw_value):
                        secrets_found.append((path, secret_type))
                        break  # 1 per file

        return secrets_found

    # --- Check 7: Security Headers ---

    def _check_security_headers(
        self,
        has_web_framework: bool,
        file_contents: dict[str, str],
        all_paths: set[str],
    ) -> list[Finding]:
        """Verifica presenza di middleware per security headers."""
        if not has_web_framework:
            return []

        # Cerca marker security headers (normalizza - e _ per matching)
        for content in file_contents.values():
            content_lower = content.lower().replace("-", "_")
            if any(marker.lower().replace("-", "_") in content_lower for marker in SECURITY_HEADERS_MARKERS):
                return []

        # Cerca in package.json per helmet
        for path in all_paths:
            if path.rsplit("/", 1)[-1] == "package.json":
                try:
                    # Already in file_contents or read from source
                    if path in file_contents:
                        if "helmet" in file_contents[path].lower():
                            return []
                except Exception:
                    pass

        return [Finding(
            id=_make_id(),
            layer=Layer.SECURITY,
            severity=Severity.LOW,
            rule_id="SEC-HEADERS-001",
            title="Nessun middleware per security headers rilevato",
            description=(
                "Il progetto usa un web framework ma non configura security headers "
                "(helmet, django-csp, flask-talisman, Content-Security-Policy, "
                "X-Content-Type-Options, X-Frame-Options). "
                "I security headers proteggono da XSS, clickjacking e content sniffing."
            ),
            framework_ref="OWASP A05:2021",
        )]

    # --- Check 8: Weak Crypto ---

    def _check_weak_crypto(self, file_contents: dict[str, str]) -> list[Finding]:
        """Cerca pattern crittografici deboli (MD5, SHA1, DES, RC4)."""
        crypto_findings: list[tuple[str, str]] = []  # (path, algo)

        for path, content in file_contents.items():
            for pattern, algo_name in WEAK_CRYPTO_PATTERNS:
                if pattern.search(content):
                    crypto_findings.append((path, algo_name))
                    break  # 1 per file

        if not crypto_findings:
            return []

        # Deduplica per algoritmo
        algos_found = sorted(set(algo for _, algo in crypto_findings))

        # Cap a 5 files
        display = crypto_findings[:5]
        more = f" (+{len(crypto_findings) - 5})" if len(crypto_findings) > 5 else ""

        return [Finding(
            id=_make_id(),
            layer=Layer.SECURITY,
            severity=Severity.MEDIUM,
            rule_id="SEC-CRYPTO-001",
            title=f"Pattern crittografici deboli ({', '.join(algos_found)})",
            description=(
                "Trovati algoritmi crittografici deprecati/deboli:\n"
                + "\n".join(f"  - {p} ({a})" for p, a in display)
                + more
                + "\nUsare SHA-256+ per hashing, AES-256 per cifratura. "
                "MD5/SHA1 non sono sicuri per hashing password o firma."
            ),
            framework_ref="NIST PR.DS-5",
        )]
