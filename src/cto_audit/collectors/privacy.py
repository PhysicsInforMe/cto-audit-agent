"""
Privacy classifier — classifica i file in 4 categorie di privacy.

Implementa le regole definite nel doc 03-hitl-flow.md per classificare
ogni file del codebase prima dell'analisi:

- ⚫ EXCLUDED: file irrilevanti (vendor, binari, lockfile, file grandi)
- 🔴 SENSITIVE: file che contengono o potrebbero contenere dati sensibili
- 🟢 SAFE: file analizzabili senza rischi privacy
- 🟡 LOCAL_LLM: non assegnata automaticamente (solo via override HITL)

L'ordine di valutazione è: EXCLUDED → SENSITIVE → SAFE.
Un file che matcha EXCLUDED non viene mai controllato per SENSITIVE.
"""

from __future__ import annotations

import fnmatch
import math
import re
from collections import Counter

from cto_audit.core.models import (
    FileClassification,
    FileInfo,
    PrivacyCategory,
)
from cto_audit.core.source import AuditSource


# --- Regole EXCLUDED (doc 03-hitl-flow.md) ---

EXCLUDED_DIRECTORIES: set[str] = {
    "node_modules",
    "vendor",
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
}

EXCLUDED_EXTENSIONS: set[str] = {
    # Immagini
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    # Font
    ".woff", ".woff2", ".ttf", ".eot",
    # Archivi e binari
    ".zip", ".tar", ".gz", ".exe", ".dll", ".so",
    # Compilati
    ".pyc", ".class", ".o",
    # Database
    ".sqlite", ".db",
}

EXCLUDED_LOCKFILES: set[str] = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "composer.lock",
    "Gemfile.lock",
}

EXCLUDED_SIZE_LIMIT: int = 1_048_576  # 1 MB


# --- Regole SENSITIVE (doc 03-hitl-flow.md) ---

SENSITIVE_FILENAME_PATTERNS: list[str] = [
    ".env", ".env.*",
    "*.pem", "*.key", "*.cert", "*.p12",
    "secrets.*", "credentials.*",
    "*secret*", "*credential*",
    "id_rsa", "id_ed25519",
    ".htpasswd", ".pgpass",
    "*.keystore", "*.jks",
]

SENSITIVE_CONTENT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+"), "Password rilevata"),
    (re.compile(r"(?i)(api[_-]?key|apikey)\s*[=:]\s*\S+"), "API key rilevata"),
    (re.compile(r"(?i)(secret[_-]?key|client[_-]?secret)\s*[=:]"), "Secret key rilevata"),
    (re.compile(r"(?i)(access[_-]?token|auth[_-]?token)\s*[=:]"), "Token di accesso rilevato"),
    (re.compile(r"(?i)(aws_access_key_id|aws_secret)"), "Credenziali AWS rilevate"),
    (re.compile(r"(?i)(database_url|db_password|db_pass)"), "Credenziali database rilevate"),
    (re.compile(r"(?i)(private[_-]?key)\s*[=:]"), "Chiave privata rilevata"),
    (re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"), "Chiave privata PEM rilevata"),
    (re.compile(r"(?i)connection[_-]?string\s*[=:]"), "Connection string rilevata"),
]

SENSITIVE_PATH_PATTERNS: list[str] = [
    "*/config/prod*",
    "*/deploy/prod*",
    "*/.ssh/*",
    "*/vault/*",
]

# Valori placeholder/esempio che non sono veri secrets (case insensitive)
PLACEHOLDER_VALUES: set[str] = {
    "none", "null", "nil", "undefined", "false", "true",
    "optional", "required", "str", "string", "int", "integer",
    "your_api_key_here", "your_key_here", "your_secret_here",
    "your_password_here", "your_token_here",
    "xxx", "xxxx", "xxxxxxxx",
    "changeme", "change_me", "replace_me", "todo", "fixme",
    "example", "test", "dummy", "placeholder", "sample",
    "...", "****",
}


ENTROPY_THRESHOLD: float = 5.0


class PrivacyClassifier:
    """
    Classifica i file di un codebase in categorie di privacy.

    Il classificatore riceve la lista di FileInfo dal FileScanner e la sorgente
    per leggere il contenuto dei file. Produce una FileClassification per ogni file.

    L'ordine di valutazione è deterministico:
    1. Controlla regole EXCLUDED (directory, estensione, size, lockfile)
    2. Controlla regole SENSITIVE (filename, contenuto, entropia, path)
    3. Se nessuna regola matcha → SAFE

    Attributes:
        source: Sorgente dati per leggere i contenuti dei file
    """

    def __init__(self, source: AuditSource) -> None:
        """
        Args:
            source: Implementazione di AuditSource per leggere i file
        """
        self.source = source

    def classify(self, files: list[FileInfo]) -> list[FileClassification]:
        """
        Classifica tutti i file forniti.

        Args:
            files: Lista di FileInfo prodotta dal FileScanner

        Returns:
            Lista di FileClassification, una per ogni file in input
        """
        results: list[FileClassification] = []
        for file_info in files:
            classification = self._classify_file(file_info)
            results.append(classification)
        return results

    def _classify_file(self, file_info: FileInfo) -> FileClassification:
        """
        Classifica un singolo file applicando le regole in ordine.

        Args:
            file_info: Informazioni sul file da classificare

        Returns:
            FileClassification con categoria e motivo
        """
        # 1. Controlla EXCLUDED
        excluded_reason = self._check_excluded(file_info)
        if excluded_reason:
            return FileClassification(
                file_info=file_info,
                category=PrivacyCategory.EXCLUDED,
                reason=excluded_reason,
                confidence=1.0,
            )

        # 2. Controlla SENSITIVE (filename prima, poi contenuto)
        sensitive_result = self._check_sensitive(file_info)
        if sensitive_result:
            reason, confidence = sensitive_result
            return FileClassification(
                file_info=file_info,
                category=PrivacyCategory.SENSITIVE,
                reason=reason,
                confidence=confidence,
            )

        # 3. Default: SAFE
        return FileClassification(
            file_info=file_info,
            category=PrivacyCategory.SAFE,
            reason="Nessun pattern sensibile rilevato",
            confidence=1.0,
        )

    # --- Regole EXCLUDED ---

    def _check_excluded(self, file_info: FileInfo) -> str | None:
        """
        Verifica se il file deve essere EXCLUDED.

        Controlla in ordine: directory, estensione, size, lockfile.

        Returns:
            Motivo dell'esclusione, o None se non escluso
        """
        path = file_info.path
        basename = path.split("/")[-1]

        # Directory escluse
        parts = path.split("/")
        for part in parts[:-1]:
            if part in EXCLUDED_DIRECTORIES:
                return f"Directory esclusa: {part}/"

        # Estensione esclusa
        ext = file_info.extension.lower()
        if ext in EXCLUDED_EXTENSIONS:
            return f"Estensione esclusa: {ext}"

        # Dimensione > 1MB
        if file_info.size > EXCLUDED_SIZE_LIMIT:
            size_mb = file_info.size / 1_048_576
            return f"File troppo grande: {size_mb:.1f} MB (limite: 1 MB)"

        # Lockfile
        if basename in EXCLUDED_LOCKFILES:
            return f"Lockfile: {basename}"

        return None

    # --- Regole SENSITIVE ---

    def _check_sensitive(self, file_info: FileInfo) -> tuple[str, float] | None:
        """
        Verifica se il file è SENSITIVE.

        Controlla in ordine: filename pattern, path pattern, contenuto (regex + entropia).
        Il contenuto viene letto solo se i check su nome e path non hanno già matchato.

        Returns:
            Tupla (motivo, confidenza) se SENSITIVE, None altrimenti
        """
        path = file_info.path
        basename = path.split("/")[-1]

        # Filename patterns
        for pattern in SENSITIVE_FILENAME_PATTERNS:
            if fnmatch.fnmatch(basename, pattern) or fnmatch.fnmatch(basename.lower(), pattern.lower()):
                return (f"Nome file sensibile: matcha pattern '{pattern}'", 1.0)

        # Path patterns (prova match diretto e con prefisso per gestire
        # pattern come */config/prod* su percorsi che iniziano senza parent)
        for pattern in SENSITIVE_PATH_PATTERNS:
            if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch("_/" + path, pattern):
                return (f"Percorso sensibile: matcha pattern '{pattern}'", 0.9)

        # Analisi contenuto (leggere il file)
        content_result = self._check_content_sensitive(file_info)
        if content_result:
            return content_result

        return None

    def _check_content_sensitive(self, file_info: FileInfo) -> tuple[str, float] | None:
        """
        Analizza il contenuto del file per pattern sensibili e alta entropia.

        Legge il file dalla sorgente. Se non leggibile (binario, permessi),
        restituisce None (il file non viene classificato come SENSITIVE per errore).

        Returns:
            Tupla (motivo, confidenza) se trovato pattern sensibile, None altrimenti
        """
        try:
            content = self.source.read_file(file_info.path)
        except (ValueError, UnicodeDecodeError, PermissionError, FileNotFoundError):
            # File non leggibile → non possiamo determinare se è sensibile
            return None

        if not content.strip():
            return None

        # Regex pattern nel contenuto
        for pattern, description in SENSITIVE_CONTENT_PATTERNS:
            match = pattern.search(content)
            if match:
                # Estrai il valore dopo = o : per verificare se è un placeholder
                matched_text = match.group(0)
                value_part = ""
                for sep in ("=", ":"):
                    if sep in matched_text:
                        value_part = matched_text.split(sep, 1)[1].strip().strip("'\"").strip()
                        break

                # Ignora valori placeholder/esempio (solo se un valore è stato estratto)
                if value_part and value_part.lower() in PLACEHOLDER_VALUES:
                    continue

                # Ignora type annotations Python (api_key: str, password: Optional[str])
                if value_part and re.match(
                    r"^(str|int|float|bool|bytes|list|dict|set|tuple|None"
                    r"|Optional|Union|Any)\b",
                    value_part,
                ):
                    continue

                # Trova la riga del match per contesto
                line_num = content[:match.start()].count("\n") + 1
                # Tronca il testo matchato per il motivo
                if len(matched_text) > 60:
                    matched_text = matched_text[:57] + "..."
                return (
                    f"{description} (riga {line_num}: {matched_text})",
                    0.95,
                )

        # Entropia Shannon su singole righe (per rilevare stringhe ad alta entropia
        # come API key, token, password generate)
        entropy_result = self._check_high_entropy_lines(content)
        if entropy_result:
            return entropy_result

        return None

    def _check_high_entropy_lines(self, content: str) -> tuple[str, float] | None:
        """
        Cerca righe con entropia Shannon sopra la soglia.

        L'entropia viene calcolata solo su righe che sembrano assegnazioni
        di variabile (contengono = o :) e hanno una parte destra
        sufficientemente lunga (>= 16 caratteri). Questo evita falsi positivi
        su codice normale.

        Returns:
            Tupla (motivo, confidenza) se trovata riga ad alta entropia, None altrimenti
        """
        for line_num, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            # Cerca parti dopo = o : che potrebbero essere secrets
            for separator in ("=", ":"):
                if separator not in line:
                    continue

                # Prendi la parte dopo il primo separatore
                _, _, value = line.partition(separator)
                value = value.strip().strip("'\"").strip()

                # Solo valori sufficientemente lunghi (evita falsi positivi)
                if len(value) < 16:
                    continue

                # Evita URL, path e valori comuni
                if value.startswith(("http://", "https://", "/", "./", "../")):
                    continue

                entropy = _shannon_entropy(value)
                if entropy >= ENTROPY_THRESHOLD:
                    # Tronca il valore per il motivo
                    display_value = value[:20] + "..." if len(value) > 20 else value
                    return (
                        f"Possibile secret/token rilevato — stringa con "
                        f"casualità elevata (riga {line_num}, "
                        f"entropia: {entropy:.2f}): {display_value}",
                        0.85,
                    )

        return None


def _shannon_entropy(data: str) -> float:
    """
    Calcola l'entropia di Shannon di una stringa.

    L'entropia misura la casualità del contenuto. Stringhe con alta entropia
    (> 4.5) sono probabilmente secrets, token, o chiavi crittografiche.
    Codice sorgente normale ha tipicamente entropia tra 2.5 e 4.0.

    Formula: H = -Σ(p(x) * log2(p(x))) per ogni carattere x

    Args:
        data: Stringa di cui calcolare l'entropia

    Returns:
        Entropia in bit (0.0 = costante, ~7.0 = massima casualità per ASCII)
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy
