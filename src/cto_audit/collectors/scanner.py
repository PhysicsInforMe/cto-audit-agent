"""
File scanner — scansiona un AuditSource e produce una lista di FileInfo.

Il FileScanner è il primo passo della pipeline di analisi:
1. Riceve un AuditSource (locale, remoto, multi)
2. Itera il file tree
3. Per ogni file non escluso, crea un FileInfo con path, size, estensione, LOC
4. Applica regole di esclusione directory (node_modules, .git, vendor, etc.)

Le regole di esclusione directory sono quelle definite nel doc 03-hitl-flow.md
come ⚫ EXCLUDED. Qui si escludono solo le directory note come irrilevanti;
la classificazione EXCLUDED completa (estensioni, size, lockfile) è gestita
dal PrivacyClassifier nel Blocco 4.
"""

from __future__ import annotations

import os

from cto_audit.core.models import FileInfo
from cto_audit.core.source import AuditSource


# Directory sempre escluse dalla scansione (da doc 03-hitl-flow.md)
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
    ".idea",
    ".vscode",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    ".eggs",
    "egg-info",
    ".gradle",
    ".next",
    ".nuxt",
    "coverage",
    ".coverage",
    ".nyc_output",
}

# File generati dal tool stesso, da escludere dalla scansione
EXCLUDED_TOOL_FILES: set[str] = {
    ".cto-audit-classification.yml",
}


class FileScanner:
    """
    Scansiona un AuditSource e produce una lista di FileInfo.

    Il scanner filtra le directory escluse e per ogni file restante
    calcola: percorso relativo, dimensione, estensione, righe di codice.

    Attributes:
        source: La sorgente dati da scansionare
    """

    def __init__(self, source: AuditSource) -> None:
        """
        Inizializza lo scanner con una sorgente dati.

        Args:
            source: Implementazione di AuditSource da scansionare
        """
        self.source = source

    def scan(self) -> list[FileInfo]:
        """
        Esegue la scansione e restituisce la lista di FileInfo.

        Per ogni file nel file tree della sorgente:
        - Verifica che non sia in una directory esclusa
        - Calcola l'estensione del file
        - Tenta di leggere il file per contare le righe di codice
        - Se il file non è leggibile (binario, permessi), LOC = 0

        Returns:
            Lista di FileInfo per tutti i file non esclusi, ordinata per path
        """
        file_tree = self.source.get_file_tree()
        results: list[FileInfo] = []

        for entry in file_tree.entries:
            # Salta le directory
            if entry.is_dir:
                continue

            # Salta i file dentro directory escluse
            if self._is_in_excluded_dir(entry.path):
                continue

            # Salta i file generati dal tool stesso
            basename = entry.path.split("/")[-1]
            if basename in EXCLUDED_TOOL_FILES:
                continue

            # Calcola estensione
            extension = self._get_extension(entry.path)

            # Calcola LOC leggendo il file
            loc = self._count_lines(entry.path)

            results.append(FileInfo(
                path=entry.path,
                size=entry.size,
                extension=extension,
                lines_of_code=loc,
            ))

        return sorted(results, key=lambda f: f.path)

    def _is_in_excluded_dir(self, path: str) -> bool:
        """
        Verifica se un file è contenuto in una directory esclusa.

        Controlla ogni componente del percorso contro la lista delle
        directory escluse.

        Args:
            path: Percorso relativo normalizzato (separatore /)

        Returns:
            True se il file è in una directory da escludere
        """
        parts = path.split("/")
        # Controlla ogni directory nel percorso (escluso il filename)
        for part in parts[:-1]:
            if part in EXCLUDED_DIRECTORIES:
                return True
            # Gestisci anche il caso di .egg-info con nome variabile
            if part.endswith(".egg-info"):
                return True
        return False

    def _get_extension(self, path: str) -> str:
        """
        Estrae l'estensione del file dal percorso.

        Gestisce file senza estensione (Dockerfile, Makefile, etc.)
        e file con estensioni multiple (.tar.gz → .gz).

        Args:
            path: Percorso del file

        Returns:
            Estensione con punto (es. ".py") o stringa vuota se assente
        """
        basename = path.split("/")[-1]
        _, ext = os.path.splitext(basename)
        return ext.lower()

    def _count_lines(self, path: str) -> int:
        """
        Conta le righe di un file leggendolo dalla sorgente.

        Se il file non è leggibile (binario, errore encoding, permessi),
        restituisce 0 senza propagare l'eccezione.

        Args:
            path: Percorso relativo del file

        Returns:
            Numero di righe, o 0 se non leggibile
        """
        try:
            content = self.source.read_file(path)
            return len(content.splitlines())
        except (ValueError, UnicodeDecodeError, PermissionError, FileNotFoundError):
            return 0
