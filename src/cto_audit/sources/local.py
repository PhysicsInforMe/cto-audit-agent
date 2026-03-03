"""
Sorgente dati locale — legge un codebase da un path sul filesystem.

`LocalRepoSource` è l'implementazione MVP di `AuditSource`.
Scansiona ricorsivamente una directory, rispetta .gitignore se presente,
e fornisce accesso ai file per le fasi successive dell'audit.
"""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path

from cto_audit.core.models import FileTree, FileTreeEntry, SourceMetadata


# File critici per l'analisi che non devono mai essere ignorati dal .gitignore.
# Anche se un .gitignore li matcha (es. *.txt), li includiamo comunque perché
# sono essenziali per il rilevamento dello stack e delle dipendenze.
NEVER_IGNORE_FILES: set[str] = {
    "requirements.txt",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "package.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
    "Makefile",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Jenkinsfile",
    ".gitignore",
    "manage.py",
}


class LocalRepoSource:
    """
    Sorgente dati che legge un codebase da una directory locale.

    Comportamento:
    - Scansiona ricorsivamente la directory target
    - Se presente un file .gitignore nella root, ne rispetta le regole
    - Ignora sempre la directory .git/
    - Gestisce file con encoding diversi (fallback a latin-1)
    - Calcola LOC per ogni file testuale

    Attributes:
        root: Path assoluto della directory root del progetto
    """

    def __init__(self, root: Path | str) -> None:
        """
        Inizializza la sorgente con il percorso della directory.

        Args:
            root: Percorso della directory da analizzare

        Raises:
            FileNotFoundError: Se il percorso non esiste
            NotADirectoryError: Se il percorso non è una directory
        """
        self.root = Path(root).resolve()
        if not self.root.exists():
            raise FileNotFoundError(f"Il percorso '{self.root}' non esiste")
        if not self.root.is_dir():
            raise NotADirectoryError(f"Il percorso '{self.root}' non è una directory")

        # Carica le regole .gitignore se presenti
        self._gitignore_patterns = self._load_gitignore()
        # Pre-compila i pattern per evitare re-compilazioni ripetute in fnmatch
        self._compiled_patterns = self._compile_patterns()
        # Cache per get_file_tree() — evita ri-scansioni costose
        self._cached_file_tree: FileTree | None = None

    def get_file_tree(self) -> FileTree:
        """
        Costruisce l'albero dei file della directory, rispettando .gitignore.

        Esclude sempre la directory .git/.
        Le entry sono ordinate per percorso relativo.
        Il risultato è cached: chiamate successive restituiscono lo stesso oggetto.

        Returns:
            FileTree con tutte le entry trovate
        """
        if self._cached_file_tree is not None:
            return self._cached_file_tree

        entries: list[FileTreeEntry] = []

        for dirpath, dirnames, filenames in os.walk(self.root):
            rel_dir = os.path.relpath(dirpath, self.root)
            if rel_dir == ".":
                rel_dir = ""

            # Filtra directory da escludere (modifica in-place per os.walk)
            dirnames[:] = [
                d for d in sorted(dirnames)
                if not self._is_ignored(
                    os.path.join(rel_dir, d) + "/" if rel_dir else d + "/"
                )
            ]

            # Aggiungi le directory (tranne la root stessa)
            if rel_dir:
                entries.append(FileTreeEntry(
                    path=rel_dir.replace("\\", "/"),
                    is_dir=True,
                    size=0,
                ))

            # Aggiungi i file
            for fname in sorted(filenames):
                rel_path = os.path.join(rel_dir, fname) if rel_dir else fname
                rel_path_normalized = rel_path.replace("\\", "/")

                if self._is_ignored(rel_path_normalized):
                    continue

                full_path = os.path.join(dirpath, fname)
                try:
                    size = os.path.getsize(full_path)
                except OSError:
                    size = 0

                entries.append(FileTreeEntry(
                    path=rel_path_normalized,
                    is_dir=False,
                    size=size,
                ))

        self._cached_file_tree = FileTree(root=str(self.root), entries=entries)
        return self._cached_file_tree

    def read_file(self, path: str) -> str:
        """
        Legge il contenuto di un file come testo.

        Prova prima UTF-8, poi fallback a latin-1 per file con encoding
        non standard. Questo copre la stragrande maggioranza dei file
        di codice sorgente.

        Args:
            path: Percorso relativo del file rispetto alla root

        Returns:
            Contenuto del file come stringa

        Raises:
            FileNotFoundError: Se il file non esiste
            PermissionError: Se non si hanno permessi di lettura
            ValueError: Se il file è binario (contiene byte null)
        """
        full_path = self.root / path
        if not full_path.exists():
            raise FileNotFoundError(f"Il file '{path}' non esiste in '{self.root}'")
        if not full_path.is_file():
            raise FileNotFoundError(f"'{path}' non è un file")

        # Prova UTF-8 prima, poi latin-1 come fallback
        try:
            content = full_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                content = full_path.read_text(encoding="latin-1")
            except UnicodeDecodeError:
                raise ValueError(f"Il file '{path}' non è decodificabile come testo")

        # Controlla se è un file binario (contiene byte null nel testo)
        if "\x00" in content:
            raise ValueError(f"Il file '{path}' sembra essere un file binario")

        return content

    def get_metadata(self) -> SourceMetadata:
        """
        Calcola e restituisce metadati sulla sorgente.

        Effettua una scansione completa per contare file e LOC.
        I risultati non sono cached — ogni chiamata ricalcola.

        Returns:
            SourceMetadata con nome directory, conteggio file, LOC totali
        """
        file_tree = self.get_file_tree()
        total_files = sum(1 for e in file_tree.entries if not e.is_dir)
        total_loc = 0

        for entry in file_tree.entries:
            if entry.is_dir:
                continue
            try:
                content = self.read_file(entry.path)
                total_loc += len(content.splitlines())
            except (ValueError, PermissionError, FileNotFoundError):
                # File binari o non leggibili: skip LOC
                pass

        return SourceMetadata(
            name=self.root.name,
            total_files=total_files,
            total_loc=total_loc,
            source_type="local",
        )

    # --- Metodi privati ---

    def _load_gitignore(self) -> list[str]:
        """
        Carica le regole dal file .gitignore nella root del progetto.

        Ignora commenti e righe vuote. Gestisce pattern con e senza slash.

        Returns:
            Lista di pattern gitignore
        """
        gitignore_path = self.root / ".gitignore"
        if not gitignore_path.exists():
            return []

        patterns: list[str] = []
        try:
            content = gitignore_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return []

        for line in content.splitlines():
            line = line.strip()
            # Ignora commenti e righe vuote
            if not line or line.startswith("#"):
                continue
            patterns.append(line)

        return patterns

    def _compile_patterns(self) -> list[tuple[str, re.Pattern[str], bool]]:
        """
        Pre-compila i pattern gitignore in regex per performance.

        Returns:
            Lista di (pattern_originale, regex_compilata, is_dir_only)
        """
        compiled = []
        for pattern in self._gitignore_patterns:
            is_dir_only = pattern.endswith("/")
            clean = pattern.rstrip("/")
            regex = re.compile(fnmatch.translate(clean))
            compiled.append((clean, regex, is_dir_only))
        return compiled

    def _is_ignored(self, rel_path: str) -> bool:
        """
        Verifica se un percorso relativo deve essere ignorato.

        Controlla prima le regole hardcoded (sempre .git/), poi i pattern
        dal .gitignore. Supporta pattern glob standard e directory con slash.
        File critici (requirements.txt, Dockerfile, etc.) non vengono mai ignorati.
        Usa regex pre-compilate per performance.

        Args:
            rel_path: Percorso relativo normalizzato (con / come separatore)

        Returns:
            True se il file/directory deve essere ignorato
        """
        # .git/ è sempre ignorata
        if rel_path == ".git/" or rel_path.startswith(".git/"):
            return True

        # File critici per l'analisi non vengono mai ignorati
        stripped = rel_path.rstrip("/")
        basename = stripped.rsplit("/", 1)[-1]
        if not rel_path.endswith("/") and basename in NEVER_IGNORE_FILES:
            return False

        for _orig, regex, is_dir_only in self._compiled_patterns:
            if is_dir_only:
                # Matcha il nome directory in qualsiasi posizione
                parts = stripped.split("/")
                if any(regex.match(part) for part in parts):
                    return True
            else:
                # Matcha il nome del file/directory
                if regex.match(basename):
                    return True
                # Matcha anche il percorso completo
                if regex.match(stripped):
                    return True

        return False
