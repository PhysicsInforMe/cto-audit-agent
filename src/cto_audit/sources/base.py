"""
Mixin base per sorgenti che clonano in directory temporanea.

Fornisce context manager per creazione/cleanup automatico della temp dir
e delega i 3 metodi Protocol a un LocalRepoSource interno.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Optional

from cto_audit.core.models import FileTree, SourceMetadata
from cto_audit.sources.local import LocalRepoSource


class TempDirSourceMixin:
    """
    Mixin per sorgenti che lavorano con directory temporanee.

    Pattern: clone/extract in temp dir → wrappa in LocalRepoSource → delega.
    Il context manager gestisce il cleanup automatico della temp dir.

    Subclassi devono implementare `_materialize()` per popolare la temp dir.
    """

    def __init__(self, source_type: str = "remote") -> None:
        self._temp_dir: Optional[Path] = None
        self._local_source: Optional[LocalRepoSource] = None
        self._source_type = source_type

    def _materialize(self, target_dir: Path) -> None:
        """
        Popola la directory target con i file della sorgente.

        Le subclassi devono implementare questo metodo per clonare,
        estrarre o copiare i file nella directory target.

        Args:
            target_dir: Directory di destinazione da popolare
        """
        raise NotImplementedError

    def __enter__(self) -> "TempDirSourceMixin":
        self._temp_dir = Path(tempfile.mkdtemp(prefix="cto-audit-"))
        try:
            self._materialize(self._temp_dir)
        except Exception:
            # Cleanup se _materialize fallisce (prima che __exit__ sia attivo)
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None
            raise
        self._local_source = LocalRepoSource(self._temp_dir)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._temp_dir and self._temp_dir.exists():
            shutil.rmtree(self._temp_dir, ignore_errors=True)
        self._temp_dir = None
        self._local_source = None

    def _ensure_materialized(self) -> LocalRepoSource:
        """Verifica che la sorgente sia materializzata (dentro context manager)."""
        if self._local_source is None:
            raise RuntimeError(
                "Sorgente non materializzata. Usa il context manager: "
                "'with source:' prima di accedere ai dati."
            )
        return self._local_source

    def get_file_tree(self) -> FileTree:
        return self._ensure_materialized().get_file_tree()

    def read_file(self, path: str) -> str:
        return self._ensure_materialized().read_file(path)

    def get_metadata(self) -> SourceMetadata:
        meta = self._ensure_materialized().get_metadata()
        return SourceMetadata(
            name=meta.name,
            total_files=meta.total_files,
            total_loc=meta.total_loc,
            source_type=self._source_type,
        )
