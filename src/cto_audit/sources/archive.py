"""
Sorgente dati da archivio — estrae ZIP o tar.gz in directory temporanea.

Usa solo la stdlib (zipfile/tarfile), nessuna dipendenza esterna.
"""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

from cto_audit.sources.base import TempDirSourceMixin


class ArchiveSource(TempDirSourceMixin):
    """
    Sorgente dati che estrae un archivio ZIP o tar.gz in una directory temporanea.

    Supporta:
    - ZIP (.zip)
    - tar.gz (.tar.gz, .tgz)
    - tar.bz2 (.tar.bz2)
    - tar (.tar)

    Args:
        archive_path: Percorso all'archivio da estrarre
    """

    def __init__(self, archive_path: str | Path) -> None:
        super().__init__(source_type="archive")
        self._archive_path = Path(archive_path).resolve()
        if not self._archive_path.exists():
            raise FileNotFoundError(
                f"L'archivio '{self._archive_path}' non esiste"
            )
        if not self._archive_path.is_file():
            raise ValueError(
                f"'{self._archive_path}' non è un file"
            )

    def _materialize(self, target_dir: Path) -> None:
        """Estrae l'archivio nella directory target."""
        name = self._archive_path.name.lower()

        if name.endswith(".zip"):
            self._extract_zip(target_dir)
        elif name.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar")):
            self._extract_tar(target_dir)
        else:
            raise ValueError(
                f"Formato archivio non supportato: {name}\n"
                f"Formati supportati: .zip, .tar.gz, .tgz, .tar.bz2, .tar"
            )

    def _extract_zip(self, target_dir: Path) -> None:
        """Estrae un archivio ZIP."""
        with zipfile.ZipFile(self._archive_path, "r") as zf:
            # Controlla che non ci siano path traversal
            for info in zf.infolist():
                if info.filename.startswith("/") or ".." in info.filename:
                    raise ValueError(
                        f"Archivio ZIP contiene percorsi non sicuri: {info.filename}"
                    )
            zf.extractall(target_dir)

    def _extract_tar(self, target_dir: Path) -> None:
        """Estrae un archivio tar (gz/bz2/plain)."""
        with tarfile.open(self._archive_path, "r:*") as tf:
            # Controlla path traversal
            for member in tf.getmembers():
                if member.name.startswith("/") or ".." in member.name:
                    raise ValueError(
                        f"Archivio tar contiene percorsi non sicuri: {member.name}"
                    )
            tf.extractall(target_dir, filter="data")
