"""
Persistenza della classificazione privacy su file YAML.

Salva e ricarica le classificazioni prodotte dal PrivacyClassifier + HITL
nel file `.cto-audit-classification.yml` nella root del progetto.

Questo consente di:
- Riusare la classificazione tra run successivi (--reuse-classification)
- Rilevare file nuovi, modificati o rimossi tra un run e l'altro
- Offrire le 3 opzioni al reload: Usa precedente / Riesegui / Rivedi solo modificati
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from cto_audit.core.models import (
    FileClassification,
    FileInfo,
    PrivacyCategory,
)


# Nome del file di persistenza
CLASSIFICATION_FILENAME = ".cto-audit-classification.yml"


class ReloadOption(str, Enum):
    """Opzioni disponibili quando esiste una classificazione precedente."""
    USE_PREVIOUS = "use_previous"       # Usa classificazione precedente (skip review)
    RERUN = "rerun"                     # Riesegui da zero
    REVIEW_MODIFIED = "review_modified" # Rivedi solo file nuovi/modificati


class DiffResult:
    """
    Risultato del confronto tra classificazione salvata e file attuali.

    Attributes:
        new_files: File presenti nel codebase ma non nella classificazione salvata
        modified_files: File presenti in entrambi ma con size diversa
        removed_files: File nella classificazione salvata ma non più nel codebase
        unchanged_files: File identici (stesso path e size)
    """

    def __init__(
        self,
        new_files: list[str],
        modified_files: list[str],
        removed_files: list[str],
        unchanged_files: list[str],
    ) -> None:
        self.new_files = new_files
        self.modified_files = modified_files
        self.removed_files = removed_files
        self.unchanged_files = unchanged_files

    @property
    def has_changes(self) -> bool:
        """True se ci sono file nuovi, modificati o rimossi."""
        return bool(self.new_files or self.modified_files or self.removed_files)

    @property
    def summary(self) -> str:
        """Riepilogo testuale delle differenze."""
        parts: list[str] = []
        total = len(self.new_files) + len(self.modified_files) + len(self.removed_files)
        parts.append(f"{total} file cambiati:")
        if self.new_files:
            parts.append(f"  {len(self.new_files)} nuovi")
        if self.modified_files:
            parts.append(f"  {len(self.modified_files)} modificati")
        if self.removed_files:
            parts.append(f"  {len(self.removed_files)} rimossi")
        return "\n".join(parts)


class ClassificationPersistence:
    """
    Gestisce il salvataggio e caricamento delle classificazioni su file YAML.

    Il file YAML ha il formato definito nel doc 03-hitl-flow.md:
    - version: numero versione formato
    - timestamp: quando è stata salvata
    - stats: conteggi per categoria
    - classifications: lista completa dei file con classificazione
    - overrides: lista delle modifiche manuali fatte durante la review

    Attributes:
        root_path: Directory root del progetto (dove salvare il file)
    """

    def __init__(self, root_path: Path | str) -> None:
        """
        Args:
            root_path: Percorso della directory root del progetto
        """
        self.root_path = Path(root_path)

    @property
    def file_path(self) -> Path:
        """Percorso completo del file di classificazione."""
        return self.root_path / CLASSIFICATION_FILENAME

    def exists(self) -> bool:
        """True se esiste una classificazione salvata."""
        return self.file_path.exists()

    def save(
        self,
        classifications: list[FileClassification],
        overrides: list[dict[str, str]] | None = None,
    ) -> None:
        """
        Salva le classificazioni su file YAML.

        Args:
            classifications: Lista completa delle classificazioni
            overrides: Lista delle modifiche manuali (opzionale)
        """
        # Calcola statistiche per categoria
        stats: dict[str, int] = {
            "total_files": len(classifications),
            "safe": 0,
            "local_llm": 0,
            "sensitive": 0,
            "excluded": 0,
        }
        for c in classifications:
            stats[c.category.value] += 1

        # Costruisci lista classificazioni serializzabile
        serialized: list[dict[str, Any]] = []
        for c in classifications:
            entry: dict[str, Any] = {
                "path": c.file_info.path,
                "size": c.file_info.size,
                "extension": c.file_info.extension,
                "lines_of_code": c.file_info.lines_of_code,
                "category": c.category.value,
                "reason": c.reason,
                "confidence": c.confidence,
            }
            serialized.append(entry)

        # Costruisci documento YAML
        document: dict[str, Any] = {
            "version": 1,
            "timestamp": datetime.now().isoformat(),
            "stats": stats,
            "classifications": serialized,
        }

        if overrides:
            document["overrides"] = overrides

        # Scrivi su file
        with open(self.file_path, "w", encoding="utf-8") as f:
            yaml.dump(document, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    def load(self) -> list[FileClassification]:
        """
        Carica le classificazioni dal file YAML.

        Returns:
            Lista di FileClassification ricostruite dal file

        Raises:
            FileNotFoundError: Se il file non esiste
            ValueError: Se il formato del file non è valido
        """
        if not self.exists():
            raise FileNotFoundError(
                f"Nessuna classificazione salvata trovata in '{self.file_path}'"
            )

        with open(self.file_path, "r", encoding="utf-8") as f:
            document = yaml.safe_load(f)

        if not isinstance(document, dict) or "classifications" not in document:
            raise ValueError(
                f"Il file '{self.file_path}' non ha un formato valido"
            )

        classifications: list[FileClassification] = []
        for entry in document["classifications"]:
            file_info = FileInfo(
                path=entry["path"],
                size=entry["size"],
                extension=entry.get("extension", ""),
                lines_of_code=entry.get("lines_of_code", 0),
            )
            classification = FileClassification(
                file_info=file_info,
                category=PrivacyCategory(entry["category"]),
                reason=entry["reason"],
                confidence=entry.get("confidence", 1.0),
            )
            classifications.append(classification)

        return classifications

    def load_overrides(self) -> list[dict[str, str]]:
        """
        Carica solo gli override dal file YAML.

        Returns:
            Lista di override (dict con file, from, to, reason)
        """
        if not self.exists():
            return []

        with open(self.file_path, "r", encoding="utf-8") as f:
            document = yaml.safe_load(f)

        return document.get("overrides", [])

    def diff(self, current_files: list[FileInfo]) -> DiffResult:
        """
        Confronta i file attuali con la classificazione salvata.

        Rileva file nuovi, modificati (size diversa), e rimossi.

        Args:
            current_files: Lista dei file attuali dal FileScanner

        Returns:
            DiffResult con le differenze trovate
        """
        if not self.exists():
            # Nessuna classificazione precedente: tutti i file sono "nuovi"
            return DiffResult(
                new_files=[f.path for f in current_files],
                modified_files=[],
                removed_files=[],
                unchanged_files=[],
            )

        saved = self.load()

        # Costruisci mappe per confronto rapido
        saved_map: dict[str, int] = {c.file_info.path: c.file_info.size for c in saved}
        current_map: dict[str, int] = {f.path: f.size for f in current_files}

        saved_paths = set(saved_map.keys())
        current_paths = set(current_map.keys())

        new_files = sorted(current_paths - saved_paths)
        removed_files = sorted(saved_paths - current_paths)

        modified_files: list[str] = []
        unchanged_files: list[str] = []
        for path in sorted(saved_paths & current_paths):
            if saved_map[path] != current_map[path]:
                modified_files.append(path)
            else:
                unchanged_files.append(path)

        return DiffResult(
            new_files=new_files,
            modified_files=modified_files,
            removed_files=removed_files,
            unchanged_files=unchanged_files,
        )

    def delete(self) -> None:
        """Elimina il file di classificazione salvato."""
        if self.exists():
            self.file_path.unlink()
