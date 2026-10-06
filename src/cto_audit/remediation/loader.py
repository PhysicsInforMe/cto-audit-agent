"""
RemediationLoader — Carica Knowledge Base YAML con lookup per rule_id e stack merging.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from cto_audit.core.models import StackInfo
from cto_audit.remediation.models import (
    EffortRange,
    RemediationEntry,
    StackSpecificRemediation,
)


class RemediationLoader:
    """
    Carica e interroga la Remediation Knowledge Base.

    Supporta lookup per rule_id e stack-specific merging.
    """

    def __init__(self, entries: dict[str, RemediationEntry]) -> None:
        self._entries = entries

    @classmethod
    def from_yaml(cls, kb_name: str = "default", kb_dir: Path | None = None) -> RemediationLoader:
        """
        Carica la KB da file YAML.

        Args:
            kb_name: Nome del file KB (senza estensione)
            kb_dir: Directory contenente i file KB

        Returns:
            RemediationLoader con tutte le entry caricate
        """
        if kb_dir is None:
            from cto_audit._data import get_data_dir
            kb_dir = get_data_dir("remediation-kb")

        kb_path = kb_dir / f"{kb_name}.yml"

        if not kb_path.exists():
            raise FileNotFoundError(
                f"Remediation KB '{kb_name}' non trovata in {kb_dir}. "
                f"File atteso: {kb_path}"
            )

        with open(kb_path, encoding="utf-8") as f:
            data: Any = yaml.safe_load(f)

        if not isinstance(data, dict):
            raise ValueError(
                f"La KB '{kb_name}' deve essere un dizionario YAML, "
                f"ricevuto: {type(data).__name__}"
            )

        entries: dict[str, RemediationEntry] = {}
        for rule_id, entry_data in data.items():
            if not isinstance(entry_data, dict):
                raise ValueError(
                    f"Entry per '{rule_id}' deve essere un dizionario, "
                    f"ricevuto: {type(entry_data).__name__}"
                )

            # Parse stack_specific
            stack_specific_raw = entry_data.get("stack_specific", {})
            stack_specific: dict[str, StackSpecificRemediation] = {}
            for stack_name, stack_data in (stack_specific_raw or {}).items():
                if isinstance(stack_data, dict):
                    stack_specific[stack_name] = StackSpecificRemediation(**stack_data)

            # Parse effort_range
            effort_data = entry_data.get("effort_range", {})
            effort_range = EffortRange(**effort_data)

            entry = RemediationEntry(
                rule_id=rule_id,
                risk_business=entry_data.get("risk_business", "").strip(),
                remediation_steps=entry_data.get("remediation_steps", []),
                effort_range=effort_range,
                priority_tier=entry_data.get("priority_tier", 2),
                stack_specific=stack_specific,
                references=entry_data.get("references", []),
            )
            entries[rule_id] = entry

        return cls(entries)

    @classmethod
    def load_all(cls, kb_dir: Path | None = None) -> RemediationLoader:
        """
        Carica e unisce tutte le KB YAML presenti nella directory.

        `default.yml` viene caricata per prima; le altre (es. `due-diligence.yml`)
        aggiungono le entry dei layer opzionali. In caso di rule_id duplicato
        vince il file caricato per ultimo (ordine alfabetico dopo default).

        Returns:
            RemediationLoader con l'unione delle entry
        """
        if kb_dir is None:
            from cto_audit._data import get_data_dir
            kb_dir = get_data_dir("remediation-kb")

        names = sorted(p.stem for p in kb_dir.glob("*.yml"))
        if "default" in names:
            names.remove("default")
            names.insert(0, "default")

        merged: dict[str, RemediationEntry] = {}
        for name in names:
            merged.update(cls.from_yaml(name, kb_dir=kb_dir).all_entries())
        return cls(merged)

    def get(self, rule_id: str) -> RemediationEntry | None:
        """Restituisce l'entry per il rule_id, o None."""
        return self._entries.get(rule_id)

    def get_for_stack(self, rule_id: str, stack_info: StackInfo) -> RemediationEntry | None:
        """
        Restituisce l'entry con remediation_steps risolti per lo stack primario.

        Se lo stack primario ha un override, restituisce una copia con
        gli step specifici; altrimenti restituisce l'entry generica.
        """
        entry = self._entries.get(rule_id)
        if entry is None:
            return None

        primary_lang = _get_primary_language(stack_info)
        if primary_lang and primary_lang in entry.stack_specific:
            specific = entry.stack_specific[primary_lang]
            return entry.model_copy(update={"remediation_steps": specific.remediation_steps})

        return entry

    def all_entries(self) -> dict[str, RemediationEntry]:
        """Restituisce tutte le entry della KB."""
        return dict(self._entries)


def _get_primary_language(stack_info: StackInfo) -> str | None:
    """Restituisce il linguaggio primario (percentuale piu alta)."""
    if not stack_info.languages:
        return None
    return max(stack_info.languages, key=stack_info.languages.get)  # type: ignore[arg-type]
