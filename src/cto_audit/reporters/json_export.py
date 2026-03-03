"""
JSON Export — Esporta il risultato dell'audit in formato JSON strutturato.

Usa model_dump() di Pydantic per serializzazione pulita.
Include: metadata, health_score, findings, compliance (se attivo),
remediation (se attivo), stack_info.
"""

from __future__ import annotations

import json
from pathlib import Path

from cto_audit.core.models import AuditDelta, AuditResult


class JSONExporter:
    """Esporta AuditResult in formato JSON."""

    def export(self, result: AuditResult, delta: AuditDelta | None = None) -> str:
        """
        Serializza l'AuditResult completo in JSON.

        Args:
            result: Risultato audit
            delta: Delta rispetto all'audit precedente (se disponibile)

        Returns:
            Stringa JSON indentata
        """
        data = result.model_dump(mode="json")
        if delta is not None:
            data["delta"] = delta.model_dump(mode="json")
        return json.dumps(data, indent=2, ensure_ascii=False, default=str)

    def save(
        self,
        result: AuditResult,
        output_path: Path,
        delta: AuditDelta | None = None,
    ) -> None:
        """Serializza e salva su file."""
        content = self.export(result, delta=delta)
        output_path.write_text(content, encoding="utf-8")
