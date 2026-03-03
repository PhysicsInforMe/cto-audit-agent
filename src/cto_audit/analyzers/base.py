"""
Interfaccia base per gli analyzer di layer.

Ogni analyzer implementa il metodo `analyze` che riceve la sorgente dati,
le informazioni sullo stack e le classificazioni privacy, e restituisce
una lista di Finding.

Tutti gli analyzer condividono questa interfaccia per consentire
composizione e orchestrazione uniforme.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from cto_audit.core.models import (
    FileClassification,
    Finding,
    StackInfo,
)
from cto_audit.core.source import AuditSource


@runtime_checkable
class BaseAnalyzer(Protocol):
    """Interfaccia comune per tutti i layer analyzer."""

    def analyze(
        self,
        source: AuditSource,
        stack_info: StackInfo,
        classifications: list[FileClassification],
    ) -> list[Finding]:
        """
        Analizza il codebase e restituisce i finding per questo layer.

        Args:
            source: sorgente dati per leggere file
            stack_info: stack tecnologico rilevato
            classifications: classificazioni privacy dei file

        Returns:
            Lista di Finding rilevati
        """
        ...
