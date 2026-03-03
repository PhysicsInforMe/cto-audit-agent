"""
Modelli Pydantic per il Compliance Engine.

Definisce le strutture dati per controlli normativi, valutazioni
e risultati della compliance check.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class ControlStatus(str, Enum):
    """Stato di un controllo compliance."""
    SATISFIED = "satisfied"
    PARTIAL = "partial"
    FAILED = "failed"


class ComplianceControl(BaseModel):
    """Singolo controllo normativo in un profilo compliance."""
    control_id: str = Field(..., description="ID univoco del controllo (es. NIS2-ART21-2D)")
    title: str = Field(..., description="Titolo del controllo")
    article_ref: str = Field(..., description="Riferimento normativo (es. Art. 21(2)(d))")
    description: str = Field(..., description="Descrizione del controllo")
    required_rules: list[str] = Field(
        default_factory=list,
        description="Rule ID che NON devono triggerare (controllo soddisfatto se nessuno scatta)"
    )
    contributing_rules: list[str] = Field(
        default_factory=list,
        description="Rule ID che contribuiscono parzialmente"
    )


class ControlEvaluation(BaseModel):
    """Risultato della valutazione di un singolo controllo."""
    control_id: str
    title: str
    article_ref: str
    status: ControlStatus
    triggered_rules: list[str] = Field(default_factory=list)
    total_rules: int = 0


class ComplianceProfile(BaseModel):
    """Profilo di compliance caricato da YAML."""
    name: str
    description: str
    version: str = "1.0"
    controls: list[ComplianceControl] = Field(default_factory=list)
