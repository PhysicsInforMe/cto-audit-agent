"""
Modelli per progetti multi-source.

Supporta scenari di consulenza con N repository analizzati come progetto unico.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from cto_audit.core.models import AuditResult, HealthScore


class ProjectSourceConfig(BaseModel):
    """Configurazione di una singola sorgente nel progetto."""
    name: str = Field(..., description="Nome identificativo della sorgente")
    source_type: str = Field(..., description="Tipo: local, github, gitlab, azure-devops, bitbucket, zip")
    path_or_url: str = Field(..., description="Path locale o URL remoto")
    token_env: Optional[str] = Field(default=None, description="Nome env var con il token")
    branch: Optional[str] = Field(default=None, description="Branch o tag")


class ProjectConfig(BaseModel):
    """Configurazione di un progetto multi-source."""
    name: str = Field(..., description="Nome del progetto")
    sources: list[ProjectSourceConfig] = Field(
        ..., min_length=1, description="Lista sorgenti da analizzare"
    )


class SourceResult(BaseModel):
    """Risultato dell'audit di una singola sorgente nel progetto."""
    name: str = Field(..., description="Nome della sorgente")
    audit_result: AuditResult = Field(..., description="Risultato dell'audit")
    loc: int = Field(default=0, ge=0, description="Righe di codice della sorgente")
    error: Optional[str] = Field(default=None, description="Errore se l'audit è fallito")


class AggregatedResult(BaseModel):
    """Risultato aggregato di un progetto multi-source."""
    project_name: str = Field(..., description="Nome del progetto")
    timestamp: datetime = Field(default_factory=datetime.now)
    source_results: list[SourceResult] = Field(
        default_factory=list, description="Risultati per sorgente"
    )
    aggregated_score: float = Field(
        default=0.0, ge=0.0, le=100.0,
        description="Score aggregato pesato per LOC"
    )
    aggregated_layer_scores: dict[str, float] = Field(
        default_factory=dict,
        description="Score aggregati per layer (pesati per LOC)"
    )
    total_loc: int = Field(default=0, ge=0, description="LOC totali del progetto")
    total_sources: int = Field(default=0, ge=0, description="Numero di sorgenti analizzate")
    failed_sources: list[str] = Field(
        default_factory=list, description="Nomi delle sorgenti fallite"
    )
