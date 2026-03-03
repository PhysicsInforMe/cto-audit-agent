"""
Configurazione runtime per CTO Audit Agent.

Gestisce tutte le opzioni configurabili a runtime tramite Pydantic Settings.
I valori possono essere impostati via CLI, variabili d'ambiente, o file di config.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings

from cto_audit.core.models import ComplianceMode, Layer


class AuditConfig(BaseSettings):
    """
    Configurazione runtime dell'audit.

    Ogni campo corrisponde a un'opzione CLI o variabile d'ambiente.
    Prefisso env: CTO_AUDIT_ (es. CTO_AUDIT_OFFLINE_MODE=true)
    """

    model_config = {"env_prefix": "CTO_AUDIT_"}

    # --- Parametri obbligatori ---
    target_path: Path = Field(
        ...,
        description="Percorso del codebase da analizzare"
    )

    # --- Output ---
    output_format: Literal["terminal", "markdown", "html", "pdf", "json"] = Field(
        default="terminal",
        description="Formato di output del report"
    )
    output_path: str | None = Field(
        default=None,
        description="Percorso file di output (se diverso da terminale)"
    )

    # --- Scoring ---
    scoring_profile: str = Field(
        default="default",
        description="Nome del profilo di scoring da usare (es. 'default', 'nist-csf', 'owasp-asvs')"
    )

    # --- Compliance ---
    compliance_profiles: list[str] = Field(
        default_factory=list,
        description="Lista dei profili compliance da attivare (es. ['nis2', 'gdpr'])"
    )
    compliance_mode: ComplianceMode = Field(
        default=ComplianceMode.HYBRID,
        description="Modalità di esecuzione compliance: cross-cutting, standalone, hybrid"
    )

    # --- Modalità operative ---
    offline_mode: bool = Field(
        default=False,
        description="Modalità offline: nessun dato esce dalla macchina"
    )
    reuse_classification: bool = Field(
        default=False,
        description="Riusa la classificazione privacy salvata da un run precedente"
    )
    auto_approve: bool = Field(
        default=False,
        description="Salta il gate HITL e approva automaticamente la classificazione"
    )

    # --- Focus ---
    focus: Layer | None = Field(
        default=None,
        description="Se specificato, esegue solo il layer indicato (es. 'infra', 'security')"
    )

    @field_validator("target_path")
    @classmethod
    def validate_target_path(cls, v: Path) -> Path:
        """Verifica che il percorso target esista e sia una directory."""
        if not v.exists():
            raise ValueError(f"Il percorso '{v}' non esiste")
        if not v.is_dir():
            raise ValueError(f"Il percorso '{v}' non è una directory")
        return v
