"""
Scoring Profile — Caricamento e validazione profili YAML.

Carica un profilo di scoring da file YAML e lo valida
con Pydantic v2. Il profilo definisce:
- Pesi per layer (devono sommare a 1.0)
- Regole con peso, penalità, severità e riferimento framework
- Peso default per regole non presenti nel profilo
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


class RuleConfig(BaseModel):
    """Configurazione di una singola regola di scoring."""
    severity: str = Field(..., description="Severità della regola (critical, high, medium, low, info)")
    weight: float = Field(..., ge=0.0, le=1.0, description="Peso della regola nel layer (0.0-1.0)")
    penalty: float = Field(..., le=0, description="Penalità in punti (valore <= 0)")
    framework_ref: str | None = Field(default=None, description="Riferimento framework/normativa")
    description: str = Field(default="", description="Descrizione della regola")

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        """Valida che la severità sia un valore valido."""
        valid = {"critical", "high", "medium", "low", "info"}
        if v not in valid:
            raise ValueError(f"Severità '{v}' non valida. Valori ammessi: {valid}")
        return v


class ScoringProfile(BaseModel):
    """Profilo di scoring caricato da YAML."""
    name: str = Field(..., min_length=1, description="Nome del profilo")
    description: str = Field(default="", description="Descrizione del profilo")
    layer_weights: dict[str, float] = Field(
        ...,
        description="Pesi per layer (devono sommare a 1.0)"
    )
    default_rule_weight: float = Field(
        default=0.5, ge=0.0, le=1.0,
        description="Peso default per regole non presenti nel profilo"
    )
    rules: dict[str, RuleConfig] = Field(
        default_factory=dict,
        description="Regole di scoring con configurazione"
    )

    @field_validator("layer_weights")
    @classmethod
    def validate_layer_weights(cls, v: dict[str, float]) -> dict[str, float]:
        """Valida che i pesi dei layer siano tra 0 e 1 e sommino a 1.0."""
        valid_layers = {"infra", "architecture", "security", "quality"}
        for layer_name, weight in v.items():
            if layer_name not in valid_layers:
                raise ValueError(
                    f"Layer '{layer_name}' non valido. Valori ammessi: {valid_layers}"
                )
            if not 0.0 <= weight <= 1.0:
                raise ValueError(
                    f"Peso per '{layer_name}' deve essere tra 0.0 e 1.0, ricevuto {weight}"
                )

        total = sum(v.values())
        if abs(total - 1.0) > 0.01:
            raise ValueError(
                f"I pesi dei layer devono sommare a 1.0, attuale: {total:.4f}"
            )
        return v

    @model_validator(mode="after")
    def validate_rules_penalties(self) -> ScoringProfile:
        """Validazione post-init: le penalità info devono essere 0."""
        for rule_id, rule in self.rules.items():
            if rule.severity == "info" and rule.penalty != 0:
                raise ValueError(
                    f"Regola '{rule_id}' ha severità 'info' ma penalità {rule.penalty} "
                    "(deve essere 0 per regole informative)"
                )
        return self

    def get_rule(self, rule_id: str) -> RuleConfig | None:
        """Restituisce la configurazione di una regola, o None se non presente."""
        return self.rules.get(rule_id)


def load_profile(profile_name: str, profiles_dir: Path | None = None) -> ScoringProfile:
    """
    Carica un profilo di scoring da file YAML.

    Cerca il file nella directory dei profili. Se profiles_dir non è
    specificata, usa la directory 'scoring-profiles' nella root del progetto.

    Args:
        profile_name: Nome del profilo (senza estensione .yml)
        profiles_dir: Directory contenente i profili YAML

    Returns:
        ScoringProfile validato

    Raises:
        FileNotFoundError: se il file del profilo non esiste
        ValueError: se il profilo YAML è invalido o malformato
    """
    if profiles_dir is None:
        from cto_audit._data import get_data_dir
        profiles_dir = get_data_dir("scoring-profiles")

    profile_path = profiles_dir / f"{profile_name}.yml"

    if not profile_path.exists():
        raise FileNotFoundError(
            f"Profilo di scoring '{profile_name}' non trovato in {profiles_dir}. "
            f"File atteso: {profile_path}"
        )

    try:
        with open(profile_path, encoding="utf-8") as f:
            data: Any = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ValueError(f"Errore nel parsing YAML del profilo '{profile_name}': {e}") from e

    if not isinstance(data, dict):
        raise ValueError(
            f"Il profilo '{profile_name}' deve essere un dizionario YAML, "
            f"ricevuto: {type(data).__name__}"
        )

    try:
        return ScoringProfile(**data)
    except Exception as e:
        raise ValueError(
            f"Errore nella validazione del profilo '{profile_name}': {e}"
        ) from e
