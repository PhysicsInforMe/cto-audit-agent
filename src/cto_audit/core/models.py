"""
Modelli dati core per CTO Audit Agent.

Contiene tutti i modelli Pydantic v2 usati dal sistema:
- FileInfo, FileClassification: informazioni e classificazione privacy dei file
- StackInfo: stack tecnologico rilevato
- Finding: singolo problema rilevato da un analyzer
- LayerScore, HealthScore: scoring tracciabile per layer e complessivo
- AuditResult: risultato finale dell'audit
- FileTree, SourceMetadata: struttura sorgente dati
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


# --- Enumerazioni ---


class PrivacyCategory(str, Enum):
    """Categoria di classificazione privacy per un file."""
    SAFE = "safe"               # 🟢 Inviabile al LLM cloud
    LOCAL_LLM = "local_llm"     # 🟡 Solo Ollama locale
    SENSITIVE = "sensitive"     # 🔴 Solo analisi locale, no LLM
    EXCLUDED = "excluded"       # ⚫ File ignorato


class Severity(str, Enum):
    """Livello di severità di un finding."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Layer(str, Enum):
    """I 4 layer di analisi CTO."""
    INFRA = "infra"
    ARCHITECTURE = "architecture"
    SECURITY = "security"
    QUALITY = "quality"


class ProjectType(str, Enum):
    """Tipo di progetto rilevato automaticamente."""
    WEB_APP = "web_app"
    FRONTEND = "frontend"
    FULL_STACK = "full_stack"
    LIBRARY = "library"
    CLI_TOOL = "cli_tool"
    DATA_PIPELINE = "data_pipeline"
    PROTOTYPE = "prototype"
    UNKNOWN = "unknown"


class ComplianceMode(str, Enum):
    """Modalità di esecuzione compliance."""
    CROSS_CUTTING = "cross-cutting"
    STANDALONE = "standalone"
    HYBRID = "hybrid"


# --- Modelli File ---


class FileInfo(BaseModel):
    """Informazioni base su un file del codebase."""
    path: str = Field(..., description="Percorso relativo del file rispetto alla root del progetto")
    size: int = Field(..., ge=0, description="Dimensione in byte")
    extension: str = Field(default="", description="Estensione del file (es. '.py', '.js')")
    lines_of_code: int = Field(default=0, ge=0, description="Numero di righe di codice")


class FileClassification(BaseModel):
    """Classificazione privacy di un singolo file."""
    file_info: FileInfo = Field(..., description="Informazioni del file classificato")
    category: PrivacyCategory = Field(..., description="Categoria di privacy assegnata")
    reason: str = Field(..., min_length=1, description="Motivo della classificazione")
    confidence: float = Field(
        default=1.0, ge=0.0, le=1.0,
        description="Livello di confidenza della classificazione (0.0-1.0)"
    )


# --- Modelli Stack ---


class StackInfo(BaseModel):
    """Informazioni sullo stack tecnologico rilevato nel codebase."""
    languages: dict[str, float] = Field(
        default_factory=dict,
        description="Linguaggi rilevati con percentuali (es. {'python': 0.65, 'javascript': 0.35})"
    )
    frameworks: list[str] = Field(
        default_factory=list,
        description="Framework rilevati (es. ['FastAPI', 'React'])"
    )
    infra_type: list[str] = Field(
        default_factory=list,
        description="Tipi di infrastruttura rilevati (es. ['Docker', 'GitHub Actions', 'Terraform'])"
    )

    @field_validator("languages")
    @classmethod
    def validate_language_percentages(cls, v: dict[str, float]) -> dict[str, float]:
        """Valida che le percentuali dei linguaggi siano tra 0 e 1."""
        for lang, pct in v.items():
            if not 0.0 <= pct <= 1.0:
                raise ValueError(
                    f"La percentuale per '{lang}' deve essere tra 0.0 e 1.0, ricevuto {pct}"
                )
        return v


class ProjectTypeResult(BaseModel):
    """Risultato della rilevazione automatica del tipo di progetto."""
    detected_type: ProjectType = Field(..., description="Tipo di progetto rilevato")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidenza della rilevazione (0.0-1.0)")
    method: str = Field(..., description="Metodo usato: rule_based, tfidf, bert")
    signals: list[str] = Field(default_factory=list, description="Segnali che hanno portato alla classificazione")


# --- Modelli Finding ---


class Finding(BaseModel):
    """
    Singolo problema/osservazione rilevato da un analyzer.

    Ogni finding ha un rule_id univoco che permette il matching
    con le regole del profilo di scoring.
    """
    id: str = Field(..., description="Identificativo univoco del finding")
    layer: Layer = Field(..., description="Layer di appartenenza")
    severity: Severity = Field(..., description="Livello di severità")
    rule_id: str = Field(..., description="ID della regola che ha generato il finding (es. INFRA-CICD-001)")
    title: str = Field(..., min_length=1, description="Titolo breve del finding")
    description: str = Field(..., min_length=1, description="Descrizione dettagliata del finding")
    file_path: str | None = Field(default=None, description="Percorso del file coinvolto (se applicabile)")
    line_number: int | None = Field(default=None, ge=1, description="Numero di riga (se applicabile)")
    confidence: float = Field(
        default=1.0, ge=0.0, le=1.0,
        description="Confidenza del finding (0.0-1.0)"
    )
    framework_ref: str | None = Field(
        default=None,
        description="Riferimento a framework/normativa (es. 'NIST PR.DS-6')"
    )


# --- Modelli Scoring ---


class EvidenceChain(BaseModel):
    """
    Catena di evidenze per un singolo finding nello scoring.

    Traccia il percorso: finding -> regola -> peso -> penalità -> framework.
    """
    finding_id: str = Field(..., description="ID del finding")
    rule_id: str = Field(..., description="ID della regola matchata")
    weight: float = Field(..., ge=0.0, le=1.0, description="Peso della regola nel layer")
    penalty: float = Field(..., le=0.0, description="Penalità applicata (valore negativo)")
    framework_ref: str | None = Field(default=None, description="Riferimento framework")


class LayerScore(BaseModel):
    """Score calcolato per un singolo layer con catena di evidenze."""
    layer: Layer = Field(..., description="Layer di appartenenza")
    score: float = Field(..., ge=0.0, le=100.0, description="Score del layer (0-100)")
    confidence: float = Field(
        default=1.0, ge=0.0, le=1.0,
        description="Confidenza dello score (0.0-1.0)"
    )
    findings: list[Finding] = Field(default_factory=list, description="Finding del layer")
    evidence_chain: list[EvidenceChain] = Field(
        default_factory=list,
        description="Catena di evidenze completa per ogni finding"
    )


class ComplianceResult(BaseModel):
    """Risultato di un check di compliance."""
    profile_name: str = Field(..., description="Nome del profilo compliance (es. 'NIS2')")
    checks_total: int = Field(..., ge=0, description="Totale controlli previsti")
    checks_satisfied: int = Field(..., ge=0, description="Controlli soddisfatti")
    checks_partial: int = Field(default=0, ge=0, description="Controlli parzialmente soddisfatti")
    checks_not_satisfied: int = Field(default=0, ge=0, description="Controlli non soddisfatti")
    details: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Dettagli per ogni singolo check"
    )

    @field_validator("checks_satisfied")
    @classmethod
    def validate_satisfied_not_exceed_total(cls, v: int, info: Any) -> int:
        """Verifica che i check soddisfatti non superino il totale."""
        total = info.data.get("checks_total", 0)
        if v > total:
            raise ValueError(
                f"checks_satisfied ({v}) non può superare checks_total ({total})"
            )
        return v


class HealthScore(BaseModel):
    """Score complessivo dell'audit con breakdown per layer."""
    overall_score: float = Field(..., ge=0.0, le=100.0, description="Score complessivo (0-100)")
    overall_confidence: float = Field(
        default=1.0, ge=0.0, le=1.0,
        description="Confidenza complessiva (0.0-1.0)"
    )
    layer_scores: dict[str, LayerScore] = Field(
        default_factory=dict,
        description="Score per ogni layer analizzato"
    )
    compliance_results: list[ComplianceResult] | None = Field(
        default=None,
        description="Risultati compliance (se profili attivati)"
    )


# --- Modello Sorgente Dati ---


class FileTreeEntry(BaseModel):
    """Singola entry nel file tree."""
    path: str = Field(..., description="Percorso relativo del file/directory")
    is_dir: bool = Field(default=False, description="True se è una directory")
    size: int = Field(default=0, ge=0, description="Dimensione in byte (0 per directory)")


class FileTree(BaseModel):
    """Albero dei file di una sorgente dati."""
    root: str = Field(..., description="Percorso root della sorgente")
    entries: list[FileTreeEntry] = Field(
        default_factory=list,
        description="Lista di file e directory"
    )


class SourceMetadata(BaseModel):
    """Metadati di una sorgente dati."""
    name: str = Field(..., description="Nome della sorgente (es. nome directory)")
    total_files: int = Field(default=0, ge=0, description="Numero totale di file")
    total_loc: int = Field(default=0, ge=0, description="Righe di codice totali")
    source_type: str = Field(default="local", description="Tipo di sorgente (local, git, multi)")


# --- Modello Risultato Finale ---


class AuditMetadata(BaseModel):
    """Metadati dell'esecuzione dell'audit."""
    timestamp: datetime = Field(default_factory=datetime.now, description="Timestamp dell'audit")
    target_path: str = Field(..., description="Percorso analizzato")
    tool_version: str = Field(default="0.1.0", description="Versione del tool")
    scoring_profile: str = Field(default="default", description="Profilo di scoring usato")
    compliance_profiles: list[str] = Field(
        default_factory=list,
        description="Profili compliance attivati"
    )
    offline_mode: bool = Field(default=False, description="True se eseguito in modalità offline")
    network_consented: bool | None = Field(
        default=None,
        description="True se utente ha acconsentito accesso rete, None se --offline"
    )
    project_type: str | None = Field(
        default=None,
        description="Tipo progetto rilevato automaticamente"
    )
    project_type_confidence: float | None = Field(
        default=None,
        description="Confidenza della rilevazione tipo progetto (0.0-1.0)"
    )


class AuditResult(BaseModel):
    """Risultato completo di un audit CTO."""
    health_score: HealthScore = Field(..., description="Score complessivo con breakdown")
    stack_info: StackInfo = Field(..., description="Stack tecnologico rilevato")
    classifications: list[FileClassification] = Field(
        default_factory=list,
        description="Classificazioni privacy dei file"
    )
    metadata: AuditMetadata = Field(..., description="Metadati dell'esecuzione")
    remediation: Any = Field(
        default=None,
        description="Risultato pipeline remediation (RemediationPipelineResult | None)"
    )


# --- Modello Delta Audit ---


class AuditDelta(BaseModel):
    """Delta tra due audit successivi dello stesso progetto."""
    previous_score: float = Field(..., ge=0.0, le=100.0, description="Score audit precedente")
    current_score: float = Field(..., ge=0.0, le=100.0, description="Score audit corrente")
    score_delta: float = Field(..., description="Differenza di score (current - previous)")
    previous_timestamp: datetime = Field(..., description="Timestamp audit precedente")
    current_timestamp: datetime = Field(..., description="Timestamp audit corrente")
    layer_deltas: dict[str, float] = Field(
        default_factory=dict,
        description="Delta score per layer (current - previous)"
    )
    new_findings: list[str] = Field(
        default_factory=list,
        description="Rule ID dei finding nuovi (presenti solo nel corrente)"
    )
    resolved_findings: list[str] = Field(
        default_factory=list,
        description="Rule ID dei finding risolti (presenti solo nel precedente)"
    )
    persistent_findings: list[str] = Field(
        default_factory=list,
        description="Rule ID dei finding persistenti (presenti in entrambi)"
    )
    days_since_previous: float = Field(
        ..., ge=0.0,
        description="Giorni trascorsi dall'audit precedente"
    )
