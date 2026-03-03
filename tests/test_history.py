"""
Test per il modulo history — salvataggio, caricamento e delta audit.

Verifica:
- Salvataggio AuditResult come JSON
- Caricamento ultimo risultato
- Lista run ordinata cronologicamente
- Calcolo delta: score, layer, finding nuovi/risolti/persistenti
- Gestione directory vuota / inesistente
- AuditDelta model
"""

import json
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from cto_audit.core.models import (
    AuditDelta,
    AuditMetadata,
    AuditResult,
    EvidenceChain,
    Finding,
    HealthScore,
    Layer,
    LayerScore,
    Severity,
    StackInfo,
)
from cto_audit.history.storage import AuditHistoryStorage


# ===== Helper =====


def _make_result(
    score: float = 75.0,
    findings: list[Finding] | None = None,
    timestamp: datetime | None = None,
    target_path: str = "/tmp/test-project",
) -> AuditResult:
    """Crea un AuditResult minimale per i test."""
    if findings is None:
        findings = []

    evidence_chain = [
        EvidenceChain(
            finding_id=f.id,
            rule_id=f.rule_id,
            weight=0.5,
            penalty=-5.0,
        )
        for f in findings
    ]

    layer_scores = {
        "infra": LayerScore(
            layer=Layer.INFRA,
            score=score,
            findings=findings,
            evidence_chain=evidence_chain,
        ),
    }

    return AuditResult(
        health_score=HealthScore(overall_score=score, layer_scores=layer_scores),
        stack_info=StackInfo(languages={"python": 1.0}),
        metadata=AuditMetadata(
            timestamp=timestamp or datetime.now(),
            target_path=target_path,
        ),
    )


def _make_finding(
    rule_id: str = "INFRA-CICD-001",
    severity: Severity = Severity.HIGH,
) -> Finding:
    """Crea un Finding minimale."""
    return Finding(
        id=f"f-{rule_id}",
        layer=Layer.INFRA,
        severity=severity,
        rule_id=rule_id,
        title=f"Test finding {rule_id}",
        description=f"Description for {rule_id}",
    )


# ===== AuditDelta Model =====


class TestAuditDelta:
    """Test per il modello AuditDelta."""

    def test_creazione_valida(self):
        """AuditDelta si istanzia correttamente."""
        now = datetime.now()
        prev = now - timedelta(days=7)

        delta = AuditDelta(
            previous_score=60.0,
            current_score=75.0,
            score_delta=15.0,
            previous_timestamp=prev,
            current_timestamp=now,
            layer_deltas={"infra": 10.0, "security": 5.0},
            new_findings=["SEC-001"],
            resolved_findings=["INFRA-002"],
            persistent_findings=["QUAL-001"],
            days_since_previous=7.0,
        )
        assert delta.score_delta == 15.0
        assert len(delta.new_findings) == 1
        assert len(delta.resolved_findings) == 1
        assert delta.days_since_previous == 7.0

    def test_score_fuori_range(self):
        """Score fuori range deve essere rifiutato."""
        with pytest.raises(ValidationError):
            AuditDelta(
                previous_score=101.0,
                current_score=75.0,
                score_delta=-26.0,
                previous_timestamp=datetime.now(),
                current_timestamp=datetime.now(),
                days_since_previous=0.0,
            )

    def test_days_negative_rifiutato(self):
        """Giorni negativi devono essere rifiutati."""
        with pytest.raises(ValidationError):
            AuditDelta(
                previous_score=75.0,
                current_score=80.0,
                score_delta=5.0,
                previous_timestamp=datetime.now(),
                current_timestamp=datetime.now(),
                days_since_previous=-1.0,
            )

    def test_delta_negativo_accettato(self):
        """Score delta negativo (peggioramento) e' valido."""
        delta = AuditDelta(
            previous_score=80.0,
            current_score=60.0,
            score_delta=-20.0,
            previous_timestamp=datetime.now(),
            current_timestamp=datetime.now(),
            days_since_previous=1.0,
        )
        assert delta.score_delta == -20.0

    def test_serializzazione_json(self):
        """AuditDelta si serializza e deserializza correttamente."""
        delta = AuditDelta(
            previous_score=60.0,
            current_score=75.0,
            score_delta=15.0,
            previous_timestamp=datetime(2025, 1, 1, 10, 0),
            current_timestamp=datetime(2025, 1, 8, 10, 0),
            layer_deltas={"infra": 15.0},
            new_findings=["SEC-001"],
            resolved_findings=[],
            persistent_findings=["INFRA-001"],
            days_since_previous=7.0,
        )
        data = delta.model_dump(mode="json")
        restored = AuditDelta.model_validate(data)
        assert restored.score_delta == delta.score_delta
        assert restored.new_findings == delta.new_findings


# ===== AuditHistoryStorage =====


class TestAuditHistoryStorage:
    """Test per AuditHistoryStorage."""

    def test_save_crea_file(self, tmp_path: Path):
        """save() crea un file JSON nella directory history."""
        storage = AuditHistoryStorage(tmp_path)
        result = _make_result(target_path=str(tmp_path))

        filepath = storage.save(result)

        assert filepath.exists()
        assert filepath.suffix == ".json"
        assert ".cto-audit" in str(filepath) and "history" in str(filepath)

    def test_save_contenuto_valido(self, tmp_path: Path):
        """Il file salvato contiene JSON valido deserializzabile."""
        storage = AuditHistoryStorage(tmp_path)
        result = _make_result(score=85.0, target_path=str(tmp_path))

        filepath = storage.save(result)

        data = json.loads(filepath.read_text(encoding="utf-8"))
        restored = AuditResult.model_validate(data)
        assert restored.health_score.overall_score == 85.0

    def test_save_crea_directory(self, tmp_path: Path):
        """save() crea la directory history se non esiste."""
        storage = AuditHistoryStorage(tmp_path)
        result = _make_result(target_path=str(tmp_path))

        storage.save(result)

        assert (tmp_path / ".cto-audit" / "history").is_dir()

    def test_load_latest_nessun_file(self, tmp_path: Path):
        """load_latest() restituisce None se non ci sono audit precedenti."""
        storage = AuditHistoryStorage(tmp_path)

        assert storage.load_latest() is None

    def test_load_latest_directory_inesistente(self, tmp_path: Path):
        """load_latest() restituisce None se la directory non esiste."""
        storage = AuditHistoryStorage(tmp_path / "nonexistent")

        assert storage.load_latest() is None

    def test_load_latest_singolo(self, tmp_path: Path):
        """load_latest() restituisce l'unico risultato salvato."""
        storage = AuditHistoryStorage(tmp_path)
        result = _make_result(score=70.0, target_path=str(tmp_path))
        storage.save(result)

        loaded = storage.load_latest()

        assert loaded is not None
        assert loaded.health_score.overall_score == 70.0

    def test_load_latest_piu_recente(self, tmp_path: Path):
        """load_latest() restituisce il risultato piu recente."""
        storage = AuditHistoryStorage(tmp_path)

        # Salva due risultati con timestamp diversi
        old_result = _make_result(
            score=60.0,
            timestamp=datetime(2025, 1, 1, 10, 0, 0),
            target_path=str(tmp_path),
        )
        new_result = _make_result(
            score=80.0,
            timestamp=datetime(2025, 1, 8, 10, 0, 0),
            target_path=str(tmp_path),
        )
        storage.save(old_result)
        storage.save(new_result)

        loaded = storage.load_latest()

        assert loaded is not None
        assert loaded.health_score.overall_score == 80.0

    def test_list_runs_vuoto(self, tmp_path: Path):
        """list_runs() restituisce lista vuota se non ci sono run."""
        storage = AuditHistoryStorage(tmp_path)

        assert storage.list_runs() == []

    def test_list_runs_ordinati(self, tmp_path: Path):
        """list_runs() restituisce i file ordinati cronologicamente."""
        storage = AuditHistoryStorage(tmp_path)

        r1 = _make_result(
            score=60.0,
            timestamp=datetime(2025, 1, 1, 10, 0, 0),
            target_path=str(tmp_path),
        )
        r2 = _make_result(
            score=70.0,
            timestamp=datetime(2025, 1, 5, 10, 0, 0),
            target_path=str(tmp_path),
        )
        r3 = _make_result(
            score=80.0,
            timestamp=datetime(2025, 1, 10, 10, 0, 0),
            target_path=str(tmp_path),
        )

        storage.save(r1)
        storage.save(r2)
        storage.save(r3)

        runs = storage.list_runs()
        assert len(runs) == 3
        # Ordinati per nome (= cronologico)
        assert "20250101" in runs[0].name
        assert "20250110" in runs[2].name


# ===== compute_delta =====


class TestComputeDelta:
    """Test per il calcolo del delta tra due audit."""

    def test_delta_score_migliorato(self):
        """Delta positivo quando lo score migliora."""
        prev = _make_result(score=60.0, timestamp=datetime(2025, 1, 1))
        curr = _make_result(score=75.0, timestamp=datetime(2025, 1, 8))

        delta = AuditHistoryStorage.compute_delta(prev, curr)

        assert delta.previous_score == 60.0
        assert delta.current_score == 75.0
        assert delta.score_delta == 15.0

    def test_delta_score_peggiorato(self):
        """Delta negativo quando lo score peggiora."""
        prev = _make_result(score=80.0, timestamp=datetime(2025, 1, 1))
        curr = _make_result(score=65.0, timestamp=datetime(2025, 1, 8))

        delta = AuditHistoryStorage.compute_delta(prev, curr)

        assert delta.score_delta == -15.0

    def test_delta_score_invariato(self):
        """Delta zero quando lo score non cambia."""
        prev = _make_result(score=75.0, timestamp=datetime(2025, 1, 1))
        curr = _make_result(score=75.0, timestamp=datetime(2025, 1, 2))

        delta = AuditHistoryStorage.compute_delta(prev, curr)

        assert delta.score_delta == 0.0

    def test_days_since_previous(self):
        """Calcola correttamente i giorni trascorsi."""
        prev = _make_result(
            score=75.0,
            timestamp=datetime(2025, 1, 1, 12, 0, 0),
        )
        curr = _make_result(
            score=80.0,
            timestamp=datetime(2025, 1, 8, 12, 0, 0),
        )

        delta = AuditHistoryStorage.compute_delta(prev, curr)

        assert delta.days_since_previous == pytest.approx(7.0, abs=0.01)

    def test_finding_nuovi(self):
        """Rileva finding presenti solo nel risultato corrente."""
        f1 = _make_finding("INFRA-001")
        f2 = _make_finding("SEC-001")

        prev = _make_result(score=70.0, findings=[f1], timestamp=datetime(2025, 1, 1))
        curr = _make_result(score=65.0, findings=[f1, f2], timestamp=datetime(2025, 1, 2))

        delta = AuditHistoryStorage.compute_delta(prev, curr)

        assert "SEC-001" in delta.new_findings
        assert "INFRA-001" not in delta.new_findings

    def test_finding_risolti(self):
        """Rileva finding presenti solo nel risultato precedente."""
        f1 = _make_finding("INFRA-001")
        f2 = _make_finding("SEC-001")

        prev = _make_result(score=65.0, findings=[f1, f2], timestamp=datetime(2025, 1, 1))
        curr = _make_result(score=75.0, findings=[f1], timestamp=datetime(2025, 1, 2))

        delta = AuditHistoryStorage.compute_delta(prev, curr)

        assert "SEC-001" in delta.resolved_findings
        assert "INFRA-001" not in delta.resolved_findings

    def test_finding_persistenti(self):
        """Rileva finding presenti in entrambi i risultati."""
        f1 = _make_finding("INFRA-001")

        prev = _make_result(score=70.0, findings=[f1], timestamp=datetime(2025, 1, 1))
        curr = _make_result(score=70.0, findings=[f1], timestamp=datetime(2025, 1, 2))

        delta = AuditHistoryStorage.compute_delta(prev, curr)

        assert "INFRA-001" in delta.persistent_findings
        assert len(delta.new_findings) == 0
        assert len(delta.resolved_findings) == 0

    def test_finding_info_ignorati(self):
        """Finding INFO non vengono inclusi nel delta."""
        f_info = _make_finding("INFRA-INFO-001", severity=Severity.INFO)
        f_high = _make_finding("SEC-001", severity=Severity.HIGH)

        prev = _make_result(score=70.0, findings=[f_info], timestamp=datetime(2025, 1, 1))
        curr = _make_result(score=70.0, findings=[f_high], timestamp=datetime(2025, 1, 2))

        delta = AuditHistoryStorage.compute_delta(prev, curr)

        # INFO non deve comparire ne tra risolti ne tra nuovi
        assert "INFRA-INFO-001" not in delta.resolved_findings
        assert "SEC-001" in delta.new_findings

    def test_layer_deltas(self):
        """Calcola i delta per ogni layer."""
        prev = _make_result(score=60.0, timestamp=datetime(2025, 1, 1))
        curr = _make_result(score=80.0, timestamp=datetime(2025, 1, 2))

        delta = AuditHistoryStorage.compute_delta(prev, curr)

        assert "infra" in delta.layer_deltas
        assert delta.layer_deltas["infra"] == 20.0

    def test_nessun_finding(self):
        """Delta con nessun finding in entrambi e' valido."""
        prev = _make_result(score=100.0, timestamp=datetime(2025, 1, 1))
        curr = _make_result(score=100.0, timestamp=datetime(2025, 1, 2))

        delta = AuditHistoryStorage.compute_delta(prev, curr)

        assert len(delta.new_findings) == 0
        assert len(delta.resolved_findings) == 0
        assert len(delta.persistent_findings) == 0


# ===== Round-trip save/load/delta =====


class TestHistoryRoundTrip:
    """Test end-to-end: save → load → delta."""

    def test_save_load_delta(self, tmp_path: Path):
        """Flusso completo: salva due audit, carica, calcola delta."""
        storage = AuditHistoryStorage(tmp_path)

        f1 = _make_finding("INFRA-001")
        f2 = _make_finding("SEC-002")

        # Primo run
        r1 = _make_result(
            score=60.0,
            findings=[f1],
            timestamp=datetime(2025, 1, 1, 10, 0, 0),
            target_path=str(tmp_path),
        )
        storage.save(r1)

        # Secondo run
        r2 = _make_result(
            score=75.0,
            findings=[f1, f2],
            timestamp=datetime(2025, 1, 8, 10, 0, 0),
            target_path=str(tmp_path),
        )

        # Carica precedente e calcola delta
        previous = storage.load_latest()
        assert previous is not None

        delta = AuditHistoryStorage.compute_delta(previous, r2)

        assert delta.score_delta == 15.0
        assert "SEC-002" in delta.new_findings
        assert "INFRA-001" in delta.persistent_findings
        assert len(delta.resolved_findings) == 0
        assert delta.days_since_previous == pytest.approx(7.0, abs=0.01)

        # Salva il secondo
        storage.save(r2)
        assert len(storage.list_runs()) == 2
