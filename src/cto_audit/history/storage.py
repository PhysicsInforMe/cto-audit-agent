"""
Audit History Storage — Salvataggio e caricamento storico audit.

Gestisce la persistenza dei risultati audit in `.cto-audit/history/`
nella root del progetto scansionato. Formato: JSON file per ogni run.

Supporta:
- Salvataggio risultato audit come JSON timestampato
- Caricamento ultimo risultato per calcolo delta
- Lista di tutti i run precedenti
- Calcolo delta tra due risultati (score, finding, layer)
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from cto_audit.core.models import AuditDelta, AuditResult, Severity


class AuditHistoryStorage:
    """
    Gestisce lo storico degli audit per un progetto.

    Salva ogni AuditResult come JSON in `.cto-audit/history/YYYYMMDD_HHMMSS.json`.
    """

    HISTORY_DIR = ".cto-audit/history"

    def __init__(self, target_path: Path) -> None:
        self._target_path = target_path
        self._history_dir = target_path / self.HISTORY_DIR

    def save(self, result: AuditResult) -> Path:
        """
        Salva un AuditResult come JSON nella directory history.

        Args:
            result: Risultato audit da salvare

        Returns:
            Path del file JSON creato
        """
        self._history_dir.mkdir(parents=True, exist_ok=True)

        timestamp = result.metadata.timestamp.strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}.json"
        filepath = self._history_dir / filename

        data = result.model_dump(mode="json")
        filepath.write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )

        return filepath

    def load_latest(self) -> AuditResult | None:
        """
        Carica il risultato dell'ultimo audit.

        Returns:
            AuditResult piu recente, o None se non ci sono audit precedenti
        """
        runs = self.list_runs()
        if not runs:
            return None

        latest = runs[-1]  # list_runs() ordina per nome (= cronologico)
        data = json.loads(latest.read_text(encoding="utf-8"))
        return AuditResult.model_validate(data)

    def list_runs(self) -> list[Path]:
        """
        Lista tutti i file di audit salvati, ordinati cronologicamente.

        Returns:
            Lista di Path dei file JSON, dal piu vecchio al piu recente
        """
        if not self._history_dir.exists():
            return []

        files = sorted(self._history_dir.glob("*.json"))
        return files

    @staticmethod
    def compute_delta(
        previous: AuditResult, current: AuditResult
    ) -> AuditDelta:
        """
        Calcola il delta tra due audit.

        Operazioni insiemistiche su rule_id (non-INFO) per determinare
        finding nuovi, risolti e persistenti.

        Args:
            previous: Risultato audit precedente
            current: Risultato audit corrente

        Returns:
            AuditDelta con tutte le metriche di confronto
        """
        # Score delta
        prev_score = previous.health_score.overall_score
        curr_score = current.health_score.overall_score

        # Layer deltas
        layer_deltas: dict[str, float] = {}
        all_layers = set(previous.health_score.layer_scores.keys()) | set(
            current.health_score.layer_scores.keys()
        )
        for layer_name in all_layers:
            prev_ls = previous.health_score.layer_scores.get(layer_name)
            curr_ls = current.health_score.layer_scores.get(layer_name)
            prev_val = prev_ls.score if prev_ls else 0.0
            curr_val = curr_ls.score if curr_ls else 0.0
            layer_deltas[layer_name] = curr_val - prev_val

        # Finding delta (solo non-INFO)
        prev_rules: set[str] = set()
        curr_rules: set[str] = set()

        for ls in previous.health_score.layer_scores.values():
            for f in ls.findings:
                if f.severity != Severity.INFO:
                    prev_rules.add(f.rule_id)

        for ls in current.health_score.layer_scores.values():
            for f in ls.findings:
                if f.severity != Severity.INFO:
                    curr_rules.add(f.rule_id)

        new_findings = sorted(curr_rules - prev_rules)
        resolved_findings = sorted(prev_rules - curr_rules)
        persistent_findings = sorted(prev_rules & curr_rules)

        # Tempo trascorso
        prev_ts = previous.metadata.timestamp
        curr_ts = current.metadata.timestamp
        days_since = (curr_ts - prev_ts).total_seconds() / 86400.0

        return AuditDelta(
            previous_score=prev_score,
            current_score=curr_score,
            score_delta=curr_score - prev_score,
            previous_timestamp=prev_ts,
            current_timestamp=curr_ts,
            layer_deltas=layer_deltas,
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            persistent_findings=persistent_findings,
            days_since_previous=max(0.0, days_since),
        )
