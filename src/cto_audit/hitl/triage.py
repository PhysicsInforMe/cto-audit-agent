"""
Finding Triage — Revisione umana dei finding e raccolta delle etichette.

Dopo lo scoring, il revisore vede i finding critical/high/medium uno per uno e
decide: conferma, declassa, scarta (oppure salta). Ogni decisione e un'etichetta
"oro" per la fase D del piano (stimatore locale di conferma).

Due destinazioni, con contenuti diversi:
- `.cto-audit/decisions.jsonl` nel repository analizzato: decisione completa,
  con titolo del finding e nota del revisore. Resta col cliente.
- directory etichette del consulente (env `CTO_AUDIT_LABELS_DIR`, default
  `~/.cto-audit/labels/decisions.jsonl`): copia anonimizzata. Solo dati
  strutturati: rule_id, layer, severita, confidence, tipo progetto, linguaggi,
  dimensioni, decisione. Mai percorsi, mai snippet, mai titolo, mai nota,
  mai nome del cliente. L'audit e identificato da un ID casuale.

Lo score del report non cambia con il triage.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from rich.console import Console
from rich.panel import Panel

from cto_audit.core.models import (
    AuditResult,
    Finding,
    Severity,
    TriageDecision,
    TriageVerdict,
)

TRIAGE_SEVERITIES = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
LOCAL_DECISIONS_FILE = Path(".cto-audit") / "decisions.jsonl"
LABELS_DIR_ENV = "CTO_AUDIT_LABELS_DIR"

_ANSWERS: dict[str, TriageVerdict | str] = {
    "c": TriageVerdict.CONFIRMED, "conferma": TriageVerdict.CONFIRMED, "y": TriageVerdict.CONFIRMED,
    "d": TriageVerdict.DOWNGRADED, "declassa": TriageVerdict.DOWNGRADED,
    "s": TriageVerdict.DISMISSED, "scarta": TriageVerdict.DISMISSED, "n": TriageVerdict.DISMISSED,
    "k": "skip", "salta": "skip", "": "skip",
    "q": "quit", "esci": "quit",
}


def default_labels_path() -> Path:
    """File aggregato delle etichette anonimizzate del consulente."""
    base = os.environ.get(LABELS_DIR_ENV)
    root = Path(base) if base else Path.home() / ".cto-audit" / "labels"
    return root / "decisions.jsonl"


class FindingTriage:
    """
    Sessione di triage interattiva sui finding di un AuditResult.

    Args:
        console: console Rich per l'output
        input_fn: funzione di input (iniettabile nei test); default `console.input`
    """

    def __init__(self, console: Console | None = None, input_fn: Callable[[str], str] | None = None) -> None:
        self.console = console or Console()
        self._input = input_fn or self.console.input

    def review(self, result: AuditResult) -> list[TriageDecision]:
        """Mostra i finding critical/high/medium e raccoglie le decisioni. Mai solleva su EOF."""
        findings = self._candidates(result)
        if not findings:
            return []

        audit_id = uuid.uuid4().hex[:12]
        self.console.print()
        self.console.print(Panel(
            f"  {len(findings)} finding da rivedere (critical, high, medium).\n\n"
            "  Per ciascuno: [bold]c[/bold] conferma, [bold]d[/bold] declassa, [bold]s[/bold] scarta, "
            "[bold]k[/bold] salta, [bold]q[/bold] termina. Dopo la scelta puoi aggiungere una nota.\n"
            "  Le decisioni non cambiano lo score: diventano etichette per la revisione futura.",
            title="TRIAGE FINDING",
            border_style="cyan",
        ))

        decisions: list[TriageDecision] = []
        for idx, finding in enumerate(findings, 1):
            self.console.print()
            self.console.print(
                f"  [{idx}/{len(findings)}] [{_sev_style(finding.severity)}]{finding.severity.value.upper()}[/] "
                f"{finding.rule_id} · {finding.layer.value}"
            )
            self.console.print(f"  [bold]{finding.title}[/bold]")
            for line in finding.description.strip().splitlines()[:6]:
                self.console.print(f"    {line}")

            verdict = self._ask_verdict()
            if verdict == "quit":
                break
            if verdict == "skip":
                continue

            note = self._ask_note()
            decisions.append(TriageDecision(
                audit_id=audit_id,
                finding_id=finding.id,
                rule_id=finding.rule_id,
                layer=finding.layer.value,
                severity=finding.severity.value,
                finding_confidence=finding.confidence,
                verdict=verdict,
                note=note or None,
                title=finding.title,
            ))

        self.console.print()
        self.console.print(f"  Triage completato: {len(decisions)} decisioni su {len(findings)} finding.")
        return decisions

    # --- helpers ---

    @staticmethod
    def _candidates(result: AuditResult) -> list[Finding]:
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2}
        out = [
            f for ls in result.health_score.layer_scores.values()
            for f in ls.findings if f.severity in TRIAGE_SEVERITIES
        ]
        out.sort(key=lambda f: (order[f.severity], f.layer.value, f.rule_id))
        return out

    def _ask_verdict(self) -> TriageVerdict | str:
        while True:
            try:
                raw = self._input("  Decisione [c/d/s/k/q]: ")
            except (EOFError, KeyboardInterrupt):
                return "quit"
            answer = _ANSWERS.get(raw.strip().lower())
            if answer is not None:
                return answer
            self.console.print("  Risposta non riconosciuta. Usa c, d, s, k oppure q.")

    def _ask_note(self) -> str:
        try:
            return self._input("  Nota (invio per nessuna): ").strip()
        except (EOFError, KeyboardInterrupt):
            return ""


class TriageStore:
    """Salva le decisioni: file completo nel repo analizzato, copia anonimizzata per il consulente."""

    def __init__(self, target_path: Path, labels_path: Path | None = None) -> None:
        self.target_path = Path(target_path)
        self.labels_path = labels_path or default_labels_path()

    def save(self, result: AuditResult, decisions: list[TriageDecision]) -> tuple[Path | None, Path | None]:
        """Scrive entrambi i file. Restituisce i percorsi scritti (None se un salvataggio fallisce)."""
        if not decisions:
            return None, None
        context = self._context(result)
        local = self._append(self.target_path / LOCAL_DECISIONS_FILE,
                             [self._local_row(d, context) for d in decisions])
        shared = self._append(self.labels_path,
                              [self._anonymous_row(d, context) for d in decisions])
        return local, shared

    @staticmethod
    def _context(result: AuditResult) -> dict:
        meta = result.metadata
        langs = result.stack_info.languages
        primary = max(langs, key=langs.get) if langs else None
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tool_version": meta.tool_version,
            "scoring_profile": meta.scoring_profile,
            "project_type": meta.project_type,
            "project_type_confidence": meta.project_type_confidence,
            "primary_language": primary,
            "languages": {k: round(v, 3) for k, v in langs.items()},
            "frameworks_count": len(result.stack_info.frameworks),
            "total_files": len(result.classifications),
            "total_loc": sum(c.file_info.lines_of_code for c in result.classifications),
            "overall_score": result.health_score.overall_score,
        }

    @staticmethod
    def _local_row(d: TriageDecision, context: dict) -> dict:
        row = d.model_dump(mode="json")
        row.update(context)
        return row

    @staticmethod
    def _anonymous_row(d: TriageDecision, context: dict) -> dict:
        row = d.model_dump(mode="json")
        row.pop("title", None)
        row.pop("note", None)
        row.pop("finding_id", None)
        row.update(context)
        return row

    @staticmethod
    def _append(path: Path, rows: list[dict]) -> Path | None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                for row in rows:
                    f.write(json.dumps(row, ensure_ascii=False) + "\n")
            return path
        except OSError:
            return None


def _sev_style(sev: Severity) -> str:
    return {"critical": "red bold", "high": "red", "medium": "yellow"}.get(sev.value, "white")
