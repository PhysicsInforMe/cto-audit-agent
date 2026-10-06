"""
Test triage HITL dei finding — sessione interattiva, salvataggio etichette, orchestrator, CLI, report.
"""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

from rich.console import Console
from typer.testing import CliRunner

from cto_audit.cli import app
from cto_audit.core.models import (
    LAYER_ORDER,
    AuditMetadata,
    AuditResult,
    FileClassification,
    FileInfo,
    Finding,
    Layer,
    PrivacyCategory,
    Severity,
    StackInfo,
    TriageVerdict,
)
from cto_audit.core.orchestrator import AuditOrchestrator
from cto_audit.hitl.triage import FindingTriage, TriageStore
from cto_audit.reporters.due_diligence import DueDiligenceReporter
from cto_audit.scoring.engine import ScoringEngine
from cto_audit.scoring.profile import load_profile
from cto_audit.sources.local import LocalRepoSource


def _finding(rule_id: str, layer: Layer, severity: Severity, title: str = "") -> Finding:
    return Finding(
        id=rule_id.lower(), layer=layer, severity=severity, rule_id=rule_id,
        title=title or f"Titolo {rule_id}", description=f"Descrizione {rule_id}\nsecret in src/config.py",
    )


def _result(findings: list[Finding]) -> AuditResult:
    hs = ScoringEngine(load_profile("due-diligence")).calculate(findings)
    return AuditResult(
        health_score=hs,
        stack_info=StackInfo(languages={"python": 0.8, "javascript": 0.2}, frameworks=["FastAPI"]),
        classifications=[FileClassification(
            file_info=FileInfo(path="src/app.py", size=10, extension=".py", lines_of_code=120),
            category=PrivacyCategory.SAFE, reason="test",
        )],
        metadata=AuditMetadata(target_path="/clienti/acme/repo", scoring_profile="due-diligence",
                               project_type="web_app", project_type_confidence=0.8, active_layers=LAYER_ORDER),
    )


def _scripted(answers: list[str]):
    it = iter(answers)

    def _input(prompt: str) -> str:
        try:
            return next(it)
        except StopIteration:
            raise EOFError
    return _input


FINDINGS = [
    _finding("SEC-SECRETS-CODE-001", Layer.SECURITY, Severity.CRITICAL, "Secrets hardcodati"),
    _finding("TEAM-BUSFACTOR-001", Layer.TEAM, Severity.HIGH, "Bus factor 1"),
    _finding("PROV-CLAIMS-001", Layer.PROVENANCE, Severity.MEDIUM, "Claims README"),
    _finding("QUAL-CHANGELOG-001", Layer.QUALITY, Severity.LOW, "Nessun changelog"),  # escluso dal triage
    Finding(id="i", layer=Layer.TEAM, severity=Severity.INFO, rule_id="TEAM-GIT-INFO", title="info", description="x"),
]


class TestFindingTriage:
    def test_ordine_e_verdetti(self):
        # critical -> high -> medium; low e info esclusi
        answers = ["c", "rotato il 3/10", "d", "", "s", "non rilevante"]
        decisions = FindingTriage(Console(file=StringIO()), _scripted(answers)).review(_result(FINDINGS))
        assert [d.rule_id for d in decisions] == ["SEC-SECRETS-CODE-001", "TEAM-BUSFACTOR-001", "PROV-CLAIMS-001"]
        assert [d.verdict for d in decisions] == [TriageVerdict.CONFIRMED, TriageVerdict.DOWNGRADED, TriageVerdict.DISMISSED]
        assert decisions[0].note == "rotato il 3/10"
        assert decisions[1].note is None
        assert len({d.audit_id for d in decisions}) == 1

    def test_salta_e_termina(self):
        answers = ["k", "q"]
        decisions = FindingTriage(Console(file=StringIO()), _scripted(answers)).review(_result(FINDINGS))
        assert decisions == []

    def test_risposta_non_valida_richiede(self):
        answers = ["boh", "c", "", "q"]
        decisions = FindingTriage(Console(file=StringIO()), _scripted(answers)).review(_result(FINDINGS))
        assert len(decisions) == 1 and decisions[0].verdict == TriageVerdict.CONFIRMED

    def test_eof_termina_senza_errore(self):
        decisions = FindingTriage(Console(file=StringIO()), _scripted([])).review(_result(FINDINGS))
        assert decisions == []

    def test_nessun_candidato(self):
        decisions = FindingTriage(Console(file=StringIO()), _scripted(["c"])).review(_result([FINDINGS[3]]))
        assert decisions == []


class TestTriageStore:
    def test_due_file_con_contenuti_diversi(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        labels = tmp_path / "labels" / "decisions.jsonl"
        decisions = FindingTriage(Console(file=StringIO()), _scripted(["c", "nota riservata", "s", ""])).review(_result(FINDINGS))
        local, shared = TriageStore(repo, labels_path=labels).save(_result(FINDINGS), decisions)

        assert local == repo / ".cto-audit" / "decisions.jsonl" and local.exists()
        assert shared == labels and shared.exists()

        local_rows = [json.loads(l) for l in local.read_text(encoding="utf-8").splitlines()]
        shared_rows = [json.loads(l) for l in shared.read_text(encoding="utf-8").splitlines()]
        assert len(local_rows) == len(shared_rows) == 2

        assert local_rows[0]["title"] == "Secrets hardcodati"
        assert local_rows[0]["note"] == "nota riservata"
        for row in shared_rows:
            assert "title" not in row and "note" not in row and "finding_id" not in row
            dumped = json.dumps(row)
            assert "acme" not in dumped and "src/" not in dumped and "config.py" not in dumped
        assert shared_rows[0]["rule_id"] == "SEC-SECRETS-CODE-001"
        assert shared_rows[0]["verdict"] == "confirmed"
        assert shared_rows[0]["primary_language"] == "python"
        assert shared_rows[0]["project_type"] == "web_app"
        assert shared_rows[0]["total_loc"] == 120
        assert shared_rows[0]["overall_score"] == _result(FINDINGS).health_score.overall_score

    def test_append_tra_sessioni(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        labels = tmp_path / "labels.jsonl"
        store = TriageStore(repo, labels_path=labels)
        d1 = FindingTriage(Console(file=StringIO()), _scripted(["c", "", "q"])).review(_result(FINDINGS))
        store.save(_result(FINDINGS), d1)
        d2 = FindingTriage(Console(file=StringIO()), _scripted(["s", "", "q"])).review(_result(FINDINGS))
        store.save(_result(FINDINGS), d2)
        assert len(labels.read_text(encoding="utf-8").splitlines()) == 2

    def test_nessuna_decisione_nessun_file(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        assert TriageStore(repo, labels_path=tmp_path / "l.jsonl").save(_result(FINDINGS), []) == (None, None)
        assert not (repo / ".cto-audit" / "decisions.jsonl").exists()


def _write(base: Path, rel: str, content: str) -> None:
    p = base / Path(rel)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


class TestOrchestrator:
    def _repo(self, tmp_path) -> Path:
        _write(tmp_path, "app.py", "API_KEY = 'sk-live-1234567890abcdefghijklmnop'\nx = 1\n")
        _write(tmp_path, "requirements.txt", "pymupdf==1.24.0\n")
        return tmp_path

    def test_triage_salva_decisioni(self, tmp_path):
        repo = self._repo(tmp_path / "repo")
        labels = tmp_path / "labels" / "decisions.jsonl"
        # Il triage non e compatibile con auto_approve: usiamo reuse_classification con un file salvato
        pre = AuditOrchestrator(source=LocalRepoSource(repo), target_path=repo, scoring_profile="due-diligence",
                                offline=True, auto_approve=True, console=Console(file=StringIO()))
        pre.run()
        orch = AuditOrchestrator(
            source=LocalRepoSource(repo), target_path=repo, scoring_profile="due-diligence",
            offline=True, reuse_classification=True, console=Console(file=StringIO()),
            triage=True, triage_input_fn=_scripted(["c", "", "c", "", "q"]), labels_path=labels,
        )
        result = orch.run()
        assert len(result.triage) == 2
        assert all(d.verdict == TriageVerdict.CONFIRMED for d in result.triage)
        assert (repo / ".cto-audit" / "decisions.jsonl").exists()
        assert labels.exists()
        assert result.model_dump_json()  # serializzabile (export JSON)

    def test_auto_approve_disattiva_triage(self, tmp_path):
        repo = self._repo(tmp_path / "repo")
        orch = AuditOrchestrator(
            source=LocalRepoSource(repo), target_path=repo, scoring_profile="due-diligence",
            offline=True, auto_approve=True, console=Console(file=StringIO()),
            triage=True, triage_input_fn=_scripted(["c", ""]), labels_path=tmp_path / "l.jsonl",
        )
        result = orch.run()
        assert result.triage == []
        assert not (tmp_path / "l.jsonl").exists()


class TestReport:
    def test_sezione_revisione(self):
        result = _result(FINDINGS)
        result.triage = FindingTriage(Console(file=StringIO()), _scripted(["c", "ruotare | subito", "d", "", "q"])).review(result)
        text = DueDiligenceReporter().report(result)
        assert "## 5.1 Revisione del consulente" in text
        assert "1 confermati, 1 declassati, 0 scartati" in text
        assert "ruotare / subito" in text   # il carattere pipe non rompe la tabella

    def test_senza_triage_nessuna_sezione(self):
        assert "Revisione del consulente" not in DueDiligenceReporter().report(_result(FINDINGS))


class TestCLI:
    def test_auto_approve_non_avvia_triage(self, tmp_path):
        _write(tmp_path, "app.py", "x = 1\n")
        runner = CliRunner()
        result = runner.invoke(app, ["scan", str(tmp_path), "--due-diligence", "--offline", "--auto-approve", "--no-llm", "--triage"])
        assert result.exit_code == 0, result.output
        assert "TRIAGE FINDING" not in result.output
