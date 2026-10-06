"""
Test modalita Due Diligence — profilo a 6 layer, scoring, orchestrator, report, CLI.
"""

from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from cto_audit.cli import app
from cto_audit.core.models import (
    LAYER_ORDER,
    AuditMetadata,
    AuditResult,
    Finding,
    GitSummary,
    HealthScore,
    Layer,
    LayerScore,
    Severity,
    StackInfo,
)
from cto_audit.core.orchestrator import AuditOrchestrator
from cto_audit.remediation.loader import RemediationLoader
from cto_audit.reporters.due_diligence import DueDiligenceReporter
from cto_audit.scoring.engine import ScoringEngine
from cto_audit.scoring.profile import ScoringProfile, load_profile
from cto_audit.sources.local import LocalRepoSource

NOW = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)


def _write(base: Path, rel: str, content: str) -> None:
    p = base / Path(rel)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _finding(rule_id: str, layer: Layer, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        id=rule_id.lower(), layer=layer, severity=severity, rule_id=rule_id,
        title=f"Titolo {rule_id}", description=f"Descrizione {rule_id}",
    )


# ============================================================
# Profilo e scoring
# ============================================================

class TestProfile:
    def test_profilo_due_diligence_ha_sei_layer(self):
        profile = load_profile("due-diligence")
        assert set(profile.layer_weights) == {l.value for l in Layer}
        assert abs(sum(profile.layer_weights.values()) - 1.0) < 0.01

    def test_profilo_default_resta_a_quattro_layer(self):
        profile = load_profile("default")
        assert set(profile.layer_weights) == {"infra", "architecture", "security", "quality"}

    def test_layer_order_copre_tutti_i_layer(self):
        assert LAYER_ORDER == [l.value for l in Layer]
        assert LAYER_ORDER[:4] == ["infra", "architecture", "security", "quality"]

    def test_profilo_con_layer_provenance_valido(self):
        ScoringProfile(name="x", layer_weights={"provenance": 0.5, "team": 0.5})

    def test_profilo_con_layer_sconosciuto_rifiutato(self):
        with pytest.raises(ValueError):
            ScoringProfile(name="x", layer_weights={"marketing": 1.0})

    def test_tutte_le_regole_dd_hanno_entry_kb(self):
        profile = load_profile("due-diligence")
        kb = RemediationLoader.load_all().all_entries()
        penalizing = [rid for rid, r in profile.rules.items() if r.severity != "info"]
        missing = [rid for rid in penalizing if rid not in kb and not rid.startswith(("SEC-DEPS-CVE",))]
        # Le regole storiche gia coperte dal KB default devono restare coperte, le nuove pure
        assert not [m for m in missing if m.startswith(("PROV-", "TEAM-"))], missing


class TestScoringEngine:
    def test_default_senza_finding_dd_produce_quattro_layer(self):
        engine = ScoringEngine(load_profile("default"))
        hs = engine.calculate([_finding("INFRA-CICD-001", Layer.INFRA)])
        assert set(hs.layer_scores) == {"infra", "architecture", "security", "quality"}

    def test_due_diligence_produce_sei_layer(self):
        engine = ScoringEngine(load_profile("due-diligence"))
        hs = engine.calculate([])
        assert set(hs.layer_scores) == {l.value for l in Layer}
        assert hs.overall_score == 100.0

    def test_finding_dd_sotto_profilo_default_compare_ma_non_pesa(self):
        engine = ScoringEngine(load_profile("default"))
        hs_clean = engine.calculate([])
        hs_prov = engine.calculate([_finding("PROV-COPYLEFT-001", Layer.PROVENANCE)])
        assert "provenance" in hs_prov.layer_scores
        assert hs_prov.layer_scores["provenance"].score < 100
        assert hs_prov.overall_score == hs_clean.overall_score

    def test_penalita_copyleft_e_bus_factor(self):
        engine = ScoringEngine(load_profile("due-diligence"))
        hs = engine.calculate([
            _finding("PROV-COPYLEFT-001", Layer.PROVENANCE),
            _finding("TEAM-BUSFACTOR-001", Layer.TEAM),
        ])
        assert hs.layer_scores["provenance"].score == 70.0
        assert hs.layer_scores["team"].score == 70.0
        # 0.20 * 30 + 0.15 * 30 = 10.5 punti di overall
        assert hs.overall_score == pytest.approx(89.5, abs=0.01)

    def test_evidence_chain_per_regole_dd(self):
        engine = ScoringEngine(load_profile("due-diligence"))
        hs = engine.calculate([_finding("PROV-SBOM-001", Layer.PROVENANCE, Severity.LOW)])
        ev = hs.layer_scores["provenance"].evidence_chain
        assert len(ev) == 1
        assert ev[0].rule_id == "PROV-SBOM-001"
        assert ev[0].framework_ref == "NIS2 Art.21(2)(d)"


# ============================================================
# Orchestrator end-to-end
# ============================================================

def _init_git_repo(path: Path, commits: int = 12) -> None:
    env = {
        "GIT_AUTHOR_NAME": "dev", "GIT_AUTHOR_EMAIL": "dev@example.com",
        "GIT_COMMITTER_NAME": "dev", "GIT_COMMITTER_EMAIL": "dev@example.com",
    }
    import os
    full_env = {**os.environ, **env}
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=path, check=True, capture_output=True)
    for i in range(commits):
        (path / f"mod{i}.py").write_text(f"v = {i}\n", encoding="utf-8")
        date = (NOW - timedelta(days=400 - i * 30)).isoformat()
        e = {**full_env, "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}
        subprocess.run(["git", "add", "-A"], cwd=path, env=e, check=True, capture_output=True)
        subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", f"Add module {i}"],
                       cwd=path, env=e, check=True, capture_output=True)


@pytest.fixture
def startup_repo(tmp_path) -> Path:
    _write(tmp_path, "README.md", "# Startup\n\nRuns in Docker. SOC 2 compliant.\n")
    _write(tmp_path, "requirements.txt", "fastapi==0.110.0\npymupdf==1.24.0\n")
    _write(tmp_path, "app/main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    _write(tmp_path, "tests/test_main.py", "def test_ok(): assert True\n")
    _write(tmp_path, ".gitignore", ".venv/\n")
    return tmp_path


class TestOrchestrator:
    def test_profilo_default_non_attiva_layer_dd(self, startup_repo):
        orch = AuditOrchestrator(
            source=LocalRepoSource(startup_repo), target_path=startup_repo,
            scoring_profile="default", offline=True, auto_approve=True,
            console=Console(file=StringIO()),
        )
        result = orch.run()
        assert set(result.health_score.layer_scores) == {"infra", "architecture", "security", "quality"}
        assert result.git_summary is None
        assert result.dependency_licenses == []
        assert result.metadata.active_layers == ["infra", "architecture", "security", "quality"]

    @pytest.mark.skipif(shutil.which("git") is None, reason="git non disponibile")
    def test_profilo_due_diligence_attiva_sei_layer(self, startup_repo):
        _init_git_repo(startup_repo)
        orch = AuditOrchestrator(
            source=LocalRepoSource(startup_repo), target_path=startup_repo,
            scoring_profile="due-diligence", offline=True, auto_approve=True,
            console=Console(file=StringIO()), board_report=True, no_llm=True,
        )
        result = orch.run()
        assert set(result.health_score.layer_scores) == {l.value for l in Layer}
        assert len(result.metadata.active_layers) == 6

        assert result.git_summary is not None and result.git_summary.available
        assert result.git_summary.total_commits == 12
        assert result.git_summary.authors_total == 1

        rules = {f.rule_id for ls in result.health_score.layer_scores.values() for f in ls.findings}
        assert "PROV-COPYLEFT-001" in rules        # pymupdf dalla KB offline
        assert "PROV-CLAIMS-001" in rules          # Docker dichiarato, nessun Dockerfile
        assert "PROV-CERT-INFO" in rules           # SOC 2
        assert "TEAM-BUSFACTOR-001" in rules       # autore unico, 12 commit
        assert any(d["name"].lower() == "pymupdf" for d in result.dependency_licenses)

    def test_focus_su_provenance_senza_git(self, startup_repo):
        orch = AuditOrchestrator(
            source=LocalRepoSource(startup_repo), target_path=startup_repo,
            scoring_profile="default", focus=Layer.PROVENANCE, offline=True, auto_approve=True,
            console=Console(file=StringIO()),
        )
        result = orch.run()
        assert "provenance" in result.health_score.layer_scores
        assert result.metadata.active_layers == ["provenance"]

    def test_team_senza_repo_git_produce_info(self, startup_repo):
        orch = AuditOrchestrator(
            source=LocalRepoSource(startup_repo), target_path=startup_repo,
            scoring_profile="due-diligence", offline=True, auto_approve=True,
            console=Console(file=StringIO()),
        )
        result = orch.run()
        team = result.health_score.layer_scores["team"]
        assert team.score == 100.0
        assert {f.rule_id for f in team.findings} == {"TEAM-GIT-INFO"}
        assert result.git_summary is not None and result.git_summary.available is False


# ============================================================
# Report di due diligence
# ============================================================

def _result_with(findings: list[Finding], git: GitSummary | None = None) -> AuditResult:
    engine = ScoringEngine(load_profile("due-diligence"))
    hs = engine.calculate(findings)
    return AuditResult(
        health_score=hs,
        stack_info=StackInfo(languages={"python": 1.0}, frameworks=["FastAPI"]),
        classifications=[],
        metadata=AuditMetadata(target_path="/tmp/x", scoring_profile="due-diligence",
                               offline_mode=True, active_layers=LAYER_ORDER),
        git_summary=git,
        dependency_licenses=[{"name": "pymupdf", "ecosystem": "PyPI", "source_file": "requirements.txt",
                              "license": "AGPL-3.0", "category": "strong_copyleft", "source": "kb"}],
    )


class TestDueDiligenceReporter:
    def test_sezioni_presenti(self):
        result = _result_with([
            _finding("PROV-COPYLEFT-001", Layer.PROVENANCE),
            _finding("TEAM-BUSFACTOR-001", Layer.TEAM),
            _finding("PROV-SBOM-001", Layer.PROVENANCE, Severity.LOW),
        ], git=GitSummary(available=True, total_commits=50, authors_total=1, authors_365d=1,
                          first_commit=NOW - timedelta(days=300), last_commit=NOW - timedelta(days=2),
                          top_author_share=1.0, top_author_share_365d=1.0, tags_total=0,
                          commits_by_month={"2026-09": 5, "2026-10": 2}))
        text = DueDiligenceReporter(kb_loader=RemediationLoader.load_all(), now=NOW).report(result)
        for heading in ["# Technical Due Diligence", "## 1. Perimetro e metodo", "## 2. Sintesi",
                        "## 3. Inventario dell'asset", "## 4. Red flag", "## 5. Yellow flag",
                        "## 6. Dichiarazioni vs evidenze", "## 7. Costo stimato di remediation",
                        "## 8. Domande per il management", "## 10. Score per layer"]:
            assert heading in text, heading
        assert "Deal flag" in text
        assert "PROV-COPYLEFT-001" in text and "TEAM-BUSFACTOR-001" in text
        assert "Rischio per l'acquirente" in text
        assert "Totale" in text   # tabella costi
        assert "Commit totali | 50" in text
        assert "2026-09" in text

    def test_domande_management_dalle_regole(self):
        result = _result_with([_finding("TEAM-ACTIVITY-001", Layer.TEAM)])
        text = DueDiligenceReporter(kb_loader=RemediationLoader.load_all(), now=NOW).report(result)
        assert "fermo da oltre sei mesi" in text

    def test_report_senza_finding_e_senza_kb(self):
        result = _result_with([])
        text = DueDiligenceReporter(now=NOW).report(result)
        assert "Nessun deal flag" in text
        assert "Nessun red flag" in text
        assert "Knowledge base di remediation non caricata" in text

    def test_git_non_disponibile_segnalato(self):
        result = _result_with([], git=GitSummary(available=False, reason="non e un repository git"))
        text = DueDiligenceReporter(now=NOW).report(result)
        assert "Storico git non disponibile" in text

    def test_save(self, tmp_path):
        result = _result_with([])
        out = tmp_path / "dd.md"
        DueDiligenceReporter(now=NOW).save(result, out)
        assert out.exists() and "Technical Due Diligence" in out.read_text(encoding="utf-8")


# ============================================================
# CLI
# ============================================================

class TestCLI:
    def test_flag_due_diligence_scrive_report(self, startup_repo, tmp_path):
        out = tmp_path / "out" / "dd.md"
        out.parent.mkdir()
        runner = CliRunner()
        result = runner.invoke(app, [
            "scan", str(startup_repo), "--due-diligence", "--offline", "--auto-approve",
            "--no-llm", "--output", str(out),
        ])
        assert result.exit_code == 0, result.output
        text = out.read_text(encoding="utf-8")
        assert "Technical Due Diligence" in text
        assert "Provenienza & IP" in text
        assert "due-diligence" in result.output

    def test_scoring_esplicito_non_sovrascritto(self, startup_repo, tmp_path):
        out = tmp_path / "dd.md"
        runner = CliRunner()
        result = runner.invoke(app, [
            "scan", str(startup_repo), "--dd", "--scoring", "vc-diligence",
            "--offline", "--auto-approve", "--no-llm", "--output", str(out),
        ])
        assert result.exit_code == 0, result.output
        assert "vc-diligence" in result.output

    def test_focus_team_accettato(self, startup_repo):
        runner = CliRunner()
        result = runner.invoke(app, ["scan", str(startup_repo), "--focus", "team", "--offline", "--auto-approve"])
        assert result.exit_code == 0, result.output
