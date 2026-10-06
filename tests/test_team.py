"""
Test TeamAnalyzer — Layer TEAM: bus factor, attivita, storico compresso.

Lavora su GitSummary costruiti a mano: nessun git richiesto.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cto_audit.analyzers.team import TeamAnalyzer
from cto_audit.core.models import Finding, GitSummary, Layer, Severity, StackInfo
from cto_audit.sources.local import LocalRepoSource

NOW = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)


def _summary(**overrides) -> GitSummary:
    base = dict(
        available=True,
        is_shallow=False,
        total_commits=120,
        merge_commits=5,
        first_commit=NOW - timedelta(days=600),
        last_commit=NOW - timedelta(days=3),
        authors_total=4,
        authors_365d=3,
        commits_90d=20,
        commits_180d=45,
        commits_365d=80,
        top_author_share=0.45,
        top_author_share_365d=0.40,
        tags_total=6,
        ai_coauthored_commits=0,
        trivial_message_commits=10,
        insertions_total=50000,
        top3_commits_insertions_share=0.20,
    )
    base.update(overrides)
    return GitSummary(**base)


def _run(summary: GitSummary | None, tmp_path) -> list[Finding]:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    source = LocalRepoSource(tmp_path)
    return TeamAnalyzer(summary, now=NOW).analyze(source, StackInfo(), [])


def _rules(findings: list[Finding]) -> set[str]:
    return {f.rule_id for f in findings if f.severity != Severity.INFO}


def _info_rules(findings: list[Finding]) -> set[str]:
    return {f.rule_id for f in findings if f.severity == Severity.INFO}


class TestUnavailable:
    def test_summary_none(self, tmp_path):
        findings = _run(None, tmp_path)
        assert _rules(findings) == set()
        assert _info_rules(findings) == {"TEAM-GIT-INFO"}
        assert all(f.layer == Layer.TEAM for f in findings)

    def test_summary_non_disponibile(self, tmp_path):
        findings = _run(GitSummary(available=False, reason="non e un repo"), tmp_path)
        assert _info_rules(findings) == {"TEAM-GIT-INFO"}
        assert "non e un repo" in findings[0].description

    def test_shallow_aggiunge_info_ma_valuta(self, tmp_path):
        findings = _run(_summary(is_shallow=True, authors_total=1, authors_365d=1,
                                 top_author_share=1.0, top_author_share_365d=1.0), tmp_path)
        assert "TEAM-GIT-INFO" in _info_rules(findings)
        assert "TEAM-BUSFACTOR-001" in _rules(findings)


class TestHealthy:
    def test_repo_sano_nessun_finding_penalizzante(self, tmp_path):
        findings = _run(_summary(), tmp_path)
        assert _rules(findings) == set()


class TestBusFactor:
    def test_autore_unico(self, tmp_path):
        findings = _run(_summary(authors_total=1, authors_365d=1, top_author_share=1.0,
                                 top_author_share_365d=1.0), tmp_path)
        assert "TEAM-BUSFACTOR-001" in _rules(findings)
        f = next(f for f in findings if f.rule_id == "TEAM-BUSFACTOR-001")
        assert f.severity == Severity.HIGH
        assert "un solo autore" in f.title

    def test_concentrazione_80_percento_ultimi_12_mesi(self, tmp_path):
        findings = _run(_summary(authors_365d=3, top_author_share_365d=0.85), tmp_path)
        assert "TEAM-BUSFACTOR-001" in _rules(findings)
        f = next(f for f in findings if f.rule_id == "TEAM-BUSFACTOR-001")
        assert "85%" in f.title

    def test_sotto_soglia_non_scatta(self, tmp_path):
        findings = _run(_summary(top_author_share_365d=0.79), tmp_path)
        assert "TEAM-BUSFACTOR-001" not in _rules(findings)

    def test_finestra_ricade_su_tutto_lo_storico_se_pochi_commit_recenti(self, tmp_path):
        findings = _run(_summary(commits_365d=5, top_author_share_365d=1.0, authors_365d=1,
                                 top_author_share=0.3, authors_total=5), tmp_path)
        # Negli ultimi 12 mesi pochi commit: si usa lo storico intero (30%), nessun bus factor
        assert "TEAM-BUSFACTOR-001" not in _rules(findings)


class TestActivity:
    def test_inattivo_oltre_180_giorni(self, tmp_path):
        findings = _run(_summary(last_commit=NOW - timedelta(days=200), commits_90d=0, commits_180d=0), tmp_path)
        rules = _rules(findings)
        assert "TEAM-ACTIVITY-001" in rules
        assert "TEAM-ACTIVITY-002" not in rules

    def test_inattivo_tra_90_e_180(self, tmp_path):
        findings = _run(_summary(last_commit=NOW - timedelta(days=120), commits_90d=0), tmp_path)
        rules = _rules(findings)
        assert "TEAM-ACTIVITY-002" in rules
        assert "TEAM-ACTIVITY-001" not in rules

    def test_attivo_nessun_finding(self, tmp_path):
        findings = _run(_summary(last_commit=NOW - timedelta(days=5)), tmp_path)
        assert not {"TEAM-ACTIVITY-001", "TEAM-ACTIVITY-002"} & _rules(findings)


class TestHistory:
    def test_storico_compresso(self, tmp_path):
        findings = _run(_summary(top3_commits_insertions_share=0.72), tmp_path)
        assert "TEAM-HISTORY-001" in _rules(findings)

    def test_storico_minimo_solo_history_002(self, tmp_path):
        findings = _run(_summary(total_commits=3, authors_total=1, authors_365d=1,
                                 top_author_share=1.0, top_author_share_365d=1.0, tags_total=0), tmp_path)
        rules = _rules(findings)
        assert rules == {"TEAM-HISTORY-002"}

    def test_nessun_tag_con_molti_commit(self, tmp_path):
        findings = _run(_summary(tags_total=0, total_commits=150), tmp_path)
        assert "TEAM-RELEASE-001" in _rules(findings)

    def test_tag_assenti_ma_pochi_commit_non_scatta(self, tmp_path):
        findings = _run(_summary(tags_total=0, total_commits=60), tmp_path)
        assert "TEAM-RELEASE-001" not in _rules(findings)


class TestMessagesAndAI:
    def test_messaggi_generici(self, tmp_path):
        findings = _run(_summary(total_commits=100, merge_commits=0, trivial_message_commits=50), tmp_path)
        assert "TEAM-MSGQUAL-001" in _rules(findings)

    def test_ai_coauthor_info(self, tmp_path):
        findings = _run(_summary(ai_coauthored_commits=30), tmp_path)
        assert "TEAM-AIGEN-INFO" in _info_rules(findings)
        f = next(f for f in findings if f.rule_id == "TEAM-AIGEN-INFO")
        assert "25%" in f.title

    def test_senza_ai_nessuna_info(self, tmp_path):
        findings = _run(_summary(ai_coauthored_commits=0), tmp_path)
        assert "TEAM-AIGEN-INFO" not in _info_rules(findings)
