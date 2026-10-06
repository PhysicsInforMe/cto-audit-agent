"""
Test GitHistoryCollector — metriche aggregate dallo storico git.

Costruisce repository git reali in tmp_path (git deve essere nel PATH,
come richiesto dai source connector). Nessun dato personale deve finire
nel GitSummary.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cto_audit.collectors.git_history import GitHistoryCollector
from cto_audit.core.models import GitSummary

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git non disponibile")

NOW = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)


def _git(repo: Path, *args: str, date: datetime | None = None, author: str = "alice@example.com") -> None:
    env = os.environ.copy()
    env.update({
        "GIT_AUTHOR_NAME": author.split("@")[0],
        "GIT_AUTHOR_EMAIL": author,
        "GIT_COMMITTER_NAME": author.split("@")[0],
        "GIT_COMMITTER_EMAIL": author,
    })
    if date is not None:
        iso = date.isoformat()
        env["GIT_AUTHOR_DATE"] = iso
        env["GIT_COMMITTER_DATE"] = iso
    subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", *args],
        cwd=repo, env=env, check=True, capture_output=True, text=True,
    )


def _init(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q", "-b", "main")


def _commit(repo: Path, filename: str, content: str, message: str, *, date: datetime, author: str = "alice@example.com") -> None:
    (repo / filename).write_text(content, encoding="utf-8")
    _git(repo, "add", "-A", date=date, author=author)
    _git(repo, "commit", "-q", "-m", message, date=date, author=author)


# ============================================================
# Casi di non disponibilita
# ============================================================

class TestUnavailable:
    def test_directory_non_git(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n")
        summary = GitHistoryCollector(tmp_path, now=NOW).collect()
        assert summary.available is False
        assert summary.reason

    def test_directory_inesistente(self, tmp_path):
        summary = GitHistoryCollector(tmp_path / "nope", now=NOW).collect()
        assert summary.available is False

    def test_repo_vuoto_senza_commit(self, tmp_path):
        _init(tmp_path)
        summary = GitHistoryCollector(tmp_path, now=NOW).collect()
        assert summary.available is False
        assert "commit" in (summary.reason or "")


# ============================================================
# Metriche su repository reale
# ============================================================

class TestMetrics:
    @pytest.fixture
    def repo(self, tmp_path) -> Path:
        _init(tmp_path)
        base = NOW - timedelta(days=500)
        # Commit iniziale grande (code dump) di alice
        _commit(tmp_path, "big.py", "\n".join(f"x{i} = {i}" for i in range(200)) + "\n",
                "Initial import of the platform", date=base)
        # Commit piccoli di alice con messaggi generici
        for i in range(5):
            _commit(tmp_path, f"f{i}.py", f"y = {i}\n", "fix", date=base + timedelta(days=10 * (i + 1)))
        # Commit di bob, uno co-firmato da un assistente AI
        _commit(tmp_path, "bob.py", "z = 1\n", "Add bob module", date=NOW - timedelta(days=30), author="bob@example.com")
        (tmp_path / "ai.py").write_text("w = 1\n", encoding="utf-8")
        _git(tmp_path, "add", "-A", date=NOW - timedelta(days=10), author="bob@example.com")
        _git(tmp_path, "commit", "-q", "-m", "Add ai module\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
             date=NOW - timedelta(days=10), author="bob@example.com")
        _git(tmp_path, "tag", "v1.0.0")
        return tmp_path

    def test_available_e_conteggi(self, repo):
        s = GitHistoryCollector(repo, now=NOW).collect()
        assert s.available is True
        assert s.is_shallow is False
        assert s.total_commits == 8
        assert s.merge_commits == 0
        assert s.authors_total == 2
        assert s.tags_total == 1

    def test_finestre_temporali(self, repo):
        s = GitHistoryCollector(repo, now=NOW).collect()
        assert s.commits_90d == 2      # bob: 30 e 10 giorni fa
        assert s.commits_180d == 2
        assert s.commits_365d == 2
        assert s.authors_365d == 1     # solo bob negli ultimi 12 mesi
        assert s.first_commit is not None and s.last_commit is not None
        assert s.first_commit < s.last_commit

    def test_quota_primo_autore(self, repo):
        s = GitHistoryCollector(repo, now=NOW).collect()
        assert s.top_author_share == pytest.approx(6 / 8, abs=0.01)
        assert s.top_author_share_365d == 1.0

    def test_code_dump_share(self, repo):
        s = GitHistoryCollector(repo, now=NOW).collect()
        # 200 righe nel primo commit su ~207 totali: i 3 commit piu grandi coprono quasi tutto
        assert s.insertions_total >= 200
        assert s.top3_commits_insertions_share > 0.9

    def test_ai_coauthor_e_messaggi_generici(self, repo):
        s = GitHistoryCollector(repo, now=NOW).collect()
        assert s.ai_coauthored_commits == 1
        assert s.trivial_message_commits == 5   # i cinque "fix"

    def test_commits_by_month_ultimi_12_mesi(self, repo):
        s = GitHistoryCollector(repo, now=NOW).collect()
        assert sum(s.commits_by_month.values()) == 2
        assert all(len(k) == 7 for k in s.commits_by_month)  # YYYY-MM

    def test_nessun_dato_personale_nel_summary(self, repo):
        s = GitHistoryCollector(repo, now=NOW).collect()
        dumped = s.model_dump_json()
        assert "alice" not in dumped
        assert "bob" not in dumped
        assert "@example.com" not in dumped


# ============================================================
# Parsing puro
# ============================================================

class TestParsing:
    def test_parse_numstat_somma_per_commit(self):
        sha_a = "a" * 40
        sha_b = "b" * 40
        out = f"{sha_a}\n10\t2\tfile.py\n5\t0\tother.py\n\n{sha_b}\n-\t-\tbinary.png\n3\t1\tx.py\n"
        parsed = GitHistoryCollector._parse_numstat(out)
        assert parsed[sha_a] == 15
        assert parsed[sha_b] == 3

    def test_parse_log_record_malformato_ignorato(self):
        out = "garbage\x1e" + "\x1f".join(["c" * 40, "a@b.c", "2026-01-01T00:00:00+00:00", "", "subject", "body"]) + "\x1e"
        commits = GitHistoryCollector._parse_log(out)
        assert len(commits) == 1
        assert commits[0]["subject"] == "subject"
        assert commits[0]["is_merge"] is False

    def test_summary_model_default(self):
        s = GitSummary(available=False, reason="x")
        assert s.total_commits == 0
        assert s.commits_by_month == {}
