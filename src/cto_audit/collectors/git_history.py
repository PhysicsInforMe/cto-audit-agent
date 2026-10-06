"""
Git History Collector — Legge lo storico git e produce un GitSummary aggregato.

Serve ai layer di due diligence (TEAM, PROVENANCE): bus factor, attivita
recente, storico compresso, commit co-firmati da assistenti AI, tag di release.

Principi:
- Solo metadati git (log, tag). Nessuna esecuzione del codice del target.
- Nessun dato personale nel risultato: email e nomi autori restano in memoria
  solo per il tempo del calcolo e NON finiscono nel GitSummary.
- Degradazione graziosa: se git non c'e, la directory non e un repo, o il
  comando fallisce, restituisce GitSummary(available=False, reason=...).
- Clone shallow (--depth 1): lo storico e troncato, il collector lo segnala
  con is_shallow=True e il TeamAnalyzer abbassa la confidence.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cto_audit.core.models import GitSummary


# Limiti di sicurezza per repo molto grandi
MAX_COMMITS = 20000
GIT_TIMEOUT_SECONDS = 120

# Separatori per il parsing del log (caratteri di controllo ASCII)
_FIELD_SEP = "\x1f"
_RECORD_SEP = "\x1e"

# Trailer che indicano un assistente AI come co-autore del commit
AI_COAUTHOR_RE = re.compile(
    r"co-authored-by:.*\b(claude|anthropic|copilot|chatgpt|openai|codex|gemini|"
    r"cursor|devin|aider|windsurf|cline|tabnine|amazon q|codewhisperer)\b",
    re.IGNORECASE,
)
# Riga di attribuzione tipica di Claude Code / Copilot nel corpo del commit
AI_GENERATED_LINE_RE = re.compile(
    r"generated with \[?(claude code|github copilot|cursor|codex)",
    re.IGNORECASE,
)

# Messaggi di commit generici (bassa qualita della storia)
TRIVIAL_SUBJECT_RE = re.compile(
    r"^(fix|fixes|fixed|wip|update|updates|updated|changes|change|test|tests|tmp|temp|"
    r"minor|stuff|more|edit|edits|typo|cleanup|clean up|misc|asd|aaa|refactor|commit|"
    r"save|saving|work|working|final|final2|done|ok|\.+|-+)[.!]*$",
    re.IGNORECASE,
)
TRIVIAL_MIN_LENGTH = 8


class GitHistoryCollector:
    """
    Raccoglie metriche aggregate dallo storico git di una directory.

    Attributes:
        root: Directory root del repository (o una sua sottodirectory)
        now: Istante di riferimento per le finestre temporali (iniettabile nei test)
    """

    def __init__(self, root: Path | str, now: datetime | None = None) -> None:
        self.root = Path(root)
        self.now = now or datetime.now(timezone.utc)

    # --- API pubblica ---

    def collect(self) -> GitSummary:
        """Legge lo storico e restituisce un GitSummary (mai solleva eccezioni)."""
        if not shutil.which("git"):
            return GitSummary(available=False, reason="git non trovato nel PATH")

        if not self.root.is_dir():
            return GitSummary(available=False, reason="directory non trovata")

        inside = self._run(["rev-parse", "--is-inside-work-tree"])
        if inside is None or inside.strip() != "true":
            return GitSummary(available=False, reason="la directory non e un repository git")

        shallow_out = self._run(["rev-parse", "--is-shallow-repository"])
        is_shallow = (shallow_out or "").strip() == "true"

        log_out = self._run([
            "log", "--all", f"-n{MAX_COMMITS}", "--date=iso-strict",
            f"--format=%H{_FIELD_SEP}%ae{_FIELD_SEP}%ad{_FIELD_SEP}%P{_FIELD_SEP}%s{_FIELD_SEP}%b{_RECORD_SEP}",
        ])
        if log_out is None:
            return GitSummary(available=False, reason="git log non eseguibile", is_shallow=is_shallow)

        commits = self._parse_log(log_out)
        if not commits:
            return GitSummary(available=False, reason="nessun commit nello storico", is_shallow=is_shallow)

        numstat_out = self._run([
            "log", "--all", f"-n{MAX_COMMITS}", "--no-merges", "--numstat", "--format=%H",
        ])
        insertions_by_commit = self._parse_numstat(numstat_out or "")

        tags_out = self._run(["tag", "--list"])
        tags_total = len([t for t in (tags_out or "").splitlines() if t.strip()])

        return self._summarize(commits, insertions_by_commit, tags_total, is_shallow)

    # --- Esecuzione git ---

    def _run(self, args: list[str]) -> str | None:
        """Esegue un comando git nella root. Restituisce stdout o None se fallisce."""
        try:
            result = subprocess.run(
                ["git", "-C", str(self.root), *args],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=GIT_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0:
            return None
        return result.stdout

    # --- Parsing ---

    @staticmethod
    def _parse_log(output: str) -> list[dict]:
        """Converte l'output del log in una lista di dict per commit."""
        commits: list[dict] = []
        for record in output.split(_RECORD_SEP):
            record = record.strip("\r\n")
            if not record.strip():
                continue
            parts = record.split(_FIELD_SEP)
            if len(parts) < 5:
                continue
            sha, email, date_str, parents, subject = parts[:5]
            body = parts[5] if len(parts) > 5 else ""
            try:
                date = datetime.fromisoformat(date_str.strip())
            except ValueError:
                continue
            if date.tzinfo is None:
                date = date.replace(tzinfo=timezone.utc)
            commits.append({
                "sha": sha.strip(),
                "email": email.strip().lower(),
                "date": date,
                "is_merge": len(parents.split()) > 1,
                "subject": subject.strip(),
                "body": body,
            })
        return commits

    @staticmethod
    def _parse_numstat(output: str) -> dict[str, int]:
        """Somma le righe inserite per commit dall'output --numstat."""
        insertions: dict[str, int] = defaultdict(int)
        current: str | None = None
        sha_re = re.compile(r"^[0-9a-f]{40}$")
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            if sha_re.match(line):
                current = line
                continue
            if current is None:
                continue
            cols = line.split("\t")
            if len(cols) >= 2 and cols[0].isdigit():
                insertions[current] += int(cols[0])
        return dict(insertions)

    # --- Aggregazione ---

    def _summarize(
        self,
        commits: list[dict],
        insertions_by_commit: dict[str, int],
        tags_total: int,
        is_shallow: bool,
    ) -> GitSummary:
        now = self.now
        d90 = now - timedelta(days=90)
        d180 = now - timedelta(days=180)
        d365 = now - timedelta(days=365)

        non_merge = [c for c in commits if not c["is_merge"]]
        merge_count = len(commits) - len(non_merge)

        dates = [c["date"] for c in commits]
        first_commit = min(dates)
        last_commit = max(dates)

        by_author: Counter[str] = Counter(c["email"] for c in non_merge)
        by_author_365: Counter[str] = Counter(c["email"] for c in non_merge if c["date"] >= d365)

        def _top_share(counter: Counter[str]) -> float:
            total = sum(counter.values())
            if total == 0:
                return 0.0
            return round(counter.most_common(1)[0][1] / total, 4)

        ai_count = sum(
            1 for c in commits
            if AI_COAUTHOR_RE.search(c["body"]) or AI_GENERATED_LINE_RE.search(c["body"])
        )
        trivial_count = sum(
            1 for c in non_merge
            if len(c["subject"]) < TRIVIAL_MIN_LENGTH or TRIVIAL_SUBJECT_RE.match(c["subject"])
        )

        insertions_total = sum(insertions_by_commit.values())
        top3 = sorted(insertions_by_commit.values(), reverse=True)[:3]
        top3_share = round(sum(top3) / insertions_total, 4) if insertions_total > 0 else 0.0

        by_month: Counter[str] = Counter(
            c["date"].strftime("%Y-%m") for c in commits if c["date"] >= d365
        )

        return GitSummary(
            available=True,
            is_shallow=is_shallow,
            total_commits=len(commits),
            merge_commits=merge_count,
            first_commit=first_commit,
            last_commit=last_commit,
            authors_total=len(by_author),
            authors_365d=len(by_author_365),
            commits_90d=sum(1 for c in commits if c["date"] >= d90),
            commits_180d=sum(1 for c in commits if c["date"] >= d180),
            commits_365d=sum(1 for c in commits if c["date"] >= d365),
            top_author_share=_top_share(by_author),
            top_author_share_365d=_top_share(by_author_365),
            tags_total=tags_total,
            ai_coauthored_commits=ai_count,
            trivial_message_commits=trivial_count,
            insertions_total=insertions_total,
            top3_commits_insertions_share=min(1.0, top3_share),
            commits_by_month=dict(sorted(by_month.items())),
        )
