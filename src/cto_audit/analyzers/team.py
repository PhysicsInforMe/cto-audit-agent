"""
Team Analyzer — Layer 6: Team & Continuita di sviluppo.

Risponde alla domanda che un investitore o un acquirente pone per prima:
"c'e un team dietro questo codice, e il codice e vivo?". Lavora solo sui
metadati git aggregati (GitSummary), senza nomi ne email.

Regole:
- TEAM-GIT-INFO:        storico git non disponibile o shallow (informativo)
- TEAM-BUSFACTOR-001:   bus factor 1 (autore unico o >=80% dei commit di un solo autore)
- TEAM-ACTIVITY-001:    nessun commit da oltre 180 giorni
- TEAM-ACTIVITY-002:    nessun commit da 90 a 180 giorni
- TEAM-HISTORY-001:     storico compresso: >=60% delle righe inserite in 3 commit
- TEAM-HISTORY-002:     storico minimo (<5 commit): la storia non e valutabile
- TEAM-RELEASE-001:     nessun tag di release con >=100 commit
- TEAM-MSGQUAL-001:     >=40% di commit con messaggio generico
- TEAM-AIGEN-INFO:      quota di commit co-firmati da assistenti AI (informativo)

Riferimento: Avelino, Passos, Hora, Valente, "A Novel Approach for Estimating
Truck Factors", ICPC 2016 (arXiv:1604.06766): il truck factor e "the minimal
number of developers that have to be hit by a truck (or quit) before a
project is incapacitated".
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from cto_audit.core.models import (
    FileClassification,
    Finding,
    GitSummary,
    Layer,
    Severity,
    StackInfo,
)
from cto_audit.core.source import AuditSource


BUS_FACTOR_SHARE_THRESHOLD = 0.80
BUS_FACTOR_MIN_COMMITS = 20
SOLO_AUTHOR_MIN_COMMITS = 10
STALE_DAYS_HIGH = 180
STALE_DAYS_MEDIUM = 90
COMPRESSED_HISTORY_SHARE = 0.60
MIN_COMMITS_FOR_HISTORY = 5
RELEASE_MIN_COMMITS = 100
TRIVIAL_SHARE_THRESHOLD = 0.40
TRIVIAL_MIN_COMMITS = 20


def _make_id() -> str:
    return str(uuid.uuid4())[:8]


class TeamAnalyzer:
    """
    Analyzer per il layer Team & Continuita.

    Riceve il GitSummary gia calcolato dal GitHistoryCollector (iniettato
    dall'orchestrator) e lo traduce in finding. Non tocca il filesystem.
    """

    def __init__(self, git_summary: GitSummary | None, now: datetime | None = None) -> None:
        self.git = git_summary
        self.now = now or datetime.now(timezone.utc)

    def analyze(
        self,
        source: AuditSource,
        stack_info: StackInfo,
        classifications: list[FileClassification],
    ) -> list[Finding]:
        git = self.git
        if git is None or not git.available:
            reason = git.reason if git is not None else "collector non eseguito"
            return [self._info(
                "TEAM-GIT-INFO",
                "Storico git non disponibile",
                f"Il layer Team non puo essere valutato: {reason}. "
                "Per la due diligence richiedere accesso al repository con storico completo "
                "(non un archivio ZIP ne un clone shallow).",
                confidence=0.2,
            )]

        findings: list[Finding] = []

        if git.is_shallow:
            # Con uno storico troncato solo la data dell'ultimo commit e affidabile:
            # bus factor, storico compresso, tag e messaggi sarebbero artefatti del clone.
            findings.append(self._info(
                "TEAM-GIT-INFO",
                "Storico git troncato (clone shallow)",
                f"Il clone contiene solo {git.total_commits} commit: bus factor, storico, tag e "
                "qualita dei messaggi non sono valutabili. Viene verificata solo l'attivita "
                "recente. Per una valutazione completa rieseguire con un clone completo "
                "(in modalita due diligence le sorgenti remote vengono clonate per intero).",
                confidence=0.4,
            ))
            findings.extend(self._check_activity(git))
            ai = self._ai_info(git)
            if ai is not None:
                findings.append(ai)
            return findings

        if git.total_commits < MIN_COMMITS_FOR_HISTORY:
            findings.append(Finding(
                id=_make_id(), layer=Layer.TEAM, severity=Severity.LOW,
                rule_id="TEAM-HISTORY-002",
                title=f"Storico minimo ({git.total_commits} commit)",
                description=(
                    f"Il repository contiene solo {git.total_commits} commit. Con una storia "
                    "cosi breve non e possibile valutare continuita, cadenza o distribuzione "
                    "del lavoro: il codice potrebbe essere stato importato da altrove. "
                    "Chiedere al management dove e stato sviluppato prima e con quale storico."
                ),
                confidence=0.9,
            ))
            ai = self._ai_info(git)
            if ai is not None:
                findings.append(ai)
            return findings

        findings.extend(self._check_bus_factor(git))
        findings.extend(self._check_activity(git))
        findings.extend(self._check_compressed_history(git))
        findings.extend(self._check_releases(git))
        findings.extend(self._check_message_quality(git))
        ai = self._ai_info(git)
        if ai is not None:
            findings.append(ai)
        return findings

    # --- Check ---

    def _check_bus_factor(self, git: GitSummary) -> list[Finding]:
        # Finestra: ultimi 365 giorni se abbastanza popolata, altrimenti tutto lo storico
        if git.commits_365d >= BUS_FACTOR_MIN_COMMITS:
            share = git.top_author_share_365d
            authors = git.authors_365d
            window = "negli ultimi 12 mesi"
            commits = git.commits_365d
        else:
            share = git.top_author_share
            authors = git.authors_total
            window = "sull'intero storico"
            commits = git.total_commits

        if authors == 1 and commits >= SOLO_AUTHOR_MIN_COMMITS:
            return [Finding(
                id=_make_id(), layer=Layer.TEAM, severity=Severity.HIGH,
                rule_id="TEAM-BUSFACTOR-001",
                title=f"Bus factor 1: un solo autore {window}",
                description=(
                    f"Tutti i {commits} commit {window} provengono da un unico autore. "
                    "La conoscenza del sistema risiede in una sola persona: la sua uscita "
                    "incapacita il progetto (truck factor 1, Avelino et al. 2016). In una "
                    "due diligence questo e un rischio di continuita e di valutazione: "
                    "verificare contratti, clausole di permanenza e documentazione di handover."
                ),
                confidence=0.95,
            )]

        if authors >= 2 and commits >= BUS_FACTOR_MIN_COMMITS and share >= BUS_FACTOR_SHARE_THRESHOLD:
            return [Finding(
                id=_make_id(), layer=Layer.TEAM, severity=Severity.HIGH,
                rule_id="TEAM-BUSFACTOR-001",
                title=f"Bus factor 1: il primo autore firma il {share:.0%} dei commit {window}",
                description=(
                    f"Su {authors} autori attivi {window}, uno solo produce il {share:.0%} dei "
                    f"{commits} commit. Gli altri contribuiscono in modo marginale, quindi la "
                    "conoscenza effettiva e concentrata (truck factor 1, Avelino et al. 2016). "
                    "Verificare chi conosce le parti critiche del sistema e come e distribuito "
                    "l'onboarding."
                ),
                confidence=0.85,
            )]
        return []

    def _check_activity(self, git: GitSummary) -> list[Finding]:
        if git.last_commit is None:
            return []
        last = git.last_commit
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        days = (self.now - last).days

        if days > STALE_DAYS_HIGH:
            return [Finding(
                id=_make_id(), layer=Layer.TEAM, severity=Severity.HIGH,
                rule_id="TEAM-ACTIVITY-001",
                title=f"Repository inattivo da {days} giorni",
                description=(
                    f"L'ultimo commit risale a {last.date().isoformat()}. Oltre sei mesi senza "
                    "modifiche significano dipendenze non aggiornate, CVE non corrette e, in "
                    "una due diligence, il dubbio che il prodotto non sia piu sviluppato. "
                    "Chiedere se lo sviluppo e proseguito in un altro repository."
                ),
                confidence=0.95,
            )]
        if days > STALE_DAYS_MEDIUM:
            return [Finding(
                id=_make_id(), layer=Layer.TEAM, severity=Severity.MEDIUM,
                rule_id="TEAM-ACTIVITY-002",
                title=f"Nessun commit da {days} giorni",
                description=(
                    f"L'ultimo commit risale a {last.date().isoformat()}; negli ultimi 90 giorni "
                    f"non ci sono state modifiche (ultimi 180 giorni: {git.commits_180d} commit). "
                    "Verificare se si tratta di una pausa pianificata o di un rallentamento."
                ),
                confidence=0.9,
            )]
        return []

    def _check_compressed_history(self, git: GitSummary) -> list[Finding]:
        if git.insertions_total <= 0:
            return []
        if git.top3_commits_insertions_share >= COMPRESSED_HISTORY_SHARE:
            return [Finding(
                id=_make_id(), layer=Layer.TEAM, severity=Severity.MEDIUM,
                rule_id="TEAM-HISTORY-001",
                title=(
                    f"Storico compresso: il {git.top3_commits_insertions_share:.0%} delle righe "
                    "arriva da 3 commit"
                ),
                description=(
                    f"Tre commit su {git.total_commits} introducono il "
                    f"{git.top3_commits_insertions_share:.0%} di tutte le righe mai inserite "
                    f"({git.insertions_total:,} righe totali). Il codice e arrivato in blocco: "
                    "import da un altro repository, storico riscritto, o generazione massiva. "
                    "Per la provenienza dell'IP chiedere dove e da chi e stato sviluppato "
                    "quel blocco iniziale."
                ),
                confidence=0.8,
            )]
        return []

    def _check_releases(self, git: GitSummary) -> list[Finding]:
        if git.total_commits >= RELEASE_MIN_COMMITS and git.tags_total == 0:
            return [Finding(
                id=_make_id(), layer=Layer.TEAM, severity=Severity.LOW,
                rule_id="TEAM-RELEASE-001",
                title="Nessun tag di release",
                description=(
                    f"Con {git.total_commits} commit non esiste alcun tag git. Senza versioni "
                    "marcate non si sa cosa gira in produzione ne si puo ricostruire una "
                    "release: segnale di processo di rilascio informale."
                ),
                confidence=0.85,
            )]
        return []

    def _check_message_quality(self, git: GitSummary) -> list[Finding]:
        non_merge = git.total_commits - git.merge_commits
        if non_merge < TRIVIAL_MIN_COMMITS:
            return []
        share = git.trivial_message_commits / non_merge
        if share >= TRIVIAL_SHARE_THRESHOLD:
            return [Finding(
                id=_make_id(), layer=Layer.TEAM, severity=Severity.LOW,
                rule_id="TEAM-MSGQUAL-001",
                title=f"Messaggi di commit generici nel {share:.0%} dei casi",
                description=(
                    f"{git.trivial_message_commits} commit su {non_merge} hanno un messaggio "
                    "generico (fix, wip, update, o meno di 8 caratteri). La storia non "
                    "documenta le decisioni: ogni ricostruzione del perche di una modifica "
                    "richiede la persona che l'ha fatta."
                ),
                confidence=0.8,
            )]
        return []

    def _ai_info(self, git: GitSummary) -> Finding | None:
        if git.ai_coauthored_commits <= 0 or git.total_commits <= 0:
            return None
        share = git.ai_coauthored_commits / git.total_commits
        return self._info(
            "TEAM-AIGEN-INFO",
            f"Commit con co-autore AI dichiarato: {share:.0%}",
            (
                f"{git.ai_coauthored_commits} commit su {git.total_commits} portano un trailer "
                "Co-Authored-By (o una riga 'Generated with') che attribuisce il lavoro a un "
                "assistente AI. Non e un difetto: e un dato di contesto per la due diligence. "
                "Chiedere quale revisione umana e prevista sul codice generato e come viene "
                "gestita la paternita dell'IP."
            ),
            confidence=1.0,
        )

    @staticmethod
    def _info(rule_id: str, title: str, description: str, confidence: float = 1.0) -> Finding:
        return Finding(
            id=_make_id(), layer=Layer.TEAM, severity=Severity.INFO,
            rule_id=rule_id, title=title, description=description, confidence=confidence,
        )
