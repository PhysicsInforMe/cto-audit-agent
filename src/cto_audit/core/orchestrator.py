"""
AuditOrchestrator — Coordinamento del flusso completo di audit.

Collega tutti i componenti della pipeline:
  Source → Scanner → Stack → Privacy → HITL → Analyzers → Scoring → Report

Gestisce:
- Classificazione privacy nel passare file agli analyzer
- Focus su un singolo layer (--focus)
- Produzione di AuditResult completo con HealthScore tracciabile
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from cto_audit.analyzers.architecture import ArchitectureAnalyzer
from cto_audit.analyzers.infra import InfraAnalyzer
from cto_audit.analyzers.provenance import ProvenanceAnalyzer
from cto_audit.analyzers.quality import QualityAnalyzer
from cto_audit.analyzers.security import SecurityAnalyzer
from cto_audit.analyzers.team import TeamAnalyzer
from cto_audit.collectors.git_history import GitHistoryCollector
from cto_audit.collectors.privacy import PrivacyClassifier
from cto_audit.collectors.project_type import ProjectTypeDetector
from cto_audit.collectors.nlp_classifier import enhance_with_nlp
from cto_audit.collectors.scanner import FileScanner
from cto_audit.collectors.stack import StackDetector
from cto_audit.core.models import (
    AuditDelta,
    AuditMetadata,
    AuditResult,
    FileClassification,
    Finding,
    GitSummary,
    HealthScore,
    Layer,
    TriageDecision,
    ProjectTypeResult,
    StackInfo,
)
from cto_audit.compliance.engine import ComplianceEngine
from cto_audit.compliance.profile import load_compliance_profile
from cto_audit.core.source import AuditSource
from cto_audit.hitl.persistence import ClassificationPersistence
from cto_audit.hitl.reviewer import HITLReviewer, ReviewResult
from cto_audit.scoring.engine import ScoringEngine
from cto_audit.scoring.profile import load_profile

from rich.console import Console
from rich.panel import Panel


class AuditOrchestrator:
    """
    Coordinatore principale del flusso di audit.

    Riceve una sorgente dati e le opzioni di configurazione,
    esegue tutte le fasi della pipeline, e produce un AuditResult.
    """

    def __init__(
        self,
        source: AuditSource,
        target_path: Path,
        scoring_profile: str = "default",
        focus: Optional[Layer] = None,
        offline: bool = False,
        auto_approve: bool = False,
        reuse_classification: bool = False,
        console: Optional[Console] = None,
        board_report: bool = False,
        no_llm: bool = False,
        compliance_profiles: Optional[list[str]] = None,
        previous_result: Optional[AuditResult] = None,
        llm_router: Optional[object] = None,
        triage: bool = False,
        triage_input_fn: Optional[object] = None,
        labels_path: Optional[Path] = None,
    ) -> None:
        self.source = source
        self.target_path = target_path
        self.scoring_profile = scoring_profile
        self.focus = focus
        self.offline = offline
        self.auto_approve = auto_approve
        self.reuse_classification = reuse_classification
        self.console = console or Console()
        self.board_report = board_report
        self.no_llm = no_llm
        self.compliance_profiles = compliance_profiles or []
        self.previous_result = previous_result
        self._llm_router = llm_router
        self.triage = triage
        self._triage_input_fn = triage_input_fn
        self._labels_path = labels_path
        self.triage_files: tuple[Path | None, Path | None] = (None, None)
        self._network_consented: bool | None = None
        self._git_summary: GitSummary | None = None
        self._dependency_licenses: list[dict] = []
        self._profile = None

    def run(self) -> AuditResult:
        """
        Esegue l'intero flusso di audit.

        Returns:
            AuditResult completo con HealthScore, stack, classificazioni e metadati
        """
        # --- Fase 1: Scan file ---
        scanner = FileScanner(self.source)
        files = scanner.scan()

        if not files:
            # Nessun file: restituisce risultato vuoto con score 100
            return self._empty_result()

        # --- Fase 2: Stack detection ---
        detector = StackDetector(self.source)
        stack_info = detector.detect(files)

        # --- Fase 2b: Project type detection ---
        project_type_result = self._detect_project_type(stack_info)

        # --- Fase 3: Classificazione privacy ---
        classifier = PrivacyClassifier(self.source)
        classifications = classifier.classify(files)

        # Gestione reuse/auto-approve
        persistence = ClassificationPersistence(self.target_path)

        if self.reuse_classification and persistence.exists():
            classifications = persistence.load()
        elif self.auto_approve:
            persistence.save(classifications)
        else:
            reviewer = HITLReviewer(console=self.console)
            result, classifications, overrides = reviewer.review(
                classifications, stack_info=stack_info
            )
            if result == ReviewResult.CANCELLED:
                return self._empty_result(stack_info=stack_info, classifications=classifications)
            persistence.save(classifications, overrides=overrides)

        # --- Fase 4: Analisi per layer (solo i layer pesati dal profilo) ---
        profile = load_profile(self.scoring_profile)
        self._profile = profile
        all_findings = self._run_analyzers(stack_info, classifications)

        # --- Fase 5: Scoring ---
        engine = ScoringEngine(
            profile,
            project_type=project_type_result.detected_type,
        )
        health_score = engine.calculate(all_findings)

        # --- Fase 5b: Compliance (se richiesto) ---
        if self.compliance_profiles:
            compliance_engine = ComplianceEngine()
            compliance_results = []
            for profile_name in self.compliance_profiles:
                try:
                    cp = load_compliance_profile(profile_name)
                    cr = compliance_engine.evaluate(cp, all_findings)
                    compliance_results.append(cr)
                except FileNotFoundError:
                    pass  # Profilo non trovato, skip silenzioso
            if compliance_results:
                health_score.compliance_results = compliance_results

        # --- Costruisci risultato parziale ---
        metadata = AuditMetadata(
            timestamp=datetime.now(),
            target_path=str(self.target_path),
            scoring_profile=self.scoring_profile,
            compliance_profiles=self.compliance_profiles,
            offline_mode=self.offline,
            network_consented=self._network_consented,
            project_type=project_type_result.detected_type.value,
            project_type_confidence=project_type_result.confidence,
            active_layers=[layer.value for layer in self._active_layers()],
        )

        result = AuditResult(
            health_score=health_score,
            stack_info=stack_info,
            classifications=classifications,
            metadata=metadata,
            git_summary=self._git_summary,
            dependency_licenses=self._dependency_licenses,
        )

        # --- Fase 6: Remediation Pipeline (se board_report attivo) ---
        if self.board_report:
            result.remediation = self._run_remediation_pipeline(
                result, engine, stack_info
            )

        # --- Fase 7: Triage HITL dei finding (etichette; lo score non cambia) ---
        if self.triage and not self.auto_approve:
            result.triage = self._run_triage(result)

        return result

    def _run_triage(self, result: AuditResult) -> list[TriageDecision]:
        """Revisione interattiva dei finding e salvataggio delle decisioni."""
        from cto_audit.hitl.triage import FindingTriage, TriageStore

        decisions = FindingTriage(console=self.console, input_fn=self._triage_input_fn).review(result)
        if decisions:
            store = TriageStore(self.target_path, labels_path=self._labels_path)
            self.triage_files = store.save(result, decisions)
            local, shared = self.triage_files
            if local:
                self.console.print(f"  Decisioni salvate in: {local}")
            if shared:
                self.console.print(f"  Etichette anonimizzate aggiunte a: {shared}")
        return decisions

    def _run_remediation_pipeline(
        self,
        result: AuditResult,
        engine: ScoringEngine,
        stack_info: StackInfo,
        delta: "AuditDelta | None" = None,
    ) -> RemediationPipelineResult:
        """Esegue la pipeline di remediation: KB + Context + What-If + LLM."""
        from cto_audit.remediation.loader import RemediationLoader
        from cto_audit.remediation.context import ContextCollector
        from cto_audit.remediation.simulator import WhatIfSimulator
        from cto_audit.remediation.models import RemediationPipelineResult

        # 1. Carica KB
        kb = RemediationLoader.load_all()

        # 2. Raccogli contesto
        context = ContextCollector().collect(result)

        # 3. Costruisci effort map dalla KB
        effort_map = {
            rule_id: entry.effort_range
            for rule_id, entry in kb.all_entries().items()
        }

        # 4. Simula what-if
        whatif = WhatIfSimulator(engine).simulate_all(
            result.health_score, effort_map
        )

        # 5. LLM interpretation: solo con un revisore umano che approva l'output.
        #    Regola: nessun testo generato da LLM entra in un report senza
        #    approvazione esplicita. Senza revisore (--auto-approve, agent mode)
        #    o con --no-llm si usa il template deterministico.
        executive_summary: str | None = None
        risk_narrative: str | None = None
        llm_used = False
        llm_hitl_approved: bool | None = None
        llm_skipped_reason: str | None = None

        from cto_audit.llm.agent import InterpretationAgent
        from cto_audit.llm.router import LLMRouter

        if self.no_llm or self.auto_approve:
            if self.no_llm:
                llm_skipped_reason = "LLM disabilitato (--no-llm): narrativa da template deterministico"
            else:
                llm_skipped_reason = (
                    "nessun revisore umano disponibile (--auto-approve): l'output LLM richiede "
                    "approvazione, quindi si usa il template deterministico"
                )
            # Router senza provider: l'agente produce la narrativa da template
            fallback_agent = InterpretationAgent(LLMRouter(providers=[]), kb)
            interpretation = fallback_agent.interpret(result, whatif, context, delta=delta)
            executive_summary = interpretation.executive_summary
            risk_narrative = interpretation.risk_narrative
        else:
            try:
                router = self._llm_router if self._llm_router is not None else LLMRouter()
                agent = InterpretationAgent(
                    router, kb,
                    hitl_enabled=True,
                    hitl_input_fn=self._llm_approval_input,
                )
                interpretation = agent.interpret(result, whatif, context, delta=delta)

                executive_summary = interpretation.executive_summary
                risk_narrative = interpretation.risk_narrative
                llm_used = interpretation.llm_used
                llm_hitl_approved = interpretation.hitl_approved
                if interpretation.hitl_approved is False:
                    llm_skipped_reason = "output LLM rifiutato dal revisore: narrativa da template deterministico"
            except Exception:
                # Graceful degradation: se LLM fallisce, continua senza
                llm_skipped_reason = "errore LLM: narrativa da template deterministico"

        return RemediationPipelineResult(
            context=context,
            whatif_results=whatif,
            executive_summary=executive_summary,
            risk_narrative=risk_narrative,
            llm_used=llm_used,
            llm_hitl_approved=llm_hitl_approved,
            llm_skipped_reason=llm_skipped_reason,
        )

    def _llm_approval_input(self, review_text: str) -> str:
        """
        Gate HITL sull'output LLM: mostra il testo generato e chiede approvazione.

        Restituisce la risposta dell'utente; EOF o interruzione valgono come rifiuto.
        """
        self.console.print()
        self.console.print(Panel(
            review_text.replace("\nApprovare output LLM? [s/n]: ", "").strip(),
            title="REVISIONE OUTPUT LLM",
            subtitle="Il testo entra nel report solo se approvato",
            border_style="magenta",
        ))
        try:
            return self.console.input("\n  Approvare l'output LLM e inserirlo nel report? [s/n]: ")
        except (EOFError, KeyboardInterrupt):
            return "n"

    def _detect_project_type(self, stack_info: StackInfo) -> ProjectTypeResult:
        """Rileva automaticamente il tipo di progetto."""
        file_tree = self.source.get_file_tree()

        # Livello 1: Rule-based
        detector = ProjectTypeDetector()
        result = detector.detect(stack_info, file_tree, self.source)

        # Livello 2/3: NLP enhancement (se confidence bassa e README disponibile)
        readme_content = None
        readme_names = ["README.md", "README.rst", "README.txt", "README"]
        for entry in file_tree.entries:
            if not entry.is_dir and entry.path.rsplit("/", 1)[-1] in readme_names:
                try:
                    readme_content = self.source.read_file(entry.path)
                except (ValueError, FileNotFoundError, UnicodeDecodeError):
                    pass
                break

        result = enhance_with_nlp(result, readme_content)
        return result

    def _request_network_consent(self) -> bool:
        """
        Chiede all'utente il consenso per l'accesso alla rete (CVE check).

        Mostra un pannello Rich con spiegazione trasparente di cosa viene
        inviato, a chi, e cosa non viene inviato. L'utente puo rifiutare
        e lo scan continua senza CVE check.

        Returns:
            True se l'utente acconsente, False altrimenti
        """
        if self.auto_approve:
            return True

        self.console.print()
        self.console.print(Panel(
            "  Il check CVE e licenze invia i seguenti dati alla rete:\n\n"
            "  [bold]Cosa viene inviato:[/bold]\n"
            "    - Nome e versione dei pacchetti rilevati (es. 'requests 2.31.0')\n\n"
            "  [bold]A chi:[/bold]\n"
            "    - Google OSV (https://osv.dev) — database vulnerabilita open source\n"
            "    - FIRST EPSS (https://api.first.org) — probabilita di sfruttamento delle CVE trovate (solo ID CVE)\n"
            + (
                "    - Registri PyPI (pypi.org) e npm (registry.npmjs.org) — licenze dipendenze\n"
                if Layer.PROVENANCE in self._active_layers() else ""
            )
            + "\n"
            "  [bold]Cosa NON viene inviato:[/bold]\n"
            "    - Codice sorgente\n"
            "    - Percorsi file\n"
            "    - Nomi progetto\n"
            "    - Nessun dato personale\n\n"
            "  Puoi rifiutare: lo scan continuera senza il check CVE.",
            title="ACCESSO ALLA RETE",
            border_style="yellow",
        ))

        try:
            response = self.console.input(
                "\n  Acconsenti all'accesso alla rete per il check CVE e licenze? [s/n]: "
            )
            return response.strip().lower() in ("s", "si", "y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False

    def _run_analyzers(
        self,
        stack_info: StackInfo,
        classifications: list[FileClassification],
    ) -> list[Finding]:
        """Esegue gli analyzer per i layer richiesti."""
        all_findings: list[Finding] = []

        # Determina se la rete e' disponibile per CVE check
        if self.offline:
            security_offline = True
            self._network_consented = None
        else:
            consented = self._request_network_consent()
            security_offline = not consented
            self._network_consented = consented

        active = self._active_layers()

        # Storico git: letto una volta sola, solo se serve ai layer di due diligence
        if Layer.TEAM in active or Layer.PROVENANCE in active:
            self._git_summary = GitHistoryCollector(self._resolve_root()).collect()

        provenance = ProvenanceAnalyzer(offline=security_offline)

        # Mappa layer → analyzer disponibili
        analyzers: dict[Layer, object] = {
            Layer.INFRA: InfraAnalyzer(),
            Layer.ARCHITECTURE: ArchitectureAnalyzer(),
            Layer.SECURITY: SecurityAnalyzer(offline=security_offline),
            Layer.QUALITY: QualityAnalyzer(),
            Layer.PROVENANCE: provenance,
            Layer.TEAM: TeamAnalyzer(self._git_summary),
        }

        for layer, analyzer in analyzers.items():
            if layer not in active:
                continue

            findings = analyzer.analyze(self.source, stack_info, classifications)
            all_findings.extend(findings)

        if Layer.PROVENANCE in active:
            self._dependency_licenses = [dl.to_dict() for dl in provenance.dependency_licenses]

        return all_findings

    def _active_layers(self) -> list[Layer]:
        """
        Layer da analizzare: quelli pesati dal profilo di scoring, oppure solo
        il layer indicato da --focus. Senza profilo caricato (fallback) i 4 layer storici.
        """
        if self.focus is not None:
            return [self.focus]
        if self._profile is None:
            return [Layer.INFRA, Layer.ARCHITECTURE, Layer.SECURITY, Layer.QUALITY]
        return [layer for layer in Layer if layer.value in self._profile.layer_weights]

    def _resolve_root(self) -> Path:
        """Directory locale su cui eseguire git (sorgente locale o clone temporaneo)."""
        root = getattr(self.source, "root", None)
        if root is None:
            inner = getattr(self.source, "_local_source", None)
            root = getattr(inner, "root", None)
        return Path(root) if root is not None else self.target_path

    def _empty_result(
        self,
        stack_info: Optional[StackInfo] = None,
        classifications: Optional[list[FileClassification]] = None,
    ) -> AuditResult:
        """Costruisce un AuditResult vuoto (nessun file o audit annullato)."""
        profile = load_profile(self.scoring_profile)
        engine = ScoringEngine(profile)
        health_score = engine.calculate([])

        return AuditResult(
            health_score=health_score,
            stack_info=stack_info or StackInfo(),
            classifications=classifications or [],
            metadata=AuditMetadata(
                timestamp=datetime.now(),
                target_path=str(self.target_path),
                scoring_profile=self.scoring_profile,
                offline_mode=self.offline,
            ),
        )
