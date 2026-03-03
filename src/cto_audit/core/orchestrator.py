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
from cto_audit.analyzers.quality import QualityAnalyzer
from cto_audit.analyzers.security import SecurityAnalyzer
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
    HealthScore,
    Layer,
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
        self._network_consented: bool | None = None

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

        # --- Fase 4: Analisi per layer ---
        all_findings = self._run_analyzers(stack_info, classifications)

        # --- Fase 5: Scoring ---
        profile = load_profile(self.scoring_profile)
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
        )

        result = AuditResult(
            health_score=health_score,
            stack_info=stack_info,
            classifications=classifications,
            metadata=metadata,
        )

        # --- Fase 6: Remediation Pipeline (se board_report attivo) ---
        if self.board_report:
            result.remediation = self._run_remediation_pipeline(
                result, engine, stack_info
            )

        return result

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
        kb = RemediationLoader.from_yaml()

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

        # 5. LLM interpretation (se non disabilitato)
        executive_summary: str | None = None
        risk_narrative: str | None = None
        llm_used = False

        if not self.no_llm:
            try:
                from cto_audit.llm.agent import InterpretationAgent
                from cto_audit.llm.router import LLMRouter

                router = LLMRouter()
                agent = InterpretationAgent(router, kb)
                interpretation = agent.interpret(result, whatif, context, delta=delta)

                executive_summary = interpretation.executive_summary
                risk_narrative = interpretation.risk_narrative
                llm_used = interpretation.llm_used
            except Exception:
                # Graceful degradation: se LLM fallisce, continua senza
                pass

        return RemediationPipelineResult(
            context=context,
            whatif_results=whatif,
            executive_summary=executive_summary,
            risk_narrative=risk_narrative,
            llm_used=llm_used,
        )

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
            "  Il check CVE invia i seguenti dati alla rete:\n\n"
            "  [bold]Cosa viene inviato:[/bold]\n"
            "    - Nome e versione dei pacchetti rilevati (es. 'requests 2.31.0')\n\n"
            "  [bold]A chi:[/bold]\n"
            "    - Google OSV (https://osv.dev) — database vulnerabilita open source\n\n"
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
                "\n  Acconsenti all'accesso alla rete per il check CVE? [s/n]: "
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

        # Mappa layer → analyzer disponibili
        analyzers: dict[Layer, object] = {
            Layer.INFRA: InfraAnalyzer(),
            Layer.ARCHITECTURE: ArchitectureAnalyzer(),
            Layer.SECURITY: SecurityAnalyzer(offline=security_offline),
            Layer.QUALITY: QualityAnalyzer(),
        }

        for layer, analyzer in analyzers.items():
            # Skip se focus è attivo e non è questo layer
            if self.focus is not None and self.focus != layer:
                continue

            findings = analyzer.analyze(self.source, stack_info, classifications)
            all_findings.extend(findings)

        return all_findings

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
