"""
Entry point CLI per CTO Audit Agent.

Usa Typer per definire il comando `cto-audit scan` con tutte le opzioni.
Collega l'intera pipeline: Source → Orchestrator → Reporter.
"""

from __future__ import annotations

import os
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

from cto_audit.core.models import ComplianceMode, Layer
from cto_audit.core.orchestrator import AuditOrchestrator
from cto_audit.history.storage import AuditHistoryStorage
from cto_audit.reporters.markdown import MarkdownReporter
from cto_audit.reporters.terminal import TerminalReporter
from cto_audit.sources.local import LocalRepoSource

app = typer.Typer(
    name="cto-audit",
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    """Analizza un codebase come farebbe un CTO esperto."""


@app.command()
def scan(
    target: str = typer.Argument(
        ...,
        help="Percorso del codebase o URL del repository da analizzare",
    ),
    source_type: str = typer.Option(
        "auto",
        "--source-type",
        help="Tipo di sorgente: auto, local, github, gitlab, azure-devops, bitbucket, zip",
    ),
    token: Optional[str] = typer.Option(
        None,
        "--token",
        envvar="CTO_AUDIT_TOKEN",
        help="Token di autenticazione per repository private (o envvar CTO_AUDIT_TOKEN)",
    ),
    branch: Optional[str] = typer.Option(
        None,
        "--branch",
        help="Branch da clonare per sorgenti remote",
    ),
    tag: Optional[str] = typer.Option(
        None,
        "--tag",
        help="Tag da clonare per sorgenti remote (alias di --branch per git)",
    ),
    focus: Optional[str] = typer.Option(
        None,
        "--focus", "-f",
        help="Esegui solo un layer specifico: infra, architecture, security, quality, provenance, team",
    ),
    compliance: Optional[str] = typer.Option(
        None,
        "--compliance", "-c",
        help="Profili compliance da attivare, separati da virgola (es. nis2,gdpr)",
    ),
    compliance_mode: str = typer.Option(
        "hybrid",
        "--compliance-mode",
        help="Modalità compliance: cross-cutting, standalone, hybrid",
    ),
    scoring: str = typer.Option(
        "default",
        "--scoring", "-s",
        help="Profilo di scoring da usare: default, vc-diligence, due-diligence",
    ),
    due_diligence: bool = typer.Option(
        False,
        "--due-diligence", "--dd",
        help=(
            "Modalita due diligence: profilo 'due-diligence' (6 layer, inclusi Provenienza & IP e "
            "Team & Continuita), pipeline remediation per le stime di effort, e report dedicato "
            "per investitore/acquirente quando --output e un file .md"
        ),
    ),
    offline: bool = typer.Option(
        False,
        "--offline",
        help="Modalità offline: nessun dato esce dalla macchina",
    ),
    reuse_classification: bool = typer.Option(
        False,
        "--reuse-classification",
        help="Riusa la classificazione privacy da un run precedente",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output", "-o",
        help="Percorso file di output (es. report.md)",
    ),
    auto_approve: bool = typer.Option(
        False,
        "--auto-approve",
        help="Salta il gate HITL e approva automaticamente la classificazione",
    ),
    board_report: bool = typer.Option(
        False,
        "--board-report",
        help="Genera board report con remediation pipeline (KB + what-if + LLM)",
    ),
    no_llm: bool = typer.Option(
        False,
        "--no-llm",
        help="Disabilita LLM, usa solo template deterministici dalla KB",
    ),
    detailed: bool = typer.Option(
        False,
        "--detailed",
        help="Report super-dettagliato con tutti i finding INFO e catena evidenze completa",
    ),
    triage: Optional[bool] = typer.Option(
        None,
        "--triage/--no-triage",
        help=(
            "Revisione interattiva dei finding critical/high/medium (conferma, declassa, scarta): "
            "le decisioni diventano etichette salvate in .cto-audit/decisions.jsonl e, anonimizzate, "
            "nella directory etichette del consulente (env CTO_AUDIT_LABELS_DIR). "
            "Attivo di default in modalita due diligence; mai con --auto-approve"
        ),
    ),
) -> None:
    """
    Scansiona un codebase e produce un audit report.

    Esegue la pipeline completa: scansione file, rilevamento stack,
    classificazione privacy, analisi per layer, scoring e report.

    Supporta sorgenti locali e remote:
      cto-audit scan /path/to/repo
      cto-audit scan https://github.com/owner/repo --token ghp_...
      cto-audit scan archive.zip
    """
    # Console creata qui (non a livello di modulo) per compatibilità
    # con CliRunner che sostituisce sys.stdout a runtime
    console = Console()

    # --- Modalita due diligence: profilo a 6 layer + remediation pipeline ---
    if due_diligence:
        if scoring == "default":
            scoring = "due-diligence"
        board_report = True

    # --- Triage: default acceso in due diligence, spento altrove; mai senza revisore ---
    run_triage = due_diligence if triage is None else triage
    if auto_approve:
        run_triage = False

    # --- Tag → branch (alias) ---
    ref = branch or tag

    # --- Determina tipo sorgente ---
    from cto_audit.sources.factory import SourceFactory

    if source_type == "auto":
        resolved_type = SourceFactory.detect_type(target)
    else:
        resolved_type = source_type

    # --- Storico git completo se il layer Team e attivo (bus factor, attivita) ---
    needs_history = due_diligence or focus == "team"
    if not needs_history:
        try:
            from cto_audit.scoring.profile import load_profile
            needs_history = "team" in load_profile(scoring).layer_weights
        except (FileNotFoundError, ValueError):
            needs_history = False

    # --- Validazione percorso (solo per sorgenti locali) ---
    if resolved_type == "local":
        target_path = Path(target).resolve()
        if not target_path.exists():
            console.print(f"[red bold]Errore:[/red bold] Il percorso '{target}' non esiste.")
            raise typer.Exit(code=1)
        if not target_path.is_dir():
            console.print(f"[red bold]Errore:[/red bold] Il percorso '{target}' non è una directory.")
            raise typer.Exit(code=1)
    else:
        # Per sorgenti remote, il target_path sarà la temp dir
        target_path = Path(target).resolve() if resolved_type == "archive" else Path.cwd()

    # --- Validazione focus ---
    focus_layer: Optional[Layer] = None
    if focus:
        try:
            focus_layer = Layer(focus.lower())
        except ValueError:
            console.print(
                f"[red bold]Errore:[/red bold] Layer '{focus}' non valido. "
                f"Valori ammessi: infra, architecture, security, quality"
            )
            raise typer.Exit(code=1)

    # --- Validazione compliance mode ---
    try:
        ComplianceMode(compliance_mode)
    except ValueError:
        console.print(
            f"[red bold]Errore:[/red bold] Modalità compliance '{compliance_mode}' non valida. "
            f"Valori ammessi: cross-cutting, standalone, hybrid"
        )
        raise typer.Exit(code=1)

    # --- Pannello iniziale ---
    compliance_profiles: list[str] = []
    if compliance:
        compliance_profiles = [p.strip() for p in compliance.split(",") if p.strip()]

    display_target = target
    console.print(Panel(
        f"  Target: [bold]{display_target}[/bold]\n"
        f"  Sorgente: {resolved_type}"
        + ("  (clone completo per lo storico git)\n" if needs_history and resolved_type not in ("local", "archive", "zip") else "\n")
        + f"  Scoring: {scoring}\n"
        f"  Compliance: {', '.join(compliance_profiles) if compliance_profiles else 'nessuna'}\n"
        f"  Offline: {'si' if offline else 'no'}\n"
        f"  Focus: {focus_layer.value if focus_layer else 'tutti i layer'}",
        title="CTO AUDIT AGENT",
        border_style="blue",
    ))

    # --- Connessione sorgente ---
    console.print("\nConnessione alla sorgente dati...")
    try:
        source = SourceFactory.create(
            source_type=resolved_type,
            path_or_url=target,
            token=token,
            branch=ref,
            shallow=not needs_history,
        )
    except (FileNotFoundError, NotADirectoryError, RuntimeError, ValueError) as e:
        console.print(f"[red bold]Errore:[/red bold] {e}")
        raise typer.Exit(code=1)

    # --- Determina se la sorgente è un context manager ---
    is_context_manager = hasattr(source, "__enter__")
    ctx = source if is_context_manager and not isinstance(source, LocalRepoSource) else nullcontext(source)

    with ctx as active_source:
        # Per sorgenti remote, usa la temp dir come target_path
        if hasattr(active_source, "_temp_dir") and active_source._temp_dir:
            target_path = active_source._temp_dir

        # --- Caricamento storico audit ---
        history = AuditHistoryStorage(target_path)
        previous_result = history.load_latest()
        if previous_result:
            prev_ts = previous_result.metadata.timestamp.strftime("%Y-%m-%d %H:%M")
            console.print(f"Audit precedente trovato: {prev_ts}")

        # --- Esecuzione orchestrator ---
        console.print("Esecuzione audit in corso...\n")
        orchestrator = AuditOrchestrator(
            source=active_source,
            target_path=target_path,
            scoring_profile=scoring,
            focus=focus_layer,
            offline=offline,
            auto_approve=auto_approve,
            reuse_classification=reuse_classification,
            console=console,
            board_report=board_report,
            no_llm=no_llm,
            compliance_profiles=compliance_profiles,
            previous_result=previous_result,
            triage=run_triage,
        )

        result = orchestrator.run()

        # --- Calcolo delta e salvataggio storico ---
        delta = None
        if previous_result:
            delta = AuditHistoryStorage.compute_delta(previous_result, result)
        history.save(result)

    # --- Report ---
    if output:
        output_path = Path(output)
        ext = output_path.suffix.lower()

        if ext == ".json":
            from cto_audit.reporters.json_export import JSONExporter
            JSONExporter().save(result, output_path, delta=delta)
        elif ext == ".pdf":
            from cto_audit.reporters.pdf import PDFReporter
            try:
                PDFReporter(detailed=detailed).save(result, output_path)
            except ImportError as e:
                console.print(f"[red bold]Errore:[/red bold] {e}")
                raise typer.Exit(code=1)
        elif ext == ".html":
            from cto_audit.reporters.html import HTMLReporter
            HTMLReporter(detailed=detailed).save(result, output_path, delta=delta)
        elif due_diligence:
            from cto_audit.remediation.loader import RemediationLoader
            from cto_audit.reporters.due_diligence import DueDiligenceReporter
            kb = RemediationLoader.load_all()
            DueDiligenceReporter(kb_loader=kb).save(result, output_path)
        elif board_report:
            from cto_audit.remediation.loader import RemediationLoader
            from cto_audit.reporters.board import BoardReporter
            kb = RemediationLoader.load_all()
            board_reporter = BoardReporter(kb_loader=kb)
            board_reporter.save(result, output_path)
        else:
            md_reporter = MarkdownReporter(detailed=detailed)
            md_reporter.save(result, output_path, delta=delta)
        console.print(f"\nReport salvato in: [bold]{output_path}[/bold]")
    else:
        # Report terminale
        terminal_reporter = TerminalReporter(console=console, detailed=detailed)
        terminal_reporter.report(result, delta=delta)


@app.command()
def project(
    config_file: str = typer.Argument(
        ...,
        help="Percorso del file YAML di configurazione progetto",
    ),
    scoring: str = typer.Option(
        "default",
        "--scoring", "-s",
        help="Profilo di scoring da usare",
    ),
    offline: bool = typer.Option(
        False,
        "--offline",
        help="Modalità offline",
    ),
    auto_approve: bool = typer.Option(
        False,
        "--auto-approve",
        help="Salta il gate HITL",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output", "-o",
        help="Percorso file di output JSON",
    ),
) -> None:
    """
    Analizza un progetto multi-repository da file YAML di configurazione.

    Il file YAML definisce N sorgenti (repo locali, remote, archivi)
    che vengono analizzate e aggregate con score pesato per LOC.
    """
    import yaml

    from cto_audit.core.project import ProjectConfig
    from cto_audit.core.project_orchestrator import ProjectOrchestrator

    console = Console()

    config_path = Path(config_file)
    if not config_path.exists():
        console.print(f"[red bold]Errore:[/red bold] Il file '{config_file}' non esiste.")
        raise typer.Exit(code=1)

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except Exception as e:
        console.print(f"[red bold]Errore YAML:[/red bold] {e}")
        raise typer.Exit(code=1)

    try:
        config = ProjectConfig(**raw)
    except Exception as e:
        console.print(f"[red bold]Errore configurazione:[/red bold] {e}")
        raise typer.Exit(code=1)

    console.print(Panel(
        f"  Progetto: [bold]{config.name}[/bold]\n"
        f"  Sorgenti: {len(config.sources)}\n"
        f"  Scoring: {scoring}\n"
        f"  Offline: {'si' if offline else 'no'}",
        title="CTO AUDIT — PROGETTO MULTI-SOURCE",
        border_style="blue",
    ))

    orchestrator = ProjectOrchestrator(
        config=config,
        scoring_profile=scoring,
        offline=offline,
        console=console,
    )

    aggregated = orchestrator.run()

    # Report
    console.print(f"\n[bold]Risultato Aggregato: {aggregated.aggregated_score}/100[/bold]")
    console.print(f"  LOC totali: {aggregated.total_loc}")
    console.print(f"  Sorgenti analizzate: {aggregated.total_sources}")
    if aggregated.failed_sources:
        console.print(f"  [red]Sorgenti fallite: {', '.join(aggregated.failed_sources)}[/red]")

    for sr in aggregated.source_results:
        console.print(f"  {sr.name}: {sr.audit_result.health_score.overall_score}/100 ({sr.loc} LOC)")

    if output:
        output_path = Path(output)
        output_path.write_text(
            aggregated.model_dump_json(indent=2),
            encoding="utf-8",
        )
        console.print(f"\nReport salvato in: [bold]{output_path}[/bold]")


@app.command()
def ui(
    port: int = typer.Option(
        8050,
        "--port",
        help="Porta per il server dashboard",
    ),
    no_browser: bool = typer.Option(
        False,
        "--no-browser",
        help="Non aprire il browser automaticamente",
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        help="Attiva debug mode",
    ),
) -> None:
    """
    Avvia la dashboard web interattiva.

    Apre un server locale con interfaccia dark "intelligence style"
    per navigare i risultati dell'audit interattivamente.
    """
    console = Console()

    try:
        from cto_audit.dashboard.app import create_app
    except ImportError:
        console.print(
            "[red bold]Errore:[/red bold] Dashboard non disponibile. "
            "Installa le dipendenze UI:\n"
            "  pip install cto-audit[ui]"
        )
        raise typer.Exit(code=1)

    console.print(Panel(
        f"  Dashboard: http://localhost:{port}\n"
        f"  Debug: {'si' if debug else 'no'}",
        title="CTO AUDIT — DASHBOARD",
        border_style="green",
    ))

    dash_app = create_app(debug=debug)

    if not no_browser:
        import webbrowser
        import threading
        threading.Timer(1.5, lambda: webbrowser.open(f"http://localhost:{port}")).start()

    dash_app.run(host="0.0.0.0", port=port, debug=debug)


@app.command()
def agent(
    target: str = typer.Argument(
        ...,
        help="Percorso del codebase da analizzare",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output", "-o",
        help="Percorso file di output JSON (default: stdout)",
    ),
    scoring: str = typer.Option(
        "default",
        "--scoring", "-s",
        help="Profilo di scoring da usare",
    ),
    offline: bool = typer.Option(
        False,
        "--offline",
        help="Modalità offline",
    ),
    source_type: str = typer.Option(
        "auto",
        "--source-type",
        help="Tipo di sorgente",
    ),
    token: Optional[str] = typer.Option(
        None,
        "--token",
        envvar="CTO_AUDIT_TOKEN",
        help="Token di autenticazione",
    ),
    branch: Optional[str] = typer.Option(
        None,
        "--branch",
        help="Branch da clonare",
    ),
) -> None:
    """
    Esegue un audit headless e produce solo JSON.

    Pensato per automazione, CI/CD e container mode.
    Equivale a scan --auto-approve con output JSON.
    """
    import json as json_module

    from cto_audit.sources.factory import SourceFactory
    from cto_audit.sources.local import LocalRepoSource

    console = Console(stderr=True)

    # Risolvi tipo sorgente
    if source_type == "auto":
        resolved_type = SourceFactory.detect_type(target)
    else:
        resolved_type = source_type

    # Validazione per local
    if resolved_type == "local":
        target_path = Path(target).resolve()
        if not target_path.exists():
            console.print(f"[red]Errore: '{target}' non esiste[/red]")
            raise typer.Exit(code=1)
        if not target_path.is_dir():
            console.print(f"[red]Errore: '{target}' non è una directory[/red]")
            raise typer.Exit(code=1)
    else:
        target_path = Path.cwd()

    try:
        source = SourceFactory.create(
            source_type=resolved_type,
            path_or_url=target,
            token=token,
            branch=branch,
        )
    except Exception as e:
        console.print(f"[red]Errore sorgente: {e}[/red]")
        raise typer.Exit(code=1)

    is_local = isinstance(source, LocalRepoSource)
    from contextlib import nullcontext
    ctx = nullcontext(source) if is_local else source

    try:
        with ctx as active_source:
            if hasattr(active_source, "_temp_dir") and active_source._temp_dir:
                target_path = active_source._temp_dir

            orchestrator = AuditOrchestrator(
                source=active_source,
                target_path=target_path,
                scoring_profile=scoring,
                offline=offline,
                auto_approve=True,
                console=console,
            )

            result = orchestrator.run()

        # Output JSON
        result_json = result.model_dump_json(indent=2)

        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(result_json, encoding="utf-8")
            console.print(f"Report salvato: {output_path}")
        else:
            # Stampa su stdout (non stderr)
            print(result_json)

    except Exception as e:
        console.print(f"[red]Errore audit: {e}[/red]")
        raise typer.Exit(code=1)
