"""
Entry point CLI per CTO Audit Agent.

Usa Typer per definire il comando `cto-audit scan` con tutte le opzioni.
Collega l'intera pipeline: Source → Orchestrator → Reporter.
"""

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
        help="Percorso del codebase da analizzare",
    ),
    focus: Optional[str] = typer.Option(
        None,
        "--focus", "-f",
        help="Esegui solo un layer specifico: infra, architecture, security, quality",
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
        help="Profilo di scoring da usare (es. default, nist-csf, owasp-asvs)",
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
) -> None:
    """
    Scansiona un codebase e produce un audit report.

    Esegue la pipeline completa: scansione file, rilevamento stack,
    classificazione privacy, analisi per layer, scoring e report.
    """
    # Console creata qui (non a livello di modulo) per compatibilità
    # con CliRunner che sostituisce sys.stdout a runtime
    console = Console()

    target_path = Path(target).resolve()

    # --- Validazione percorso ---
    if not target_path.exists():
        console.print(f"[red bold]Errore:[/red bold] Il percorso '{target}' non esiste.")
        raise typer.Exit(code=1)
    if not target_path.is_dir():
        console.print(f"[red bold]Errore:[/red bold] Il percorso '{target}' non è una directory.")
        raise typer.Exit(code=1)

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

    console.print(Panel(
        f"  Target: [bold]{target_path}[/bold]\n"
        f"  Scoring: {scoring}\n"
        f"  Compliance: {', '.join(compliance_profiles) if compliance_profiles else 'nessuna'}\n"
        f"  Offline: {'si' if offline else 'no'}\n"
        f"  Focus: {focus_layer.value if focus_layer else 'tutti i layer'}",
        title="CTO AUDIT AGENT",
        border_style="blue",
    ))

    # --- Connessione sorgente ---
    console.print("\nConnessione alla sorgente dati...")
    try:
        source = LocalRepoSource(target_path)
    except (FileNotFoundError, NotADirectoryError) as e:
        console.print(f"[red bold]Errore:[/red bold] {e}")
        raise typer.Exit(code=1)

    # --- Caricamento storico audit ---
    history = AuditHistoryStorage(target_path)
    previous_result = history.load_latest()
    if previous_result:
        prev_ts = previous_result.metadata.timestamp.strftime("%Y-%m-%d %H:%M")
        console.print(f"Audit precedente trovato: {prev_ts}")

    # --- Esecuzione orchestrator ---
    console.print("Esecuzione audit in corso...\n")
    orchestrator = AuditOrchestrator(
        source=source,
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
        elif board_report:
            from cto_audit.remediation.loader import RemediationLoader
            from cto_audit.reporters.board import BoardReporter
            kb = RemediationLoader.from_yaml()
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
