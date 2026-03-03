"""
Terminal Reporter — Output Rich per il report di audit.

Genera un output terminale formattato con Rich che mostra:
- Pannello CTO AUDIT REPORT con stack e metadati
- Health Score complessivo con indicatore colorato
- Score per layer con severità
- Top 5 azioni prioritarie (finding con penalità più alta)
- Catena di evidenze (opzionale)

Il formato segue il mock del doc 01-concept.
"""

from __future__ import annotations

from cto_audit.core.models import (
    AuditDelta,
    AuditResult,
    Finding,
    HealthScore,
    Layer,
    Severity,
    StackInfo,
)

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


# Mappa severità → emoji e colore
SEVERITY_STYLE: dict[str, tuple[str, str]] = {
    "critical": ("CRIT", "red bold"),
    "high": ("HIGH", "red"),
    "medium": ("MED", "yellow"),
    "low": ("LOW", "blue"),
    "info": ("INFO", "dim"),
}

# Mappa layer → emoji e nome
LAYER_DISPLAY: dict[str, tuple[str, str]] = {
    "infra": ("INFRASTRUTTURA", "bold"),
    "architecture": ("ARCHITETTURA", "bold"),
    "security": ("SICUREZZA", "bold"),
    "quality": ("QUALITA CODICE", "bold"),
}


def _score_color(score: float) -> str:
    """Restituisce il colore Rich in base allo score."""
    if score >= 80:
        return "green"
    elif score >= 60:
        return "yellow"
    elif score >= 40:
        return "dark_orange"
    else:
        return "red"


def _score_label(score: float) -> str:
    """Restituisce un'etichetta testuale per lo score."""
    if score >= 80:
        return "BUONO"
    elif score >= 60:
        return "ATTENZIONE"
    elif score >= 40:
        return "INSUFFICIENTE"
    else:
        return "CRITICO"


def _confidence_badge(confidence: float) -> str:
    """Restituisce un badge colorato per la confidence."""
    pct = f"{confidence:.0%}"
    if confidence >= 0.7:
        return f"[green]{pct} OK[/green]"
    elif confidence >= 0.4:
        return f"[yellow]{pct} ![/yellow]"
    else:
        return f"[red]{pct} !![/red]"


class TerminalReporter:
    """
    Reporter per output terminale Rich.

    Produce un report completo con health score, layer scores,
    top 5 azioni prioritarie e stack rilevato.
    """

    def __init__(self, console: Console | None = None, detailed: bool = False) -> None:
        self.console = console or Console()
        self.detailed = detailed

    def report(
        self,
        result: AuditResult,
        show_evidence: bool = False,
        delta: AuditDelta | None = None,
    ) -> None:
        """
        Genera il report completo a terminale.

        Args:
            result: Risultato dell'audit completo
            show_evidence: Se True, mostra la catena di evidenze per ogni score
            delta: Delta rispetto all'audit precedente (se disponibile)
        """
        self._show_header(result)
        self._show_health_score(result.health_score)
        self._show_layer_scores(result.health_score)

        if delta:
            self._show_delta(delta)

        self._show_top_actions(result.health_score)

        if show_evidence or self.detailed:
            self._show_evidence(result.health_score)

    def _show_header(self, result: AuditResult) -> None:
        """Mostra il pannello di intestazione con stack e metadati."""
        stack = result.stack_info
        meta = result.metadata

        lines: list[str] = []

        # Stack info
        if stack.languages:
            lang_parts = [
                f"{lang.capitalize()} ({pct:.0%})"
                for lang, pct in sorted(stack.languages.items(), key=lambda x: -x[1])[:5]
            ]
            lines.append(f"  Stack: {', '.join(lang_parts)}")

        if stack.frameworks:
            lines.append(f"  Framework: {', '.join(stack.frameworks[:6])}")

        if stack.infra_type:
            lines.append(f"  Infra: {', '.join(stack.infra_type[:6])}")

        # Metadati
        total_files = len(result.classifications)
        lines.append(f"  File analizzati: {total_files}")
        lines.append(f"  Scoring: {meta.scoring_profile}")
        if meta.project_type:
            pt_label = meta.project_type.replace("_", " ").title()
            pt_conf = f" ({meta.project_type_confidence:.0%})" if meta.project_type_confidence else ""
            lines.append(f"  Tipo progetto: {pt_label}{pt_conf}")
        if meta.offline_mode:
            lines.append("  Modalita: Offline")

        self.console.print(Panel(
            "\n".join(lines),
            title="CTO AUDIT REPORT",
            border_style="blue",
        ))

    def _show_health_score(self, health: HealthScore) -> None:
        """Mostra lo health score complessivo."""
        score = health.overall_score
        color = _score_color(score)
        label = _score_label(score)

        conf = health.overall_confidence
        conf_badge = _confidence_badge(conf)

        self.console.print()
        self.console.print(
            f"  HEALTH SCORE:  [{color} bold]{score:.0f}/100[/{color} bold]"
            f"  {label}  {conf_badge}",
        )
        self.console.print()

    def _show_layer_scores(self, health: HealthScore) -> None:
        """Mostra gli score per ogni layer."""
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Layer", style="bold", min_width=20)
        table.add_column("Score", justify="right", min_width=8)
        table.add_column("Confidence", min_width=16)
        table.add_column("Stato", min_width=12)
        table.add_column("Finding", justify="right", min_width=8)

        for layer_name in ["infra", "architecture", "security", "quality"]:
            if layer_name not in health.layer_scores:
                continue

            ls = health.layer_scores[layer_name]
            display_name, _ = LAYER_DISPLAY.get(layer_name, (layer_name.upper(), "bold"))
            color = _score_color(ls.score)
            label = _score_label(ls.score)
            num_findings = len([f for f in ls.findings if f.severity != Severity.INFO])
            conf_badge = _confidence_badge(ls.confidence)

            table.add_row(
                display_name,
                f"[{color}]{ls.score:.0f}/100[/{color}]",
                conf_badge,
                f"[{color}]{label}[/{color}]",
                str(num_findings),
            )

        self.console.print(table)
        self.console.print()

    def _show_top_actions(self, health: HealthScore) -> None:
        """Mostra le top 5 azioni prioritarie (finding con penalità più alta)."""
        # Raccogli tutti i finding non-info con le loro penalità
        action_items: list[tuple[float, Finding]] = []

        for layer_name, ls in health.layer_scores.items():
            for i, finding in enumerate(ls.findings):
                if finding.severity == Severity.INFO:
                    continue
                # Cerca la penalità nell'evidence chain
                penalty = 0.0
                if i < len(ls.evidence_chain):
                    penalty = abs(ls.evidence_chain[i].penalty)
                action_items.append((penalty, finding))

        # Ordina per penalità decrescente
        action_items.sort(key=lambda x: x[0], reverse=True)
        top_5 = action_items[:5]

        if not top_5:
            self.console.print(Panel(
                "  Nessuna azione richiesta. Il codebase e in ottimo stato!",
                title="AZIONI PRIORITARIE",
                border_style="green",
            ))
            return

        lines: list[str] = []
        for idx, (penalty, finding) in enumerate(top_5, 1):
            sev_label, sev_style = SEVERITY_STYLE.get(
                finding.severity.value, ("???", "dim")
            )
            lines.append(
                f"  {idx}. [{sev_style}]{sev_label}[/{sev_style}] {finding.title}"
            )
            if finding.file_path:
                lines.append(f"     File: {finding.file_path}")
            if finding.framework_ref:
                lines.append(f"     Ref: {finding.framework_ref}")
            lines.append("")

        self.console.print(Panel(
            "\n".join(lines).rstrip(),
            title="TOP 5 AZIONI PRIORITARIE",
            border_style="yellow",
        ))

    def _show_delta(self, delta: AuditDelta) -> None:
        """Mostra il pannello delta rispetto all'audit precedente."""
        # Trend score
        sign = "+" if delta.score_delta > 0 else ""
        if delta.score_delta > 0:
            trend_color = "green"
            trend_label = "MIGLIORATO"
        elif delta.score_delta < 0:
            trend_color = "red"
            trend_label = "PEGGIORATO"
        else:
            trend_color = "yellow"
            trend_label = "INVARIATO"

        lines: list[str] = [
            f"  Score: {delta.previous_score:.0f} -> {delta.current_score:.0f} "
            f"([{trend_color}]{sign}{delta.score_delta:.1f}[/{trend_color}] {trend_label})",
            f"  Giorni dall'ultimo audit: {delta.days_since_previous:.1f}",
            "",
        ]

        # Layer deltas
        for layer_name in ["infra", "architecture", "security", "quality"]:
            if layer_name in delta.layer_deltas:
                ld = delta.layer_deltas[layer_name]
                layer_sign = "+" if ld > 0 else ""
                layer_display, _ = LAYER_DISPLAY.get(layer_name, (layer_name.upper(), "bold"))
                ld_color = "green" if ld > 0 else "red" if ld < 0 else "dim"
                lines.append(
                    f"  {layer_display}: [{ld_color}]{layer_sign}{ld:.1f}[/{ld_color}]"
                )

        # Finding summary
        lines.append("")
        if delta.resolved_findings:
            lines.append(
                f"  [green]Risolti: {len(delta.resolved_findings)}[/green]"
            )
        if delta.new_findings:
            lines.append(
                f"  [red]Nuovi: {len(delta.new_findings)}[/red]"
            )
        if delta.persistent_findings:
            lines.append(
                f"  Persistenti: {len(delta.persistent_findings)}"
            )

        self.console.print(Panel(
            "\n".join(lines).rstrip(),
            title="DELTA RISPETTO ALL'ULTIMO AUDIT",
            border_style=trend_color,
        ))
        self.console.print()

    def _show_evidence(self, health: HealthScore) -> None:
        """Mostra la catena di evidenze per ogni layer."""
        self.console.print()
        self.console.print("[bold]Catena di Evidenze:[/bold]")

        for layer_name in ["infra", "architecture", "security", "quality"]:
            if layer_name not in health.layer_scores:
                continue

            ls = health.layer_scores[layer_name]
            if not ls.evidence_chain:
                continue

            display_name, _ = LAYER_DISPLAY.get(layer_name, (layer_name.upper(), "bold"))

            table = Table(
                title=f"{display_name} (Score: {ls.score:.0f}/100)",
                show_header=True,
                header_style="bold",
            )
            table.add_column("Rule ID", min_width=18)
            table.add_column("Weight", justify="right", min_width=8)
            table.add_column("Penalty", justify="right", min_width=10)
            table.add_column("Framework", min_width=18)

            for ev in ls.evidence_chain:
                table.add_row(
                    ev.rule_id,
                    f"{ev.weight:.2f}",
                    f"{ev.penalty:.1f}",
                    ev.framework_ref or "-",
                )

            self.console.print(table)
            self.console.print()
