"""
Review interattivo Human-in-the-Loop per le classificazioni privacy.

Il HITLReviewer è il gate obbligatorio tra la scansione e l'analisi.
Presenta all'utente un riepilogo delle classificazioni e permette di
confermare, modificare, o annullare prima di procedere.

L'interfaccia usa Rich per la presentazione terminale come da mock
nel doc 03-hitl-flow.md.
"""

from __future__ import annotations

from enum import Enum
from typing import Callable

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cto_audit.core.models import (
    FileClassification,
    PrivacyCategory,
    StackInfo,
)


class ReviewAction(str, Enum):
    """Azioni disponibili nel menu della review."""
    CONFIRM = "C"           # Conferma e procedi
    VIEW_SAFE = "V"         # Visualizza tutti i file SAFE
    VIEW_SENSITIVE = "S"    # Visualizza dettaglio SENSITIVE
    VIEW_EXCLUDED = "X"     # Visualizza file ESCLUSI
    EDIT = "E"              # Modifica classificazione di un file
    ALL_SENSITIVE = "A"     # Sposta tutto a SENSITIVE
    QUIT = "Q"              # Annulla audit


class ReviewResult(str, Enum):
    """Risultato della review."""
    CONFIRMED = "confirmed"     # L'utente ha confermato
    CANCELLED = "cancelled"     # L'utente ha annullato


class HITLReviewer:
    """
    Gate interattivo Human-in-the-Loop per la review delle classificazioni.

    Presenta il summary, permette di esplorare e modificare le classificazioni,
    e richiede conferma esplicita prima di procedere all'analisi.

    L'I/O è disaccoppiato tramite funzioni iniettabili (input_fn, console),
    per consentire il testing senza interazione reale.

    Attributes:
        console: Console Rich per l'output
        input_fn: Funzione per l'input utente (default: builtin input)
    """

    def __init__(
        self,
        console: Console | None = None,
        input_fn: Callable[[str], str] | None = None,
    ) -> None:
        """
        Args:
            console: Console Rich (creata automaticamente se non fornita)
            input_fn: Funzione per l'input utente (default: builtin input)
        """
        self.console = console or Console()
        self.input_fn = input_fn or input

    def review(
        self,
        classifications: list[FileClassification],
        stack_info: StackInfo | None = None,
    ) -> tuple[ReviewResult, list[FileClassification], list[dict[str, str]]]:
        """
        Esegue la review interattiva completa.

        Mostra il summary, poi entra nel loop del menu dove l'utente può
        visualizzare, modificare, o confermare le classificazioni.

        Args:
            classifications: Lista di classificazioni dal PrivacyClassifier
            stack_info: Info sullo stack rilevato (opzionale, per il summary)

        Returns:
            Tupla con:
            - ReviewResult: CONFIRMED o CANCELLED
            - list[FileClassification]: classificazioni finali (possibilmente modificate)
            - list[dict]: lista degli override effettuati
        """
        # Copia lavorabile delle classificazioni
        working = list(classifications)
        overrides: list[dict[str, str]] = []

        # Mostra summary iniziale
        self._show_summary(working, stack_info)

        # Loop menu principale
        while True:
            action = self._show_menu()

            if action == ReviewAction.CONFIRM:
                # Mostra riepilogo finale e chiedi conferma
                if self._show_final_summary(working, overrides):
                    return (ReviewResult.CONFIRMED, working, overrides)
                # Se non conferma, torna al menu

            elif action == ReviewAction.VIEW_SAFE:
                self._show_files_by_category(working, PrivacyCategory.SAFE)

            elif action == ReviewAction.VIEW_SENSITIVE:
                self._show_files_by_category(working, PrivacyCategory.SENSITIVE)

            elif action == ReviewAction.VIEW_EXCLUDED:
                self._show_files_by_category(working, PrivacyCategory.EXCLUDED)

            elif action == ReviewAction.EDIT:
                result = self._edit_classification(working)
                if result:
                    override, working = result
                    overrides.append(override)

            elif action == ReviewAction.ALL_SENSITIVE:
                working, new_overrides = self._move_all_to_sensitive(working)
                overrides.extend(new_overrides)

            elif action == ReviewAction.QUIT:
                return (ReviewResult.CANCELLED, classifications, [])

    # --- Visualizzazione ---

    def _show_summary(
        self,
        classifications: list[FileClassification],
        stack_info: StackInfo | None = None,
    ) -> None:
        """Mostra il pannello di riepilogo iniziale come da mock doc 03."""
        by_cat = self._group_by_category(classifications)
        total = len(classifications)
        total_loc = sum(c.file_info.lines_of_code for c in classifications)

        # Header
        lines: list[str] = []
        lines.append(f"  Scansionati: {total} file | {total_loc:,} LOC")

        if stack_info:
            if stack_info.languages:
                lang_str = ", ".join(
                    f"{lang.capitalize()} ({pct:.0%})"
                    for lang, pct in sorted(stack_info.languages.items(), key=lambda x: -x[1])[:3]
                )
                lines.append(f"  Stack rilevato: {lang_str}")
            if stack_info.frameworks:
                lines.append(f"  Framework: {', '.join(stack_info.frameworks[:5])}")
            if stack_info.infra_type:
                lines.append(f"  Infra: {', '.join(stack_info.infra_type[:5])}")

        lines.append("")
        lines.append(f"  [green]SAFE (LLM cloud):[/green]             {len(by_cat.get(PrivacyCategory.SAFE, []))} file")
        lines.append(f"  [yellow]LOCAL LLM (Ollama):[/yellow]           {len(by_cat.get(PrivacyCategory.LOCAL_LLM, []))} file")
        lines.append(f"  [red]SENSITIVE (solo locale):[/red]       {len(by_cat.get(PrivacyCategory.SENSITIVE, []))} file")
        lines.append(f"  [dim]ESCLUSI (vendor/binari):[/dim]       {len(by_cat.get(PrivacyCategory.EXCLUDED, []))} file")

        # Mostra file SENSITIVE in dettaglio
        sensitive = by_cat.get(PrivacyCategory.SENSITIVE, [])
        if sensitive:
            lines.append("")
            lines.append("  [red bold]FILE CLASSIFICATI COME SENSITIVE:[/red bold]")
            table = Table(show_header=True, padding=(0, 1), expand=True)
            table.add_column("#", style="dim", width=4)
            table.add_column("File", style="red")
            table.add_column("Motivo")
            for i, c in enumerate(sensitive[:15], 1):
                table.add_row(str(i), c.file_info.path, c.reason[:50])
            if len(sensitive) > 15:
                table.add_row("...", f"(altri {len(sensitive) - 15} file)", "")
            self.console.print(Panel("\n".join(lines), title="CLASSIFICATION REVIEW", border_style="blue"))
            self.console.print(table)
        else:
            lines.append("")
            lines.append("  [green]Nessun file sensibile rilevato.[/green]")
            self.console.print(Panel("\n".join(lines), title="CLASSIFICATION REVIEW", border_style="blue"))

    def _show_menu(self) -> ReviewAction:
        """Mostra il menu azioni e restituisce la scelta dell'utente."""
        self.console.print()
        self.console.print("[bold]Cosa vuoi fare?[/bold]")
        self.console.print("  [C] Conferma classificazione e procedi")
        self.console.print("  [V] Visualizza tutti i file SAFE")
        self.console.print("  [S] Visualizza dettaglio file SENSITIVE")
        self.console.print("  [X] Visualizza file ESCLUSI")
        self.console.print("  [E] Modifica classificazione di un file")
        self.console.print("  [A] Sposta TUTTO a SENSITIVE (analisi 100% locale)")
        self.console.print("  [Q] Annulla audit")
        self.console.print()

        while True:
            choice = self.input_fn("  Scelta: ").strip().upper()
            try:
                return ReviewAction(choice)
            except ValueError:
                self.console.print(f"  [red]Scelta non valida: '{choice}'. Riprova.[/red]")

    def _show_files_by_category(
        self,
        classifications: list[FileClassification],
        category: PrivacyCategory,
    ) -> None:
        """Mostra tutti i file di una categoria in una tabella."""
        by_cat = self._group_by_category(classifications)
        files = by_cat.get(category, [])

        cat_labels = {
            PrivacyCategory.SAFE: ("SAFE", "green"),
            PrivacyCategory.LOCAL_LLM: ("LOCAL LLM", "yellow"),
            PrivacyCategory.SENSITIVE: ("SENSITIVE", "red"),
            PrivacyCategory.EXCLUDED: ("ESCLUSI", "dim"),
        }
        label, style = cat_labels[category]

        if not files:
            self.console.print(f"\n  Nessun file [{style}]{label}[/{style}].\n")
            return

        table = Table(title=f"File {label} ({len(files)})", show_header=True)
        table.add_column("#", style="dim", width=5)
        table.add_column("File", style=style)
        table.add_column("Motivo")
        table.add_column("Size", justify="right")

        for i, c in enumerate(files, 1):
            size_str = self._format_size(c.file_info.size)
            table.add_row(str(i), c.file_info.path, c.reason[:60], size_str)

        self.console.print(table)

    def _show_final_summary(
        self,
        classifications: list[FileClassification],
        overrides: list[dict[str, str]],
    ) -> bool:
        """
        Mostra il riepilogo finale e chiede conferma per procedere.

        Returns:
            True se l'utente conferma, False altrimenti
        """
        by_cat = self._group_by_category(classifications)

        lines: list[str] = []
        lines.append(f"  [green]SAFE -> LLM Cloud:[/green]        {len(by_cat.get(PrivacyCategory.SAFE, []))} file")
        lines.append(f"  [yellow]LOCAL LLM -> Ollama:[/yellow]      {len(by_cat.get(PrivacyCategory.LOCAL_LLM, []))} file")
        lines.append(f"  [red]SENSITIVE -> Solo locale:[/red]  {len(by_cat.get(PrivacyCategory.SENSITIVE, []))} file")
        lines.append(f"  [dim]ESCLUSI:[/dim]                   {len(by_cat.get(PrivacyCategory.EXCLUDED, []))} file")
        lines.append("")
        lines.append(f"  Modifiche manuali: {len(overrides)}")

        local_llm_count = len(by_cat.get(PrivacyCategory.LOCAL_LLM, []))
        excluded_count = len(by_cat.get(PrivacyCategory.EXCLUDED, []))
        if local_llm_count:
            lines.append(f"  [yellow]! {local_llm_count} file analizzati con qualità ridotta (Ollama)[/yellow]")
        if excluded_count:
            lines.append(f"  [dim]! {excluded_count} file ignorati[/dim]")

        self.console.print(Panel(
            "\n".join(lines),
            title="RIEPILOGO CLASSIFICAZIONE FINALE",
            border_style="green",
        ))

        answer = self.input_fn("  Procedi con l'analisi? [s/N]: ").strip().lower()
        return answer in ("s", "si", "sì", "y", "yes")

    # --- Modifica classificazione ---

    def _edit_classification(
        self,
        classifications: list[FileClassification],
    ) -> tuple[dict[str, str], list[FileClassification]] | None:
        """
        Permette di modificare la classificazione di un singolo file.

        Returns:
            Tupla (override dict, lista aggiornata) o None se annullato
        """
        # Mostra solo file non esclusi (modificare un EXCLUDED ha poco senso)
        editable = [c for c in classifications if c.category != PrivacyCategory.EXCLUDED]
        if not editable:
            self.console.print("  [dim]Nessun file modificabile.[/dim]")
            return None

        self.console.print("\n  Inserisci il numero del file o il path (vuoto per annullare):")

        # Mostra lista numerata
        for i, c in enumerate(editable, 1):
            cat_icon = {"safe": "[green]SAFE[/green]", "local_llm": "[yellow]LOCAL[/yellow]",
                        "sensitive": "[red]SENS[/red]", "excluded": "[dim]EXCL[/dim]"}
            self.console.print(f"    {i:3d}  {cat_icon[c.category.value]}  {c.file_info.path}")

        choice = self.input_fn("  File: ").strip()
        if not choice:
            return None

        # Trova il file scelto
        target: FileClassification | None = None
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(editable):
                target = editable[idx]
        except ValueError:
            # Prova come path
            for c in editable:
                if c.file_info.path == choice:
                    target = c
                    break

        if target is None:
            self.console.print("  [red]File non trovato.[/red]")
            return None

        old_cat = target.category
        self.console.print(f"\n  File: {target.file_info.path}")
        self.console.print(f"  Classificazione attuale: {old_cat.value}")
        self.console.print(f"  Motivo: {target.reason}")

        # Menu nuova classificazione
        self.console.print("\n  Nuova classificazione:")
        self.console.print("  [1] SAFE -> LLM cloud (qualità massima)")
        self.console.print("  [2] LOCAL LLM -> Ollama locale (qualità media)")
        self.console.print("  [3] SENSITIVE -> solo locale (qualità ridotta)")
        self.console.print("  [4] ESCLUDI -> ignorato")

        new_choice = self.input_fn("  Scelta: ").strip()
        cat_map = {"1": PrivacyCategory.SAFE, "2": PrivacyCategory.LOCAL_LLM,
                    "3": PrivacyCategory.SENSITIVE, "4": PrivacyCategory.EXCLUDED}
        new_cat = cat_map.get(new_choice)
        if new_cat is None:
            self.console.print("  [red]Scelta non valida.[/red]")
            return None

        if new_cat == old_cat:
            self.console.print("  [dim]Nessuna modifica.[/dim]")
            return None

        # Se si sposta da SENSITIVE a SAFE: richiedi CONFERMO
        if old_cat == PrivacyCategory.SENSITIVE and new_cat == PrivacyCategory.SAFE:
            self.console.print(f"\n  [red bold]ATTENZIONE:[/red bold] Questo file contiene pattern sensibili:")
            self.console.print(f"    {target.reason}")
            self.console.print("  Inviando questo file al LLM cloud, dati sensibili potrebbero")
            self.console.print("  transitare su server esterni.")
            confirm = self.input_fn("  Sei sicuro? Digita 'CONFERMO' per procedere: ").strip()
            if confirm != "CONFERMO":
                self.console.print("  [dim]Operazione annullata.[/dim]")
                return None

        # Applica la modifica
        override = {
            "file": target.file_info.path,
            "from": old_cat.value,
            "to": new_cat.value,
            "reason": "Override manuale HITL",
        }

        # Ricostruisci la lista con la modifica applicata
        new_classifications: list[FileClassification] = []
        for c in classifications:
            if c.file_info.path == target.file_info.path:
                new_classifications.append(FileClassification(
                    file_info=c.file_info,
                    category=new_cat,
                    reason=f"Override manuale: {old_cat.value} -> {new_cat.value}",
                    confidence=1.0,
                ))
            else:
                new_classifications.append(c)

        self.console.print(f"  [green]OK:[/green] {target.file_info.path} -> {new_cat.value}")
        return (override, new_classifications)

    def _move_all_to_sensitive(
        self,
        classifications: list[FileClassification],
    ) -> tuple[list[FileClassification], list[dict[str, str]]]:
        """
        Sposta tutti i file SAFE e LOCAL_LLM a SENSITIVE.

        Returns:
            Tupla (nuova lista, lista override)
        """
        overrides: list[dict[str, str]] = []
        new_classifications: list[FileClassification] = []

        for c in classifications:
            if c.category in (PrivacyCategory.SAFE, PrivacyCategory.LOCAL_LLM):
                overrides.append({
                    "file": c.file_info.path,
                    "from": c.category.value,
                    "to": PrivacyCategory.SENSITIVE.value,
                    "reason": "Spostato a SENSITIVE (batch)",
                })
                new_classifications.append(FileClassification(
                    file_info=c.file_info,
                    category=PrivacyCategory.SENSITIVE,
                    reason="Spostato a SENSITIVE (analisi 100% locale)",
                    confidence=1.0,
                ))
            else:
                new_classifications.append(c)

        moved = len(overrides)
        self.console.print(f"  [yellow]{moved} file spostati a SENSITIVE.[/yellow]")
        return (new_classifications, overrides)

    # --- Utility ---

    @staticmethod
    def _group_by_category(
        classifications: list[FileClassification],
    ) -> dict[PrivacyCategory, list[FileClassification]]:
        """Raggruppa le classificazioni per categoria."""
        groups: dict[PrivacyCategory, list[FileClassification]] = {}
        for c in classifications:
            groups.setdefault(c.category, []).append(c)
        return groups

    @staticmethod
    def _format_size(size: int) -> str:
        """Formatta una dimensione in byte in modo leggibile."""
        if size < 1024:
            return f"{size} B"
        elif size < 1_048_576:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / 1_048_576:.1f} MB"
