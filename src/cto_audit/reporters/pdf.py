"""
PDF Reporter — Converte il report HTML in PDF via WeasyPrint.

Riusa l'HTMLReporter per generare il contenuto, poi converte in PDF.
Richiede il pacchetto opzionale weasyprint: pip install cto-audit[pdf]

Nota: WeasyPrint richiede dipendenze di sistema (GTK/Cairo).
Su Windows: https://doc.courtbouillon.org/weasyprint/stable/first_steps.html
"""

from __future__ import annotations

from pathlib import Path

from cto_audit.core.models import AuditResult
from cto_audit.reporters.html import HTMLReporter


class PDFReporter:
    """
    Reporter PDF basato su HTMLReporter + WeasyPrint.

    Genera l'HTML internamente e lo converte in PDF.
    Supporta --detailed come gli altri reporter.
    """

    def __init__(self, detailed: bool = False) -> None:
        self.detailed = detailed
        self._html_reporter = HTMLReporter(detailed=detailed)

    def save(self, result: AuditResult, output_path: Path) -> None:
        """
        Genera e salva il report in formato PDF.

        Args:
            result: Risultato dell'audit
            output_path: Percorso file di output (.pdf)

        Raises:
            ImportError: se weasyprint non è installato
        """
        try:
            from weasyprint import HTML  # type: ignore[import-untyped]
        except ImportError:
            raise ImportError(
                "Per generare report PDF serve WeasyPrint.\n"
                "Installa con: pip install cto-audit[pdf]\n\n"
                "Nota: WeasyPrint richiede anche dipendenze di sistema (GTK/Cairo).\n"
                "Vedi: https://doc.courtbouillon.org/weasyprint/stable/first_steps.html"
            ) from None

        html_content = self._html_reporter.report(result)
        HTML(string=html_content).write_pdf(str(output_path))
