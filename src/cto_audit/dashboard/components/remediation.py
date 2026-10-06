"""
Componente Remediation — Tabella azioni prioritarie, effort, impatto score.
"""

from __future__ import annotations

from typing import Any, Optional

import dash_bootstrap_components as dbc
from dash import html

from cto_audit.core.models import AuditResult
from cto_audit.dashboard.theme import (
    CARD_BG, CARD_BORDER, COLOR_GOOD, COLOR_WARNING, COLOR_DANGER,
    COLOR_INFO, TEXT_PRIMARY, TEXT_SECONDARY,
)


def build_remediation(result: Optional[AuditResult]) -> html.Div:
    """Costruisce la vista remediation."""
    if result is None:
        return _empty_state(
            "Nessun audit disponibile.",
            "Avvia un audit dalla pagina Overview per visualizzare le azioni di remediation.",
        )

    if result.remediation is None:
        return _empty_state(
            "Nessuna azione di remediation generata.",
            "Il progetto analizzato non ha prodotto suggerimenti di remediation. "
            "Questo puo accadere se non ci sono finding nella knowledge base "
            "o se il progetto ha un health score molto elevato.",
        )

    rem = result.remediation

    # Accesso sicuro: rem può essere oggetto Pydantic o dict (dopo JSON roundtrip)
    def _get(field: str, default=None):
        if isinstance(rem, dict):
            return rem.get(field, default)
        return getattr(rem, field, default)

    children = [html.H4("Remediation Pipeline", className="mb-3")]

    # Executive summary (se disponibile da LLM)
    summary = _get("executive_summary")
    if summary:
        children.append(dbc.Card([
            dbc.CardHeader(html.H5("Executive Summary")),
            dbc.CardBody(html.P(summary, style={"color": TEXT_PRIMARY})),
        ], style={"backgroundColor": CARD_BG, "border": f"1px solid {CARD_BORDER}"},
           className="mb-3"))

    # Risk narrative (se disponibile da LLM)
    narrative = _get("risk_narrative")
    if narrative:
        children.append(dbc.Card([
            dbc.CardHeader(html.H5("Analisi del Rischio")),
            dbc.CardBody(html.P(narrative, style={"color": TEXT_PRIMARY})),
        ], style={"backgroundColor": CARD_BG, "border": f"1px solid {CARD_BORDER}"},
           className="mb-3"))

    # Tabella azioni prioritarie (whatif_results)
    whatif_results = _get("whatif_results", []) or []
    if whatif_results:
        # Ordina per impatto (delta) decrescente
        sorted_results = sorted(
            whatif_results,
            key=lambda w: _wget(w, "delta", 0),
            reverse=True,
        )

        children.append(dbc.Card([
            dbc.CardHeader(html.H5(
                f"Azioni Prioritarie ({len(sorted_results)} interventi identificati)"
            )),
            dbc.CardBody(_build_actions_table(sorted_results)),
        ], style={"backgroundColor": CARD_BG, "border": f"1px solid {CARD_BORDER}"},
           className="mb-3"))

        # Riepilogo impatto
        total_delta = sum(_wget(w, "delta", 0) for w in sorted_results)
        current = _wget(sorted_results[0], "current_score", 0) if sorted_results else 0
        children.append(dbc.Card([
            dbc.CardHeader(html.H5("Riepilogo Impatto")),
            dbc.CardBody(
                dbc.Row([
                    dbc.Col([
                        html.H6("Interventi totali", style={"color": TEXT_SECONDARY}),
                        html.H3(str(len(sorted_results)), style={"color": TEXT_PRIMARY}),
                    ], width=3, style={"textAlign": "center"}),
                    dbc.Col([
                        html.H6("Score attuale", style={"color": TEXT_SECONDARY}),
                        html.H3(
                            f"{current:.0f}",
                            style={"color": _score_color(current)},
                        ),
                    ], width=3, style={"textAlign": "center"}),
                    dbc.Col([
                        html.H6("Miglioramento potenziale", style={"color": TEXT_SECONDARY}),
                        html.H3(
                            f"+{total_delta:.1f}",
                            style={"color": COLOR_GOOD},
                        ),
                    ], width=3, style={"textAlign": "center"}),
                    dbc.Col([
                        html.H6("Score proiettato", style={"color": TEXT_SECONDARY}),
                        html.H3(
                            f"{min(100, current + total_delta):.0f}",
                            style={"color": COLOR_GOOD},
                        ),
                    ], width=3, style={"textAlign": "center"}),
                ]),
            ),
        ], style={"backgroundColor": CARD_BG, "border": f"1px solid {CARD_BORDER}"},
           className="mb-3"))
    else:
        children.append(dbc.Card([
            dbc.CardBody([
                html.P(
                    "Nessuna simulazione what-if disponibile per i finding rilevati.",
                    style={"color": TEXT_SECONDARY, "textAlign": "center", "padding": "20px"},
                ),
            ]),
        ], style={"backgroundColor": CARD_BG, "border": f"1px solid {CARD_BORDER}"},
           className="mb-3"))

    return html.Div(children)


def _wget(obj, field: str, default=None):
    """Accesso sicuro a campo: funziona con oggetti Pydantic e dict."""
    if isinstance(obj, dict):
        return obj.get(field, default)
    return getattr(obj, field, default)


def _build_actions_table(whatif_results: list) -> dbc.Table:
    """Tabella delle azioni prioritarie ordinate per impatto."""
    header = html.Thead(html.Tr([
        html.Th("Priorita", style={"width": "70px"}),
        html.Th("Regola"),
        html.Th("Impatto Score", style={"width": "130px"}),
        html.Th("Effort", style={"width": "100px"}),
        html.Th("Efficienza", style={"width": "120px"}),
    ]))

    rows = []
    for i, w in enumerate(whatif_results):
        priority = i + 1
        if priority <= 3:
            badge_color = COLOR_DANGER
        elif priority <= 7:
            badge_color = COLOR_WARNING
        else:
            badge_color = COLOR_INFO

        # Effort
        effort_text = "N/A"
        effort = _wget(w, "effort")
        if effort:
            t_shirt = _wget(effort, "t_shirt", "?")
            min_h = _wget(effort, "min_hours", 0)
            max_h = _wget(effort, "max_hours", 0)
            effort_text = f"{t_shirt} ({min_h}-{max_h}h)"

        # Efficienza
        efficiency = _wget(w, "impact_effort_ratio", 0)
        if efficiency > 1.0:
            eff_color = COLOR_GOOD
            eff_label = "Ottima"
        elif efficiency > 0.3:
            eff_color = COLOR_WARNING
            eff_label = "Buona"
        else:
            eff_color = TEXT_SECONDARY
            eff_label = "Bassa"

        delta = _wget(w, "delta", 0)
        rule_id = _wget(w, "rule_id", "N/A")

        rows.append(html.Tr([
            html.Td(
                html.Span(f"#{priority}", style={
                    "backgroundColor": badge_color, "color": "#0d1117",
                    "borderRadius": "4px", "padding": "2px 8px",
                    "fontWeight": "bold", "fontSize": "0.85rem",
                }),
            ),
            html.Td(
                html.Span(rule_id, style={
                    "fontFamily": "monospace", "color": TEXT_PRIMARY,
                    "fontWeight": "bold",
                }),
            ),
            html.Td(
                html.Span(f"+{delta:.1f} pts", style={
                    "color": COLOR_GOOD, "fontWeight": "bold",
                }),
            ),
            html.Td(effort_text, style={"color": TEXT_SECONDARY, "fontSize": "0.9rem"}),
            html.Td(
                html.Span(eff_label, style={"color": eff_color, "fontWeight": "bold"}),
            ),
        ]))

    return dbc.Table(
        [header, html.Tbody(rows)],
        bordered=True, hover=True, color="dark",
        style={"fontSize": "0.9rem"},
    )


def _score_color(score: float) -> str:
    """Colore per score."""
    if score >= 70:
        return COLOR_GOOD
    if score >= 40:
        return COLOR_WARNING
    return COLOR_DANGER


def _empty_state(title: str, description: str) -> html.Div:
    """Card stato vuoto per remediation."""
    return html.Div([
        html.H4("Remediation Pipeline", className="mb-3"),
        dbc.Card([
            dbc.CardBody([
                html.H5(title, style={"color": "#e6edf3", "textAlign": "center"}),
                html.P(description, style={
                    "color": "#8b949e", "textAlign": "center",
                    "maxWidth": "500px", "margin": "12px auto 0",
                }),
            ], style={"padding": "40px 20px"}),
        ], style={"backgroundColor": CARD_BG, "border": f"1px solid {CARD_BORDER}"}),
    ])
