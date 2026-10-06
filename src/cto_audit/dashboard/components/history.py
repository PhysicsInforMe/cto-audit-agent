"""
Componente History — Line chart score nel tempo, bar chart deltas.
"""

from __future__ import annotations

from typing import Optional

import dash_bootstrap_components as dbc
from dash import html

from cto_audit.core.models import AuditDelta, AuditResult
from cto_audit.dashboard.theme import CARD_BG, CARD_BORDER, COLOR_GOOD, COLOR_DANGER


def build_history(result: Optional[AuditResult], delta: Optional[AuditDelta] = None) -> html.Div:
    """Costruisce la vista history."""
    if result is None:
        return _empty_state(
            "Nessun audit disponibile.",
            "Avvia un audit dalla pagina Overview per iniziare a tracciare lo storico.",
        )

    children = [html.H4("Storico Audit", className="mb-3")]

    if delta is None:
        return html.Div([
            html.H4("Storico Audit", className="mb-3"),
            dbc.Card([
                dbc.CardBody([
                    html.H5(
                        "Nessun audit precedente disponibile.",
                        style={"color": "#e6edf3", "textAlign": "center"},
                    ),
                    html.P(
                        "Il confronto storico sara disponibile dopo il secondo audit "
                        "sullo stesso progetto. I risultati vengono salvati automaticamente "
                        "nella cartella .cto-audit/history/.",
                        style={
                            "color": "#8b949e", "textAlign": "center",
                            "maxWidth": "500px", "margin": "12px auto 0",
                        },
                    ),
                ], style={"padding": "40px 20px"}),
            ], style={"backgroundColor": CARD_BG, "border": f"1px solid {CARD_BORDER}"}),
        ])

    # Delta score
    arrow = "↑" if delta.score_delta > 0 else "↓" if delta.score_delta < 0 else "="
    color = COLOR_GOOD if delta.score_delta >= 0 else COLOR_DANGER

    children.append(dbc.Card([
        dbc.CardHeader("Delta Score"),
        dbc.CardBody([
            html.H2(
                f"{arrow} {abs(delta.score_delta):.1f}",
                style={"color": color, "textAlign": "center"},
            ),
            html.P(
                f"Da {delta.previous_score:.0f} a {delta.current_score:.0f} "
                f"({delta.days_since_previous:.0f} giorni)",
                className="text-center text-muted",
            ),
        ]),
    ], style={"backgroundColor": CARD_BG, "border": f"1px solid {CARD_BORDER}"}, className="mb-3"))

    # Findings nuovi/risolti
    if delta.new_findings or delta.resolved_findings:
        children.append(dbc.Row([
            dbc.Col(dbc.Card([
                dbc.CardHeader("Nuovi Finding"),
                dbc.CardBody(html.Ul([html.Li(f) for f in delta.new_findings]) if delta.new_findings else html.P("Nessuno", className="text-muted")),
            ], style={"backgroundColor": CARD_BG, "border": f"1px solid {CARD_BORDER}"}), width=6),
            dbc.Col(dbc.Card([
                dbc.CardHeader("Finding Risolti"),
                dbc.CardBody(html.Ul([html.Li(f) for f in delta.resolved_findings]) if delta.resolved_findings else html.P("Nessuno", className="text-muted")),
            ], style={"backgroundColor": CARD_BG, "border": f"1px solid {CARD_BORDER}"}), width=6),
        ], className="mb-3"))

    return html.Div(children)


def _empty_state(title: str, description: str) -> html.Div:
    """Card stato vuoto per history."""
    return html.Div([
        html.H4("Storico Audit", className="mb-3"),
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
