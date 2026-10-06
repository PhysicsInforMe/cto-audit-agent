"""
Componente Compliance — Card per profilo NIS2/GDPR, progress ring, tabella controlli.
"""

from __future__ import annotations

from typing import Optional

import dash_bootstrap_components as dbc
import plotly.graph_objects as go
from dash import dcc, html

from cto_audit.core.models import AuditResult, ComplianceResult
from cto_audit.dashboard.theme import (
    CARD_BG, CARD_BORDER, COLOR_GOOD, COLOR_WARNING, COLOR_DANGER, TEXT_PRIMARY,
)


def compliance_ring(cr: ComplianceResult) -> dcc.Graph:
    """Ring chart per un profilo compliance."""
    pct = cr.checks_satisfied / cr.checks_total * 100 if cr.checks_total > 0 else 0
    fig = go.Figure(go.Pie(
        values=[cr.checks_satisfied, cr.checks_partial, cr.checks_not_satisfied],
        labels=["Soddisfatti", "Parziali", "Non soddisfatti"],
        marker={"colors": [COLOR_GOOD, COLOR_WARNING, COLOR_DANGER]},
        hole=0.65,
        textinfo="none",
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": TEXT_PRIMARY},
        height=200,
        margin=dict(t=20, b=20, l=20, r=20),
        showlegend=False,
        annotations=[{
            "text": f"{pct:.0f}%",
            "x": 0.5, "y": 0.5,
            "font": {"size": 24, "color": TEXT_PRIMARY},
            "showarrow": False,
        }],
    )
    return dcc.Graph(figure=fig, config={"displayModeBar": False})


def compliance_card(cr: ComplianceResult) -> dbc.Card:
    """Card per un singolo profilo compliance."""
    return dbc.Card([
        dbc.CardHeader(html.H5(cr.profile_name.upper())),
        dbc.CardBody([
            compliance_ring(cr),
            html.P(
                f"{cr.checks_satisfied}/{cr.checks_total} controlli soddisfatti",
                className="text-center text-muted",
            ),
        ]),
    ], style={"backgroundColor": CARD_BG, "border": f"1px solid {CARD_BORDER}"})


def build_compliance(result: Optional[AuditResult]) -> html.Div:
    """Costruisce la vista compliance."""
    if result is None:
        return _empty_state(
            "Nessun audit disponibile.",
            "Avvia un audit dalla pagina Overview per visualizzare lo stato compliance.",
        )

    crs = result.health_score.compliance_results
    if not crs:
        return _empty_state(
            "Nessun profilo compliance attivato.",
            "I profili compliance (NIS2, GDPR) vengono attivati automaticamente "
            "quando il progetto contiene indicatori rilevanti. "
            "Per forzare un profilo, usa il flag --compliance-profile da CLI.",
        )

    cards = [dbc.Col(compliance_card(cr), width=4) for cr in crs]

    return html.Div([
        html.H4("Compliance", className="mb-3"),
        dbc.Row(cards, className="mb-4"),
    ])


def _empty_state(title: str, description: str) -> html.Div:
    """Card stato vuoto per compliance."""
    return html.Div([
        html.H4("Compliance", className="mb-3"),
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
