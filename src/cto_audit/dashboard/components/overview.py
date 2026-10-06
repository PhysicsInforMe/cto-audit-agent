"""
Componente Overview — Gauge health score, card layer, stack badges, maturity.
"""

from __future__ import annotations

from typing import Any, Optional

import dash_bootstrap_components as dbc
import plotly.graph_objects as go
from dash import dcc, html

from cto_audit.core.models import AuditResult
from cto_audit.dashboard.theme import (
    BG_DARK, CARD_BG, CARD_BORDER, COLOR_GOOD, COLOR_WARNING, COLOR_DANGER,
    TEXT_PRIMARY, TEXT_SECONDARY, score_color,
)


def health_gauge(score: float) -> dcc.Graph:
    """Gauge indicatore per l'health score complessivo."""
    color = score_color(score)
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        title={"text": "Health Score", "font": {"color": TEXT_PRIMARY, "size": 18}},
        number={"font": {"color": color, "size": 48}, "suffix": "/100"},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": TEXT_SECONDARY},
            "bar": {"color": color},
            "bgcolor": CARD_BG,
            "bordercolor": CARD_BORDER,
            "steps": [
                {"range": [0, 40], "color": "rgba(255,51,51,0.15)"},
                {"range": [40, 70], "color": "rgba(240,180,0,0.15)"},
                {"range": [70, 100], "color": "rgba(0,255,65,0.15)"},
            ],
        },
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": TEXT_PRIMARY},
        height=250,
        margin=dict(t=50, b=10, l=30, r=30),
    )
    return dcc.Graph(figure=fig, config={"displayModeBar": False})


def layer_card(layer_name: str, score: float, finding_count: int) -> dbc.Card:
    """Card per un singolo layer."""
    color = score_color(score)
    return dbc.Card([
        dbc.CardBody([
            html.H6(layer_name.upper(), className="text-muted mb-2"),
            html.H3(f"{score:.0f}", style={"color": color}),
            html.Small(f"{finding_count} finding", className="text-muted"),
        ], style={"textAlign": "center"}),
    ], style={"backgroundColor": CARD_BG, "border": f"1px solid {CARD_BORDER}"})


def stack_badges(languages: dict[str, float], frameworks: list[str]) -> html.Div:
    """Badges per linguaggi e framework."""
    badges = []
    for lang, pct in sorted(languages.items(), key=lambda x: -x[1]):
        badges.append(dbc.Badge(
            f"{lang} {pct*100:.0f}%",
            color="dark",
            className="me-1 mb-1",
            style={"border": f"1px solid {COLOR_GOOD}"},
        ))
    for fw in frameworks:
        badges.append(dbc.Badge(
            fw, color="dark", className="me-1 mb-1",
            style={"border": f"1px solid {TEXT_SECONDARY}"},
        ))
    return html.Div(badges)


def build_overview(result: Optional[AuditResult]) -> html.Div:
    """Costruisce la vista overview completa."""
    if result is None:
        return html.Div(
            dbc.Card([
                dbc.CardBody([
                    html.H5(
                        "Nessun audit disponibile.",
                        style={"color": "#e6edf3", "textAlign": "center"},
                    ),
                    html.P(
                        "Seleziona il tipo di sorgente, inserisci il path o URL "
                        "del repository e clicca 'Avvia Audit' per iniziare.",
                        style={
                            "color": "#8b949e", "textAlign": "center",
                            "maxWidth": "500px", "margin": "12px auto 0",
                        },
                    ),
                ], style={"padding": "40px 20px"}),
            ], style={"backgroundColor": CARD_BG, "border": f"1px solid {CARD_BORDER}"}),
        )

    hs = result.health_score
    layer_cards = []
    for layer_name, ls in hs.layer_scores.items():
        layer_cards.append(dbc.Col(
            layer_card(layer_name, ls.score, len(ls.findings)),
            width=3,
        ))

    return html.Div([
        dbc.Row([
            dbc.Col(health_gauge(hs.overall_score), width=4),
            dbc.Col([
                html.H5("Stack Tecnologico", className="mb-3"),
                stack_badges(result.stack_info.languages, result.stack_info.frameworks),
                html.Hr(style={"borderColor": CARD_BORDER}),
                html.Small(
                    f"Tipo progetto: {result.metadata.project_type or 'N/A'}",
                    className="text-muted",
                ),
            ], width=8),
        ], className="mb-4"),
        dbc.Row(layer_cards, className="mb-4"),
    ])
