"""
Componente Project View — Vista multi-repo: score aggregato + breakdown per repo.
"""

from __future__ import annotations

from typing import Optional

import dash_bootstrap_components as dbc
import plotly.graph_objects as go
from dash import dcc, html

from cto_audit.core.project import AggregatedResult
from cto_audit.dashboard.theme import (
    CARD_BG, CARD_BORDER, COLOR_GOOD, COLOR_WARNING, COLOR_DANGER,
    TEXT_PRIMARY, TEXT_SECONDARY, score_color,
)


def build_project_view(aggregated: Optional[AggregatedResult]) -> html.Div:
    """Costruisce la vista progetto multi-repo."""
    if aggregated is None:
        return html.Div([
            html.H4("Vista Progetto", className="mb-3"),
            dbc.Card([
                dbc.CardBody([
                    html.H5(
                        "Nessun progetto multi-repo caricato.",
                        style={"color": "#e6edf3", "textAlign": "center"},
                    ),
                    html.P(
                        "La vista progetto permette di analizzare piu repository insieme "
                        "con uno score aggregato. Per usarla, crea un file YAML di configurazione "
                        "e avvia con: cto-audit project config.yml",
                        style={
                            "color": "#8b949e", "textAlign": "center",
                            "maxWidth": "500px", "margin": "12px auto 0",
                        },
                    ),
                ], style={"padding": "40px 20px"}),
            ], style={"backgroundColor": CARD_BG, "border": f"1px solid {CARD_BORDER}"}),
        ])

    # Score aggregato
    agg_color = score_color(aggregated.aggregated_score)

    # Bar chart per repo
    names = [sr.name for sr in aggregated.source_results]
    scores = [sr.audit_result.health_score.overall_score for sr in aggregated.source_results]
    colors = [score_color(s) for s in scores]

    fig = go.Figure(go.Bar(
        x=names, y=scores,
        marker_color=colors,
        text=[f"{s:.0f}" for s in scores],
        textposition="auto",
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": TEXT_PRIMARY},
        yaxis={"range": [0, 100], "title": "Score"},
        xaxis={"title": "Repository"},
        height=300,
        margin=dict(t=20, b=60, l=50, r=20),
    )

    return html.Div([
        html.H4(f"Progetto: {aggregated.project_name}", className="mb-3"),
        dbc.Row([
            dbc.Col(dbc.Card([
                dbc.CardBody([
                    html.H6("Score Aggregato", className="text-muted"),
                    html.H2(f"{aggregated.aggregated_score:.0f}/100", style={"color": agg_color}),
                ], style={"textAlign": "center"}),
            ], style={"backgroundColor": CARD_BG, "border": f"1px solid {CARD_BORDER}"}), width=3),
            dbc.Col(dbc.Card([
                dbc.CardBody([
                    html.H6("LOC Totali", className="text-muted"),
                    html.H2(f"{aggregated.total_loc:,}"),
                ], style={"textAlign": "center"}),
            ], style={"backgroundColor": CARD_BG, "border": f"1px solid {CARD_BORDER}"}), width=3),
            dbc.Col(dbc.Card([
                dbc.CardBody([
                    html.H6("Sorgenti", className="text-muted"),
                    html.H2(str(aggregated.total_sources)),
                ], style={"textAlign": "center"}),
            ], style={"backgroundColor": CARD_BG, "border": f"1px solid {CARD_BORDER}"}), width=3),
            dbc.Col(dbc.Card([
                dbc.CardBody([
                    html.H6("Fallite", className="text-muted"),
                    html.H2(str(len(aggregated.failed_sources)),
                            style={"color": COLOR_DANGER if aggregated.failed_sources else COLOR_GOOD}),
                ], style={"textAlign": "center"}),
            ], style={"backgroundColor": CARD_BG, "border": f"1px solid {CARD_BORDER}"}), width=3),
        ], className="mb-4"),
        dbc.Card([
            dbc.CardHeader("Score per Repository"),
            dbc.CardBody(dcc.Graph(figure=fig, config={"displayModeBar": False})),
        ], style={"backgroundColor": CARD_BG, "border": f"1px solid {CARD_BORDER}"}),
    ])
