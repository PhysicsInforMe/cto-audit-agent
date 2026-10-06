"""
Layout principale della dashboard con sidebar navigation.
"""

from __future__ import annotations

import dash_bootstrap_components as dbc
from dash import dcc, html

from cto_audit.dashboard.theme import BG_DARK, CARD_BG, CARD_BORDER, COLOR_GOOD, TEXT_PRIMARY, CUSTOM_CSS


def build_layout() -> html.Div:
    """Costruisce il layout principale della dashboard."""
    sidebar = html.Div([
        html.H4("CTO AUDIT", className="mb-4", style={"color": COLOR_GOOD, "fontWeight": "bold"}),
        dbc.Nav([
            dbc.NavLink("Overview", href="/", active="exact", id="nav-overview"),
            dbc.NavLink("Layers", href="/layers", active="exact", id="nav-layers"),
            dbc.NavLink("Findings", href="/findings", active="exact", id="nav-findings"),
            dbc.NavLink("Remediation", href="/remediation", active="exact", id="nav-remediation"),
            dbc.NavLink("Compliance", href="/compliance", active="exact", id="nav-compliance"),
            dbc.NavLink("History", href="/history", active="exact", id="nav-history"),
            dbc.NavLink("Progetto", href="/project", active="exact", id="nav-project"),
            dbc.NavLink("Guida", href="/guide", active="exact", id="nav-guide",
                        style={"marginTop": "12px", "borderTop": f"1px solid {CARD_BORDER}",
                               "paddingTop": "12px"}),
        ], vertical=True, pills=True),
        html.Hr(style={"borderColor": CARD_BORDER}),
        html.Div(id="source-picker-sidebar"),
    ], style={
        "position": "fixed", "top": 0, "left": 0, "bottom": 0,
        "width": "220px", "padding": "20px",
        "backgroundColor": CARD_BG,
        "borderRight": f"1px solid {CARD_BORDER}",
        "overflowY": "auto",
    })

    content = html.Div([
        dcc.Location(id="url", refresh=False),
        html.Div(id="page-content", style={"padding": "20px"}),
    ], style={
        "marginLeft": "220px",
        "backgroundColor": BG_DARK,
        "minHeight": "100vh",
    })

    return html.Div([
        # CSS personalizzato
        html.Div(style={"display": "none"}, id="custom-css-holder"),
        dcc.Markdown(
            f"<style>{CUSTOM_CSS}</style>",
            dangerously_allow_html=True,
        ),
        # Store per dati audit
        dcc.Store(id="audit-result-store"),
        dcc.Store(id="audit-delta-store"),
        dcc.Store(id="project-result-store"),
        dcc.Store(id="scan-status-store", data="idle"),
        # Layout
        sidebar,
        content,
    ], style={"backgroundColor": BG_DARK})
