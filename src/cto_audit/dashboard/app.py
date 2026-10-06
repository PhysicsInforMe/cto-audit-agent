"""
Dash app factory — crea e configura l'applicazione dashboard.
"""

from __future__ import annotations

from typing import Optional

import dash
import dash_bootstrap_components as dbc

from cto_audit.dashboard.callbacks import register_callbacks
from cto_audit.dashboard.layout import build_layout


def create_app(
    debug: bool = False,
    title: str = "CTO Audit Agent",
) -> dash.Dash:
    """
    Crea e configura l'app Dash.

    Args:
        debug: Attiva debug mode
        title: Titolo della pagina

    Returns:
        App Dash configurata e pronta per il run
    """
    app = dash.Dash(
        __name__,
        external_stylesheets=[dbc.themes.CYBORG],
        title=title,
        suppress_callback_exceptions=True,
    )

    app.layout = build_layout()
    register_callbacks(app)

    return app
