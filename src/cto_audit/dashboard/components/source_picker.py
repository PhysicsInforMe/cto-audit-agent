"""
Componente Source Picker — Dropdown tipo sorgente, campi condizionali, bottone scan.
"""

from __future__ import annotations

import dash_bootstrap_components as dbc
from dash import dcc, html

from cto_audit.dashboard.theme import CARD_BG, CARD_BORDER, COLOR_GOOD, TEXT_SECONDARY

_INPUT_STYLE = {
    "backgroundColor": "#1c2128", "color": "#e6edf3",
    "border": f"1px solid {CARD_BORDER}",
}

_HELP_STYLE = {"color": TEXT_SECONDARY, "fontSize": "0.8rem", "marginTop": "4px"}

_PLACEHOLDERS = {
    "local": "C:\\Users\\mario\\progetti\\mio-app  oppure  /home/mario/app",
    "github": "https://github.com/owner/nome-repo",
    "gitlab": "https://gitlab.com/owner/nome-repo",
    "azure-devops": "https://dev.azure.com/org/project/_git/repo",
    "bitbucket": "https://bitbucket.org/owner/nome-repo",
    "archive": "C:\\Users\\mario\\code.zip  oppure  /tmp/code.tar.gz",
}


def build_source_picker() -> html.Div:
    """Costruisce il source picker per avviare un audit."""
    return html.Div([
        dbc.Card([
            dbc.CardHeader(html.H5("Avvia Audit")),
            dbc.CardBody([
                # Istruzioni rapide
                dbc.Alert([
                    html.Strong("Come si usa: "),
                    "1) Scegli il tipo di sorgente  ",
                    "2) Inserisci il path o URL del ",
                    html.Strong("repository"),
                    " (non del profilo utente)  ",
                    "3) Clicca 'Avvia Audit'",
                ], color="info", style={"fontSize": "0.85rem", "padding": "8px 12px"}),
                dbc.Row([
                    dbc.Col([
                        dbc.Label("Tipo Sorgente"),
                        dcc.Dropdown(
                            id="source-type-dropdown",
                            options=[
                                {"label": "Path Locale", "value": "local"},
                                {"label": "GitHub", "value": "github"},
                                {"label": "GitLab", "value": "gitlab"},
                                {"label": "Azure DevOps", "value": "azure-devops"},
                                {"label": "Bitbucket", "value": "bitbucket"},
                                {"label": "Archivio ZIP/tar", "value": "archive"},
                            ],
                            value="local",
                            clearable=False,
                            style={"backgroundColor": "#1c2128", "color": "#e6edf3"},
                        ),
                    ], width=4),
                    dbc.Col([
                        dbc.Label("Path / URL del repository"),
                        dbc.Input(
                            id="source-path-input",
                            type="text",
                            placeholder=_PLACEHOLDERS["local"],
                            style=_INPUT_STYLE,
                        ),
                        html.Div(
                            "Inserisci il percorso completo della cartella del progetto.",
                            id="source-path-help",
                            style=_HELP_STYLE,
                        ),
                    ], width=8),
                ], className="mb-3"),
                dbc.Row([
                    dbc.Col([
                        dbc.Label("Token (opzionale)"),
                        dbc.Input(
                            id="source-token-input",
                            type="password",
                            placeholder="Per repo private",
                            style=_INPUT_STYLE,
                        ),
                        html.Div(
                            "Necessario solo per repository privati.",
                            style=_HELP_STYLE,
                        ),
                    ], width=4),
                    dbc.Col([
                        dbc.Label("Branch (opzionale)"),
                        dbc.Input(
                            id="source-branch-input",
                            type="text",
                            placeholder="main, develop, v2.0...",
                            style=_INPUT_STYLE,
                        ),
                        html.Div(
                            "Lascia vuoto per il branch di default.",
                            style=_HELP_STYLE,
                        ),
                    ], width=4),
                    dbc.Col([
                        dbc.Label("\u00a0"),
                        html.Div([
                            dbc.Button(
                                "Avvia Audit",
                                id="start-scan-button",
                                color="success",
                                className="w-100",
                                style={"backgroundColor": COLOR_GOOD, "border": "none",
                                       "color": "#0d1117", "fontWeight": "bold"},
                            ),
                        ]),
                    ], width=4),
                ]),
            ]),
        ], style={"backgroundColor": CARD_BG, "border": f"1px solid {CARD_BORDER}"}),
        # Progress bar per scan in corso
        html.Div(id="scan-progress", className="mt-3"),
        # Interval per polling progresso
        dcc.Interval(id="scan-interval", interval=1000, disabled=True),
    ])
