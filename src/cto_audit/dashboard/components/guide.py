"""
Componente Guida — Documentazione integrata nella dashboard.
"""

from __future__ import annotations

import dash_bootstrap_components as dbc
from dash import html

from cto_audit.dashboard.theme import CARD_BG, CARD_BORDER, TEXT_SECONDARY


def build_guide() -> html.Div:
    """Costruisce la pagina di guida utente."""
    return html.Div([
        html.H3("Guida Utente", className="mb-4"),

        # --- Come avviare un audit ---
        _section("Come avviare un audit", [
            _step("1", "Scegli il tipo di sorgente",
                  "Seleziona 'Path Locale' per analizzare una cartella sul tuo computer, "
                  "oppure 'GitHub', 'GitLab', ecc. per un repository remoto."),
            _step("2", "Inserisci il percorso o URL",
                  "Per sorgenti locali: il percorso completo della cartella del progetto. "
                  "Per sorgenti remote: l'URL completo del repository (non del profilo utente)."),
            _step("3", "Clicca 'Avvia Audit'",
                  "L'analisi richiede alcuni secondi. Al termine, i risultati compariranno "
                  "automaticamente nelle sezioni Overview, Layers, Findings, ecc."),
        ]),

        # --- Formati URL corretti ---
        _section("Formati URL corretti", [
            _table([
                ("GitHub", "https://github.com/owner/nome-repo",
                 "https://github.com/owner (profilo, non repo!)"),
                ("GitLab", "https://gitlab.com/owner/nome-repo",
                 "https://gitlab.com/owner"),
                ("Azure DevOps", "https://dev.azure.com/org/project/_git/repo",
                 "https://dev.azure.com/org"),
                ("Bitbucket", "https://bitbucket.org/owner/nome-repo",
                 "https://bitbucket.org/owner"),
            ]),
            html.P([
                html.Strong("Attenzione: "),
                "l'URL deve puntare a un ",
                html.Strong("repository specifico"),
                ", non alla pagina del profilo utente o dell'organizzazione.",
            ], style={"color": "#f0b400", "fontSize": "0.9rem", "marginTop": "8px"}),
        ]),

        # --- Interpretare i risultati ---
        _section("Interpretare i risultati", [
            html.H6("Health Score (0-100)", style={"color": "#e6edf3"}),
            _score_table(),
            html.H6("I 4 Layer di analisi", className="mt-3", style={"color": "#e6edf3"}),
            _layer_table(),
        ]),

        # --- Interpretare i finding ---
        _section("Severity dei finding", [
            _severity_table(),
            html.P(
                "I finding sono i singoli problemi rilevati dall'audit. Ogni finding ha un "
                "rule_id (es. SEC-SECRETS-CODE-001) che identifica la regola, una severity "
                "che indica la gravita, e una penalty che riduce il punteggio del layer.",
                style={"color": TEXT_SECONDARY, "marginTop": "8px"},
            ),
        ]),

        # --- Sezioni della dashboard ---
        _section("Sezioni della dashboard", [
            _nav_table(),
        ]),

        # --- Errori comuni ---
        _section("Errori comuni e soluzioni", [
            _error_table(),
        ]),

        # --- Repo private ---
        _section("Repository privati", [
            html.P([
                "Per analizzare repository privati, inserisci un ",
                html.Strong("token di autenticazione"),
                " nel campo 'Token':",
            ], style={"color": "#e6edf3"}),
            html.Ul([
                html.Li("GitHub: Personal Access Token (Settings > Developer settings > Tokens)"),
                html.Li("GitLab: Personal Access Token (Preferences > Access Tokens)"),
                html.Li("Azure DevOps: Personal Access Token (User Settings > PAT)"),
                html.Li("Bitbucket: App Password (Personal settings > App passwords)"),
            ], style={"color": TEXT_SECONDARY, "fontSize": "0.9rem"}),
            html.P(
                "Il token non viene mai salvato o loggato. Viene usato solo per il clone.",
                style={"color": TEXT_SECONDARY, "fontStyle": "italic"},
            ),
        ]),
    ])


def _section(title: str, children: list) -> dbc.Card:
    """Crea una sezione della guida."""
    return dbc.Card([
        dbc.CardHeader(html.H5(title)),
        dbc.CardBody(children),
    ], style={"backgroundColor": CARD_BG, "border": f"1px solid {CARD_BORDER}"},
       className="mb-3")


def _step(number: str, title: str, desc: str) -> html.Div:
    """Crea uno step numerato."""
    return html.Div([
        html.Div([
            html.Span(number, style={
                "backgroundColor": "#00ff41", "color": "#0d1117",
                "borderRadius": "50%", "width": "28px", "height": "28px",
                "display": "inline-flex", "alignItems": "center",
                "justifyContent": "center", "fontWeight": "bold",
                "marginRight": "10px", "fontSize": "0.9rem",
            }),
            html.Strong(title, style={"color": "#e6edf3"}),
        ], style={"display": "flex", "alignItems": "center", "marginBottom": "4px"}),
        html.P(desc, style={"color": TEXT_SECONDARY, "marginLeft": "38px",
                            "marginBottom": "12px", "fontSize": "0.9rem"}),
    ])


def _table(rows: list) -> dbc.Table:
    """Crea una tabella URL con colonne Sorgente, Corretto, Sbagliato."""
    header = html.Thead(html.Tr([
        html.Th("Sorgente"), html.Th("URL Corretto"), html.Th("URL Sbagliato"),
    ]))
    body = html.Tbody([
        html.Tr([
            html.Td(r[0]),
            html.Td(r[1], style={"color": "#00ff41", "fontFamily": "monospace", "fontSize": "0.85rem"}),
            html.Td(r[2], style={"color": "#ff3333", "fontFamily": "monospace", "fontSize": "0.85rem"}),
        ]) for r in rows
    ])
    return dbc.Table([header, body], bordered=True, color="dark",
                     style={"fontSize": "0.9rem"})


def _score_table() -> dbc.Table:
    """Tabella interpretazione Health Score."""
    rows = [
        ("90-100", "Eccellente", "Pratiche mature, rischio minimo", "#00ff41"),
        ("75-89", "Buono", "Solida base con aree di miglioramento", "#00ff41"),
        ("60-74", "Sufficiente", "Funziona ma accumula tech debt", "#f0b400"),
        ("40-59", "Insufficiente", "Rischi significativi, remediation urgente", "#ff6b35"),
        ("0-39", "Critico", "Rischio operativo elevato, intervento immediato", "#ff3333"),
    ]
    header = html.Thead(html.Tr([html.Th("Range"), html.Th("Giudizio"), html.Th("Significato")]))
    body = html.Tbody([
        html.Tr([
            html.Td(r[0], style={"color": r[3], "fontWeight": "bold"}),
            html.Td(r[1]), html.Td(r[2]),
        ]) for r in rows
    ])
    return dbc.Table([header, body], bordered=True, color="dark",
                     style={"fontSize": "0.9rem"})


def _layer_table() -> dbc.Table:
    """Tabella dei 4 layer."""
    rows = [
        ("Security", "0.30", "Secrets, SQL injection, CVE, autenticazione, crittografia"),
        ("Architecture", "0.25", "Struttura progetto, coupling, test, migrazioni"),
        ("Infrastructure", "0.25", "CI/CD, Docker, IaC, monitoraggio, lockfile"),
        ("Quality", "0.20", "README, linter, typing, complessita, pre-commit"),
    ]
    header = html.Thead(html.Tr([html.Th("Layer"), html.Th("Peso"), html.Th("Cosa analizza")]))
    body = html.Tbody([html.Tr([html.Td(r[0]), html.Td(r[1]), html.Td(r[2])]) for r in rows])
    return dbc.Table([header, body], bordered=True, color="dark",
                     style={"fontSize": "0.9rem"})


def _severity_table() -> dbc.Table:
    """Tabella severity."""
    rows = [
        ("critical", "Rischio immediato, potenzialmente esistenziale", "#ff3333"),
        ("high", "Rischio significativo per operativita o sicurezza", "#ff6b35"),
        ("medium", "Problema reale ma gestibile", "#f0b400"),
        ("low", "Miglioramento consigliato, non urgente", "#58a6ff"),
        ("info", "Osservazione informativa, nessuna penalita", "#8b949e"),
    ]
    header = html.Thead(html.Tr([html.Th("Severity"), html.Th("Significato")]))
    body = html.Tbody([
        html.Tr([
            html.Td(r[0], style={"color": r[2], "fontWeight": "bold"}),
            html.Td(r[1]),
        ]) for r in rows
    ])
    return dbc.Table([header, body], bordered=True, color="dark",
                     style={"fontSize": "0.9rem"})


def _nav_table() -> dbc.Table:
    """Tabella sezioni dashboard."""
    rows = [
        ("Overview", "Punteggio complessivo, breakdown per layer, stack tecnologico rilevato"),
        ("Layers", "Dettaglio per ogni layer: finding, evidence chain, regole attivate"),
        ("Findings", "Tabella di tutti i finding, filtrabile per severity, layer e rule_id"),
        ("Remediation", "Azioni prioritarie ordinate per impatto/sforzo, simulazione what-if"),
        ("Compliance", "Stato dei controlli NIS2 e GDPR, percentuale di conformita"),
        ("History", "Confronto con l'audit precedente: score trend, finding nuovi e risolti"),
        ("Progetto", "Vista multi-repo con score aggregato (richiede config YAML)"),
    ]
    header = html.Thead(html.Tr([html.Th("Sezione"), html.Th("Cosa mostra")]))
    body = html.Tbody([html.Tr([html.Td(r[0]), html.Td(r[1])]) for r in rows])
    return dbc.Table([header, body], bordered=True, color="dark",
                     style={"fontSize": "0.9rem"})


def _error_table() -> dbc.Table:
    """Tabella errori comuni."""
    rows = [
        ("Repository non trovato",
         "L'URL non punta a un repository valido. Verifica che sia l'URL "
         "del repo (con owner/nome-repo), non del profilo utente."),
        ("Autenticazione fallita",
         "Il repository e privato e serve un token. Genera un Personal Access Token "
         "dalla piattaforma e inseriscilo nel campo 'Token'."),
        ("Git non trovato",
         "Git non e installato. Per repo remoti, installa Git da https://git-scm.com"),
        ("Percorso non esiste",
         "Il path locale inserito non esiste. Verifica il percorso completo della cartella."),
        ("Nessuna connessione",
         "Non c'e connessione a internet. Per repo remoti serve la rete. "
         "Per analisi offline, usa un path locale."),
    ]
    header = html.Thead(html.Tr([html.Th("Errore"), html.Th("Soluzione")]))
    body = html.Tbody([
        html.Tr([
            html.Td(r[0], style={"color": "#ff3333", "fontWeight": "bold"}),
            html.Td(r[1]),
        ]) for r in rows
    ])
    return dbc.Table([header, body], bordered=True, color="dark",
                     style={"fontSize": "0.9rem"})
