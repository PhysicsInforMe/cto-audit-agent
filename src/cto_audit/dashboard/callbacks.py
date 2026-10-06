"""
Registrazione callback Dash: scan trigger, navigation, filtri.
"""

from __future__ import annotations

import json
import threading
from contextlib import nullcontext
from pathlib import Path
from typing import Optional

from dash import Input, Output, State, callback_context, no_update
from dash.exceptions import PreventUpdate

from cto_audit.core.models import AuditResult


def register_callbacks(app) -> None:
    """Registra tutti i callback sull'app Dash."""

    @app.callback(
        Output("page-content", "children"),
        [Input("url", "pathname"),
         Input("audit-result-store", "data")],
        [State("audit-delta-store", "data"),
         State("project-result-store", "data")],
    )
    def navigate(pathname, result_json, delta_json, project_json):
        """Routing URL → componente."""
        from cto_audit.dashboard.components.source_picker import build_source_picker

        result = _deserialize_result(result_json)
        delta = None

        if pathname == "/layers":
            from cto_audit.dashboard.components.layers import build_layers
            return build_layers(result)
        elif pathname == "/findings":
            from cto_audit.dashboard.components.findings import build_findings_table
            return build_findings_table(result)
        elif pathname == "/remediation":
            from cto_audit.dashboard.components.remediation import build_remediation
            return build_remediation(result)
        elif pathname == "/compliance":
            from cto_audit.dashboard.components.compliance import build_compliance
            return build_compliance(result)
        elif pathname == "/history":
            from cto_audit.dashboard.components.history import build_history
            return build_history(result, delta)
        elif pathname == "/guide":
            from cto_audit.dashboard.components.guide import build_guide
            return build_guide()
        elif pathname == "/project":
            from cto_audit.dashboard.components.project_view import build_project_view
            from cto_audit.core.project import AggregatedResult
            agg = None
            if project_json:
                try:
                    agg = AggregatedResult.model_validate_json(project_json)
                except Exception:
                    pass
            return build_project_view(agg)
        else:
            # Default: overview + source picker
            from dash import html
            from cto_audit.dashboard.components.overview import build_overview
            return html.Div([
                build_source_picker(),
                html.Hr(style={"borderColor": "#30363d"}),
                build_overview(result),
            ])

    @app.callback(
        [Output("audit-result-store", "data"),
         Output("scan-progress", "children"),
         Output("scan-status-store", "data")],
        [Input("start-scan-button", "n_clicks")],
        [State("source-type-dropdown", "value"),
         State("source-path-input", "value"),
         State("source-token-input", "value"),
         State("source-branch-input", "value")],
        prevent_initial_call=True,
    )
    def trigger_scan(n_clicks, source_type, path_or_url, token, branch):
        """Avvia un audit quando l'utente clicca 'Avvia Audit'."""
        import dash_bootstrap_components as dbc
        from dash import html

        if not path_or_url:
            return no_update, dbc.Alert("Inserisci un path o URL.", color="warning"), "idle"

        # Validazione input
        error = _validate_input(source_type, path_or_url.strip())
        if error:
            return no_update, dbc.Alert([
                html.Strong("Errore di input: "),
                error,
            ], color="warning"), "idle"

        try:
            result = _run_audit(source_type, path_or_url.strip(), token, branch)
            result_json = result.model_dump_json()
            return result_json, dbc.Alert("Audit completato!", color="success"), "done"
        except Exception as e:
            friendly = _friendly_error(str(e), source_type, path_or_url.strip())
            return no_update, dbc.Alert([
                html.Strong("Errore: "),
                html.Span(friendly),
            ], color="danger"), "error"


def _validate_input(source_type: str, path_or_url: str) -> Optional[str]:
    """Valida l'input utente e restituisce messaggio di errore o None."""
    import re

    if source_type == "local":
        p = Path(path_or_url)
        if not p.exists():
            return f"Il percorso '{path_or_url}' non esiste. Verifica che sia corretto."
        if not p.is_dir():
            return f"'{path_or_url}' non e una cartella. Inserisci il percorso di una directory."

    elif source_type in ("github", "gitlab", "bitbucket"):
        host_map = {
            "github": "github.com",
            "gitlab": "gitlab.com",
            "bitbucket": "bitbucket.org",
        }
        host = host_map[source_type]
        # Deve avere almeno owner/repo nell'URL
        pattern = rf"https?://{re.escape(host)}/[^/]+/[^/]+"
        if not re.match(pattern, path_or_url):
            if re.match(rf"https?://{re.escape(host)}/[^/]+/?$", path_or_url):
                return (
                    f"Hai inserito un profilo utente, non un repository. "
                    f"L'URL deve essere nel formato: https://{host}/owner/nome-repo"
                )
            return (
                f"URL non valido per {source_type}. "
                f"Formato atteso: https://{host}/owner/nome-repo"
            )

    elif source_type == "azure-devops":
        if "dev.azure.com" not in path_or_url and "visualstudio.com" not in path_or_url:
            return (
                "URL non valido per Azure DevOps. "
                "Formato atteso: https://dev.azure.com/org/project/_git/repo"
            )

    elif source_type == "archive":
        p = Path(path_or_url)
        if not p.exists():
            return f"Il file '{path_or_url}' non esiste."
        valid_ext = (".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tar")
        if not any(path_or_url.lower().endswith(ext) for ext in valid_ext):
            return f"Formato archivio non supportato. Formati validi: {', '.join(valid_ext)}"

    return None


def _friendly_error(error_msg: str, source_type: str, path_or_url: str) -> str:
    """Trasforma messaggi di errore tecnici in messaggi comprensibili."""
    lower = error_msg.lower()

    if "not found" in lower and "repository" in lower:
        return (
            f"Repository non trovato: '{path_or_url}'. "
            "Verifica che l'URL sia corretto e che il repository esista. "
            "Se e un repo privato, inserisci il token di autenticazione."
        )
    if "authentication" in lower or "401" in lower or "403" in lower:
        return (
            "Autenticazione fallita. Se il repository e privato, "
            "inserisci un token valido nel campo 'Token'."
        )
    if "git" in lower and ("not found" in lower or "not recognized" in lower):
        return (
            "Git non e installato o non e nel PATH. "
            "Per analizzare repository remoti, installa Git: https://git-scm.com"
        )
    if "could not resolve host" in lower or "name or service not known" in lower:
        return "Nessuna connessione a internet. Verifica la tua rete."
    if "permission denied" in lower:
        return f"Permesso negato per '{path_or_url}'. Verifica i permessi di accesso."
    if "not a directory" in lower or "is not a directory" in lower:
        return f"'{path_or_url}' non e una cartella. Inserisci il percorso di un progetto."

    return error_msg


def _run_audit(
    source_type: str,
    path_or_url: str,
    token: Optional[str],
    branch: Optional[str],
) -> AuditResult:
    """Esegue l'audit (sincrono, in thread del callback)."""
    from cto_audit.core.orchestrator import AuditOrchestrator
    from cto_audit.sources.factory import SourceFactory
    from cto_audit.sources.local import LocalRepoSource

    source = SourceFactory.create(
        source_type=source_type,
        path_or_url=path_or_url,
        token=token or None,
        branch=branch or None,
    )

    is_local = isinstance(source, LocalRepoSource)
    ctx = nullcontext(source) if is_local else source

    with ctx as active_source:
        if hasattr(active_source, "_temp_dir") and active_source._temp_dir:
            target_path = active_source._temp_dir
        else:
            target_path = Path(path_or_url).resolve()

        orchestrator = AuditOrchestrator(
            source=active_source,
            target_path=target_path,
            offline=True,
            auto_approve=True,
            board_report=True,
        )
        return orchestrator.run()


def _deserialize_result(json_data) -> Optional[AuditResult]:
    """Deserializza AuditResult da JSON string."""
    if not json_data:
        return None
    try:
        return AuditResult.model_validate_json(json_data)
    except Exception:
        return None
