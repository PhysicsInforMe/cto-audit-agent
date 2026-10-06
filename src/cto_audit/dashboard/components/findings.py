"""
Componente Findings — DataTable filtrabile/ordinabile.
"""

from __future__ import annotations

from typing import Optional

import dash_bootstrap_components as dbc
from dash import dash_table, html

from cto_audit.core.models import AuditResult
from cto_audit.dashboard.theme import CARD_BG, CARD_BORDER, TEXT_PRIMARY, TEXT_SECONDARY


def build_findings_table(result: Optional[AuditResult]) -> html.Div:
    """Tabella findings filtrabile per severity, layer, rule_id."""
    if result is None:
        return html.Div(html.P("Nessun dato.", className="text-muted text-center mt-5"))

    all_findings = []
    for layer_name, ls in result.health_score.layer_scores.items():
        for f in ls.findings:
            all_findings.append({
                "severity": f.severity.value.upper(),
                "layer": layer_name.upper(),
                "rule_id": f.rule_id,
                "title": f.title,
                "file": f.file_path or "-",
                "confidence": f"{f.confidence:.0%}",
            })

    if not all_findings:
        return html.Div(html.P("Nessun finding rilevato.", className="text-muted text-center mt-5"))

    return html.Div([
        html.H4("Tutti i Findings", className="mb-3"),
        dash_table.DataTable(
            id="findings-table",
            columns=[
                {"name": "Severity", "id": "severity"},
                {"name": "Layer", "id": "layer"},
                {"name": "Rule ID", "id": "rule_id"},
                {"name": "Title", "id": "title"},
                {"name": "File", "id": "file"},
                {"name": "Confidence", "id": "confidence"},
            ],
            data=all_findings,
            filter_action="native",
            sort_action="native",
            sort_mode="multi",
            page_size=20,
            style_header={
                "backgroundColor": CARD_BG,
                "color": TEXT_PRIMARY,
                "fontWeight": "bold",
                "border": f"1px solid {CARD_BORDER}",
            },
            style_cell={
                "backgroundColor": CARD_BG,
                "color": TEXT_PRIMARY,
                "border": f"1px solid {CARD_BORDER}",
                "textAlign": "left",
                "padding": "8px",
                "fontFamily": "monospace",
                "fontSize": "13px",
            },
            style_filter={
                "backgroundColor": "#1c2128",
                "color": TEXT_PRIMARY,
            },
            style_data_conditional=[
                {"if": {"filter_query": '{severity} = "CRITICAL"'}, "color": "#ff3333"},
                {"if": {"filter_query": '{severity} = "HIGH"'}, "color": "#ff6b6b"},
                {"if": {"filter_query": '{severity} = "MEDIUM"'}, "color": "#f0b400"},
                {"if": {"filter_query": '{severity} = "LOW"'}, "color": "#58a6ff"},
                {"if": {"filter_query": '{severity} = "INFO"'}, "color": TEXT_SECONDARY},
            ],
        ),
    ])
