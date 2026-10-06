"""
Componente Layers — Tab per layer, findings list, evidence chain table.
"""

from __future__ import annotations

from typing import Optional

import dash_bootstrap_components as dbc
from dash import html

from cto_audit.core.models import AuditResult, LayerScore
from cto_audit.dashboard.theme import CARD_BG, CARD_BORDER, score_color


def layer_detail(layer_name: str, ls: LayerScore) -> dbc.Card:
    """Dettaglio di un singolo layer con findings ed evidence chain."""
    findings_rows = []
    for f in ls.findings:
        findings_rows.append(html.Tr([
            html.Td(f.severity.value.upper(),
                     style={"color": score_color(100 if f.severity.value == "info" else 0)}),
            html.Td(f.rule_id, className="monospace"),
            html.Td(f.title),
            html.Td(f.file_path or "-", className="monospace"),
        ]))

    evidence_rows = []
    for ev in ls.evidence_chain:
        evidence_rows.append(html.Tr([
            html.Td(ev.rule_id, className="monospace"),
            html.Td(f"{ev.weight:.2f}"),
            html.Td(f"{ev.penalty:.1f}"),
            html.Td(ev.framework_ref or "-"),
        ]))

    return dbc.Card([
        dbc.CardHeader(html.H5(f"{layer_name.upper()} — {ls.score:.0f}/100",
                                style={"color": score_color(ls.score)})),
        dbc.CardBody([
            html.H6("Findings"),
            dbc.Table([
                html.Thead(html.Tr([
                    html.Th("Severity"), html.Th("Rule"), html.Th("Title"), html.Th("File"),
                ])),
                html.Tbody(findings_rows),
            ], bordered=True, hover=True, size="sm", color="dark") if findings_rows else html.P("Nessun finding.", className="text-muted"),
            html.Hr(style={"borderColor": CARD_BORDER}),
            html.H6("Evidence Chain"),
            dbc.Table([
                html.Thead(html.Tr([
                    html.Th("Rule"), html.Th("Weight"), html.Th("Penalty"), html.Th("Framework"),
                ])),
                html.Tbody(evidence_rows),
            ], bordered=True, hover=True, size="sm", color="dark") if evidence_rows else html.P("Nessuna evidenza.", className="text-muted"),
        ]),
    ], style={"backgroundColor": CARD_BG, "border": f"1px solid {CARD_BORDER}"}, className="mb-3")


def build_layers(result: Optional[AuditResult]) -> html.Div:
    """Costruisce la vista layers con tab."""
    if result is None:
        return html.Div(html.P("Nessun dato.", className="text-muted text-center mt-5"))

    tabs = []
    for layer_name, ls in result.health_score.layer_scores.items():
        tabs.append(dbc.Tab(
            layer_detail(layer_name, ls),
            label=f"{layer_name.upper()} ({ls.score:.0f})",
        ))

    return html.Div([
        html.H4("Analisi per Layer", className="mb-3"),
        dbc.Tabs(tabs),
    ])
