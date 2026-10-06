"""
Integration test — creazione app, verifica layout, dcc.Store inizializzati.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from cto_audit.core.models import (
    AuditMetadata, AuditResult, HealthScore, StackInfo,
    LayerScore, Layer, Finding, Severity, EvidenceChain,
)
from cto_audit.dashboard.app import create_app


class TestCreateApp:
    def test_crea_app(self):
        app = create_app()
        assert app is not None
        assert app.title == "CTO Audit Agent"

    def test_layout_non_none(self):
        app = create_app()
        assert app.layout is not None

    def test_layout_contiene_stores(self):
        """Layout contiene tutti i dcc.Store necessari."""
        app = create_app()
        # Naviga il layout tree per trovare gli store
        layout_str = str(app.layout)
        assert "audit-result-store" in layout_str
        assert "audit-delta-store" in layout_str
        assert "project-result-store" in layout_str
        assert "scan-status-store" in layout_str

    def test_layout_contiene_location(self):
        """Layout contiene dcc.Location per routing."""
        app = create_app()
        layout_str = str(app.layout)
        assert "url" in layout_str

    def test_layout_contiene_sidebar(self):
        """Layout contiene la sidebar con navigation."""
        app = create_app()
        layout_str = str(app.layout)
        assert "nav-overview" in layout_str
        assert "nav-layers" in layout_str
        assert "nav-findings" in layout_str

    def test_custom_title(self):
        app = create_app(title="Test Dashboard")
        assert app.title == "Test Dashboard"


class TestDashboardScanIntegration:
    def test_scan_produce_risultato_visualizzabile(self, tmp_path):
        """Simula: source picker → scan → risultato in store → rendering."""
        from cto_audit.dashboard.callbacks import _run_audit
        from cto_audit.dashboard.components.overview import build_overview

        (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
        (tmp_path / "README.md").write_text("# Test\n", encoding="utf-8")

        result = _run_audit("local", str(tmp_path), None, None)
        assert isinstance(result, AuditResult)

        # Il risultato è renderizzabile senza errori
        overview = build_overview(result)
        assert overview is not None

    def test_scan_risultato_serializzabile_e_deserializzabile(self, tmp_path):
        """Il risultato è serializzabile in JSON e ricostruibile."""
        from cto_audit.dashboard.callbacks import _run_audit, _deserialize_result

        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

        result = _run_audit("local", str(tmp_path), None, None)
        json_str = result.model_dump_json()

        restored = _deserialize_result(json_str)
        assert restored is not None
        assert restored.health_score.overall_score == result.health_score.overall_score

    def test_tutti_i_componenti_renderizzano(self, tmp_path):
        """Tutti i componenti renderizzano senza errore con dati reali."""
        from cto_audit.dashboard.callbacks import _run_audit

        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text(
            "from flask import Flask\napp = Flask(__name__)\n",
            encoding="utf-8",
        )
        (tmp_path / "requirements.txt").write_text("flask>=3.0\n", encoding="utf-8")

        result = _run_audit("local", str(tmp_path), None, None)

        from cto_audit.dashboard.components.overview import build_overview
        from cto_audit.dashboard.components.layers import build_layers
        from cto_audit.dashboard.components.findings import build_findings_table
        from cto_audit.dashboard.components.remediation import build_remediation
        from cto_audit.dashboard.components.compliance import build_compliance
        from cto_audit.dashboard.components.history import build_history
        from cto_audit.dashboard.components.source_picker import build_source_picker

        assert build_overview(result) is not None
        assert build_layers(result) is not None
        assert build_findings_table(result) is not None
        assert build_remediation(result) is not None
        assert build_compliance(result) is not None
        assert build_history(result) is not None
        assert build_source_picker() is not None
