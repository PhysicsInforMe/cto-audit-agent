"""
Integration test — verifica import chain completa: exe_entry → dashboard → layout.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


class TestExeImportChain:
    def test_import_exe_entry(self):
        """exe_entry è importabile senza errori."""
        from cto_audit import exe_entry
        assert hasattr(exe_entry, "main")

    def test_import_dashboard_app(self):
        """dashboard.app è importabile."""
        from cto_audit.dashboard.app import create_app
        assert callable(create_app)

    def test_create_app_senza_errori(self):
        """create_app() non produce errori."""
        from cto_audit.dashboard.app import create_app
        app = create_app()
        assert app is not None

    def test_layout_rendering_senza_errori(self):
        """Il layout si renderizza senza errori."""
        from cto_audit.dashboard.layout import build_layout
        layout = build_layout()
        assert layout is not None

    def test_yaml_data_trovati_dev_mode(self):
        """In dev mode, tutti i YAML data files sono trovati."""
        from cto_audit._data import get_data_dir

        for subdir in ["scoring-profiles", "remediation-kb", "compliance-profiles"]:
            data_dir = get_data_dir(subdir)
            assert data_dir.is_dir(), f"Directory {subdir} non trovata"

    def test_yaml_data_trovati_frozen_mode(self, tmp_path):
        """In frozen mode (mockato), i YAML data files sono trovati."""
        from cto_audit._data import get_data_dir

        meipass = tmp_path / "meipass"
        for subdir in ["scoring-profiles", "remediation-kb", "compliance-profiles"]:
            (meipass / subdir).mkdir(parents=True)
            (meipass / subdir / "test.yml").write_text("test: true", encoding="utf-8")

        with patch.object(sys, "_MEIPASS", str(meipass), create=True):
            for subdir in ["scoring-profiles", "remediation-kb", "compliance-profiles"]:
                result = get_data_dir(subdir)
                assert result == meipass / subdir
