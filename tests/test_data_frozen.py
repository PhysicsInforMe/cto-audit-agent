"""
Test per _data.get_data_dir con sys._MEIPASS mockato (frozen mode).
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from cto_audit._data import get_data_dir


class TestDataFrozenMode:
    def test_frozen_mode_trova_dati(self, tmp_path):
        """In frozen mode, cerca prima in MEIPASS."""
        # Crea una dir che simula MEIPASS
        meipass = tmp_path / "meipass"
        (meipass / "scoring-profiles").mkdir(parents=True)
        (meipass / "scoring-profiles" / "default.yml").write_text("test", encoding="utf-8")

        with patch.object(sys, "_MEIPASS", str(meipass), create=True):
            result = get_data_dir("scoring-profiles")
            assert result == meipass / "scoring-profiles"

    def test_frozen_mode_fallback_se_non_trovato(self, tmp_path):
        """In frozen mode, se non trovato in MEIPASS, fallback a percorsi normali."""
        meipass = tmp_path / "meipass"
        meipass.mkdir()
        # Non creare la dir in meipass

        with patch.object(sys, "_MEIPASS", str(meipass), create=True):
            # Dovrebbe fare fallback ai percorsi normali (dev mode o installed)
            # Questo funzionerà se siamo in dev mode
            result = get_data_dir("scoring-profiles")
            assert result.is_dir()

    def test_dev_mode_senza_meipass(self):
        """Senza _MEIPASS, usa i percorsi normali."""
        # Assicurati che _MEIPASS non sia settato
        if hasattr(sys, "_MEIPASS"):
            pytest.skip("sys._MEIPASS è già settato")

        result = get_data_dir("scoring-profiles")
        assert result.is_dir()
