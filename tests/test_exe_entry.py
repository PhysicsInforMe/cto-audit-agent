"""
Test per exe_entry.py — verifica che main() crea app Dash e apre browser.
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest


class TestExeEntry:
    @patch("cto_audit.exe_entry.webbrowser.open")
    @patch("cto_audit.dashboard.app.create_app")
    def test_main_crea_app(self, mock_create_app, mock_browser_open):
        """main() crea un'app Dash e chiama app.run."""
        mock_app = MagicMock()
        mock_create_app.return_value = mock_app

        # Avvia main ma stoppa subito il server (mock)
        from cto_audit.exe_entry import main
        main(port=9999)

        mock_create_app.assert_called_once()
        mock_app.run.assert_called_once_with(host="127.0.0.1", port=9999, debug=False)

    @patch("cto_audit.exe_entry.webbrowser.open")
    @patch("cto_audit.dashboard.app.create_app")
    def test_main_apre_browser(self, mock_create_app, mock_browser_open):
        """main() avvia un timer per aprire il browser."""
        mock_app = MagicMock()
        mock_create_app.return_value = mock_app

        from cto_audit.exe_entry import main

        with patch("cto_audit.exe_entry.threading.Timer") as mock_timer:
            mock_timer_instance = MagicMock()
            mock_timer.return_value = mock_timer_instance

            main(port=8050)

            mock_timer.assert_called_once()
            mock_timer_instance.start.assert_called_once()
