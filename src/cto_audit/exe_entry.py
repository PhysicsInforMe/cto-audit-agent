"""
Entry point per l'eseguibile standalone (.exe / .app).

Crea l'app Dash, apre il browser, avvia il server.
Usato da PyInstaller come punto di ingresso.
"""

from __future__ import annotations

import sys
import webbrowser
import threading


def main(port: int = 8050) -> None:
    """
    Entry point per l'eseguibile.

    Crea l'app Dash, apre il browser e avvia il server.
    """
    from cto_audit.dashboard.app import create_app

    app = create_app(title="CTO Audit Agent")

    # Apri il browser dopo un breve delay
    threading.Timer(1.5, lambda: webbrowser.open(f"http://localhost:{port}")).start()

    # Avvia il server
    app.run(host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    main()
