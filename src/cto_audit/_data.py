"""
Resolver per le directory dati (scoring-profiles, remediation-kb, compliance-profiles).

Gestisce tre modalità:
- Frozen (PyInstaller): i dati sono in sys._MEIPASS
- Installato via pip: i dati sono in cto_audit/data/ dentro il package
- Sviluppo: i dati sono nella root del progetto
"""

from __future__ import annotations

import sys
from pathlib import Path

# Directory root del package
_PACKAGE_DIR = Path(__file__).resolve().parent

# Directory root del progetto (dev mode)
_PROJECT_ROOT = _PACKAGE_DIR.parent.parent


def get_data_dir(subdir: str) -> Path:
    """
    Restituisce il percorso alla directory dati richiesta.

    Ordine di ricerca:
    1. Frozen mode (PyInstaller): sys._MEIPASS
    2. Installed mode: cto_audit/data/ dentro il package
    3. Dev mode: root del progetto

    Args:
        subdir: Sottodirectory da cercare (es. "scoring-profiles")

    Returns:
        Path alla directory dati

    Raises:
        FileNotFoundError: se la directory non viene trovata
    """
    # 0. Frozen mode (PyInstaller)
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        frozen_data = Path(meipass) / subdir
        if frozen_data.is_dir():
            return frozen_data

    # 1. Installed mode: data copiato dentro il package
    pkg_data = _PACKAGE_DIR / "data" / subdir
    if pkg_data.is_dir():
        return pkg_data

    # 2. Dev mode: data nella root del progetto
    dev_data = _PROJECT_ROOT / subdir
    if dev_data.is_dir():
        return dev_data

    raise FileNotFoundError(
        f"Directory dati '{subdir}' non trovata. "
        f"Cercato in:\n  - {pkg_data}\n  - {dev_data}"
    )
