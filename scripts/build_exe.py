#!/usr/bin/env python3
"""
Script di build per l'eseguibile standalone.

Usa PyInstaller per creare un .exe/.app con la dashboard integrata.

Usage:
    python scripts/build_exe.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> None:
    """Esegue il build PyInstaller."""
    project_root = Path(__file__).resolve().parent.parent
    spec_file = project_root / "cto-audit.spec"

    if not spec_file.exists():
        print(f"Errore: {spec_file} non trovato")
        sys.exit(1)

    print("Build CTO Audit Agent — Eseguibile Standalone")
    print(f"  Spec: {spec_file}")
    print(f"  Output: {project_root / 'dist'}")
    print()

    cmd = [
        sys.executable, "-m", "PyInstaller",
        str(spec_file),
        "--clean",
        "--noconfirm",
    ]

    result = subprocess.run(cmd, cwd=str(project_root))

    if result.returncode == 0:
        print("\nBuild completato! Eseguibile in dist/cto-audit")
    else:
        print(f"\nBuild fallito (exit code {result.returncode})")
        sys.exit(1)


if __name__ == "__main__":
    main()
