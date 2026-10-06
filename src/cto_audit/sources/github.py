"""
Sorgente dati GitHub — clone via git di repository GitHub.

Supporta repository pubbliche e private (via PAT token).
Clone shallow (--depth 1) per default, con opzione full clone.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Optional


from cto_audit.sources.base import TempDirSourceMixin


def _check_git_available() -> None:
    """Verifica che git sia disponibile su PATH."""
    if not shutil.which("git"):
        raise RuntimeError(
            "Git non trovato. Installa git e assicurati che sia nel PATH.\n"
            "  → Windows: https://git-scm.com/download/win\n"
            "  → macOS: brew install git\n"
            "  → Linux: sudo apt install git"
        )


class GitHubSource(TempDirSourceMixin):
    """
    Sorgente dati per repository GitHub.

    Clona il repository in una directory temporanea e delega a LocalRepoSource.
    Supporta repository private tramite Personal Access Token (PAT).

    Args:
        url: URL del repository GitHub (es. https://github.com/owner/repo)
        token: Personal Access Token per repo private (opzionale)
        branch: Branch o tag da clonare (opzionale, default: branch principale)
        shallow: Clone shallow (--depth 1) per velocità (default: True)
    """

    def __init__(
        self,
        url: str,
        token: Optional[str] = None,
        branch: Optional[str] = None,
        shallow: bool = True,
    ) -> None:
        super().__init__(source_type="github")
        _check_git_available()
        self._url = url
        self._token = token
        self._branch = branch
        self._shallow = shallow

    def _build_clone_url(self) -> str:
        """Costruisce l'URL di clone con token se presente."""
        if self._token:
            # https://{token}@github.com/owner/repo.git
            return self._url.replace("https://", f"https://{self._token}@")
        return self._url

    def _materialize(self, target_dir: Path) -> None:
        """Clona il repository nella directory target."""
        cmd = ["git", "clone"]

        if self._shallow:
            cmd.extend(["--depth", "1"])

        if self._branch:
            cmd.extend(["--branch", self._branch])

        cmd.extend([self._build_clone_url(), str(target_dir)])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.returncode != 0:
            # Mai loggare l'URL con token nell'errore
            safe_url = self._url
            raise RuntimeError(
                f"Errore nel clone del repository: {safe_url}\n"
                f"git stderr: {result.stderr.strip()}"
            )
