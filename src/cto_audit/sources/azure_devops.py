"""
Sorgente dati Azure DevOps — clone via git di repository Azure DevOps.

Autenticazione via PAT con formato {token}@dev.azure.com/...
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Optional

from cto_audit.sources.base import TempDirSourceMixin


class AzureDevOpsSource(TempDirSourceMixin):
    """
    Sorgente dati per repository Azure DevOps.

    Autenticazione usa il formato https://{token}@dev.azure.com/...

    Args:
        url: URL del repository Azure DevOps
        token: Personal Access Token per autenticazione (opzionale)
        branch: Branch o tag da clonare (opzionale)
        shallow: Clone shallow --depth 1 (default: True)
    """

    def __init__(
        self,
        url: str,
        token: Optional[str] = None,
        branch: Optional[str] = None,
        shallow: bool = True,
    ) -> None:
        super().__init__(source_type="azure-devops")
        if not shutil.which("git"):
            raise RuntimeError(
                "Git non trovato. Installa git e assicurati che sia nel PATH."
            )
        self._url = url
        self._token = token
        self._branch = branch
        self._shallow = shallow

    def _build_clone_url(self) -> str:
        """Costruisce l'URL di clone con token se presente."""
        if self._token:
            # https://{token}@dev.azure.com/org/project/_git/repo
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
            safe_url = self._url
            raise RuntimeError(
                f"Errore nel clone del repository Azure DevOps: {safe_url}\n"
                f"git stderr: {result.stderr.strip()}"
            )
