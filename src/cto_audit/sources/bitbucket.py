"""
Sorgente dati Bitbucket — clone via git di repository Bitbucket.

Supporta Bitbucket Cloud (x-token-auth:{token}@) e Bitbucket Server.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Optional

from cto_audit.sources.base import TempDirSourceMixin


class BitbucketSource(TempDirSourceMixin):
    """
    Sorgente dati per repository Bitbucket.

    Supporta sia Bitbucket Cloud che Server. L'autenticazione usa
    il formato x-token-auth:{token}@ per Cloud.

    Args:
        url: URL del repository Bitbucket
        token: Access token per repo private (opzionale)
        branch: Branch o tag da clonare (opzionale)
        shallow: Clone shallow --depth 1 (default: True)
        server: Se True, usa formato autenticazione Bitbucket Server (default: False)
    """

    def __init__(
        self,
        url: str,
        token: Optional[str] = None,
        branch: Optional[str] = None,
        shallow: bool = True,
        server: bool = False,
    ) -> None:
        super().__init__(source_type="bitbucket")
        if not shutil.which("git"):
            raise RuntimeError(
                "Git non trovato. Installa git e assicurati che sia nel PATH."
            )
        self._url = url
        self._token = token
        self._branch = branch
        self._shallow = shallow
        self._server = server

    def _build_clone_url(self) -> str:
        """Costruisce l'URL di clone con token se presente."""
        if self._token:
            if self._server:
                # Bitbucket Server: https://{token}@bitbucket.mycompany.com/...
                return self._url.replace("https://", f"https://{self._token}@")
            else:
                # Bitbucket Cloud: https://x-token-auth:{token}@bitbucket.org/...
                return self._url.replace(
                    "https://", f"https://x-token-auth:{self._token}@"
                )
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
                f"Errore nel clone del repository Bitbucket: {safe_url}\n"
                f"git stderr: {result.stderr.strip()}"
            )
