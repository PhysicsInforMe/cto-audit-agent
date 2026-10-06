"""
Factory per creare la sorgente dati corretta in base al tipo.

Usata da CLI e dashboard per istanziare la sorgente appropriata
dato il tipo, il path/URL, e le credenziali.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from cto_audit.sources.local import LocalRepoSource


# Tipi di sorgente supportati
SOURCE_TYPES = {
    "local", "github", "gitlab", "azure-devops", "bitbucket", "zip", "archive",
}


class SourceFactory:
    """
    Factory che crea la sorgente dati appropriata.

    Supporta auto-detection del tipo di sorgente dall'input.
    """

    @staticmethod
    def create(
        source_type: str,
        path_or_url: str,
        token: Optional[str] = None,
        branch: Optional[str] = None,
        shallow: bool = True,
    ):
        """
        Crea e restituisce la sorgente dati appropriata.

        Args:
            source_type: Tipo di sorgente (auto, local, github, gitlab, azure-devops, bitbucket, zip)
            path_or_url: Path locale o URL remoto
            token: Token di autenticazione (opzionale)
            branch: Branch o tag da clonare (opzionale)
            shallow: Clone shallow per sorgenti git (default: True)

        Returns:
            Un'istanza della sorgente appropriata

        Raises:
            ValueError: Se il tipo di sorgente non è supportato
        """
        if source_type == "auto":
            source_type = SourceFactory.detect_type(path_or_url)

        if source_type == "local":
            return LocalRepoSource(path_or_url)

        if source_type == "github":
            from cto_audit.sources.github import GitHubSource
            return GitHubSource(path_or_url, token=token, branch=branch, shallow=shallow)

        if source_type == "gitlab":
            from cto_audit.sources.gitlab import GitLabSource
            return GitLabSource(path_or_url, token=token, branch=branch, shallow=shallow)

        if source_type == "azure-devops":
            from cto_audit.sources.azure_devops import AzureDevOpsSource
            return AzureDevOpsSource(path_or_url, token=token, branch=branch, shallow=shallow)

        if source_type == "bitbucket":
            from cto_audit.sources.bitbucket import BitbucketSource
            return BitbucketSource(path_or_url, token=token, branch=branch, shallow=shallow)

        if source_type in ("zip", "archive"):
            from cto_audit.sources.archive import ArchiveSource
            return ArchiveSource(path_or_url)

        raise ValueError(
            f"Tipo di sorgente '{source_type}' non supportato.\n"
            f"Tipi supportati: {', '.join(sorted(SOURCE_TYPES))}"
        )

    @staticmethod
    def detect_type(path_or_url: str) -> str:
        """
        Rileva automaticamente il tipo di sorgente dall'input.

        Logica:
        - URL github.com → github
        - URL gitlab.com → gitlab
        - URL dev.azure.com / visualstudio.com → azure-devops
        - URL bitbucket.org → bitbucket
        - Estensione .zip/.tar.gz/.tgz → archive
        - Altrimenti → local

        Args:
            path_or_url: Path locale o URL remoto

        Returns:
            Tipo di sorgente rilevato
        """
        lower = path_or_url.lower()

        # URL-based detection
        if "github.com" in lower:
            return "github"
        if "gitlab.com" in lower or "gitlab" in lower.split("/")[2] if lower.startswith("https://") and len(lower.split("/")) > 2 else False:
            return "gitlab"
        if "dev.azure.com" in lower or "visualstudio.com" in lower:
            return "azure-devops"
        if "bitbucket.org" in lower:
            return "bitbucket"

        # Extension-based detection
        if lower.endswith((".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tar")):
            return "archive"

        # Default: local
        return "local"
