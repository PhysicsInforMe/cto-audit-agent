"""
Interfaccia astratta per le sorgenti dati dell'audit.

Definisce il Protocol `AuditSource` che tutte le sorgenti (locale, git, multi)
devono implementare. Questo garantisce che l'intero sistema sia disaccoppiato
dalla sorgente dati specifica.

Implementazioni:
- LocalRepoSource (MVP) — sources/local.py
- GitRemoteSource (futuro) — sources/git.py
- MultiSource (futuro) — aggrega più sorgenti
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from cto_audit.core.models import FileTree, SourceMetadata


@runtime_checkable
class AuditSource(Protocol):
    """
    Protocol per le sorgenti dati dell'audit.

    Ogni sorgente deve poter:
    - Fornire l'albero dei file del progetto
    - Leggere il contenuto di un singolo file
    - Fornire metadati sulla sorgente

    Il Protocol è runtime_checkable per consentire isinstance() nei test
    e nell'orchestrator.
    """

    def get_file_tree(self) -> FileTree:
        """
        Restituisce l'albero completo dei file della sorgente.

        L'albero contiene tutti i file e directory trovati, escludendo
        quelli filtrati dalla sorgente (es. .gitignore per LocalRepoSource).

        Returns:
            FileTree con root e lista di FileTreeEntry
        """
        ...

    def read_file(self, path: str) -> str:
        """
        Legge e restituisce il contenuto testuale di un file.

        Args:
            path: Percorso relativo del file rispetto alla root della sorgente

        Returns:
            Contenuto del file come stringa

        Raises:
            FileNotFoundError: Se il file non esiste
            UnicodeDecodeError: Se il file non è decodificabile come testo
            PermissionError: Se non si hanno i permessi di lettura
        """
        ...

    def get_metadata(self) -> SourceMetadata:
        """
        Restituisce metadati sulla sorgente dati.

        Returns:
            SourceMetadata con nome, totale file, LOC, tipo sorgente
        """
        ...
