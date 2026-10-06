"""
Sorgenti dati per CTO Audit Agent.

Tutte le sorgenti implementano il Protocol AuditSource (core/source.py).
Le sorgenti remote seguono il pattern: clone in temp dir → LocalRepoSource.
"""

from cto_audit.sources.local import LocalRepoSource
from cto_audit.sources.base import TempDirSourceMixin
from cto_audit.sources.factory import SourceFactory

__all__ = [
    "LocalRepoSource",
    "TempDirSourceMixin",
    "SourceFactory",
]
