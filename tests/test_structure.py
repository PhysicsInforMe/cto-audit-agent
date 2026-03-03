"""
Test per la struttura directory e importabilità dei moduli.

Verifica che tutti i package e moduli del progetto siano importabili
e che la struttura sia coerente con il design.
"""

import importlib


class TestStrutturaImport:
    """Verifica che i moduli principali siano importabili."""

    def test_import_package_root(self):
        """Il package root cto_audit è importabile."""
        import cto_audit
        assert cto_audit.__version__ == "0.1.0"

    def test_import_core_models(self):
        """I modelli core sono importabili direttamente."""
        from cto_audit.core.models import (
            AuditMetadata,
            AuditResult,
            ComplianceMode,
            ComplianceResult,
            EvidenceChain,
            FileClassification,
            FileInfo,
            FileTree,
            FileTreeEntry,
            Finding,
            HealthScore,
            Layer,
            LayerScore,
            PrivacyCategory,
            Severity,
            SourceMetadata,
            StackInfo,
        )

    def test_import_core_config(self):
        """La configurazione è importabile."""
        from cto_audit.core.config import AuditConfig

    def test_import_subpackages(self):
        """Tutti i subpackage sono importabili."""
        packages = [
            "cto_audit.core",
            "cto_audit.sources",
            "cto_audit.collectors",
            "cto_audit.hitl",
            "cto_audit.analyzers",
            "cto_audit.scoring",
            "cto_audit.compliance",
            "cto_audit.llm",
            "cto_audit.reporters",
        ]
        for pkg in packages:
            mod = importlib.import_module(pkg)
            assert mod is not None, f"Impossibile importare {pkg}"
