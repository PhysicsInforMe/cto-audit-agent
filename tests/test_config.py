"""
Test per la configurazione runtime del Blocco 1.

Verifica:
- Caricamento valori di default corretti
- Validazione percorso target (esiste, è directory)
- Tutti i campi opzionali hanno default sensati
"""

import os
import tempfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from cto_audit.core.config import AuditConfig
from cto_audit.core.models import ComplianceMode, Layer


class TestAuditConfig:
    """Test per AuditConfig."""

    def test_config_con_path_valido(self, tmp_path):
        """Config si istanzia con un percorso valido."""
        config = AuditConfig(target_path=tmp_path)
        assert config.target_path == tmp_path
        assert config.output_format == "terminal"
        assert config.scoring_profile == "default"
        assert config.compliance_profiles == []
        assert config.compliance_mode == ComplianceMode.HYBRID
        assert config.offline_mode is False
        assert config.reuse_classification is False
        assert config.auto_approve is False
        assert config.focus is None

    def test_config_path_inesistente_rifiutato(self):
        """Path che non esiste deve essere rifiutato."""
        with pytest.raises(ValidationError, match="non esiste"):
            AuditConfig(target_path=Path("/path/che/non/esiste"))

    def test_config_path_file_rifiutato(self, tmp_path):
        """Path che è un file (non directory) deve essere rifiutato."""
        file_path = tmp_path / "file.txt"
        file_path.touch()
        with pytest.raises(ValidationError, match="non è una directory"):
            AuditConfig(target_path=file_path)

    def test_config_con_focus(self, tmp_path):
        """Config accetta un focus layer valido."""
        config = AuditConfig(target_path=tmp_path, focus=Layer.INFRA)
        assert config.focus == Layer.INFRA

    def test_config_con_focus_stringa(self, tmp_path):
        """Config accetta focus come stringa valida."""
        config = AuditConfig(target_path=tmp_path, focus="security")
        assert config.focus == Layer.SECURITY

    def test_config_focus_invalido(self, tmp_path):
        """Focus con layer non valido deve essere rifiutato."""
        with pytest.raises(ValidationError):
            AuditConfig(target_path=tmp_path, focus="compliance")

    def test_config_compliance_mode(self, tmp_path):
        """Config accetta tutte le modalità compliance."""
        for mode in ComplianceMode:
            config = AuditConfig(target_path=tmp_path, compliance_mode=mode)
            assert config.compliance_mode == mode

    def test_config_output_format_validi(self, tmp_path):
        """Tutti i formati di output sono accettati."""
        for fmt in ["terminal", "markdown", "html", "pdf", "json"]:
            config = AuditConfig(target_path=tmp_path, output_format=fmt)
            assert config.output_format == fmt

    def test_config_output_format_invalido(self, tmp_path):
        """Formato output non valido deve essere rifiutato."""
        with pytest.raises(ValidationError):
            AuditConfig(target_path=tmp_path, output_format="xml")

    def test_config_completa(self, tmp_path):
        """Config con tutti i parametri espliciti."""
        config = AuditConfig(
            target_path=tmp_path,
            output_format="markdown",
            output_path="report.md",
            scoring_profile="nist-csf",
            compliance_profiles=["nis2", "gdpr"],
            compliance_mode=ComplianceMode.STANDALONE,
            offline_mode=True,
            reuse_classification=True,
            auto_approve=True,
            focus=Layer.ARCHITECTURE,
        )
        assert config.output_format == "markdown"
        assert config.output_path == "report.md"
        assert config.scoring_profile == "nist-csf"
        assert config.compliance_profiles == ["nis2", "gdpr"]
        assert config.compliance_mode == ComplianceMode.STANDALONE
        assert config.offline_mode is True
        assert config.reuse_classification is True
        assert config.auto_approve is True
        assert config.focus == Layer.ARCHITECTURE
