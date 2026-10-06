"""
Test per i modelli Pydantic del Blocco 1.

Verifica:
- Istanziazione corretta con dati validi
- Rifiuto di dati invalidi (severity errate, score fuori range, etc.)
- Validazioni custom (percentuali linguaggi, compliance checks, etc.)
"""

import pytest
from pydantic import ValidationError

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


# ===== FileInfo =====


class TestFileInfo:
    """Test per il modello FileInfo."""

    def test_creazione_valida(self):
        """FileInfo si istanzia correttamente con dati validi."""
        fi = FileInfo(path="src/main.py", size=1024, extension=".py", lines_of_code=50)
        assert fi.path == "src/main.py"
        assert fi.size == 1024
        assert fi.extension == ".py"
        assert fi.lines_of_code == 50

    def test_default_extension_vuota(self):
        """Extension default è stringa vuota."""
        fi = FileInfo(path="Makefile", size=256)
        assert fi.extension == ""
        assert fi.lines_of_code == 0

    def test_size_negativa_rifiutata(self):
        """Size negativa deve essere rifiutata."""
        with pytest.raises(ValidationError):
            FileInfo(path="test.py", size=-1)

    def test_loc_negativo_rifiutato(self):
        """Lines of code negative devono essere rifiutate."""
        with pytest.raises(ValidationError):
            FileInfo(path="test.py", size=0, lines_of_code=-10)


# ===== FileClassification =====


class TestFileClassification:
    """Test per il modello FileClassification."""

    def test_classificazione_safe(self):
        """Classificazione SAFE con motivo valido."""
        fi = FileInfo(path="src/app.py", size=500, extension=".py")
        fc = FileClassification(
            file_info=fi,
            category=PrivacyCategory.SAFE,
            reason="Nessun pattern sensibile rilevato",
        )
        assert fc.category == PrivacyCategory.SAFE
        assert fc.confidence == 1.0  # default

    def test_classificazione_sensitive(self):
        """Classificazione SENSITIVE con confidenza custom."""
        fi = FileInfo(path=".env", size=128)
        fc = FileClassification(
            file_info=fi,
            category=PrivacyCategory.SENSITIVE,
            reason="Variabili ambiente",
            confidence=0.95,
        )
        assert fc.category == PrivacyCategory.SENSITIVE
        assert fc.confidence == 0.95

    def test_reason_vuota_rifiutata(self):
        """Il motivo della classificazione non può essere vuoto."""
        fi = FileInfo(path="test.py", size=100)
        with pytest.raises(ValidationError):
            FileClassification(
                file_info=fi,
                category=PrivacyCategory.SAFE,
                reason="",
            )

    def test_confidence_fuori_range(self):
        """Confidenza fuori range 0-1 deve essere rifiutata."""
        fi = FileInfo(path="test.py", size=100)
        with pytest.raises(ValidationError):
            FileClassification(
                file_info=fi,
                category=PrivacyCategory.SAFE,
                reason="Test",
                confidence=1.5,
            )

    def test_categoria_invalida_rifiutata(self):
        """Categoria non valida deve essere rifiutata."""
        fi = FileInfo(path="test.py", size=100)
        with pytest.raises(ValidationError):
            FileClassification(
                file_info=fi,
                category="non_esiste",
                reason="Test",
            )

    def test_tutte_le_categorie(self):
        """Tutte e 4 le categorie sono valide."""
        fi = FileInfo(path="test.py", size=100)
        for cat in PrivacyCategory:
            fc = FileClassification(file_info=fi, category=cat, reason="Test")
            assert fc.category == cat


# ===== StackInfo =====


class TestStackInfo:
    """Test per il modello StackInfo."""

    def test_stack_completo(self):
        """StackInfo si istanzia con tutti i campi."""
        si = StackInfo(
            languages={"python": 0.65, "javascript": 0.35},
            frameworks=["FastAPI", "React"],
            infra_type=["Docker", "GitHub Actions"],
        )
        assert si.languages["python"] == 0.65
        assert "FastAPI" in si.frameworks
        assert "Docker" in si.infra_type

    def test_stack_vuoto(self):
        """StackInfo si istanzia vuoto con default."""
        si = StackInfo()
        assert si.languages == {}
        assert si.frameworks == []
        assert si.infra_type == []

    def test_percentuale_linguaggio_fuori_range(self):
        """Percentuale linguaggio > 1.0 deve essere rifiutata."""
        with pytest.raises(ValidationError):
            StackInfo(languages={"python": 1.5})

    def test_percentuale_linguaggio_negativa(self):
        """Percentuale linguaggio negativa deve essere rifiutata."""
        with pytest.raises(ValidationError):
            StackInfo(languages={"python": -0.1})


# ===== Finding =====


class TestFinding:
    """Test per il modello Finding."""

    def test_finding_completo(self):
        """Finding si istanzia con tutti i campi."""
        f = Finding(
            id="f-001",
            layer=Layer.INFRA,
            severity=Severity.CRITICAL,
            rule_id="INFRA-CICD-001",
            title="Nessun CI/CD pipeline configurato",
            description="Non è stato trovato nessun file di CI/CD nel progetto.",
            file_path=None,
            confidence=1.0,
            framework_ref="NIST PR.DS-6",
        )
        assert f.layer == Layer.INFRA
        assert f.severity == Severity.CRITICAL
        assert f.framework_ref == "NIST PR.DS-6"

    def test_finding_minimo(self):
        """Finding con solo campi obbligatori."""
        f = Finding(
            id="f-002",
            layer=Layer.SECURITY,
            severity=Severity.LOW,
            rule_id="SEC-001",
            title="Info finding",
            description="Trovato pattern minore",
        )
        assert f.file_path is None
        assert f.line_number is None
        assert f.framework_ref is None

    def test_severity_invalida(self):
        """Severity non valida deve essere rifiutata."""
        with pytest.raises(ValidationError):
            Finding(
                id="f-003",
                layer=Layer.INFRA,
                severity="urgente",
                rule_id="INFRA-001",
                title="Test",
                description="Test desc",
            )

    def test_layer_invalido(self):
        """Layer non valido deve essere rifiutato."""
        with pytest.raises(ValidationError):
            Finding(
                id="f-004",
                layer="compliance",
                severity=Severity.HIGH,
                rule_id="COMP-001",
                title="Test",
                description="Test desc",
            )

    def test_title_vuoto_rifiutato(self):
        """Title vuoto deve essere rifiutato."""
        with pytest.raises(ValidationError):
            Finding(
                id="f-005",
                layer=Layer.QUALITY,
                severity=Severity.INFO,
                rule_id="QUAL-001",
                title="",
                description="Test desc",
            )

    def test_line_number_zero_rifiutato(self):
        """Line number 0 deve essere rifiutato (min 1)."""
        with pytest.raises(ValidationError):
            Finding(
                id="f-006",
                layer=Layer.SECURITY,
                severity=Severity.MEDIUM,
                rule_id="SEC-002",
                title="Test",
                description="Test desc",
                line_number=0,
            )

    def test_tutte_le_severity(self):
        """Tutte e 5 le severity sono valide."""
        for sev in Severity:
            f = Finding(
                id=f"f-{sev.value}",
                layer=Layer.INFRA,
                severity=sev,
                rule_id="TEST-001",
                title="Test",
                description="Test desc",
            )
            assert f.severity == sev


# ===== LayerScore =====


class TestLayerScore:
    """Test per il modello LayerScore."""

    def test_score_valido(self):
        """LayerScore con score valido 0-100."""
        ls = LayerScore(layer=Layer.INFRA, score=42.5)
        assert ls.score == 42.5
        assert ls.findings == []
        assert ls.evidence_chain == []

    def test_score_perfetto(self):
        """Score 100 è valido."""
        ls = LayerScore(layer=Layer.QUALITY, score=100.0)
        assert ls.score == 100.0

    def test_score_zero(self):
        """Score 0 è valido."""
        ls = LayerScore(layer=Layer.SECURITY, score=0.0)
        assert ls.score == 0.0

    def test_score_sopra_100_rifiutato(self):
        """Score > 100 deve essere rifiutato."""
        with pytest.raises(ValidationError):
            LayerScore(layer=Layer.INFRA, score=101.0)

    def test_score_negativo_rifiutato(self):
        """Score negativo deve essere rifiutato."""
        with pytest.raises(ValidationError):
            LayerScore(layer=Layer.INFRA, score=-1.0)

    def test_score_con_finding_e_evidenze(self):
        """LayerScore con finding e catena di evidenze."""
        finding = Finding(
            id="f-001",
            layer=Layer.INFRA,
            severity=Severity.CRITICAL,
            rule_id="INFRA-CICD-001",
            title="Nessun CI/CD",
            description="No pipeline trovato",
        )
        evidence = EvidenceChain(
            finding_id="f-001",
            rule_id="INFRA-CICD-001",
            weight=0.25,
            penalty=-25.0,
            framework_ref="NIST PR.DS-6",
        )
        ls = LayerScore(
            layer=Layer.INFRA,
            score=75.0,
            findings=[finding],
            evidence_chain=[evidence],
        )
        assert len(ls.findings) == 1
        assert len(ls.evidence_chain) == 1
        assert ls.evidence_chain[0].penalty == -25.0


# ===== EvidenceChain =====


class TestEvidenceChain:
    """Test per il modello EvidenceChain."""

    def test_evidenza_valida(self):
        """EvidenceChain si istanzia correttamente."""
        ec = EvidenceChain(
            finding_id="f-001",
            rule_id="INFRA-001",
            weight=0.25,
            penalty=-25.0,
        )
        assert ec.weight == 0.25
        assert ec.penalty == -25.0
        assert ec.framework_ref is None

    def test_penalty_positiva_rifiutata(self):
        """Penalità positiva deve essere rifiutata (deve essere <= 0)."""
        with pytest.raises(ValidationError):
            EvidenceChain(
                finding_id="f-001",
                rule_id="INFRA-001",
                weight=0.25,
                penalty=5.0,
            )

    def test_weight_fuori_range(self):
        """Weight > 1.0 deve essere rifiutato."""
        with pytest.raises(ValidationError):
            EvidenceChain(
                finding_id="f-001",
                rule_id="INFRA-001",
                weight=1.5,
                penalty=-10.0,
            )


# ===== HealthScore =====


class TestHealthScore:
    """Test per il modello HealthScore."""

    def test_health_score_base(self):
        """HealthScore minimo con solo overall_score."""
        hs = HealthScore(overall_score=42.0)
        assert hs.overall_score == 42.0
        assert hs.layer_scores == {}
        assert hs.compliance_results is None

    def test_health_score_completo(self):
        """HealthScore con layer scores e compliance."""
        infra_score = LayerScore(layer=Layer.INFRA, score=28.0)
        arch_score = LayerScore(layer=Layer.ARCHITECTURE, score=45.0)
        compliance = ComplianceResult(
            profile_name="NIS2",
            checks_total=28,
            checks_satisfied=12,
        )
        hs = HealthScore(
            overall_score=42.0,
            layer_scores={"infra": infra_score, "architecture": arch_score},
            compliance_results=[compliance],
        )
        assert len(hs.layer_scores) == 2
        assert hs.compliance_results[0].profile_name == "NIS2"

    def test_overall_score_fuori_range(self):
        """Overall score fuori range 0-100 deve essere rifiutato."""
        with pytest.raises(ValidationError):
            HealthScore(overall_score=150.0)


# ===== ComplianceResult =====


class TestComplianceResult:
    """Test per il modello ComplianceResult."""

    def test_compliance_valido(self):
        """ComplianceResult con dati validi."""
        cr = ComplianceResult(
            profile_name="GDPR",
            checks_total=15,
            checks_satisfied=8,
            checks_partial=3,
            checks_not_satisfied=4,
        )
        assert cr.checks_total == 15
        assert cr.checks_satisfied == 8

    def test_satisfied_maggiore_di_total_rifiutato(self):
        """checks_satisfied > checks_total deve essere rifiutato."""
        with pytest.raises(ValidationError):
            ComplianceResult(
                profile_name="NIS2",
                checks_total=10,
                checks_satisfied=15,
            )

    def test_checks_negativi_rifiutati(self):
        """Conteggi negativi devono essere rifiutati."""
        with pytest.raises(ValidationError):
            ComplianceResult(
                profile_name="NIS2",
                checks_total=-1,
                checks_satisfied=0,
            )


# ===== FileTree e SourceMetadata =====


class TestFileTree:
    """Test per FileTree e SourceMetadata."""

    def test_file_tree_valido(self):
        """FileTree si istanzia con entries."""
        ft = FileTree(
            root="/path/to/project",
            entries=[
                FileTreeEntry(path="src/main.py", is_dir=False, size=1024),
                FileTreeEntry(path="src/", is_dir=True),
            ],
        )
        assert ft.root == "/path/to/project"
        assert len(ft.entries) == 2
        assert ft.entries[0].is_dir is False
        assert ft.entries[1].is_dir is True

    def test_source_metadata_valida(self):
        """SourceMetadata si istanzia con valori corretti."""
        sm = SourceMetadata(name="my-project", total_files=312, total_loc=45000)
        assert sm.name == "my-project"
        assert sm.source_type == "local"  # default

    def test_source_metadata_default(self):
        """SourceMetadata con solo il nome usa i default."""
        sm = SourceMetadata(name="test")
        assert sm.total_files == 0
        assert sm.total_loc == 0
        assert sm.source_type == "local"


# ===== AuditResult =====


class TestAuditResult:
    """Test per il modello AuditResult."""

    def test_audit_result_completo(self):
        """AuditResult si istanzia con tutti i componenti."""
        result = AuditResult(
            health_score=HealthScore(overall_score=42.0),
            stack_info=StackInfo(
                languages={"python": 0.7, "javascript": 0.3},
                frameworks=["FastAPI"],
            ),
            classifications=[],
            metadata=AuditMetadata(target_path="/path/to/project"),
        )
        assert result.health_score.overall_score == 42.0
        assert result.stack_info.languages["python"] == 0.7
        assert result.metadata.tool_version == "0.1.0"
        assert result.metadata.offline_mode is False


# ===== Enumerazioni =====


class TestEnumerazioni:
    """Test per le enumerazioni."""

    def test_privacy_category_valori(self):
        """PrivacyCategory ha tutti i 4 valori."""
        assert len(PrivacyCategory) == 4
        assert PrivacyCategory.SAFE.value == "safe"
        assert PrivacyCategory.LOCAL_LLM.value == "local_llm"
        assert PrivacyCategory.SENSITIVE.value == "sensitive"
        assert PrivacyCategory.EXCLUDED.value == "excluded"

    def test_severity_valori(self):
        """Severity ha tutti i 5 valori, nell'ordine giusto."""
        assert len(Severity) == 5
        values = [s.value for s in Severity]
        assert values == ["critical", "high", "medium", "low", "info"]

    def test_layer_valori(self):
        """Layer ha i 4 valori storici piu i 2 di due diligence."""
        assert len(Layer) == 6
        assert Layer.INFRA.value == "infra"
        assert Layer.ARCHITECTURE.value == "architecture"
        assert Layer.SECURITY.value == "security"
        assert Layer.QUALITY.value == "quality"
        assert Layer.PROVENANCE.value == "provenance"
        assert Layer.TEAM.value == "team"

    def test_compliance_mode_valori(self):
        """ComplianceMode ha tutti i 3 valori."""
        assert len(ComplianceMode) == 3
        assert ComplianceMode.CROSS_CUTTING.value == "cross-cutting"
        assert ComplianceMode.STANDALONE.value == "standalone"
        assert ComplianceMode.HYBRID.value == "hybrid"
