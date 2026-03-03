"""
Test per il Blocco 9 — Scoring Engine Pluggable.

Copre:
- Caricamento profilo YAML (default e custom)
- Validazione profilo (errori layer_weights, severità, etc.)
- ScoringEngine: calcolo score per layer
- Catena di evidenze completa
- Score 100/100 con zero finding
- Score basso con molti finding critici
- Finding senza regola nel profilo → peso default
- HealthScore aggregato con pesi per layer
"""

import textwrap
import uuid

import pytest

from cto_audit.core.models import (
    EvidenceChain,
    Finding,
    HealthScore,
    Layer,
    LayerScore,
    Severity,
)
from cto_audit.core.models import ProjectType
from cto_audit.scoring.engine import DEFAULT_PENALTIES, ScoringEngine, LAYER_RULES, WEB_ONLY_RULES
from cto_audit.scoring.profile import (
    RuleConfig,
    ScoringProfile,
    load_profile,
)


# --- Helper ---

def _make_finding(
    rule_id: str = "TEST-001",
    layer: Layer = Layer.INFRA,
    severity: Severity = Severity.MEDIUM,
    framework_ref: str | None = None,
) -> Finding:
    """Crea un Finding di test con valori ragionevoli."""
    return Finding(
        id=str(uuid.uuid4()),
        layer=layer,
        severity=severity,
        rule_id=rule_id,
        title=f"Test finding {rule_id}",
        description=f"Descrizione del finding {rule_id}",
        framework_ref=framework_ref,
    )


def _make_profile(**overrides) -> ScoringProfile:
    """Crea un ScoringProfile di test con regole base."""
    defaults = {
        "name": "test",
        "description": "Profilo di test",
        "layer_weights": {
            "infra": 0.35,
            "architecture": 0.25,
            "security": 0.25,
            "quality": 0.15,
        },
        "default_rule_weight": 0.5,
        "rules": {
            "TEST-001": RuleConfig(
                severity="medium",
                weight=0.5,
                penalty=-10,
                description="Regola di test",
            ),
            "TEST-CRITICAL": RuleConfig(
                severity="critical",
                weight=1.0,
                penalty=-25,
                description="Regola critica di test",
            ),
            "TEST-INFO": RuleConfig(
                severity="info",
                weight=0.0,
                penalty=0,
                description="Regola informativa",
            ),
        },
    }
    defaults.update(overrides)
    return ScoringProfile(**defaults)


# ============================================================
# Test ScoringProfile — Validazione
# ============================================================

class TestScoringProfile:
    """Test validazione e costruzione del profilo."""

    def test_profilo_valido(self):
        """Un profilo con tutti i campi validi si crea senza errori."""
        profile = _make_profile()
        assert profile.name == "test"
        assert len(profile.rules) == 3
        assert abs(sum(profile.layer_weights.values()) - 1.0) < 0.01

    def test_layer_weights_sommano_a_uno(self):
        """I pesi dei layer devono sommare a 1.0."""
        with pytest.raises(ValueError, match="sommare a 1.0"):
            _make_profile(layer_weights={
                "infra": 0.5,
                "architecture": 0.3,
                "security": 0.3,
                "quality": 0.1,
            })

    def test_layer_weights_layer_invalido(self):
        """Un layer non valido nel profilo viene rifiutato."""
        with pytest.raises(ValueError, match="non valido"):
            _make_profile(layer_weights={
                "infra": 0.35,
                "architecture": 0.25,
                "security": 0.25,
                "banana": 0.15,
            })

    def test_layer_weight_negativo(self):
        """Un peso negativo per layer viene rifiutato."""
        with pytest.raises(ValueError):
            _make_profile(layer_weights={
                "infra": -0.1,
                "architecture": 0.5,
                "security": 0.3,
                "quality": 0.3,
            })

    def test_severity_invalida(self):
        """Una severità non valida viene rifiutata."""
        with pytest.raises(ValueError, match="non valida"):
            RuleConfig(severity="catastrofico", weight=0.5, penalty=-10)

    def test_penalty_positiva_rifiutata(self):
        """Una penalità positiva viene rifiutata."""
        with pytest.raises(ValueError):
            RuleConfig(severity="medium", weight=0.5, penalty=10)

    def test_weight_fuori_range(self):
        """Un peso fuori range [0, 1] viene rifiutato."""
        with pytest.raises(ValueError):
            RuleConfig(severity="medium", weight=1.5, penalty=-10)

    def test_info_con_penalty_non_zero(self):
        """Una regola info con penalità != 0 viene rifiutata dal model_validator."""
        with pytest.raises(ValueError, match="info"):
            _make_profile(rules={
                "BAD-INFO": RuleConfig(
                    severity="info",
                    weight=0.0,
                    penalty=-5,
                ),
            })

    def test_get_rule_esistente(self):
        """get_rule() restituisce la regola se presente."""
        profile = _make_profile()
        rule = profile.get_rule("TEST-001")
        assert rule is not None
        assert rule.severity == "medium"
        assert rule.penalty == -10

    def test_get_rule_non_esistente(self):
        """get_rule() restituisce None per regole non presenti."""
        profile = _make_profile()
        assert profile.get_rule("INESISTENTE-001") is None

    def test_default_rule_weight(self):
        """default_rule_weight è usato come fallback."""
        profile = _make_profile(default_rule_weight=0.3)
        assert profile.default_rule_weight == 0.3

    def test_nome_profilo_vuoto_rifiutato(self):
        """Un nome profilo vuoto viene rifiutato."""
        with pytest.raises(ValueError):
            _make_profile(name="")


# ============================================================
# Test load_profile — Caricamento da YAML
# ============================================================

class TestLoadProfile:
    """Test caricamento profili da file YAML."""

    def test_carica_profilo_default(self, tmp_path):
        """Carica il profilo default dalla directory scoring-profiles."""
        from pathlib import Path
        # Usa il vero profilo default del progetto
        root = Path(__file__).resolve().parent.parent / "scoring-profiles"
        if root.exists():
            profile = load_profile("default", profiles_dir=root)
            assert profile.name == "default"
            assert abs(sum(profile.layer_weights.values()) - 1.0) < 0.01
            assert len(profile.rules) > 0

    def test_carica_profilo_custom(self, tmp_path):
        """Carica un profilo custom da una directory temporanea."""
        yaml_content = textwrap.dedent("""\
            name: custom
            description: "Profilo custom di test"
            layer_weights:
              infra: 0.40
              architecture: 0.20
              security: 0.30
              quality: 0.10
            default_rule_weight: 0.3
            rules:
              MY-RULE-001:
                severity: high
                weight: 0.8
                penalty: -15
                framework_ref: "NIST PR.DS-6"
                description: "Regola custom"
        """)
        profile_file = tmp_path / "custom.yml"
        profile_file.write_text(yaml_content, encoding="utf-8")

        profile = load_profile("custom", profiles_dir=tmp_path)
        assert profile.name == "custom"
        assert profile.layer_weights["infra"] == 0.40
        assert "MY-RULE-001" in profile.rules
        assert profile.rules["MY-RULE-001"].framework_ref == "NIST PR.DS-6"

    def test_profilo_non_trovato(self, tmp_path):
        """FileNotFoundError se il profilo non esiste."""
        with pytest.raises(FileNotFoundError, match="non trovato"):
            load_profile("inesistente", profiles_dir=tmp_path)

    def test_yaml_malformato(self, tmp_path):
        """ValueError per YAML malformato."""
        bad_file = tmp_path / "bad.yml"
        bad_file.write_text("{{{{non yaml valido", encoding="utf-8")
        with pytest.raises(ValueError, match="parsing YAML"):
            load_profile("bad", profiles_dir=tmp_path)

    def test_yaml_non_dizionario(self, tmp_path):
        """ValueError se il YAML non è un dizionario."""
        list_file = tmp_path / "lista.yml"
        list_file.write_text("- uno\n- due\n- tre\n", encoding="utf-8")
        with pytest.raises(ValueError, match="dizionario"):
            load_profile("lista", profiles_dir=tmp_path)

    def test_yaml_campi_mancanti(self, tmp_path):
        """ValueError se mancano campi obbligatori."""
        incomplete = tmp_path / "incompleto.yml"
        incomplete.write_text("name: incompleto\n", encoding="utf-8")
        with pytest.raises(ValueError, match="validazione"):
            load_profile("incompleto", profiles_dir=tmp_path)


# ============================================================
# Test ScoringEngine — Score per layer
# ============================================================

class TestScoringEngineLayer:
    """Test calcolo score per singolo layer."""

    def test_score_100_senza_finding(self):
        """Score 100/100 se non ci sono finding."""
        profile = _make_profile()
        engine = ScoringEngine(profile)
        result = engine.score_layer(Layer.INFRA, [])
        assert result.score == 100.0
        assert result.layer == Layer.INFRA
        assert len(result.findings) == 0
        assert len(result.evidence_chain) == 0

    def test_score_con_un_finding(self):
        """Score calcolato correttamente con un finding."""
        profile = _make_profile()
        engine = ScoringEngine(profile)
        finding = _make_finding(rule_id="TEST-001")
        result = engine.score_layer(Layer.INFRA, [finding])
        # Penalità: |-10| * 0.5 = 5.0 → score = 95.0
        assert result.score == 95.0
        assert len(result.evidence_chain) == 1
        assert result.evidence_chain[0].penalty == -5.0

    def test_score_con_finding_critico(self):
        """Un finding critico sottrae più punti."""
        profile = _make_profile()
        engine = ScoringEngine(profile)
        finding = _make_finding(rule_id="TEST-CRITICAL", severity=Severity.CRITICAL)
        result = engine.score_layer(Layer.INFRA, [finding])
        # Penalità: |-25| * 1.0 = 25.0 → score = 75.0
        assert result.score == 75.0

    def test_score_info_non_penalizza(self):
        """Un finding info non sottrae punti."""
        profile = _make_profile()
        engine = ScoringEngine(profile)
        finding = _make_finding(rule_id="TEST-INFO", severity=Severity.INFO)
        result = engine.score_layer(Layer.INFRA, [finding])
        # Penalità: |0| * 0.0 = 0.0 → score = 100.0
        assert result.score == 100.0

    def test_score_minimo_zero(self):
        """Lo score non va mai sotto zero."""
        profile = _make_profile()
        engine = ScoringEngine(profile)
        # 10 finding critici con penalità -25 * 1.0 = 250 totale → score clamped a 0
        findings = [
            _make_finding(rule_id="TEST-CRITICAL", severity=Severity.CRITICAL)
            for _ in range(10)
        ]
        result = engine.score_layer(Layer.INFRA, findings)
        assert result.score == 0.0

    def test_score_multipli_finding(self):
        """Score con multipli finding di severità diverse."""
        profile = _make_profile()
        engine = ScoringEngine(profile)
        findings = [
            _make_finding(rule_id="TEST-001"),       # -10 * 0.5 = 5
            _make_finding(rule_id="TEST-CRITICAL", severity=Severity.CRITICAL),  # -25 * 1.0 = 25
            _make_finding(rule_id="TEST-INFO", severity=Severity.INFO),  # 0
        ]
        result = engine.score_layer(Layer.INFRA, findings)
        # 100 - 5 - 25 - 0 = 70.0
        assert result.score == 70.0
        assert len(result.evidence_chain) == 3


# ============================================================
# Test ScoringEngine — Finding senza regola nel profilo
# ============================================================

class TestScoringEngineDefault:
    """Test gestione finding con regole non presenti nel profilo."""

    def test_finding_senza_regola_usa_default(self):
        """Finding con rule_id non nel profilo → peso e penalità default."""
        profile = _make_profile(default_rule_weight=0.5)
        engine = ScoringEngine(profile)
        finding = _make_finding(rule_id="UNKNOWN-001", severity=Severity.HIGH)
        result = engine.score_layer(Layer.INFRA, [finding])
        # Penalità default per high: -10 * 0.5 = 5 → score = 95
        expected_penalty = abs(DEFAULT_PENALTIES["high"]) * 0.5
        assert result.score == 100.0 - expected_penalty
        assert len(result.evidence_chain) == 1

    def test_finding_senza_regola_critical(self):
        """Finding critical senza regola → penalità default critical."""
        profile = _make_profile(default_rule_weight=1.0)
        engine = ScoringEngine(profile)
        finding = _make_finding(rule_id="UNKNOWN-CRIT", severity=Severity.CRITICAL)
        result = engine.score_layer(Layer.INFRA, [finding])
        # Penalità default per critical: -20 * 1.0 = 20 → score = 80
        assert result.score == 80.0

    def test_finding_senza_regola_info(self):
        """Finding info senza regola → penalità 0."""
        profile = _make_profile()
        engine = ScoringEngine(profile)
        finding = _make_finding(rule_id="UNKNOWN-INFO", severity=Severity.INFO)
        result = engine.score_layer(Layer.INFRA, [finding])
        assert result.score == 100.0

    def test_framework_ref_da_finding(self):
        """Per regola non nel profilo, usa framework_ref del finding."""
        profile = _make_profile()
        engine = ScoringEngine(profile)
        finding = _make_finding(
            rule_id="UNKNOWN-001",
            severity=Severity.LOW,
            framework_ref="NIS2 Art.21",
        )
        result = engine.score_layer(Layer.INFRA, [finding])
        assert result.evidence_chain[0].framework_ref == "NIS2 Art.21"


# ============================================================
# Test ScoringEngine — Catena di evidenze
# ============================================================

class TestEvidenceChain:
    """Test completezza e correttezza della catena di evidenze."""

    def test_evidence_chain_completa(self):
        """Ogni finding produce un'EvidenceChain con tutti i campi."""
        profile = _make_profile(rules={
            "RULE-A": RuleConfig(
                severity="high",
                weight=0.8,
                penalty=-15,
                framework_ref="NIST PR.DS-6",
            ),
        })
        engine = ScoringEngine(profile)
        finding = _make_finding(rule_id="RULE-A", severity=Severity.HIGH)
        result = engine.score_layer(Layer.INFRA, [finding])

        assert len(result.evidence_chain) == 1
        ev = result.evidence_chain[0]
        assert ev.finding_id == finding.id
        assert ev.rule_id == "RULE-A"
        assert ev.weight == 0.8
        assert ev.penalty == -12.0  # |-15| * 0.8 = 12.0, stored as -12.0
        assert ev.framework_ref == "NIST PR.DS-6"

    def test_evidence_chain_framework_fallback(self):
        """Se la regola non ha framework_ref, usa quello del finding."""
        profile = _make_profile(rules={
            "RULE-B": RuleConfig(
                severity="medium",
                weight=0.5,
                penalty=-10,
                framework_ref=None,
            ),
        })
        engine = ScoringEngine(profile)
        finding = _make_finding(
            rule_id="RULE-B",
            framework_ref="ISO 27001 A.12",
        )
        result = engine.score_layer(Layer.INFRA, [finding])
        assert result.evidence_chain[0].framework_ref == "ISO 27001 A.12"

    def test_evidence_chain_ordine_corretto(self):
        """Le evidenze seguono lo stesso ordine dei finding."""
        profile = _make_profile()
        engine = ScoringEngine(profile)
        findings = [
            _make_finding(rule_id="TEST-001"),
            _make_finding(rule_id="TEST-CRITICAL", severity=Severity.CRITICAL),
        ]
        result = engine.score_layer(Layer.INFRA, findings)
        assert result.evidence_chain[0].rule_id == "TEST-001"
        assert result.evidence_chain[1].rule_id == "TEST-CRITICAL"


# ============================================================
# Test ScoringEngine — HealthScore aggregato
# ============================================================

class TestHealthScore:
    """Test calcolo HealthScore complessivo."""

    def test_health_score_senza_finding(self):
        """HealthScore 100/100 con zero finding."""
        profile = _make_profile()
        engine = ScoringEngine(profile)
        result = engine.calculate([])
        assert result.overall_score == 100.0
        # Tutti i layer hanno score 100
        for layer_score in result.layer_scores.values():
            assert layer_score.score == 100.0

    def test_health_score_con_finding(self):
        """HealthScore calcolato con media pesata corretta."""
        profile = _make_profile()
        engine = ScoringEngine(profile)
        # Solo un finding infra: TEST-001 → penalità 5 → infra score = 95
        findings = [_make_finding(rule_id="TEST-001", layer=Layer.INFRA)]
        result = engine.calculate(findings)

        # infra: 95 * 0.35 = 33.25
        # architecture: 100 * 0.25 = 25.0
        # security: 100 * 0.25 = 25.0
        # quality: 100 * 0.15 = 15.0
        # totale: 98.25
        assert result.overall_score == 98.25
        assert result.layer_scores["infra"].score == 95.0
        assert result.layer_scores["architecture"].score == 100.0

    def test_health_score_multipli_layer(self):
        """HealthScore con finding su più layer."""
        profile = _make_profile()
        engine = ScoringEngine(profile)
        findings = [
            _make_finding(rule_id="TEST-001", layer=Layer.INFRA),          # infra -5
            _make_finding(rule_id="TEST-CRITICAL", layer=Layer.ARCHITECTURE, severity=Severity.CRITICAL),  # arch -25
        ]
        result = engine.calculate(findings)

        # infra: 95 * 0.35 = 33.25
        # architecture: 75 * 0.25 = 18.75
        # security: 100 * 0.25 = 25.0
        # quality: 100 * 0.15 = 15.0
        # totale: 92.0
        assert result.overall_score == 92.0

    def test_health_score_tutti_layer_presenti(self):
        """HealthScore include tutti e 4 i layer anche senza finding."""
        profile = _make_profile()
        engine = ScoringEngine(profile)
        result = engine.calculate([])
        assert "infra" in result.layer_scores
        assert "architecture" in result.layer_scores
        assert "security" in result.layer_scores
        assert "quality" in result.layer_scores

    def test_health_score_basso_molti_critici(self):
        """Score molto basso con molti finding critici su tutti i layer."""
        profile = _make_profile()
        engine = ScoringEngine(profile)
        findings = []
        for layer in Layer:
            for _ in range(5):
                findings.append(_make_finding(
                    rule_id="TEST-CRITICAL",
                    layer=layer,
                    severity=Severity.CRITICAL,
                ))
        result = engine.calculate(findings)
        # 5 critici per layer: 5 * 25 = 125 → score layer = 0 per tutti
        assert result.overall_score == 0.0
        for ls in result.layer_scores.values():
            assert ls.score == 0.0


# ============================================================
# Test scoring/models.py — Re-export
# ============================================================

class TestScoringModels:
    """Test che i modelli sono re-esportati correttamente."""

    def test_import_evidence_chain(self):
        """EvidenceChain importabile da scoring.models."""
        from cto_audit.scoring.models import EvidenceChain as EC
        assert EC is EvidenceChain

    def test_import_layer_score(self):
        """LayerScore importabile da scoring.models."""
        from cto_audit.scoring.models import LayerScore as LS
        assert LS is LayerScore

    def test_import_health_score(self):
        """HealthScore importabile da scoring.models."""
        from cto_audit.scoring.models import HealthScore as HS
        assert HS is HealthScore


# ============================================================
# Test profilo default reale
# ============================================================

class TestProfiloDefault:
    """Test sul profilo default.yml reale del progetto."""

    @pytest.fixture()
    def default_profile(self):
        """Carica il profilo default dalla directory del progetto."""
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent / "scoring-profiles"
        return load_profile("default", profiles_dir=root)

    def test_layer_weights_sommano_a_uno(self, default_profile):
        """I pesi del profilo default sommano a 1.0."""
        total = sum(default_profile.layer_weights.values())
        assert abs(total - 1.0) < 0.01

    def test_regole_infra_presenti(self, default_profile):
        """Il profilo default contiene le regole INFRA."""
        infra_rules = [r for r in default_profile.rules if r.startswith("INFRA-")]
        assert len(infra_rules) >= 10

    def test_regole_arch_presenti(self, default_profile):
        """Il profilo default contiene le regole ARCH."""
        arch_rules = [r for r in default_profile.rules if r.startswith("ARCH-")]
        assert len(arch_rules) >= 6

    def test_pesi_cto_corretti(self, default_profile):
        """I pesi layer riflettono la priorità CTO: security > arch ≥ infra > quality."""
        w = default_profile.layer_weights
        assert w["security"] >= w["architecture"]
        assert w["security"] >= w["infra"]
        assert w["quality"] <= w["architecture"]

    def test_scoring_completo_con_profilo_default(self, default_profile):
        """Test end-to-end: scoring con profilo default e finding reali."""
        engine = ScoringEngine(default_profile)

        findings = [
            _make_finding(rule_id="INFRA-CICD-001", layer=Layer.INFRA, severity=Severity.HIGH),
            _make_finding(rule_id="INFRA-DOCKER-003", layer=Layer.INFRA, severity=Severity.MEDIUM),
            _make_finding(rule_id="ARCH-COUPLING-001", layer=Layer.ARCHITECTURE, severity=Severity.HIGH),
            _make_finding(rule_id="ARCH-TEST-001", layer=Layer.ARCHITECTURE, severity=Severity.CRITICAL),
        ]
        result = engine.calculate(findings)

        # Verifica che lo score sia ragionevole
        assert 0.0 <= result.overall_score <= 100.0
        assert result.layer_scores["infra"].score < 100.0
        assert result.layer_scores["architecture"].score < 100.0
        assert result.layer_scores["security"].score == 100.0
        assert result.layer_scores["quality"].score == 100.0

        # Verifica catena di evidenze
        infra_chain = result.layer_scores["infra"].evidence_chain
        assert len(infra_chain) == 2
        assert infra_chain[0].rule_id == "INFRA-CICD-001"


# ============================================================
# Test Confidence Scoring
# ============================================================

class TestConfidenceScoring:
    """Test calcolo confidence per layer e overall."""

    def test_confidence_default_no_project_type(self):
        """Confidence calcolata anche senza project_type (default None)."""
        profile = _make_profile()
        engine = ScoringEngine(profile)
        result = engine.calculate([])
        # Senza finding, coverage è 0. Confidence = 0*0.7 + 1.0*0.3 = 0.3
        for ls in result.layer_scores.values():
            assert 0.0 <= ls.confidence <= 1.0

    def test_confidence_with_findings(self):
        """Confidence aumenta con più finding (più coverage)."""
        profile = _make_profile()
        engine = ScoringEngine(profile)

        # Un finding infra copre 1 regola su 8 nel layer
        findings = [
            _make_finding(rule_id="INFRA-CICD-001", layer=Layer.INFRA, severity=Severity.HIGH),
        ]
        result = engine.calculate(findings)
        infra_conf = result.layer_scores["infra"].confidence
        # Coverage = 1/8 = 0.125 → conf = 0.125*0.7 + 1.0*0.3 = 0.3875
        assert infra_conf > 0.3

    def test_confidence_web_only_rules_excluded_for_library(self):
        """Per progetto library, WEB_ONLY_RULES non contano nella coverage."""
        profile = _make_profile()
        engine = ScoringEngine(profile, project_type=ProjectType.LIBRARY)

        # Security con nessun finding: coverage di sole regole applicabili
        result = engine.score_layer(Layer.SECURITY, [])
        # Per library, 4 regole web-only escluse, restano 4 regole applicabili
        # Coverage = 0/4 = 0.0 → conf = 0.0*0.7 + 1.0*0.3 = 0.3
        assert result.confidence == 0.3

    def test_confidence_web_app_includes_all_rules(self):
        """Per web_app, tutte le regole security sono applicabili."""
        profile = _make_profile()
        engine = ScoringEngine(profile, project_type=ProjectType.WEB_APP)

        result = engine.score_layer(Layer.SECURITY, [])
        # Per web_app, tutte le 8 regole sono applicabili
        # Coverage = 0/8 = 0.0 → conf = 0.0*0.7 + 1.0*0.3 = 0.3
        assert result.confidence == 0.3

    def test_confidence_high_with_full_coverage(self):
        """Alta confidence quando tutte le regole del layer sono coperte."""
        profile = _make_profile()
        engine = ScoringEngine(profile, project_type=ProjectType.LIBRARY)

        # Crea finding per TUTTE le regole quality
        findings = []
        for rule_id in LAYER_RULES["quality"]:
            findings.append(_make_finding(
                rule_id=rule_id,
                layer=Layer.QUALITY,
                severity=Severity.MEDIUM,
            ))
        result = engine.score_layer(Layer.QUALITY, findings)
        # Coverage = 10/10 = 1.0 → conf = 1.0*0.7 + 1.0*0.3 = 1.0
        assert result.confidence == 1.0

    def test_overall_confidence_is_weighted_average(self):
        """Overall confidence è la media pesata delle confidence per layer."""
        profile = _make_profile()
        engine = ScoringEngine(profile)
        result = engine.calculate([])

        # Tutte le confidence dei layer sono uguali (0.3 ciascuna),
        # quindi la media pesata è 0.3
        assert result.overall_confidence == pytest.approx(0.3, abs=0.01)

    def test_confidence_info_finding_counts_as_checked(self):
        """Finding INFO conta come regola verificata per la coverage."""
        profile = _make_profile()
        engine = ScoringEngine(profile)

        findings = [
            _make_finding(
                rule_id="INFRA-CICD-001",
                layer=Layer.INFRA,
                severity=Severity.INFO,  # CI/CD trovato → info
            ),
        ]
        result = engine.score_layer(Layer.INFRA, findings)
        # Coverage = 1/8 = 0.125 → conf = 0.125*0.7 + 1.0*0.3 = 0.3875
        # Più alto di senza finding
        assert result.confidence > 0.3

    def test_layer_score_has_confidence_field(self):
        """LayerScore include il campo confidence."""
        profile = _make_profile()
        engine = ScoringEngine(profile)
        result = engine.score_layer(Layer.INFRA, [])
        assert hasattr(result, "confidence")
        assert 0.0 <= result.confidence <= 1.0

    def test_health_score_has_overall_confidence(self):
        """HealthScore include overall_confidence."""
        profile = _make_profile()
        engine = ScoringEngine(profile)
        result = engine.calculate([])
        assert hasattr(result, "overall_confidence")
        assert 0.0 <= result.overall_confidence <= 1.0
