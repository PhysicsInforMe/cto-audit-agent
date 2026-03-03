"""
Test per What-If Simulator.
"""

import pytest

from cto_audit.core.models import Finding, Layer, Severity
from cto_audit.remediation.models import EffortRange
from cto_audit.remediation.simulator import WhatIfSimulator
from cto_audit.scoring.engine import ScoringEngine
from cto_audit.scoring.profile import load_profile


def _make_finding(rule_id: str, layer: Layer = Layer.INFRA, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        id=f"test-{rule_id}",
        layer=layer,
        severity=severity,
        rule_id=rule_id,
        title=f"Test {rule_id}",
        description=f"Test finding for {rule_id}",
    )


@pytest.fixture
def engine():
    profile = load_profile("default")
    return ScoringEngine(profile)


class TestWhatIfSimulator:
    def test_zero_findings(self, engine):
        """Con zero finding, simulate_all restituisce lista vuota."""
        health = engine.calculate([])
        sim = WhatIfSimulator(engine)
        results = sim.simulate_all(health)
        assert results == []

    def test_single_rule(self, engine):
        """Rimuovere una singola regola migliora lo score."""
        findings = [_make_finding("INFRA-CICD-001", severity=Severity.CRITICAL)]
        health = engine.calculate(findings)

        sim = WhatIfSimulator(engine)
        results = sim.simulate(health, ["INFRA-CICD-001"])

        assert len(results) == 1
        r = results[0]
        assert r.rule_id == "INFRA-CICD-001"
        assert r.delta > 0
        assert r.projected_score > r.current_score
        assert r.projected_score == 100.0  # Rimuovendo l'unico finding

    def test_nonexistent_rule(self, engine):
        """Simulare una regola senza finding restituisce lista vuota."""
        findings = [_make_finding("INFRA-CICD-001", severity=Severity.CRITICAL)]
        health = engine.calculate(findings)

        sim = WhatIfSimulator(engine)
        results = sim.simulate(health, ["NONEXISTENT-001"])
        assert results == []

    def test_ordering_by_impact_effort_ratio(self, engine):
        """I risultati sono ordinati per impact_effort_ratio decrescente."""
        findings = [
            _make_finding("INFRA-CICD-001", severity=Severity.CRITICAL),
            _make_finding("INFRA-DOCKER-002", severity=Severity.LOW),
        ]
        health = engine.calculate(findings)

        effort_map = {
            "INFRA-CICD-001": EffortRange(min_hours=4, max_hours=16, t_shirt="M"),
            "INFRA-DOCKER-002": EffortRange(min_hours=1, max_hours=2, t_shirt="XS"),
        }

        sim = WhatIfSimulator(engine)
        results = sim.simulate_all(health, effort_map)

        assert len(results) == 2
        # Ordinati per ratio decrescente
        assert results[0].impact_effort_ratio >= results[1].impact_effort_ratio

    def test_effort_ratio_calculation(self, engine):
        """Il ratio e calcolato come delta / avg_hours."""
        findings = [_make_finding("INFRA-CICD-001", severity=Severity.CRITICAL)]
        health = engine.calculate(findings)

        effort = EffortRange(min_hours=4, max_hours=16, t_shirt="M")
        effort_map = {"INFRA-CICD-001": effort}

        sim = WhatIfSimulator(engine)
        results = sim.simulate(health, ["INFRA-CICD-001"], effort_map)

        assert len(results) == 1
        r = results[0]
        expected_ratio = r.delta / effort.avg_hours
        assert abs(r.impact_effort_ratio - round(expected_ratio, 4)) < 0.001

    def test_no_effort_ratio_equals_delta(self, engine):
        """Senza effort, il ratio e uguale al delta."""
        findings = [_make_finding("INFRA-CICD-001", severity=Severity.CRITICAL)]
        health = engine.calculate(findings)

        sim = WhatIfSimulator(engine)
        results = sim.simulate(health, ["INFRA-CICD-001"])

        assert len(results) == 1
        assert results[0].impact_effort_ratio == results[0].delta

    def test_simulate_all(self, engine):
        """simulate_all include tutte le regole con finding."""
        findings = [
            _make_finding("INFRA-CICD-001", severity=Severity.CRITICAL),
            _make_finding("INFRA-DOCKER-001", severity=Severity.CRITICAL),
            _make_finding("ARCH-TEST-001", layer=Layer.ARCHITECTURE, severity=Severity.HIGH),
        ]
        health = engine.calculate(findings)

        sim = WhatIfSimulator(engine)
        results = sim.simulate_all(health)

        rule_ids = {r.rule_id for r in results}
        assert "INFRA-CICD-001" in rule_ids
        assert "INFRA-DOCKER-001" in rule_ids
        assert "ARCH-TEST-001" in rule_ids

    def test_multiple_findings_same_rule(self, engine):
        """Multipli finding della stessa regola vengono rimossi tutti."""
        findings = [
            Finding(
                id="test-1", layer=Layer.ARCHITECTURE, severity=Severity.MEDIUM,
                rule_id="ARCH-SCALE-001", title="Big file 1", description="File grande 1",
            ),
            Finding(
                id="test-2", layer=Layer.ARCHITECTURE, severity=Severity.MEDIUM,
                rule_id="ARCH-SCALE-001", title="Big file 2", description="File grande 2",
            ),
        ]
        health = engine.calculate(findings)

        sim = WhatIfSimulator(engine)
        results = sim.simulate(health, ["ARCH-SCALE-001"])

        assert len(results) == 1
        r = results[0]
        assert r.projected_score == 100.0
        assert r.delta > 0

    def test_with_default_profile_realistic(self, engine):
        """Test con profilo default e finding realistici."""
        findings = [
            _make_finding("INFRA-CICD-001", severity=Severity.CRITICAL),
            _make_finding("INFRA-DOCKER-001", severity=Severity.CRITICAL),
            _make_finding("INFRA-IAC-001", severity=Severity.HIGH),
            _make_finding("INFRA-DEPS-001", severity=Severity.HIGH),
            _make_finding("ARCH-TEST-001", layer=Layer.ARCHITECTURE, severity=Severity.HIGH),
            _make_finding("ARCH-STRUCT-001", layer=Layer.ARCHITECTURE, severity=Severity.MEDIUM),
        ]
        health = engine.calculate(findings)

        effort_map = {
            "INFRA-CICD-001": EffortRange(min_hours=4, max_hours=16, t_shirt="M"),
            "INFRA-DOCKER-001": EffortRange(min_hours=4, max_hours=16, t_shirt="M"),
            "INFRA-IAC-001": EffortRange(min_hours=8, max_hours=40, t_shirt="L"),
            "INFRA-DEPS-001": EffortRange(min_hours=1, max_hours=4, t_shirt="S"),
            "ARCH-TEST-001": EffortRange(min_hours=8, max_hours=40, t_shirt="L"),
            "ARCH-STRUCT-001": EffortRange(min_hours=8, max_hours=40, t_shirt="L"),
        }

        sim = WhatIfSimulator(engine)
        results = sim.simulate_all(health, effort_map)

        assert len(results) == 6
        # Il primo dovrebbe avere il miglior ratio
        assert results[0].impact_effort_ratio >= results[-1].impact_effort_ratio
        # Tutti i delta devono essere positivi
        for r in results:
            assert r.delta > 0
