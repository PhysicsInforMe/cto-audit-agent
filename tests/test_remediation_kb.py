"""
Test per Remediation Knowledge Base — modelli, loader, cross-validazione.
"""

import pytest
import yaml
from pathlib import Path

from cto_audit.remediation.models import (
    EffortRange,
    RemediationEntry,
    StackSpecificRemediation,
    WhatIfResult,
    RemediationPipelineResult,
)
from cto_audit.remediation.loader import RemediationLoader
from cto_audit.core.models import StackInfo
from cto_audit.scoring.profile import load_profile


# --- Test EffortRange ---

class TestEffortRange:
    def test_valid_effort(self):
        e = EffortRange(min_hours=4, max_hours=16, t_shirt="M")
        assert e.min_hours == 4
        assert e.max_hours == 16
        assert e.t_shirt == "M"

    def test_avg_hours(self):
        e = EffortRange(min_hours=4, max_hours=16, t_shirt="M")
        assert e.avg_hours == 10.0

    def test_all_tshirt_sizes(self):
        for size in ["XS", "S", "M", "L", "XL"]:
            e = EffortRange(min_hours=1, max_hours=2, t_shirt=size)
            assert e.t_shirt == size

    def test_invalid_tshirt(self):
        with pytest.raises(Exception):
            EffortRange(min_hours=1, max_hours=2, t_shirt="XXL")

    def test_min_hours_zero(self):
        with pytest.raises(Exception):
            EffortRange(min_hours=0, max_hours=2, t_shirt="S")


# --- Test RemediationEntry ---

class TestRemediationEntry:
    def test_valid_entry(self):
        entry = RemediationEntry(
            rule_id="INFRA-CICD-001",
            risk_business="Senza CI/CD ogni deploy e manuale e rischioso.",
            remediation_steps=["Step 1", "Step 2"],
            effort_range=EffortRange(min_hours=4, max_hours=16, t_shirt="M"),
            priority_tier=1,
            stack_specific={},
            references=["NIST PR.DS-6"],
        )
        assert entry.rule_id == "INFRA-CICD-001"
        assert entry.priority_tier == 1
        assert len(entry.remediation_steps) == 2

    def test_risk_business_too_short(self):
        with pytest.raises(Exception):
            RemediationEntry(
                rule_id="X",
                risk_business="Corto",  # < 10 chars
                remediation_steps=["Step"],
                effort_range=EffortRange(min_hours=1, max_hours=2, t_shirt="S"),
            )

    def test_empty_remediation_steps(self):
        with pytest.raises(Exception):
            RemediationEntry(
                rule_id="X",
                risk_business="Rischio business lungo abbastanza",
                remediation_steps=[],
                effort_range=EffortRange(min_hours=1, max_hours=2, t_shirt="S"),
            )

    def test_priority_tier_bounds(self):
        with pytest.raises(Exception):
            RemediationEntry(
                rule_id="X",
                risk_business="Rischio business lungo abbastanza",
                remediation_steps=["Step"],
                effort_range=EffortRange(min_hours=1, max_hours=2, t_shirt="S"),
                priority_tier=4,
            )

    def test_get_steps_for_stack_generic(self):
        entry = RemediationEntry(
            rule_id="X",
            risk_business="Rischio business lungo abbastanza",
            remediation_steps=["Generic step"],
            effort_range=EffortRange(min_hours=1, max_hours=2, t_shirt="S"),
            stack_specific={
                "python": StackSpecificRemediation(remediation_steps=["Python step"]),
            },
        )
        assert entry.get_steps_for_stack(None) == ["Generic step"]
        assert entry.get_steps_for_stack("go") == ["Generic step"]

    def test_get_steps_for_stack_specific(self):
        entry = RemediationEntry(
            rule_id="X",
            risk_business="Rischio business lungo abbastanza",
            remediation_steps=["Generic step"],
            effort_range=EffortRange(min_hours=1, max_hours=2, t_shirt="S"),
            stack_specific={
                "python": StackSpecificRemediation(remediation_steps=["Python step"]),
            },
        )
        assert entry.get_steps_for_stack("python") == ["Python step"]


# --- Test RemediationLoader ---

class TestRemediationLoader:
    def test_load_default_kb(self):
        loader = RemediationLoader.from_yaml("default")
        entries = loader.all_entries()
        assert len(entries) > 0
        assert "INFRA-CICD-001" in entries

    def test_all_entries_are_valid(self):
        loader = RemediationLoader.from_yaml("default")
        for rule_id, entry in loader.all_entries().items():
            assert entry.rule_id == rule_id
            assert len(entry.risk_business) >= 10
            assert len(entry.remediation_steps) >= 1
            assert entry.effort_range.min_hours >= 1
            assert entry.effort_range.max_hours >= entry.effort_range.min_hours
            assert entry.priority_tier in (1, 2, 3)

    def test_get_existing_rule(self):
        loader = RemediationLoader.from_yaml("default")
        entry = loader.get("INFRA-CICD-001")
        assert entry is not None
        assert entry.rule_id == "INFRA-CICD-001"

    def test_get_nonexistent_rule(self):
        loader = RemediationLoader.from_yaml("default")
        entry = loader.get("NONEXISTENT-001")
        assert entry is None

    def test_get_for_stack_python(self):
        loader = RemediationLoader.from_yaml("default")
        stack = StackInfo(languages={"python": 0.8, "javascript": 0.2})
        entry = loader.get_for_stack("INFRA-CICD-001", stack)
        assert entry is not None
        # Python-specific steps should be returned
        assert any("python" in s.lower() or "pytest" in s.lower() or "ruff" in s.lower()
                    for s in entry.remediation_steps)

    def test_get_for_stack_no_specific(self):
        loader = RemediationLoader.from_yaml("default")
        stack = StackInfo(languages={"rust": 0.9})
        entry = loader.get_for_stack("INFRA-CICD-001", stack)
        assert entry is not None
        # Should return generic steps
        assert entry.remediation_steps == loader.get("INFRA-CICD-001").remediation_steps

    def test_get_for_stack_empty_languages(self):
        loader = RemediationLoader.from_yaml("default")
        stack = StackInfo()
        entry = loader.get_for_stack("INFRA-CICD-001", stack)
        assert entry is not None

    def test_kb_not_found(self):
        with pytest.raises(FileNotFoundError):
            RemediationLoader.from_yaml("nonexistent")


# --- Cross-validazione KB ↔ Scoring Profile ---

class TestKBCrossValidation:
    """Verifica che ogni regola penalizzante nel scoring profile abbia entry nella KB."""

    def test_all_penalizing_rules_in_kb(self):
        """Ogni regola con penalty < 0 nel profilo default deve avere entry nella KB."""
        profile = load_profile("default")
        loader = RemediationLoader.from_yaml("default")
        kb_entries = loader.all_entries()

        missing = []
        for rule_id, rule in profile.rules.items():
            if rule.penalty < 0:
                if rule_id not in kb_entries:
                    missing.append(rule_id)

        assert not missing, (
            f"Regole penalizzanti senza entry nella KB: {missing}"
        )

    def test_kb_entries_match_profile_rules(self):
        """Ogni entry nella KB deve corrispondere a una regola nel profilo."""
        profile = load_profile("default")
        loader = RemediationLoader.from_yaml("default")

        orphans = []
        for rule_id in loader.all_entries():
            if rule_id not in profile.rules:
                orphans.append(rule_id)

        assert not orphans, (
            f"Entry KB senza regola nel profilo: {orphans}"
        )

    def test_exactly_37_penalizing_rules(self):
        """Il profilo default ha esattamente 37 regole penalizzanti (18 INFRA+ARCH + 9 SEC + 10 QUAL)."""
        profile = load_profile("default")
        penalizing = [r for r, c in profile.rules.items() if c.penalty < 0]
        assert len(penalizing) == 37

    def test_kb_has_37_entries(self):
        """La KB default ha esattamente 37 entry (18 INFRA+ARCH + 9 SEC + 10 QUAL)."""
        loader = RemediationLoader.from_yaml("default")
        assert len(loader.all_entries()) == 37


# --- Test WhatIfResult e RemediationPipelineResult ---

class TestPipelineModels:
    def test_whatif_result(self):
        r = WhatIfResult(
            rule_id="INFRA-CICD-001",
            current_score=50.0,
            projected_score=75.0,
            delta=25.0,
            effort=EffortRange(min_hours=4, max_hours=16, t_shirt="M"),
            impact_effort_ratio=2.5,
        )
        assert r.delta == 25.0

    def test_remediation_pipeline_result_empty(self):
        r = RemediationPipelineResult()
        assert r.context is None
        assert r.whatif_results == []
        assert not r.llm_used
