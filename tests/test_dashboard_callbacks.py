"""
Test per la logica callback — funzioni pure Python, nessun server Dash.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from cto_audit.core.models import (
    AuditMetadata, AuditResult, HealthScore, StackInfo,
)
from cto_audit.dashboard.callbacks import _deserialize_result, _run_audit


class TestDeserializeResult:
    def test_none_input(self):
        assert _deserialize_result(None) is None

    def test_empty_string(self):
        assert _deserialize_result("") is None

    def test_invalid_json(self):
        assert _deserialize_result("not json") is None

    def test_valid_json(self):
        result = AuditResult(
            health_score=HealthScore(overall_score=75.0),
            stack_info=StackInfo(),
            classifications=[],
            metadata=AuditMetadata(
                timestamp=datetime.now(),
                target_path="/test",
            ),
        )
        json_str = result.model_dump_json()
        deserialized = _deserialize_result(json_str)
        assert deserialized is not None
        assert deserialized.health_score.overall_score == 75.0


class TestRunAudit:
    def test_audit_locale(self, tmp_path):
        """_run_audit su path locale produce AuditResult."""
        (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
        result = _run_audit("local", str(tmp_path), None, None)
        assert isinstance(result, AuditResult)
        assert result.health_score.overall_score >= 0

    def test_audit_path_inesistente(self):
        """_run_audit su path inesistente solleva eccezione."""
        with pytest.raises(Exception):
            _run_audit("local", "/path/che/non/esiste", None, None)
