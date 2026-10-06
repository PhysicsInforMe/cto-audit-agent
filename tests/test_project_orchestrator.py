"""
Test per ProjectOrchestrator — mock sources, aggregazione, gestione errori.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cto_audit.core.project import ProjectConfig, ProjectSourceConfig
from cto_audit.core.project_orchestrator import ProjectOrchestrator


@pytest.fixture
def repo_a(tmp_path: Path) -> Path:
    """Repo sintetica A — Python."""
    d = tmp_path / "repo_a"
    d.mkdir()
    (d / "src").mkdir()
    (d / "src" / "app.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n"
        "@app.get('/')\ndef home():\n    return 'hello'\n",
        encoding="utf-8",
    )
    (d / "requirements.txt").write_text("flask>=3.0\n", encoding="utf-8")
    (d / "README.md").write_text("# Repo A\n", encoding="utf-8")
    return d


@pytest.fixture
def repo_b(tmp_path: Path) -> Path:
    """Repo sintetica B — JS."""
    d = tmp_path / "repo_b"
    d.mkdir()
    (d / "index.js").write_text(
        "const express = require('express');\nconst app = express();\napp.listen(3000);\n",
        encoding="utf-8",
    )
    (d / "package.json").write_text('{"dependencies":{"express":"^4.0"}}\n', encoding="utf-8")
    (d / "README.md").write_text("# Repo B\n", encoding="utf-8")
    return d


class TestProjectOrchestrator:
    def test_audit_due_sorgenti_locali(self, repo_a, repo_b):
        """Audit di 2 repo locali produce AggregatedResult valido."""
        config = ProjectConfig(
            name="Test Project",
            sources=[
                ProjectSourceConfig(name="repo-a", source_type="local", path_or_url=str(repo_a)),
                ProjectSourceConfig(name="repo-b", source_type="local", path_or_url=str(repo_b)),
            ],
        )
        orch = ProjectOrchestrator(config=config, offline=True)
        result = orch.run()

        assert result.project_name == "Test Project"
        assert result.total_sources == 2
        assert len(result.source_results) == 2
        assert result.aggregated_score > 0
        assert result.total_loc > 0

    def test_score_individuali_presenti(self, repo_a, repo_b):
        """Ogni source_result ha il suo audit_result."""
        config = ProjectConfig(
            name="Test",
            sources=[
                ProjectSourceConfig(name="a", source_type="local", path_or_url=str(repo_a)),
                ProjectSourceConfig(name="b", source_type="local", path_or_url=str(repo_b)),
            ],
        )
        orch = ProjectOrchestrator(config=config, offline=True)
        result = orch.run()

        for sr in result.source_results:
            assert sr.audit_result.health_score.overall_score >= 0
            assert sr.loc > 0

    def test_sorgente_fallita_non_blocca_le_altre(self, repo_a):
        """Se una sorgente fallisce, le altre continuano."""
        config = ProjectConfig(
            name="Test",
            sources=[
                ProjectSourceConfig(name="good", source_type="local", path_or_url=str(repo_a)),
                ProjectSourceConfig(name="bad", source_type="local", path_or_url="/path/che/non/esiste"),
            ],
        )
        orch = ProjectOrchestrator(config=config, offline=True)
        result = orch.run()

        assert result.total_sources == 1
        assert "bad" in result.failed_sources
        assert len(result.source_results) == 1
        assert result.source_results[0].name == "good"


class TestAggregation:
    def test_media_pesata_per_loc(self, repo_a, repo_b):
        """Score aggregato è media pesata per LOC."""
        config = ProjectConfig(
            name="Test",
            sources=[
                ProjectSourceConfig(name="a", source_type="local", path_or_url=str(repo_a)),
                ProjectSourceConfig(name="b", source_type="local", path_or_url=str(repo_b)),
            ],
        )
        orch = ProjectOrchestrator(config=config, offline=True)
        result = orch.run()

        # Verifica la media pesata manualmente
        total_loc = sum(sr.loc for sr in result.source_results)
        expected = sum(
            sr.audit_result.health_score.overall_score * sr.loc
            for sr in result.source_results
        ) / total_loc
        assert abs(result.aggregated_score - round(expected, 1)) < 0.2

    def test_layer_scores_aggregati(self, repo_a, repo_b):
        """I layer score sono aggregati."""
        config = ProjectConfig(
            name="Test",
            sources=[
                ProjectSourceConfig(name="a", source_type="local", path_or_url=str(repo_a)),
                ProjectSourceConfig(name="b", source_type="local", path_or_url=str(repo_b)),
            ],
        )
        orch = ProjectOrchestrator(config=config, offline=True)
        result = orch.run()

        # Dovrebbe avere almeno qualche layer
        assert len(result.aggregated_layer_scores) > 0
