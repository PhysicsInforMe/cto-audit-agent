"""
Integration test — flusso completo YAML config → ProjectOrchestrator → AggregatedResult.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from cto_audit.core.project import ProjectConfig, AggregatedResult
from cto_audit.core.project_orchestrator import ProjectOrchestrator


@pytest.fixture
def multi_repo_setup(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    """Crea 3 repo locali e un file config YAML."""
    # Repo 1 — Python
    repo1 = tmp_path / "repo1"
    repo1.mkdir()
    (repo1 / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (repo1 / "README.md").write_text("# Repo 1\n", encoding="utf-8")

    # Repo 2 — JS
    repo2 = tmp_path / "repo2"
    repo2.mkdir()
    (repo2 / "index.js").write_text("console.log('hi');\n", encoding="utf-8")
    (repo2 / "package.json").write_text('{"name":"repo2"}\n', encoding="utf-8")

    # Repo 3 — Python + Docker
    repo3 = tmp_path / "repo3"
    repo3.mkdir()
    (repo3 / "main.py").write_text("import sys\nprint(sys.argv)\n", encoding="utf-8")
    (repo3 / "Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")

    # Config YAML
    config_data = {
        "name": "Test Multi-Project",
        "sources": [
            {"name": "repo1", "source_type": "local", "path_or_url": str(repo1)},
            {"name": "repo2", "source_type": "local", "path_or_url": str(repo2)},
            {"name": "repo3", "source_type": "local", "path_or_url": str(repo3)},
        ],
    }
    config_path = tmp_path / "project.yml"
    config_path.write_text(yaml.dump(config_data), encoding="utf-8")

    return config_path, repo1, repo2, repo3


class TestProjectIntegration:
    def test_yaml_to_aggregated_result(self, multi_repo_setup):
        """Flusso completo: YAML → ProjectOrchestrator → AggregatedResult."""
        config_path, _, _, _ = multi_repo_setup

        with open(config_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)

        config = ProjectConfig(**raw)
        orch = ProjectOrchestrator(config=config, offline=True)
        result = orch.run()

        assert isinstance(result, AggregatedResult)
        assert result.project_name == "Test Multi-Project"
        assert result.total_sources == 3
        assert len(result.source_results) == 3
        assert result.aggregated_score > 0
        assert result.failed_sources == []

    def test_ogni_repo_ha_audit_result(self, multi_repo_setup):
        """Ogni repo produce il suo AuditResult."""
        config_path, _, _, _ = multi_repo_setup

        with open(config_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)

        config = ProjectConfig(**raw)
        orch = ProjectOrchestrator(config=config, offline=True)
        result = orch.run()

        names = [sr.name for sr in result.source_results]
        assert "repo1" in names
        assert "repo2" in names
        assert "repo3" in names

        for sr in result.source_results:
            assert sr.audit_result.health_score.overall_score >= 0
            assert sr.audit_result.stack_info is not None

    def test_aggregazione_coerente(self, multi_repo_setup):
        """Lo score aggregato è coerente con i singoli."""
        config_path, _, _, _ = multi_repo_setup

        with open(config_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)

        config = ProjectConfig(**raw)
        orch = ProjectOrchestrator(config=config, offline=True)
        result = orch.run()

        # Score aggregato deve essere nel range degli score individuali
        scores = [sr.audit_result.health_score.overall_score for sr in result.source_results]
        assert min(scores) - 1 <= result.aggregated_score <= max(scores) + 1

    def test_serializzazione_json(self, multi_repo_setup):
        """AggregatedResult è serializzabile in JSON."""
        config_path, _, _, _ = multi_repo_setup

        with open(config_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)

        config = ProjectConfig(**raw)
        orch = ProjectOrchestrator(config=config, offline=True)
        result = orch.run()

        json_str = result.model_dump_json()
        assert "Test Multi-Project" in json_str
        assert "aggregated_score" in json_str
