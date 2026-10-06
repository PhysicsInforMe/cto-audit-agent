"""
Test per i modelli Pydantic del progetto multi-source.
"""

from __future__ import annotations

import pytest

from cto_audit.core.project import (
    AggregatedResult,
    ProjectConfig,
    ProjectSourceConfig,
    SourceResult,
)


class TestProjectSourceConfig:
    def test_campi_obbligatori(self):
        cfg = ProjectSourceConfig(
            name="backend",
            source_type="github",
            path_or_url="https://github.com/acme/api",
        )
        assert cfg.name == "backend"
        assert cfg.source_type == "github"
        assert cfg.token_env is None
        assert cfg.branch is None

    def test_campi_opzionali(self):
        cfg = ProjectSourceConfig(
            name="backend",
            source_type="github",
            path_or_url="https://github.com/acme/api",
            token_env="GITHUB_TOKEN",
            branch="main",
        )
        assert cfg.token_env == "GITHUB_TOKEN"
        assert cfg.branch == "main"

    def test_validazione_nome_obbligatorio(self):
        with pytest.raises(Exception):
            ProjectSourceConfig(source_type="local", path_or_url="/path")


class TestProjectConfig:
    def test_config_valida(self):
        cfg = ProjectConfig(
            name="Acme Platform",
            sources=[
                ProjectSourceConfig(name="api", source_type="local", path_or_url="/path"),
            ],
        )
        assert cfg.name == "Acme Platform"
        assert len(cfg.sources) == 1

    def test_config_multi_source(self):
        cfg = ProjectConfig(
            name="Acme",
            sources=[
                ProjectSourceConfig(name="api", source_type="local", path_or_url="/a"),
                ProjectSourceConfig(name="web", source_type="local", path_or_url="/b"),
                ProjectSourceConfig(name="libs", source_type="zip", path_or_url="/c.zip"),
            ],
        )
        assert len(cfg.sources) == 3

    def test_config_senza_sources(self):
        with pytest.raises(Exception):
            ProjectConfig(name="Empty", sources=[])

    def test_serializzazione_dict(self):
        cfg = ProjectConfig(
            name="Test",
            sources=[
                ProjectSourceConfig(name="api", source_type="local", path_or_url="/path"),
            ],
        )
        d = cfg.model_dump()
        assert d["name"] == "Test"
        assert len(d["sources"]) == 1


class TestAggregatedResult:
    def test_default_values(self):
        r = AggregatedResult(project_name="Test")
        assert r.aggregated_score == 0.0
        assert r.total_loc == 0
        assert r.total_sources == 0
        assert r.failed_sources == []

    def test_serializzazione_json(self):
        r = AggregatedResult(
            project_name="Test",
            aggregated_score=75.5,
            total_loc=10000,
            total_sources=3,
        )
        json_str = r.model_dump_json()
        assert "Test" in json_str
        assert "75.5" in json_str
