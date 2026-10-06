"""
ProjectOrchestrator — gestisce audit multi-source.

Itera le sorgenti di un progetto, esegue AuditOrchestrator per ciascuna,
e aggrega i risultati con media pesata per LOC.
"""

from __future__ import annotations

import os
from contextlib import nullcontext
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console

from cto_audit.core.models import AuditResult
from cto_audit.core.orchestrator import AuditOrchestrator
from cto_audit.core.project import (
    AggregatedResult,
    ProjectConfig,
    ProjectSourceConfig,
    SourceResult,
)
from cto_audit.sources.factory import SourceFactory
from cto_audit.sources.local import LocalRepoSource


class ProjectOrchestrator:
    """
    Orchestratore per progetti multi-source.

    Itera le sorgenti configurate, esegue un audit per ciascuna,
    e produce un AggregatedResult con score pesati per LOC.
    """

    def __init__(
        self,
        config: ProjectConfig,
        scoring_profile: str = "default",
        offline: bool = False,
        console: Optional[Console] = None,
    ) -> None:
        self.config = config
        self.scoring_profile = scoring_profile
        self.offline = offline
        self.console = console or Console()

    def run(self) -> AggregatedResult:
        """Esegue l'audit su tutte le sorgenti e aggrega i risultati."""
        source_results: list[SourceResult] = []
        failed_sources: list[str] = []

        for src_config in self.config.sources:
            self.console.print(f"\n  Analisi: [bold]{src_config.name}[/bold]...")
            try:
                result, loc = self._audit_single_source(src_config)
                source_results.append(SourceResult(
                    name=src_config.name,
                    audit_result=result,
                    loc=loc,
                ))
            except Exception as e:
                self.console.print(f"  [red]Errore su {src_config.name}: {e}[/red]")
                failed_sources.append(src_config.name)

        # Aggregazione
        aggregated_score, aggregated_layers, total_loc = self._aggregate(source_results)

        return AggregatedResult(
            project_name=self.config.name,
            timestamp=datetime.now(),
            source_results=source_results,
            aggregated_score=aggregated_score,
            aggregated_layer_scores=aggregated_layers,
            total_loc=total_loc,
            total_sources=len(source_results),
            failed_sources=failed_sources,
        )

    def _audit_single_source(
        self, src_config: ProjectSourceConfig
    ) -> tuple[AuditResult, int]:
        """Esegue l'audit su una singola sorgente."""
        # Risolvi token da env var se specificato
        token = None
        if src_config.token_env:
            token = os.environ.get(src_config.token_env)

        source = SourceFactory.create(
            source_type=src_config.source_type,
            path_or_url=src_config.path_or_url,
            token=token,
            branch=src_config.branch,
        )

        is_local = isinstance(source, LocalRepoSource)
        ctx = nullcontext(source) if is_local else source

        with ctx as active_source:
            if hasattr(active_source, "_temp_dir") and active_source._temp_dir:
                target_path = active_source._temp_dir
            else:
                target_path = Path(src_config.path_or_url).resolve()

            orchestrator = AuditOrchestrator(
                source=active_source,
                target_path=target_path,
                scoring_profile=self.scoring_profile,
                offline=self.offline,
                auto_approve=True,
                console=self.console,
            )

            result = orchestrator.run()
            meta = active_source.get_metadata()
            return result, meta.total_loc

    def _aggregate(
        self, source_results: list[SourceResult]
    ) -> tuple[float, dict[str, float], int]:
        """Aggrega score con media pesata per LOC."""
        if not source_results:
            return 0.0, {}, 0

        total_loc = sum(sr.loc for sr in source_results)

        if total_loc == 0:
            # Se nessuna LOC, media semplice
            n = len(source_results)
            avg_score = sum(
                sr.audit_result.health_score.overall_score for sr in source_results
            ) / n
            # Aggrega per layer
            all_layers: dict[str, list[float]] = {}
            for sr in source_results:
                for layer_name, ls in sr.audit_result.health_score.layer_scores.items():
                    all_layers.setdefault(layer_name, []).append(ls.score)
            avg_layers = {k: sum(v) / len(v) for k, v in all_layers.items()}
            return round(avg_score, 1), avg_layers, 0

        # Media pesata per LOC
        weighted_score = sum(
            sr.audit_result.health_score.overall_score * sr.loc
            for sr in source_results
        ) / total_loc

        # Per layer
        layer_weighted: dict[str, float] = {}
        layer_loc: dict[str, int] = {}
        for sr in source_results:
            for layer_name, ls in sr.audit_result.health_score.layer_scores.items():
                layer_weighted[layer_name] = layer_weighted.get(layer_name, 0.0) + ls.score * sr.loc
                layer_loc[layer_name] = layer_loc.get(layer_name, 0) + sr.loc

        avg_layers = {
            k: round(layer_weighted[k] / layer_loc[k], 1)
            for k in layer_weighted
        }

        return round(weighted_score, 1), avg_layers, total_loc
