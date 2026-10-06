"""
Test EPSS — client FIRST EPSS, arricchimento del finding CVE, report di due diligence.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import httpx

from cto_audit.analyzers.security import SecurityAnalyzer
from cto_audit.collectors.cve_checker import CVEResult, DependencyInfo
from cto_audit.collectors.epss import EPSS_BATCH_SIZE, EPSSScore, query_epss, summarize
from cto_audit.core.models import (
    LAYER_ORDER,
    AuditMetadata,
    AuditResult,
    Finding,
    Layer,
    Severity,
    StackInfo,
)
from cto_audit.reporters.due_diligence import DueDiligenceReporter
from cto_audit.scoring.engine import ScoringEngine
from cto_audit.scoring.profile import load_profile
from cto_audit.sources.local import LocalRepoSource


def _client(rows_by_cve: dict[str, tuple[float, float]], calls: list[str] | None = None, status: int = 200) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request.url.params.get("cve", ""))
        if status != 200:
            return httpx.Response(status)
        asked = request.url.params.get("cve", "").split(",")
        data = [
            {"cve": c, "epss": str(rows_by_cve[c][0]), "percentile": str(rows_by_cve[c][1]), "date": "2026-10-06"}
            for c in asked if c in rows_by_cve
        ]
        return httpx.Response(200, json={"status": "OK", "total": len(data), "data": data})
    return httpx.Client(transport=httpx.MockTransport(handler))


# ============================================================
# query_epss
# ============================================================

class TestQueryEPSS:
    def test_parsing(self):
        client = _client({"CVE-2024-0001": (0.42, 0.99), "CVE-2023-0002": (0.003, 0.60)})
        scores = query_epss(["CVE-2024-0001", "CVE-2023-0002"], client=client)
        assert scores["CVE-2024-0001"] == EPSSScore("CVE-2024-0001", 0.42, 0.99, "2026-10-06")
        assert scores["CVE-2023-0002"].epss == 0.003

    def test_id_non_cve_ignorati_e_dedup(self):
        calls: list[str] = []
        client = _client({"CVE-2024-0001": (0.1, 0.5)}, calls)
        scores = query_epss(["GHSA-xxxx-yyyy", "cve-2024-0001", "CVE-2024-0001", ""], client=client)
        assert set(scores) == {"CVE-2024-0001"}
        assert calls == ["CVE-2024-0001"]

    def test_batching(self):
        ids = [f"CVE-2024-{i:05d}" for i in range(EPSS_BATCH_SIZE + 5)]
        calls: list[str] = []
        client = _client({c: (0.01, 0.1) for c in ids}, calls)
        scores = query_epss(ids, client=client)
        assert len(scores) == len(ids)
        assert len(calls) == 2
        assert all(len(c) <= 2000 for c in calls)

    def test_lista_vuota(self):
        assert query_epss([]) == {}

    def test_errore_http_degrada(self):
        client = _client({}, status=500)
        assert query_epss(["CVE-2024-0001"], client=client) == {}

    def test_errore_rete_degrada(self):
        def handler(request):
            raise httpx.ConnectError("offline")
        client = httpx.Client(transport=httpx.MockTransport(handler))
        assert query_epss(["CVE-2024-0001"], client=client) == {}

    def test_summarize(self):
        scores = {
            "CVE-2024-0001": EPSSScore("CVE-2024-0001", 0.42, 0.99, "2026-10-06"),
            "CVE-2023-0002": EPSSScore("CVE-2023-0002", 0.003, 0.60, "2026-10-06"),
        }
        s = summarize(scores)
        assert s["max_cve"] == "CVE-2024-0001"
        assert s["max_epss"] == 0.42
        assert s["scored_cves"] == 2
        assert s["source"] == "FIRST EPSS"
        assert json.dumps(s)  # serializzabile
        assert summarize({}) == {}


# ============================================================
# SecurityAnalyzer: finding CVE arricchito
# ============================================================

def _write(base: Path, rel: str, content: str) -> None:
    p = base / Path(rel)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _cve_results() -> list[CVEResult]:
    return [
        CVEResult(DependencyInfo("requests", "2.25.0", "PyPI", "requirements.txt"),
                  cve_ids=["CVE-2023-0002"], summaries=[], severities=[]),
        CVEResult(DependencyInfo("pillow", "8.0.0", "PyPI", "requirements.txt"),
                  cve_ids=["CVE-2024-0001", "CVE-2022-0003"], summaries=[], severities=[]),
    ]


def _epss_scores() -> dict[str, EPSSScore]:
    return {
        "CVE-2024-0001": EPSSScore("CVE-2024-0001", 0.42, 0.99, "2026-10-06"),
        "CVE-2023-0002": EPSSScore("CVE-2023-0002", 0.003, 0.60, "2026-10-06"),
    }


class TestSecurityAnalyzerEPSS:
    def _run(self, tmp_path, epss):
        _write(tmp_path, "requirements.txt", "requests==2.25.0\npillow==8.0.0\n")
        _write(tmp_path, "app.py", "x = 1\n")
        with patch("cto_audit.collectors.cve_checker.query_osv", return_value=_cve_results()), \
             patch("cto_audit.collectors.epss.query_epss", return_value=epss):
            findings = SecurityAnalyzer(offline=False).analyze(
                LocalRepoSource(tmp_path), StackInfo(languages={"python": 1.0}), []
            )
        return next(f for f in findings if f.rule_id == "SEC-DEPS-CVE-001")

    def test_ordinamento_e_testo(self, tmp_path):
        f = self._run(tmp_path, _epss_scores())
        # pillow (EPSS 42%) prima di requests (0.3%)
        assert f.description.index("pillow") < f.description.index("requests")
        assert "CVE-2024-0001 (EPSS 42%)" in f.description
        assert "CVE-2024-0001 con 42%" in f.description
        assert "2 CVE su 3" in f.description
        assert "non modifica lo score" in f.description

    def test_extra_popolato(self, tmp_path):
        f = self._run(tmp_path, _epss_scores())
        assert f.extra["epss"]["max_cve"] == "CVE-2024-0001"
        assert f.extra["epss"]["max_epss"] == 0.42
        assert f.extra["epss"]["scored_cves"] == 2

    def test_severita_invariata_dal_epss(self, tmp_path):
        with_epss = self._run(tmp_path, _epss_scores())
        without = self._run(tmp_path, {})
        assert with_epss.severity == without.severity == Severity.MEDIUM
        assert without.extra == {}
        assert "non disponibile" in without.description

    def test_offline_nessuna_chiamata(self, tmp_path):
        _write(tmp_path, "requirements.txt", "requests==2.25.0\n")
        _write(tmp_path, "app.py", "x = 1\n")
        with patch("cto_audit.collectors.epss.query_epss") as q:
            findings = SecurityAnalyzer(offline=True).analyze(LocalRepoSource(tmp_path), StackInfo(languages={"python": 1.0}), [])
        assert not q.called
        assert not [f for f in findings if f.rule_id == "SEC-DEPS-CVE-001"]


# ============================================================
# Report di due diligence
# ============================================================

class TestDueDiligenceReportEPSS:
    def _result(self, findings: list[Finding]) -> AuditResult:
        hs = ScoringEngine(load_profile("due-diligence")).calculate(findings)
        return AuditResult(
            health_score=hs, stack_info=StackInfo(languages={"python": 1.0}), classifications=[],
            metadata=AuditMetadata(target_path="/tmp/x", scoring_profile="due-diligence", active_layers=LAYER_ORDER),
        )

    def test_riga_epss_e_ordinamento(self):
        cve = Finding(id="a", layer=Layer.SECURITY, severity=Severity.HIGH, rule_id="SEC-DEPS-CVE-001",
                      title="CVE note nelle dipendenze", description="...",
                      extra={"epss": summarize(_epss_scores())})
        other = Finding(id="b", layer=Layer.INFRA, severity=Severity.HIGH, rule_id="INFRA-CICD-001",
                        title="Nessun CI/CD", description="...")
        text = DueDiligenceReporter(now=datetime(2026, 10, 6, tzinfo=timezone.utc)).report(self._result([other, cve]))
        assert "Probabilita di sfruttamento (FIRST EPSS, 2026-10-06)" in text
        assert "CVE-2024-0001 al 42%" in text
        # a parita di severita HIGH, il finding con EPSS viene prima
        assert text.index("CVE note nelle dipendenze") < text.index("Nessun CI/CD")

    def test_finding_senza_extra_invariato(self):
        f = Finding(id="b", layer=Layer.INFRA, severity=Severity.HIGH, rule_id="INFRA-CICD-001",
                    title="Nessun CI/CD", description="...")
        text = DueDiligenceReporter().report(self._result([f]))
        assert "EPSS" not in text.split("## 4. Red flag")[1].split("## 5.")[0]
