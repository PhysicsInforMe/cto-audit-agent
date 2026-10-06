"""
Test ProvenanceAnalyzer e LicenseChecker — Layer PROVENANCE.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from cto_audit.analyzers.provenance import ProvenanceAnalyzer
from cto_audit.collectors.cve_checker import DependencyInfo
from cto_audit.collectors.license_checker import (
    LicenseCategory,
    LicenseChecker,
    classify_license,
)
from cto_audit.core.models import Finding, Layer, Severity, StackInfo
from cto_audit.sources.local import LocalRepoSource


def _write(base: Path, rel: str, content: str) -> None:
    p = base / Path(rel)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _run(repo: Path, stack: StackInfo | None = None, analyzer: ProvenanceAnalyzer | None = None) -> list[Finding]:
    source = LocalRepoSource(repo)
    stack = stack or StackInfo(languages={"python": 1.0})
    analyzer = analyzer or ProvenanceAnalyzer(offline=True)
    return analyzer.analyze(source, stack, [])


def _rules(findings: list[Finding]) -> set[str]:
    return {f.rule_id for f in findings if f.severity != Severity.INFO}


def _info(findings: list[Finding]) -> set[str]:
    return {f.rule_id for f in findings if f.severity == Severity.INFO}


# ============================================================
# classify_license
# ============================================================

class TestClassifyLicense:
    @pytest.mark.parametrize("text,expected", [
        ("MIT", LicenseCategory.PERMISSIVE),
        ("Apache-2.0", LicenseCategory.PERMISSIVE),
        ("BSD-3-Clause", LicenseCategory.PERMISSIVE),
        ("GPL-3.0-only", LicenseCategory.STRONG_COPYLEFT),
        # La FOSS License Exception (MySQL) copre solo la combinazione con altro software FOSS:
        # per un prodotto proprietario resta GPL a tutti gli effetti.
        ("GNU GPLv2 (with FOSS License Exception)", LicenseCategory.STRONG_COPYLEFT),
        ("GPLv2 with linking exception", LicenseCategory.WEAK_COPYLEFT),
        ("AGPL-3.0 (dual: Artifex commercial)", LicenseCategory.STRONG_COPYLEFT),
        ("SSPL-1.0", LicenseCategory.STRONG_COPYLEFT),
        ("LGPL-2.1", LicenseCategory.WEAK_COPYLEFT),
        ("MPL-2.0", LicenseCategory.WEAK_COPYLEFT),
        ("SEE LICENSE IN LICENSE.md", LicenseCategory.NONSTANDARD),
        ("Commercial", LicenseCategory.NONSTANDARD),
        ("https://www.highcharts.com/license", LicenseCategory.NONSTANDARD),
        ("UNLICENSED", LicenseCategory.NONSTANDARD),
        ("", LicenseCategory.UNKNOWN),
        (None, LicenseCategory.UNKNOWN),
        ("Something Weird 1.0", LicenseCategory.UNKNOWN),
    ])
    def test_classificazione(self, text, expected):
        assert classify_license(text) == expected


# ============================================================
# LicenseChecker
# ============================================================

class TestLicenseChecker:
    def test_offline_usa_solo_kb(self):
        deps = [
            DependencyInfo("pymupdf", "1.24", "PyPI", "requirements.txt"),
            DependencyInfo("requests", "2.31", "PyPI", "requirements.txt"),
        ]
        results = LicenseChecker(offline=True).check(deps)
        by_name = {r.name: r for r in results}
        assert by_name["pymupdf"].category == LicenseCategory.STRONG_COPYLEFT
        assert by_name["pymupdf"].source == "kb"
        assert by_name["requests"].category == LicenseCategory.UNKNOWN
        assert by_name["requests"].source == "none"

    def test_dedup_per_ecosistema_e_nome(self):
        deps = [
            DependencyInfo("PyMuPDF", "1.24", "PyPI", "requirements.txt"),
            DependencyInfo("pymupdf", "1.25", "PyPI", "pyproject.toml"),
        ]
        results = LicenseChecker(offline=True).check(deps)
        assert len(results) == 1

    def test_online_interroga_registri(self):
        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "pypi.org/pypi/requests/json" in url:
                return httpx.Response(200, json={"info": {"license_expression": "Apache-2.0"}})
            if "pypi.org/pypi/weirdpkg/json" in url:
                return httpx.Response(200, json={"info": {"license": "", "classifiers": [
                    "License :: OSI Approved :: GNU Affero General Public License v3"]}})
            if "registry.npmjs.org/left-pad/latest" in url:
                return httpx.Response(200, json={"license": {"type": "MIT"}})
            return httpx.Response(404)

        client = httpx.Client(transport=httpx.MockTransport(handler))
        deps = [
            DependencyInfo("requests", "2.31", "PyPI", "requirements.txt"),
            DependencyInfo("weirdpkg", "1.0", "PyPI", "requirements.txt"),
            DependencyInfo("left-pad", "1.3", "npm", "package.json"),
            DependencyInfo("missing", "1.0", "npm", "package.json"),
            DependencyInfo("pymupdf", "1.24", "PyPI", "requirements.txt"),
        ]
        results = {r.name: r for r in LicenseChecker(offline=False, client=client).check(deps)}
        assert results["requests"].category == LicenseCategory.PERMISSIVE
        assert results["requests"].source == "registry"
        assert results["weirdpkg"].category == LicenseCategory.STRONG_COPYLEFT
        assert results["left-pad"].category == LicenseCategory.PERMISSIVE
        assert results["missing"].category == LicenseCategory.UNKNOWN
        assert results["pymupdf"].source == "kb"   # la KB ha la precedenza

    def test_errore_rete_degrada_a_unknown(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("offline")
        client = httpx.Client(transport=httpx.MockTransport(handler))
        deps = [DependencyInfo("requests", "2.31", "PyPI", "requirements.txt")]
        results = LicenseChecker(offline=False, client=client).check(deps)
        assert results[0].category == LicenseCategory.UNKNOWN


# ============================================================
# PROV-LICENSE-001 — dichiarazione di licenza / copyright
# ============================================================

class TestOwnLicense:
    def test_licenza_agpl_del_repo_segnalata(self, tmp_path):
        _write(tmp_path, "LICENSE", "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007\n")
        _write(tmp_path, "app.py", "x = 1\n")
        findings = _run(tmp_path)
        f = next(f for f in findings if f.rule_id == "PROV-OWNLICENSE-INFO")
        assert f.severity == Severity.INFO
        assert "copyleft forte" in f.title

    def test_licenza_mit_del_repo(self, tmp_path):
        _write(tmp_path, "LICENSE", "MIT License\n\nCopyright (c) 2026 Acme\n")
        _write(tmp_path, "app.py", "x = 1\n")
        f = next(f for f in _run(tmp_path) if f.rule_id == "PROV-OWNLICENSE-INFO")
        assert "permissiva" in f.title

    def test_senza_license_nessuna_info(self, tmp_path):
        _write(tmp_path, "app.py", "x = 1\n")
        assert "PROV-OWNLICENSE-INFO" not in _info(_run(tmp_path))


class TestLicenseDeclaration:
    def test_nessuna_licenza(self, tmp_path):
        _write(tmp_path, "app.py", "x = 1\n")
        assert "PROV-LICENSE-001" in _rules(_run(tmp_path))

    def test_file_license_presente(self, tmp_path):
        _write(tmp_path, "LICENSE", "Copyright (c) 2026 Acme. All rights reserved.\n")
        _write(tmp_path, "app.py", "x = 1\n")
        assert "PROV-LICENSE-001" not in _rules(_run(tmp_path))

    def test_nota_copyright_nel_readme(self, tmp_path):
        _write(tmp_path, "README.md", "# App\n\n(c) 2026 Acme Srl\n")
        _write(tmp_path, "app.py", "x = 1\n")
        assert "PROV-LICENSE-001" not in _rules(_run(tmp_path))


# ============================================================
# Licenze dipendenze
# ============================================================

class TestDependencyLicenses:
    def test_copyleft_forte_offline(self, tmp_path):
        _write(tmp_path, "requirements.txt", "pymupdf==1.24.0\nrequests==2.31.0\n")
        _write(tmp_path, "app.py", "x = 1\n")
        findings = _run(tmp_path)
        assert "PROV-COPYLEFT-001" in _rules(findings)
        f = next(f for f in findings if f.rule_id == "PROV-COPYLEFT-001")
        assert "pymupdf" in f.description
        assert f.severity == Severity.HIGH
        assert "PROV-LICENSE-INFO" in _info(findings)

    def test_copyleft_debole(self, tmp_path):
        _write(tmp_path, "requirements.txt", "paramiko==3.4.0\n")
        _write(tmp_path, "app.py", "x = 1\n")
        findings = _run(tmp_path)
        assert "PROV-COPYLEFT-002" in _rules(findings)
        assert "PROV-COPYLEFT-001" not in _rules(findings)

    def test_commerciale_npm(self, tmp_path):
        _write(tmp_path, "package.json", json.dumps({"dependencies": {"highcharts": "^11.0.0", "react": "^18.0.0"}}))
        _write(tmp_path, "index.js", "console.log(1)\n")
        findings = _run(tmp_path, StackInfo(languages={"javascript": 1.0}))
        assert "PROV-COMMERCIAL-001" in _rules(findings)
        f = next(f for f in findings if f.rule_id == "PROV-COMMERCIAL-001")
        assert "highcharts" in f.description

    def test_solo_permissive_nessun_finding(self, tmp_path):
        _write(tmp_path, "requirements.txt", "requests==2.31.0\nnumpy==1.26.0\n")
        _write(tmp_path, "app.py", "x = 1\n")
        findings = _run(tmp_path)
        assert not {"PROV-COPYLEFT-001", "PROV-COPYLEFT-002", "PROV-COMMERCIAL-001"} & _rules(findings)

    def test_inventario_esposto_dall_analyzer(self, tmp_path):
        _write(tmp_path, "requirements.txt", "pymupdf==1.24.0\n")
        _write(tmp_path, "app.py", "x = 1\n")
        analyzer = ProvenanceAnalyzer(offline=True)
        _run(tmp_path, analyzer=analyzer)
        assert len(analyzer.dependency_licenses) == 1
        assert analyzer.dependency_licenses[0].to_dict()["category"] == "strong_copyleft"


# ============================================================
# Codice vendorizzato e copyright di terzi
# ============================================================

class TestVendoredAndCopyright:
    def test_vendor_dir_con_sorgenti(self, tmp_path):
        _write(tmp_path, "vendor/lib/thing.js", "module.exports = 1;\n")
        _write(tmp_path, "src/app.js", "console.log(1)\n")
        findings = _run(tmp_path, StackInfo(languages={"javascript": 1.0}))
        assert "PROV-VENDORED-001" in _rules(findings)

    def test_deps_dir_in_progetto_c(self, tmp_path):
        _write(tmp_path, "deps/lua/lua.c", "int main(){return 0;}\n")
        _write(tmp_path, "src/server.c", "int x;\n")
        assert "PROV-VENDORED-001" in _rules(_run(tmp_path, StackInfo(languages={"c": 1.0})))

    def test_frasi_di_licenza_non_contano_come_titolari(self, tmp_path):
        _write(tmp_path, "src/a.py", "# Copyright (c) 2026 Acme Srl\n# The above copyright notice shall be included\nx = 1\n")
        _write(tmp_path, "src/b.py", "# Copyright holders and contributors\ny = 2\n")
        assert "PROV-COPYRIGHT-001" not in _rules(_run(tmp_path))

    def test_vendor_dir_senza_sorgenti_non_scatta(self, tmp_path):
        _write(tmp_path, "vendor/fonts/readme.txt", "fonts\n")
        _write(tmp_path, "src/app.py", "x = 1\n")
        assert "PROV-VENDORED-001" not in _rules(_run(tmp_path))

    def test_copyright_di_piu_titolari(self, tmp_path):
        _write(tmp_path, "src/a.py", "# Copyright (c) 2021 Globex Corporation\nx = 1\n")
        _write(tmp_path, "src/b.py", "# Copyright 2019-2020 Initech Inc.\ny = 2\n")
        _write(tmp_path, "src/c.py", "# Copyright (c) 2026 Globex Corporation\nz = 3\n")
        findings = _run(tmp_path)
        assert "PROV-COPYRIGHT-001" in _rules(findings)
        f = next(f for f in findings if f.rule_id == "PROV-COPYRIGHT-001")
        assert "2 titolari" in f.title

    def test_copyright_multipli_in_progetto_oss_e_basso(self, tmp_path):
        _write(tmp_path, "LICENSE", "MIT License\n\nCopyright (c) 2026 Acme\n")
        _write(tmp_path, "src/a.py", "# Copyright (c) 2021 Globex Corporation\nx = 1\n")
        _write(tmp_path, "src/b.py", "# Copyright 2019 Initech Inc.\ny = 2\n")
        findings = _run(tmp_path)
        assert "PROV-COPYRIGHT-002" in _rules(findings)
        assert "PROV-COPYRIGHT-001" not in _rules(findings)

    def test_licenza_mit_senza_la_parola_mit(self, tmp_path):
        _write(tmp_path, "LICENSE", "Copyright (c) 2013-2026 Ghost Foundation\n\nPermission is hereby granted, free of charge, to any person\n")
        _write(tmp_path, "app.py", "x = 1\n")
        f = next(f for f in _run(tmp_path) if f.rule_id == "PROV-OWNLICENSE-INFO")
        assert "permissiva" in f.title

    def test_copyright_unico_titolare_non_scatta(self, tmp_path):
        _write(tmp_path, "src/a.py", "# Copyright (c) 2026 Acme Srl\nx = 1\n")
        _write(tmp_path, "src/b.py", "# Copyright (c) 2026 Acme Srl\ny = 2\n")
        assert "PROV-COPYRIGHT-001" not in _rules(_run(tmp_path))


# ============================================================
# README claims e certificazioni
# ============================================================

class TestReadmeClaims:
    def test_istruzione_docker_run_non_e_un_claim(self, tmp_path):
        _write(tmp_path, "README.md", "# App\n\nQuick start: docker run -p 6379:6379 redis\n")
        _write(tmp_path, "app.py", "x = 1\n")
        assert "PROV-CLAIMS-001" not in _rules(_run(tmp_path))

    def test_claim_docker_e_a_severita_bassa(self, tmp_path):
        _write(tmp_path, "README.md", "# App\n\nBuild with docker build . and deploy with the Helm chart.\n")
        _write(tmp_path, "app.py", "x = 1\n")
        f = next(f for f in _run(tmp_path) if f.rule_id == "PROV-CLAIMS-001")
        assert f.severity == Severity.LOW

    def test_claim_docker_senza_dockerfile(self, tmp_path):
        _write(tmp_path, "README.md", "# App\n\nA Dockerfile is provided; the Helm chart deploys it. IaC with Terraform.\n")
        _write(tmp_path, "app.py", "x = 1\n")
        findings = _run(tmp_path)
        assert "PROV-CLAIMS-001" in _rules(findings)
        f = next(f for f in findings if f.rule_id == "PROV-CLAIMS-001")
        assert "Docker" in f.description and "Kubernetes" in f.description

    def test_claim_riscontrato_non_scatta(self, tmp_path):
        _write(tmp_path, "README.md", "# App\n\nRuns in Docker. CI with GitHub Actions. Unit tests included.\n")
        _write(tmp_path, "Dockerfile", "FROM python:3.12\n")
        _write(tmp_path, ".github/workflows/ci.yml", "on: push\n")
        _write(tmp_path, "tests/test_app.py", "def test_x(): pass\n")
        _write(tmp_path, "app.py", "x = 1\n")
        assert "PROV-CLAIMS-001" not in _rules(_run(tmp_path))

    def test_claim_riscontrato_via_stack_info(self, tmp_path):
        _write(tmp_path, "README.md", "# App\n\nInfrastructure as Code with Terraform.\n")
        _write(tmp_path, "app.py", "x = 1\n")
        stack = StackInfo(languages={"python": 1.0}, infra_type=["Terraform"])
        assert "PROV-CLAIMS-001" not in _rules(_run(tmp_path, stack))

    def test_certificazioni_dichiarate_info(self, tmp_path):
        _write(tmp_path, "README.md", "# App\n\nWe are SOC 2 Type II and ISO 27001 certified.\n")
        _write(tmp_path, "app.py", "x = 1\n")
        findings = _run(tmp_path)
        assert "PROV-CERT-INFO" in _info(findings)
        f = next(f for f in findings if f.rule_id == "PROV-CERT-INFO")
        assert "SOC" in f.title and "27001" in f.title

    def test_senza_readme_nessun_claim(self, tmp_path):
        _write(tmp_path, "app.py", "x = 1\n")
        findings = _run(tmp_path)
        assert "PROV-CLAIMS-001" not in _rules(findings)
        assert "PROV-CERT-INFO" not in _info(findings)


# ============================================================
# SBOM
# ============================================================

class TestSBOM:
    def test_nessun_sbom(self, tmp_path):
        _write(tmp_path, "app.py", "x = 1\n")
        findings = _run(tmp_path)
        assert "PROV-SBOM-001" in _rules(findings)
        f = next(f for f in findings if f.rule_id == "PROV-SBOM-001")
        assert f.framework_ref == "NIS2 Art.21(2)(d)"

    @pytest.mark.parametrize("name", ["sbom.json", "bom.xml", "release.spdx.json", "app.cdx.json", "docs/sbom.cdx.xml"])
    def test_sbom_presente(self, tmp_path, name):
        _write(tmp_path, name, "{}\n")
        _write(tmp_path, "app.py", "x = 1\n")
        assert "PROV-SBOM-001" not in _rules(_run(tmp_path))


class TestLayerAssignment:
    def test_tutti_i_finding_sono_provenance(self, tmp_path):
        _write(tmp_path, "README.md", "# App\n\nDocker, SOC 2.\n")
        _write(tmp_path, "requirements.txt", "pymupdf==1.24.0\nparamiko==3.4\n")
        _write(tmp_path, "vendor/x.py", "# Copyright (c) 2020 Other Corp\nx=1\n")
        _write(tmp_path, "src/a.py", "# Copyright (c) 2026 Acme Srl\nx = 1\n")
        findings = _run(tmp_path)
        assert findings
        assert all(f.layer == Layer.PROVENANCE for f in findings)
