"""
Test per CVE Checker — parsing dipendenze e query OSV API.

Test offline: mock dell'API OSV per non dipendere dalla rete.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from cto_audit.collectors.cve_checker import (
    CVEResult,
    DependencyInfo,
    parse_dependencies,
    query_osv,
    _parse_python_deps,
    _parse_npm_deps,
    _parse_cargo_deps,
    _parse_go_deps,
    _parse_ruby_deps,
    _parse_maven_deps,
    _parse_composer_deps,
)


# ============================================================
# Test parsing dipendenze
# ============================================================


class TestParsePythonDeps:
    def test_requirements_txt(self):
        content = "django==4.2.0\nflask>=2.0\nrequests~=2.31.0\n"
        deps = _parse_python_deps(content, "requirements.txt")
        assert len(deps) == 3
        assert deps[0].name == "django"
        assert deps[0].version == "4.2.0"
        assert deps[0].ecosystem == "PyPI"

    def test_pinned_versions(self):
        content = "pyyaml==6.0.1\nurllib3>=1.26.5\n"
        deps = _parse_python_deps(content, "requirements.txt")
        assert len(deps) == 2
        assert deps[0].version == "6.0.1"

    def test_empty(self):
        deps = _parse_python_deps("# just a comment\n", "requirements.txt")
        assert len(deps) == 0


class TestParseNpmDeps:
    def test_package_json(self):
        content = json.dumps({
            "dependencies": {"express": "^4.18.2", "lodash": "~4.17.21"},
            "devDependencies": {"jest": "29.7.0"},
        })
        deps = _parse_npm_deps(content, "package.json")
        assert len(deps) == 3
        names = {d.name for d in deps}
        assert "express" in names
        assert "lodash" in names
        assert "jest" in names

    def test_invalid_json(self):
        deps = _parse_npm_deps("not json", "package.json")
        assert len(deps) == 0


class TestParseCargoDeps:
    def test_cargo_toml(self):
        content = (
            "[dependencies]\n"
            'serde = "1.0"\n'
            'tokio = { version = "1.35", features = ["full"] }\n'
            'clap = "4.4"\n'
        )
        deps = _parse_cargo_deps(content, "Cargo.toml")
        assert len(deps) >= 2
        names = {d.name for d in deps}
        assert "serde" in names
        assert all(d.ecosystem == "crates.io" for d in deps)


class TestParseGoDeps:
    def test_go_mod(self):
        content = (
            "module github.com/example/app\n\ngo 1.22\n\nrequire (\n"
            "\tgithub.com/gin-gonic/gin v1.9.1\n"
            "\tgorm.io/gorm v1.25.5\n)\n"
        )
        deps = _parse_go_deps(content, "go.mod")
        assert len(deps) == 2
        assert deps[0].name == "github.com/gin-gonic/gin"
        assert deps[0].version == "1.9.1"
        assert deps[0].ecosystem == "Go"


class TestParseRubyDeps:
    def test_gemfile(self):
        content = (
            "source 'https://rubygems.org'\n"
            "gem 'rails', '~> 7.1'\n"
            "gem 'pg', '~> 1.5'\n"
            "gem 'puma'\n"  # No version → skipped
        )
        deps = _parse_ruby_deps(content, "Gemfile")
        assert len(deps) == 2
        assert deps[0].name == "rails"
        assert deps[0].version == "7.1"
        assert deps[0].ecosystem == "RubyGems"


class TestParseMavenDeps:
    def test_pom_xml(self):
        content = (
            "<dependencies>\n"
            "  <dependency>\n"
            "    <groupId>org.springframework.boot</groupId>\n"
            "    <artifactId>spring-boot-starter-web</artifactId>\n"
            "    <version>3.2.1</version>\n"
            "  </dependency>\n"
            "</dependencies>\n"
        )
        deps = _parse_maven_deps(content, "pom.xml")
        assert len(deps) == 1
        assert deps[0].name == "spring-boot-starter-web"
        assert deps[0].version == "3.2.1"


class TestParseComposerDeps:
    def test_composer_json(self):
        content = json.dumps({
            "require": {"php": "^8.1", "laravel/framework": "^10.0", "ext-pdo": "*"},
            "require-dev": {"phpunit/phpunit": "^10.0"},
        })
        deps = _parse_composer_deps(content, "composer.json")
        # php e ext-pdo devono essere esclusi
        names = {d.name for d in deps}
        assert "laravel/framework" in names
        assert "phpunit/phpunit" in names
        assert "php" not in names
        assert "ext-pdo" not in names


# ============================================================
# Test parse_dependencies (end-to-end con source mock)
# ============================================================


class TestParseDependencies:
    def test_multi_ecosystem(self):
        source = MagicMock()
        source.read_file.side_effect = lambda path: {
            "requirements.txt": "django==4.2\nflask>=2.0\n",
            "package.json": json.dumps({"dependencies": {"express": "^4.18"}}),
        }.get(path, "")

        deps = parse_dependencies(
            {"requirements.txt", "package.json", "src/main.py"},
            source,
        )
        ecosystems = {d.ecosystem for d in deps}
        assert "PyPI" in ecosystems
        assert "npm" in ecosystems

    def test_file_read_error(self):
        source = MagicMock()
        source.read_file.side_effect = FileNotFoundError

        deps = parse_dependencies({"requirements.txt"}, source)
        assert deps == []


# ============================================================
# Test query_osv (mock API)
# ============================================================


class TestQueryOSV:
    def test_empty_deps(self):
        assert query_osv([]) == []

    def test_api_returns_vulns(self):
        deps = [
            DependencyInfo(name="django", version="2.0", ecosystem="PyPI", source_file="requirements.txt"),
        ]

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [{
                "vulns": [{
                    "id": "GHSA-xxx",
                    "aliases": ["CVE-2019-14232"],
                    "summary": "Django SQL injection",
                    "severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
                }],
            }],
        }
        mock_response.raise_for_status = MagicMock()

        with patch("cto_audit.collectors.cve_checker.httpx.post", return_value=mock_response):
            results = query_osv(deps)

        assert len(results) == 1
        assert "CVE-2019-14232" in results[0].cve_ids
        assert results[0].dependency.name == "django"

    def test_api_no_vulns(self):
        deps = [
            DependencyInfo(name="django", version="5.0", ecosystem="PyPI", source_file="requirements.txt"),
        ]

        mock_response = MagicMock()
        mock_response.json.return_value = {"results": [{"vulns": []}]}
        mock_response.raise_for_status = MagicMock()

        with patch("cto_audit.collectors.cve_checker.httpx.post", return_value=mock_response):
            results = query_osv(deps)

        assert len(results) == 0

    def test_api_timeout(self):
        """API non raggiungibile → lista vuota (degradazione graziosa)."""
        deps = [
            DependencyInfo(name="django", version="2.0", ecosystem="PyPI", source_file="requirements.txt"),
        ]

        import httpx
        with patch("cto_audit.collectors.cve_checker.httpx.post", side_effect=httpx.TimeoutException("timeout")):
            results = query_osv(deps)

        assert results == []

    def test_api_http_error(self):
        """API restituisce errore HTTP → lista vuota."""
        deps = [
            DependencyInfo(name="django", version="2.0", ecosystem="PyPI", source_file="requirements.txt"),
        ]

        import httpx
        with patch("cto_audit.collectors.cve_checker.httpx.post", side_effect=httpx.HTTPError("500")):
            results = query_osv(deps)

        assert results == []


# ============================================================
# Test integrazione SecurityAnalyzer con CVE online
# ============================================================


class TestSecurityAnalyzerCVE:
    def test_offline_skips_cve(self):
        """In modalità offline, il check CVE non viene eseguito."""
        from cto_audit.analyzers.security import SecurityAnalyzer
        analyzer = SecurityAnalyzer(offline=True)
        # Il metodo _check_cve_online deve restituire lista vuota
        result = analyzer._check_cve_online(set(), MagicMock())
        assert result == []

    def test_online_calls_osv(self):
        """In modalità online, il check CVE viene eseguito."""
        from cto_audit.analyzers.security import SecurityAnalyzer
        analyzer = SecurityAnalyzer(offline=False)

        source = MagicMock()
        source.read_file.return_value = "django==2.0\n"

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "results": [{
                "vulns": [{
                    "id": "GHSA-xxx",
                    "aliases": ["CVE-2019-14232"],
                    "summary": "Test vuln",
                }],
            }],
        }
        mock_response.raise_for_status = MagicMock()

        with patch("cto_audit.collectors.cve_checker.httpx.post", return_value=mock_response):
            findings = analyzer._check_cve_online({"requirements.txt"}, source)

        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-DEPS-CVE-001"
        assert "CVE-2019-14232" in findings[0].description
