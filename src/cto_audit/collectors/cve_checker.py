"""
CVE Checker — Controlla dipendenze contro il database OSV (Google Open Source Vulnerabilities).

Usa l'API gratuita OSV (https://api.osv.dev) per trovare CVE note
nelle dipendenze del progetto. Nessun API key richiesto.

Supporta: PyPI, npm, Maven, Go, crates.io, RubyGems, Packagist.
Degradazione graziosa: se offline o API non raggiungibile, restituisce lista vuota.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from cto_audit.core.source import AuditSource


# OSV API endpoint (batch query)
OSV_API_URL = "https://api.osv.dev/v1/querybatch"
OSV_TIMEOUT = 15  # secondi


# Mapping estensione/file → ecosistema OSV
ECOSYSTEM_MAP: dict[str, str] = {
    "requirements.txt": "PyPI",
    "Pipfile": "PyPI",
    "pyproject.toml": "PyPI",
    "package.json": "npm",
    "Cargo.toml": "crates.io",
    "go.mod": "Go",
    "Gemfile": "RubyGems",
    "pom.xml": "Maven",
    "build.gradle": "Maven",
    "build.gradle.kts": "Maven",
    "composer.json": "Packagist",
}


@dataclass
class DependencyInfo:
    """Una dipendenza con nome, versione e ecosistema."""
    name: str
    version: str
    ecosystem: str
    source_file: str


@dataclass
class CVEResult:
    """Risultato di una query CVE per una dipendenza."""
    dependency: DependencyInfo
    cve_ids: list[str] = field(default_factory=list)
    summaries: list[str] = field(default_factory=list)
    severities: list[str] = field(default_factory=list)


def parse_dependencies(all_paths: set[str], source: AuditSource) -> list[DependencyInfo]:
    """
    Analizza i file manifest del progetto ed estrae tutte le dipendenze con versione.

    Returns:
        Lista di DependencyInfo per ogni dipendenza trovata con versione specifica.
    """
    deps: list[DependencyInfo] = []

    for path in all_paths:
        basename = path.rsplit("/", 1)[-1]
        ecosystem = ECOSYSTEM_MAP.get(basename)
        if not ecosystem:
            continue

        try:
            content = source.read_file(path)
        except (ValueError, FileNotFoundError, PermissionError, UnicodeDecodeError):
            continue

        if ecosystem == "PyPI":
            deps.extend(_parse_python_deps(content, path))
        elif ecosystem == "npm":
            deps.extend(_parse_npm_deps(content, path))
        elif ecosystem == "crates.io":
            deps.extend(_parse_cargo_deps(content, path))
        elif ecosystem == "Go":
            deps.extend(_parse_go_deps(content, path))
        elif ecosystem == "RubyGems":
            deps.extend(_parse_ruby_deps(content, path))
        elif ecosystem == "Maven":
            deps.extend(_parse_maven_deps(content, path))
        elif ecosystem == "Packagist":
            deps.extend(_parse_composer_deps(content, path))

    return deps


def query_osv(deps: list[DependencyInfo]) -> list[CVEResult]:
    """
    Interroga l'API OSV in batch per trovare vulnerabilità note.

    Args:
        deps: Lista di dipendenze con versione

    Returns:
        Lista di CVEResult per le dipendenze con vulnerabilità trovate.
        Lista vuota se l'API non è raggiungibile.
    """
    if not deps:
        return []

    # Costruisci batch query
    queries = []
    for dep in deps:
        queries.append({
            "package": {"name": dep.name, "ecosystem": dep.ecosystem},
            "version": dep.version,
        })

    # OSV supporta max 1000 query per batch
    results: list[CVEResult] = []
    batch_size = 1000

    for i in range(0, len(queries), batch_size):
        batch_queries = queries[i:i + batch_size]
        batch_deps = deps[i:i + batch_size]

        try:
            response = httpx.post(
                OSV_API_URL,
                json={"queries": batch_queries},
                timeout=OSV_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, httpx.TimeoutException, json.JSONDecodeError):
            # API non raggiungibile — degradazione graziosa
            return []

        batch_results = data.get("results", [])
        for dep, result_data in zip(batch_deps, batch_results):
            vulns = result_data.get("vulns", [])
            if not vulns:
                continue

            cve_ids = []
            summaries = []
            severities = []

            for vuln in vulns:
                # Prendi ID CVE se disponibile, altrimenti ID OSV
                vuln_id = vuln.get("id", "")
                aliases = vuln.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
                if cve_id and cve_id not in cve_ids:
                    cve_ids.append(cve_id)

                summary = vuln.get("summary", "")
                if summary and summary not in summaries:
                    summaries.append(summary)

                # Estrai severity
                for sev_data in vuln.get("severity", []):
                    sev_score = sev_data.get("score", "")
                    if sev_score and sev_score not in severities:
                        severities.append(sev_score)

            if cve_ids:
                results.append(CVEResult(
                    dependency=dep,
                    cve_ids=cve_ids[:10],  # Cap a 10 CVE per dipendenza
                    summaries=summaries[:5],
                    severities=severities[:5],
                ))

    return results


# --- Parser per ecosystem ---

def _parse_python_deps(content: str, source_file: str) -> list[DependencyInfo]:
    """Parse requirements.txt / pyproject.toml."""
    deps: list[DependencyInfo] = []
    # requirements.txt: package==1.0.0 o package>=1.0.0
    pattern = re.compile(
        r"^([a-zA-Z0-9_-]+)\s*[=<>~!]=*\s*([0-9][0-9.]*)",
        re.MULTILINE,
    )
    for match in pattern.finditer(content):
        name = match.group(1).lower().replace("_", "-")
        version = match.group(2)
        deps.append(DependencyInfo(name=name, version=version, ecosystem="PyPI", source_file=source_file))
    return deps


def _parse_npm_deps(content: str, source_file: str) -> list[DependencyInfo]:
    """Parse package.json."""
    deps: list[DependencyInfo] = []
    try:
        pkg = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return deps

    all_deps: dict[str, Any] = {}
    all_deps.update(pkg.get("dependencies", {}))
    all_deps.update(pkg.get("devDependencies", {}))

    version_pattern = re.compile(r"[~^]?(\d+\.\d+[\d.]*)")
    for name, version_spec in all_deps.items():
        if isinstance(version_spec, str):
            match = version_pattern.match(version_spec)
            if match:
                deps.append(DependencyInfo(
                    name=name, version=match.group(1),
                    ecosystem="npm", source_file=source_file,
                ))
    return deps


def _parse_cargo_deps(content: str, source_file: str) -> list[DependencyInfo]:
    """Parse Cargo.toml."""
    deps: list[DependencyInfo] = []
    # Simple: name = "version" o name = { version = "..." }
    simple_pattern = re.compile(
        r'^([a-zA-Z0-9_-]+)\s*=\s*"(\d+\.\d+[\d.]*)"',
        re.MULTILINE,
    )
    table_pattern = re.compile(
        r'^([a-zA-Z0-9_-]+)\s*=\s*\{.*?version\s*=\s*"(\d+\.\d+[\d.]*)"',
        re.MULTILINE,
    )

    in_deps = False
    for line in content.split("\n"):
        stripped = line.strip()
        if stripped.startswith("[") and "dependencies" in stripped.lower():
            in_deps = True
            continue
        elif stripped.startswith("["):
            in_deps = False
            continue

        if in_deps:
            match = simple_pattern.match(stripped) or table_pattern.match(stripped)
            if match:
                deps.append(DependencyInfo(
                    name=match.group(1), version=match.group(2),
                    ecosystem="crates.io", source_file=source_file,
                ))
    return deps


def _parse_go_deps(content: str, source_file: str) -> list[DependencyInfo]:
    """Parse go.mod."""
    deps: list[DependencyInfo] = []
    pattern = re.compile(
        r"^\s+(\S+)\s+v(\d+\.\d+[\d.]*)",
        re.MULTILINE,
    )
    for match in pattern.finditer(content):
        deps.append(DependencyInfo(
            name=match.group(1), version=match.group(2),
            ecosystem="Go", source_file=source_file,
        ))
    return deps


def _parse_ruby_deps(content: str, source_file: str) -> list[DependencyInfo]:
    """Parse Gemfile."""
    deps: list[DependencyInfo] = []
    # gem 'name', '~> 1.0'
    pattern = re.compile(
        r"""gem\s+['"]([a-zA-Z0-9_-]+)['"](?:\s*,\s*['"]~?>?\s*(\d+\.\d+[\d.]*)['"])?""",
    )
    for match in pattern.finditer(content):
        version = match.group(2)
        if version:
            deps.append(DependencyInfo(
                name=match.group(1), version=version,
                ecosystem="RubyGems", source_file=source_file,
            ))
    return deps


def _parse_maven_deps(content: str, source_file: str) -> list[DependencyInfo]:
    """Parse pom.xml (simplified)."""
    deps: list[DependencyInfo] = []
    # <artifactId>name</artifactId> ... <version>1.0.0</version>
    pattern = re.compile(
        r"<artifactId>([^<]+)</artifactId>\s*(?:<[^v][^<]*</[^<]*>\s*)*<version>(\d+\.\d+[\d.]*)</version>",
        re.DOTALL,
    )
    for match in pattern.finditer(content):
        deps.append(DependencyInfo(
            name=match.group(1), version=match.group(2),
            ecosystem="Maven", source_file=source_file,
        ))
    return deps


def _parse_composer_deps(content: str, source_file: str) -> list[DependencyInfo]:
    """Parse composer.json."""
    deps: list[DependencyInfo] = []
    try:
        pkg = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return deps

    all_deps: dict[str, Any] = {}
    all_deps.update(pkg.get("require", {}))
    all_deps.update(pkg.get("require-dev", {}))

    version_pattern = re.compile(r"[~^]?(\d+\.\d+[\d.]*)")
    for name, version_spec in all_deps.items():
        if name == "php" or name.startswith("ext-"):
            continue
        if isinstance(version_spec, str):
            match = version_pattern.match(version_spec)
            if match:
                deps.append(DependencyInfo(
                    name=name, version=match.group(1),
                    ecosystem="Packagist", source_file=source_file,
                ))
    return deps
