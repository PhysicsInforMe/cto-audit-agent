"""
License Checker — Classifica le licenze delle dipendenze dichiarate.

Due modalita:
- Offline: usa una Knowledge Base curata di pacchetti con licenza copyleft
  o commerciale/non standard. Ogni voce e stata verificata sul registro
  ufficiale (PyPI JSON API, npm registry) il 2026-10-06.
- Online: interroga PyPI (https://pypi.org/pypi/<pkg>/json) e npm
  (https://registry.npmjs.org/<pkg>/latest) per ogni dipendenza, con la KB
  come primo livello. Richiede il consenso rete (stesso gate del CVE check).

Cosa viene inviato in modalita online: solo il nome del pacchetto.
Nessuna versione, nessun percorso, nessun codice.

Le categorie seguono la pratica della due diligence software:
- STRONG_COPYLEFT: GPL, AGPL, SSPL. In un prodotto proprietario distribuito
  o erogato via rete impongono obblighi di rilascio del sorgente o una
  licenza commerciale alternativa.
- WEAK_COPYLEFT: LGPL, MPL, EPL, CDDL. Obblighi limitati al componente.
- PERMISSIVE: MIT, BSD, Apache, ISC, 0BSD, Unlicense, PSF, Zlib.
- NONSTANDARD: "SEE LICENSE IN ...", "Commercial", URL, UNLICENSED,
  proprietary. Richiede verifica contrattuale.
- UNKNOWN: metadato assente o non interpretabile.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

import httpx

from cto_audit.collectors.cve_checker import DependencyInfo


REGISTRY_TIMEOUT = 10  # secondi per richiesta
MAX_ONLINE_LOOKUPS = 300


class LicenseCategory(str, Enum):
    STRONG_COPYLEFT = "strong_copyleft"
    WEAK_COPYLEFT = "weak_copyleft"
    PERMISSIVE = "permissive"
    NONSTANDARD = "nonstandard"
    UNKNOWN = "unknown"


@dataclass
class DependencyLicense:
    """Licenza rilevata per una dipendenza."""
    name: str
    ecosystem: str
    source_file: str
    license: str
    category: LicenseCategory
    source: str  # "kb" | "registry" | "none"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "ecosystem": self.ecosystem,
            "source_file": self.source_file,
            "license": self.license,
            "category": self.category.value,
            "source": self.source,
        }


# --- Knowledge Base offline ---
# Chiave: (ecosistema OSV, nome pacchetto lowercase). Valore: licenza come
# dichiarata dal registro. Verificata il 2026-10-06 su pypi.org / registry.npmjs.org.
OFFLINE_LICENSE_KB: dict[tuple[str, str], str] = {
    # PyPI — strong copyleft
    ("PyPI", "pymupdf"): "AGPL-3.0 (dual: Artifex commercial)",
    ("PyPI", "mysqlclient"): "GPL-2.0-or-later",
    ("PyPI", "mysql-connector-python"): "GPL-2.0 (with FOSS License Exception)",
    ("PyPI", "pyqt5"): "GPL-3.0",
    ("PyPI", "pyqt6"): "GPL-3.0-only",
    ("PyPI", "ansible"): "GPL-3.0-or-later",
    ("PyPI", "ansible-core"): "GPL-3.0-or-later",
    ("PyPI", "rpy2"): "GPL-2.0-or-later",
    ("PyPI", "gnureadline"): "GPL-3.0-or-later",
    # PyPI — weak copyleft
    ("PyPI", "paramiko"): "LGPL-2.1",
    ("PyPI", "psycopg2"): "LGPL with exceptions",
    ("PyPI", "psycopg2-binary"): "LGPL with exceptions",
    ("PyPI", "pygit2"): "GPL-2.0 with linking exception",
    # npm — non standard / commerciale
    ("npm", "ckeditor5"): "SEE LICENSE IN LICENSE.md",
    ("npm", "tinymce"): "SEE LICENSE IN license.md",
    ("npm", "highcharts"): "https://www.highcharts.com/license",
    ("npm", "ag-grid-enterprise"): "Commercial",
    ("npm", "handsontable"): "SEE LICENSE IN LICENSE.txt",
    ("npm", "@mui/x-data-grid-pro"): "SEE LICENSE IN LICENSE",
    ("npm", "@mui/x-data-grid-premium"): "SEE LICENSE IN LICENSE",
    ("npm", "n8n"): "SEE LICENSE IN LICENSE.md",
    # npm — weak copyleft
    ("npm", "jsreport"): "LGPL",
}


# --- Classificazione ---

_STRONG_RE = re.compile(
    r"\b(agpl|affero|sspl|gpl-?[23](?:\.0)?(?:-only|-or-later|\+)?|gplv[23]|"
    r"gnu general public license|general public license)\b",
    re.IGNORECASE,
)
_WEAK_RE = re.compile(
    r"\b(lgpl|lesser general public|library general public|mpl-?2|mozilla public|"
    r"epl-?[12]|eclipse public|cddl|osl-?3|eupl|cecill-c)\b",
    re.IGNORECASE,
)
_PERMISSIVE_RE = re.compile(
    r"\b(mit|bsd|apache|isc|0bsd|unlicense|psf|python software foundation|zlib|"
    r"cc0|wtfpl|artistic|boost|bsl-1\.0|public domain|blueoak)\b"
    # Firme testuali: il testo MIT e BSD spesso non contiene il nome della licenza
    r"|permission is hereby granted, free of charge"
    r"|redistribution and use in source and binary forms",
    re.IGNORECASE,
)
_NONSTANDARD_RE = re.compile(
    r"(see license in|see licen[cs]e|commercial|proprietary|unlicensed|all rights reserved|"
    r"https?://|custom|elastic license|elv2|sustainable use|business source|bsl-1\.1|"
    r"server side public)",
    re.IGNORECASE,
)
# Eccezioni che riducono il GPL a un rischio "weak" (linking/classpath exception)
_EXCEPTION_RE = re.compile(r"(linking exception|classpath exception|with exception)", re.IGNORECASE)


def classify_license(text: str | None) -> LicenseCategory:
    """Classifica una stringa di licenza (SPDX o testo libero)."""
    if not text or not text.strip():
        return LicenseCategory.UNKNOWN
    t = text.strip()

    # Linking/classpath exception: obbligo limitato, trattato come weak copyleft
    if _STRONG_RE.search(t) and _EXCEPTION_RE.search(t) and not re.search(r"agpl|affero|sspl", t, re.I):
        return LicenseCategory.WEAK_COPYLEFT
    if _STRONG_RE.search(t):
        return LicenseCategory.STRONG_COPYLEFT
    if _WEAK_RE.search(t):
        return LicenseCategory.WEAK_COPYLEFT
    if _NONSTANDARD_RE.search(t):
        return LicenseCategory.NONSTANDARD
    if _PERMISSIVE_RE.search(t):
        return LicenseCategory.PERMISSIVE
    return LicenseCategory.UNKNOWN


class LicenseChecker:
    """
    Verifica le licenze delle dipendenze.

    Args:
        offline: se True usa solo la KB locale, nessuna richiesta di rete
        client: client httpx iniettabile (test)
    """

    def __init__(self, offline: bool = True, client: httpx.Client | None = None) -> None:
        self.offline = offline
        self._client = client

    def check(self, deps: list[DependencyInfo]) -> list[DependencyLicense]:
        """Restituisce la licenza per ogni dipendenza (dedup per ecosistema+nome)."""
        seen: set[tuple[str, str]] = set()
        results: list[DependencyLicense] = []
        lookups = 0

        for dep in deps:
            key = (dep.ecosystem, dep.name.lower())
            if key in seen:
                continue
            seen.add(key)

            kb_license = OFFLINE_LICENSE_KB.get(key)
            if kb_license is not None:
                results.append(DependencyLicense(
                    name=dep.name, ecosystem=dep.ecosystem, source_file=dep.source_file,
                    license=kb_license, category=classify_license(kb_license), source="kb",
                ))
                continue

            if not self.offline and lookups < MAX_ONLINE_LOOKUPS:
                lookups += 1
                reg_license = self._lookup_registry(dep.ecosystem, dep.name)
                if reg_license is not None:
                    results.append(DependencyLicense(
                        name=dep.name, ecosystem=dep.ecosystem, source_file=dep.source_file,
                        license=reg_license, category=classify_license(reg_license), source="registry",
                    ))
                    continue

            results.append(DependencyLicense(
                name=dep.name, ecosystem=dep.ecosystem, source_file=dep.source_file,
                license="", category=LicenseCategory.UNKNOWN, source="none",
            ))

        return results

    # --- Registri ---

    def _lookup_registry(self, ecosystem: str, name: str) -> str | None:
        """Interroga il registro del pacchetto. None se non supportato o errore."""
        if ecosystem == "PyPI":
            return self._lookup_pypi(name)
        if ecosystem == "npm":
            return self._lookup_npm(name)
        return None

    def _get_json(self, url: str) -> dict | None:
        try:
            if self._client is not None:
                resp = self._client.get(url, timeout=REGISTRY_TIMEOUT)
            else:
                resp = httpx.get(url, timeout=REGISTRY_TIMEOUT, follow_redirects=True)
            if resp.status_code != 200:
                return None
            data = resp.json()
            return data if isinstance(data, dict) else None
        except (httpx.HTTPError, ValueError):
            return None

    def _lookup_pypi(self, name: str) -> str | None:
        data = self._get_json(f"https://pypi.org/pypi/{name}/json")
        if not data:
            return None
        info = data.get("info") or {}
        expr = info.get("license_expression")
        if isinstance(expr, str) and expr.strip():
            return expr.strip()
        lic = info.get("license")
        if isinstance(lic, str) and lic.strip():
            # Alcuni pacchetti incollano l'intero testo della licenza: tieni la prima riga
            return lic.strip().splitlines()[0][:120]
        for c in info.get("classifiers") or []:
            if isinstance(c, str) and c.startswith("License ::"):
                return c.split("::")[-1].strip()
        return None

    def _lookup_npm(self, name: str) -> str | None:
        data = self._get_json(f"https://registry.npmjs.org/{name}/latest")
        if not data:
            return None
        lic = data.get("license")
        if isinstance(lic, dict):
            lic = lic.get("type")
        if isinstance(lic, str) and lic.strip():
            return lic.strip()
        licenses = data.get("licenses")
        if isinstance(licenses, list) and licenses:
            first = licenses[0]
            if isinstance(first, dict) and first.get("type"):
                return str(first["type"])
        return None
