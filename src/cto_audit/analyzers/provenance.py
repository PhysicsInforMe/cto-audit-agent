"""
Provenance Analyzer — Layer 5: Provenienza & Proprieta Intellettuale.

Domanda di due diligence: "il codice e davvero loro, e possono venderlo?".
Analisi statica: file di licenza, header di copyright, codice di terze parti
incorporato, licenze delle dipendenze, SBOM, e coerenza tra quello che il
README dichiara e quello che il repository contiene.

Regole:
- PROV-LICENSE-001:    nessuna dichiarazione di licenza o copyright nel repository
- PROV-COPYLEFT-001:   dipendenze con licenza copyleft forte (GPL, AGPL, SSPL)
- PROV-COPYLEFT-002:   dipendenze con licenza copyleft debole (LGPL, MPL, EPL)
- PROV-COMMERCIAL-001: dipendenze con licenza commerciale o non standard
- PROV-LICENSE-INFO:   inventario licenze (informativo: quante note, quante ignote)
- PROV-VENDORED-001:   codice di terze parti incorporato (vendor/, third_party/...)
- PROV-COPYRIGHT-001:  header di copyright intestati a piu titolari diversi
- PROV-CLAIMS-001:     dichiarazioni del README non riscontrate nel codice
- PROV-CERT-INFO:      certificazioni dichiarate non verificabili dal codice (informativo)
- PROV-SBOM-001:       nessun SBOM (CycloneDX / SPDX) nel repository

Il check licenze dipendenze usa LicenseChecker: KB offline sempre, registri
PyPI/npm solo con consenso rete.
"""

from __future__ import annotations

import re
import uuid
from collections import Counter

from cto_audit.collectors.cve_checker import parse_dependencies
from cto_audit.collectors.license_checker import (
    DependencyLicense,
    LicenseCategory,
    LicenseChecker,
)
from cto_audit.core.models import (
    FileClassification,
    Finding,
    Layer,
    Severity,
    StackInfo,
)
from cto_audit.core.source import AuditSource


def _make_id() -> str:
    return str(uuid.uuid4())[:8]


# --- Licenza / copyright del repository ---

LICENSE_FILENAMES: set[str] = {
    "license", "license.md", "license.txt", "license.rst",
    "licence", "licence.md", "licence.txt",
    "copying", "copying.md", "copying.txt",
    "copyright", "copyright.md", "copyright.txt",
    "notice", "notice.md", "notice.txt",
}
README_NAMES: set[str] = {"readme.md", "readme.rst", "readme.txt", "readme"}
COPYRIGHT_NOTICE_RE = re.compile(r"(copyright|\(c\)|©|all rights reserved|licen[cs]e)", re.IGNORECASE)

# --- Codice di terze parti incorporato ---

VENDORED_DIRS: set[str] = {
    "vendor", "vendors", "third_party", "third-party", "thirdparty",
    "3rdparty", "3rd_party", "3rd-party", "external", "externals", "extern",
}
SOURCE_EXTENSIONS: set[str] = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".rs",
    ".cs", ".php", ".kt", ".scala", ".c", ".cc", ".cpp", ".h", ".hpp", ".swift", ".m",
}
SKIP_DIRS: set[str] = {
    "node_modules", ".git", "__pycache__", "venv", ".venv", "env", "build",
    "dist", "target", ".tox", ".mypy_cache", ".pytest_cache", "site-packages",
    ".next", ".nuxt", "coverage",
}

# --- Header di copyright nei sorgenti ---

COPYRIGHT_HEADER_RE = re.compile(
    r"copyright\s*(?:\(c\)|©)?\s*(?:\d{4}(?:\s*[-–,]\s*\d{4})?)?\s*(?:,?\s*by\s+)?"
    r"([A-Z][A-Za-z0-9&.,'\- ]{2,60}?)(?=\s*(?:\.|,|<|\(|$|all rights|licensed|-))",
    re.IGNORECASE | re.MULTILINE,
)
COPYRIGHT_HEADER_LINES = 40
COPYRIGHT_MAX_FILES = 3000
_COPYRIGHT_NOISE = {"all rights reserved", "the authors", "contributors", "its contributors", "the author"}

# --- SBOM ---

SBOM_NAME_RE = re.compile(
    r"(^|/)(sbom|bom)(\.cdx|\.spdx)?\.(json|xml|yaml|yml)$|\.spdx(\.json|\.yaml|\.yml|\.rdf)?$|\.cdx\.(json|xml)$|cyclonedx",
    re.IGNORECASE,
)

# --- Claims del README verificabili dal codice ---
# (regex sul README, chiave evidenza)
README_CLAIMS: list[tuple[str, re.Pattern[str], str]] = [
    ("Docker / container", re.compile(r"\b(docker|container(?:ized|ised)?|docker-compose)\b", re.I), "docker"),
    ("Kubernetes", re.compile(r"\b(kubernetes|k8s|helm chart|helm)\b", re.I), "kubernetes"),
    ("Infrastructure as Code", re.compile(r"\b(terraform|pulumi|cloudformation|ansible|bicep|infrastructure as code|iac)\b", re.I), "iac"),
    ("CI/CD", re.compile(r"\b(ci/cd|cicd|continuous integration|continuous delivery|continuous deployment|github actions|gitlab ci)\b", re.I), "ci"),
    ("Test automatizzati", re.compile(r"\b(unit tests?|test suite|test coverage|fully tested|\d{2,3}\s?% coverage|automated tests?)\b", re.I), "tests"),
]
CERTIFICATION_RE = re.compile(
    r"\b(soc\s?2|soc\s?ii|iso\s?/?\s?iec\s?27001|iso\s?27001|hipaa|pci[- ]?dss|gdpr[- ]compliant|"
    r"gdpr compliance|fedramp|csa star|iso\s?9001|iso\s?42001|tisax)\b",
    re.IGNORECASE,
)

CI_INFRA_KEYWORDS = ("actions", "gitlab ci", "jenkins", "circleci", "travis", "azure pipelines", "bitbucket pipelines", "drone", "buildkite")
IAC_INFRA_KEYWORDS = ("terraform", "pulumi", "ansible", "cloudformation", "bicep", "opentofu")


class ProvenanceAnalyzer:
    """
    Analyzer per il layer Provenienza & IP.

    Args:
        offline: se True il check licenze usa solo la KB locale
        license_checker: checker iniettabile (test)
    """

    def __init__(
        self,
        offline: bool = True,
        license_checker: LicenseChecker | None = None,
    ) -> None:
        self.offline = offline
        self._checker = license_checker or LicenseChecker(offline=offline)
        # Popolato da analyze(): inventario completo, usato dall'orchestrator per il report
        self.dependency_licenses: list[DependencyLicense] = []

    def analyze(
        self,
        source: AuditSource,
        stack_info: StackInfo,
        classifications: list[FileClassification],
    ) -> list[Finding]:
        file_tree = source.get_file_tree()
        all_paths: set[str] = set()
        dir_paths: set[str] = set()
        for entry in file_tree.entries:
            (dir_paths if entry.is_dir else all_paths).add(entry.path.replace("\\", "/"))

        readme = self._read_readme(all_paths, source)

        findings: list[Finding] = []
        findings.extend(self._check_license_declaration(all_paths, readme))
        findings.extend(self._check_dependency_licenses(all_paths, source))
        findings.extend(self._check_vendored(all_paths, dir_paths))
        findings.extend(self._check_copyright_holders(all_paths, source))
        findings.extend(self._check_readme_claims(all_paths, stack_info, readme))
        findings.extend(self._check_sbom(all_paths))
        return findings

    # --- Helpers ---

    @staticmethod
    def _read_readme(all_paths: set[str], source: AuditSource) -> str:
        for p in sorted(all_paths):
            if "/" in p:
                continue
            if p.lower() in README_NAMES:
                try:
                    return source.read_file(p)
                except (ValueError, FileNotFoundError, PermissionError, UnicodeDecodeError):
                    return ""
        return ""

    @staticmethod
    def _is_source_file(path: str) -> bool:
        parts = path.split("/")
        if any(part in SKIP_DIRS for part in parts):
            return False
        basename = parts[-1]
        ext = "." + basename.rsplit(".", 1)[-1].lower() if "." in basename else ""
        return ext in SOURCE_EXTENSIONS

    # --- Check 1: dichiarazione di licenza / copyright ---

    def _check_license_declaration(self, all_paths: set[str], readme: str) -> list[Finding]:
        root_lower = {p.lower() for p in all_paths if "/" not in p}
        if root_lower & LICENSE_FILENAMES:
            return []
        if readme and COPYRIGHT_NOTICE_RE.search(readme):
            return []
        return [Finding(
            id=_make_id(), layer=Layer.PROVENANCE, severity=Severity.MEDIUM,
            rule_id="PROV-LICENSE-001",
            title="Nessuna dichiarazione di licenza o copyright",
            description=(
                "Nel repository non c'e un file LICENSE/COPYING/NOTICE ne una nota di "
                "copyright nel README. Per un asset proprietario basta una riga "
                "('Copyright (c) <anno> <societa>. All rights reserved.'), ma la sua assenza "
                "lascia indeterminato chi detiene i diritti e a quali condizioni il codice "
                "possa essere usato, ceduto o licenziato."
            ),
            confidence=0.9,
        )]

    # --- Check 2: licenze delle dipendenze ---

    def _check_dependency_licenses(self, all_paths: set[str], source: AuditSource) -> list[Finding]:
        deps = parse_dependencies(all_paths, source)
        if not deps:
            self.dependency_licenses = []
            return []

        licenses = self._checker.check(deps)
        self.dependency_licenses = licenses

        by_cat: dict[LicenseCategory, list[DependencyLicense]] = {c: [] for c in LicenseCategory}
        for dl in licenses:
            by_cat[dl.category].append(dl)

        findings: list[Finding] = []

        strong = by_cat[LicenseCategory.STRONG_COPYLEFT]
        if strong:
            findings.append(Finding(
                id=_make_id(), layer=Layer.PROVENANCE, severity=Severity.HIGH,
                rule_id="PROV-COPYLEFT-001",
                title=f"Dipendenze con licenza copyleft forte ({len(strong)})",
                description=(
                    "Le seguenti dipendenze sono rilasciate con licenza GPL/AGPL/SSPL:\n"
                    + "\n".join(f"  - {d.name} ({d.ecosystem}): {d.license} [{d.source_file}]" for d in strong[:10])
                    + (f"\n  (+{len(strong) - 10} altre)" if len(strong) > 10 else "")
                    + "\nIn un prodotto proprietario distribuito, o erogato via rete nel caso AGPL, "
                    "queste licenze possono imporre il rilascio del sorgente oppure l'acquisto di "
                    "una licenza commerciale. Verificare con il legale: e un tema di cessione e "
                    "valutazione, non solo tecnico."
                ),
                confidence=0.9 if all(d.source == "kb" for d in strong) else 0.8,
            ))

        weak = by_cat[LicenseCategory.WEAK_COPYLEFT]
        if weak:
            findings.append(Finding(
                id=_make_id(), layer=Layer.PROVENANCE, severity=Severity.LOW,
                rule_id="PROV-COPYLEFT-002",
                title=f"Dipendenze con licenza copyleft debole ({len(weak)})",
                description=(
                    "Dipendenze LGPL/MPL/EPL o GPL con linking exception:\n"
                    + "\n".join(f"  - {d.name} ({d.ecosystem}): {d.license}" for d in weak[:10])
                    + "\nGli obblighi sono limitati al componente (modifiche da rilasciare, "
                    "linking dinamico), ma vanno documentati nell'inventario licenze."
                ),
                confidence=0.85,
            ))

        nonstd = by_cat[LicenseCategory.NONSTANDARD]
        if nonstd:
            findings.append(Finding(
                id=_make_id(), layer=Layer.PROVENANCE, severity=Severity.MEDIUM,
                rule_id="PROV-COMMERCIAL-001",
                title=f"Dipendenze con licenza commerciale o non standard ({len(nonstd)})",
                description=(
                    "Dipendenze con licenza dichiarata come commerciale, 'SEE LICENSE IN', URL o "
                    "non riconducibile a uno standard SPDX:\n"
                    + "\n".join(f"  - {d.name} ({d.ecosystem}): {d.license}" for d in nonstd[:10])
                    + "\nServe la prova di una licenza commerciale valida e trasferibile: senza, "
                    "il prodotto usa software per cui l'azienda potrebbe non avere diritti."
                ),
                confidence=0.85,
            ))

        known = len(licenses) - len(by_cat[LicenseCategory.UNKNOWN])
        mode = "KB offline" if self.offline else "KB + registri PyPI/npm"
        findings.append(Finding(
            id=_make_id(), layer=Layer.PROVENANCE, severity=Severity.INFO,
            rule_id="PROV-LICENSE-INFO",
            title=f"Inventario licenze: {known}/{len(licenses)} dipendenze classificate ({mode})",
            description=(
                f"Dipendenze dichiarate: {len(licenses)}. Licenza nota per {known}, "
                f"ignota per {len(by_cat[LicenseCategory.UNKNOWN])}. "
                f"Permissive: {len(by_cat[LicenseCategory.PERMISSIVE])}, copyleft forte: {len(strong)}, "
                f"copyleft debole: {len(weak)}, commerciali/non standard: {len(nonstd)}."
                + ("" if not self.offline else " In modalita offline solo la KB curata e consultata: "
                   "per l'inventario completo rieseguire con accesso rete.")
            ),
        ))
        return findings

    # --- Check 3: codice di terze parti incorporato ---

    def _check_vendored(self, all_paths: set[str], dir_paths: set[str]) -> list[Finding]:
        hits: Counter[str] = Counter()
        for p in all_paths:
            parts = p.split("/")
            for i, part in enumerate(parts[:-1]):
                if part.lower() in VENDORED_DIRS:
                    ext = "." + parts[-1].rsplit(".", 1)[-1].lower() if "." in parts[-1] else ""
                    if ext in SOURCE_EXTENSIONS:
                        hits["/".join(parts[: i + 1])] += 1
                    break
        if not hits:
            return []
        total = sum(hits.values())
        listing = "\n".join(f"  - {d}/: {n} file sorgente" for d, n in hits.most_common(5))
        return [Finding(
            id=_make_id(), layer=Layer.PROVENANCE, severity=Severity.MEDIUM,
            rule_id="PROV-VENDORED-001",
            title=f"Codice di terze parti incorporato ({total} file sorgente)",
            description=(
                "Directory tipiche di codice vendorizzato con file sorgente al loro interno:\n"
                + listing
                + "\nIl codice copiato nel repository non passa dal package manager: licenza, "
                "versione e CVE non sono tracciate. Verificare la licenza di ogni componente "
                "e se sono state apportate modifiche locali."
            ),
            confidence=0.8,
        )]

    # --- Check 4: titolari di copyright negli header ---

    def _check_copyright_holders(self, all_paths: set[str], source: AuditSource) -> list[Finding]:
        holders: Counter[str] = Counter()
        scanned = 0
        for p in sorted(all_paths):
            if not self._is_source_file(p):
                continue
            if scanned >= COPYRIGHT_MAX_FILES:
                break
            scanned += 1
            try:
                content = source.read_file(p)
            except (ValueError, FileNotFoundError, PermissionError, UnicodeDecodeError):
                continue
            head = "\n".join(content.splitlines()[:COPYRIGHT_HEADER_LINES])
            for m in COPYRIGHT_HEADER_RE.finditer(head):
                holder = re.sub(r"\s+", " ", m.group(1)).strip(" .,-")
                if len(holder) < 3 or holder.lower() in _COPYRIGHT_NOISE:
                    continue
                holders[holder] += 1

        if len(holders) < 2:
            return []
        listing = "\n".join(f"  - {h} ({n} file)" for h, n in holders.most_common(5))
        return [Finding(
            id=_make_id(), layer=Layer.PROVENANCE, severity=Severity.MEDIUM,
            rule_id="PROV-COPYRIGHT-001",
            title=f"Header di copyright intestati a {len(holders)} titolari diversi",
            description=(
                "I sorgenti contengono notice di copyright con intestatari diversi:\n"
                + listing
                + "\nPiu titolari nello stesso repository significano codice ripreso da altri "
                "progetti o da collaboratori esterni. Per ogni intestatario diverso dalla "
                "societa serve la licenza o la cessione dei diritti."
            ),
            confidence=0.7,
        )]

    # --- Check 5: claims del README ---

    def _check_readme_claims(self, all_paths: set[str], stack_info: StackInfo, readme: str) -> list[Finding]:
        if not readme:
            return []

        evidence = self._collect_evidence(all_paths, stack_info)
        unmatched: list[str] = []
        for label, pattern, key in README_CLAIMS:
            if pattern.search(readme) and not evidence.get(key, False):
                unmatched.append(label)

        findings: list[Finding] = []
        if unmatched:
            findings.append(Finding(
                id=_make_id(), layer=Layer.PROVENANCE, severity=Severity.MEDIUM,
                rule_id="PROV-CLAIMS-001",
                title=f"Dichiarazioni del README non riscontrate nel codice ({len(unmatched)})",
                description=(
                    "Il README menziona capacita di cui il repository non contiene traccia:\n"
                    + "\n".join(f"  - {u}" for u in unmatched)
                    + "\nPuo trattarsi di documentazione aspirazionale o di componenti che vivono "
                    "in un altro repository. In due diligence ogni dichiarazione non riscontrata "
                    "va fatta dimostrare."
                ),
                confidence=0.7,
            ))

        certs = sorted({m.group(1).upper().replace("  ", " ") for m in CERTIFICATION_RE.finditer(readme)})
        if certs:
            findings.append(Finding(
                id=_make_id(), layer=Layer.PROVENANCE, severity=Severity.INFO,
                rule_id="PROV-CERT-INFO",
                title=f"Certificazioni o conformita dichiarate nel README: {', '.join(certs)}",
                description=(
                    "Il README dichiara conformita o certificazioni che non sono verificabili "
                    "dal codice. Richiedere i report di audit, i certificati e la data di validita."
                ),
            ))
        return findings

    @staticmethod
    def _collect_evidence(all_paths: set[str], stack_info: StackInfo) -> dict[str, bool]:
        infra_lower = [i.lower() for i in stack_info.infra_type]
        basenames = {p.rsplit("/", 1)[-1].lower() for p in all_paths}
        lower_paths = {p.lower() for p in all_paths}

        has_docker = (
            any("docker" in i for i in infra_lower)
            or "dockerfile" in basenames
            or any(b.startswith("docker-compose") for b in basenames)
        )
        has_k8s = (
            any("kubernetes" in i or "helm" in i for i in infra_lower)
            or any(p.startswith(("k8s/", "kubernetes/", "helm/", "charts/")) for p in lower_paths)
            or "chart.yaml" in basenames
        )
        has_iac = (
            any(k in i for i in infra_lower for k in IAC_INFRA_KEYWORDS)
            or any(b.endswith(".tf") for b in basenames)
            or "pulumi.yaml" in basenames
        )
        has_ci = (
            any(k in i for i in infra_lower for k in CI_INFRA_KEYWORDS)
            or any(p.startswith(".github/workflows/") for p in lower_paths)
            or ".gitlab-ci.yml" in basenames
            or "jenkinsfile" in basenames
            or any(p.startswith(".circleci/") for p in lower_paths)
            or "azure-pipelines.yml" in basenames
            or "bitbucket-pipelines.yml" in basenames
        )
        has_tests = any(
            part in ("tests", "test", "__tests__", "spec", "specs")
            for p in lower_paths for part in p.split("/")[:-1]
        ) or any(
            b.startswith("test_") or b.endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts", "_test.go"))
            for b in basenames
        )
        return {"docker": has_docker, "kubernetes": has_k8s, "iac": has_iac, "ci": has_ci, "tests": has_tests}

    # --- Check 6: SBOM ---

    def _check_sbom(self, all_paths: set[str]) -> list[Finding]:
        if any(SBOM_NAME_RE.search(p) for p in all_paths):
            return []
        return [Finding(
            id=_make_id(), layer=Layer.PROVENANCE, severity=Severity.LOW,
            rule_id="PROV-SBOM-001",
            title="Nessun SBOM nel repository",
            description=(
                "Non e presente una Software Bill of Materials (CycloneDX o SPDX). Lo SBOM e "
                "l'inventario dei componenti con versione e licenza: senza, la verifica della "
                "supply chain va rifatta a mano a ogni audit."
            ),
            framework_ref="NIS2 Art.21(2)(d)",
            confidence=0.95,
        )]
