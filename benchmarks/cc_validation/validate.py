"""
CC Validation Script — Confronto CTO Audit Agent vs Claude Code (o altro LLM).

Workflow:
1. `scan`: esegue `cto-audit scan` su una repo (profilo default o due-diligence)
   e stampa il prompt da dare all'LLM
2. L'utente esegue l'LLM sulla stessa repo, 2-3 volte, e salva ogni output
3. `compare`: confronta tool e LLM su score, layer, finding, severita, evidenze,
   e misura la stabilita dell'LLM tra le sue esecuzioni

Uso:
    python validate.py scan /path/to/repo [--due-diligence]
    python validate.py compare tool.json llm_run1.json [llm_run2.json ...] [--repo /path/to/repo]

Perche un confronto con un LLM e utile ma non e un oracolo:
- l'LLM vede il codice con un contesto limitato e non e deterministico;
- il tool e deterministico ma copre solo le regole che ha;
- le metriche qui sotto separano i due errori: cosa il tool non vede (recall)
  e cosa l'LLM afferma senza evidenza nel repository (evidence rate).
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from itertools import combinations
from pathlib import Path


# ---------------------------------------------------------------------------
# Prompt per l'LLM
# ---------------------------------------------------------------------------

CC_PROMPT_TEMPLATE = """Analizza questo codebase come un CTO esperto. Produci un report strutturato con:

1. SCORE COMPLESSIVO (0-100)

2. SCORE PER LAYER (0-100 ciascuno):
   - Infrastructure: CI/CD, Docker, IaC, monitoraggio
   - Architecture: struttura progetto, separazione layer, dipendenze
   - Security: secrets, SQL injection, XSS, dipendenze vulnerabili, auth
   - Quality: test, linting, documentazione, complessita
{dd_layers}
3. FINDING (lista di problemi trovati):
   Per ogni finding indica:
   - LAYER: infrastructure|architecture|security|quality{dd_layer_names}
   - SEVERITY: critical|high|medium|low|info
   - CATEGORY: una tra: {categories}
   - TITLE: titolo breve
   - DESCRIPTION: descrizione
   - EVIDENCE: percorso del file (o dei file) che dimostra il finding, relativo alla root del repo.
     Se il finding non ha un file che lo dimostra, scrivi "none".

4. GIUDIZIO COMPLESSIVO (2-3 righe)
{dd_questions}
Rispondi SOLO con JSON valido, con questa struttura:
{{
  "overall_score": 75,
  "layer_scores": {{
    "infrastructure": 70,
    "architecture": 80,
    "security": 65,
    "quality": 85{dd_layer_scores}
  }},
  "findings": [
    {{
      "layer": "security",
      "severity": "high",
      "category": "hardcoded-secrets",
      "title": "Secrets hardcoded nel codice",
      "description": "...",
      "evidence": ["config/settings.py"]
    }}
  ],
  "summary": "..."{dd_answers}
}}
"""

DD_LAYERS_TEXT = """   - Provenance: licenza e copyright del repository, licenze delle dipendenze (copyleft, commerciali),
     codice di terze parti copiato, titolari di copyright diversi, dichiarazioni del README senza riscontro, SBOM
   - Team: bus factor dallo storico git, attivita recente, storico compresso, tag di release, qualita dei commit
"""
DD_QUESTIONS_TEXT = """
5. DUE DILIGENCE: rispondi anche a queste domande (yes/no/n/d + una riga di motivazione):
   - deal_flag_ip: ci sono rischi che bloccano la cessione dell'asset (licenze copyleft in prodotto proprietario,
     codice di terzi senza cessione, licenze commerciali non provate)?
   - deal_flag_team: c'e un rischio di continuita (bus factor 1, repository fermo da oltre 6 mesi)?
   - deal_flag_secrets: ci sono secret esposti nel repository?
"""
DD_ANSWERS_JSON = """,
  "due_diligence": {
    "deal_flag_ip": {"answer": "no", "reason": "..."},
    "deal_flag_team": {"answer": "yes", "reason": "..."},
    "deal_flag_secrets": {"answer": "no", "reason": "..."}
  }"""

# ---------------------------------------------------------------------------
# Categorie: il ponte tra i rule_id del tool e le parole dell'LLM
# ---------------------------------------------------------------------------

# categoria -> (rule_id del tool, parole chiave per riconoscerla nei finding dell'LLM)
CATEGORY_MAP: dict[str, tuple[list[str], list[str]]] = {
    # infra
    "no-ci-cd": (["INFRA-CICD-001"], ["ci/cd", "ci cd", "cicd", "pipeline", "github actions", "continuous integration"]),
    "no-container": (["INFRA-DOCKER-001"], ["no docker", "nessun docker", "dockerfile mancante", "containeriz", "senza container"]),
    "dockerfile-hygiene": (["INFRA-DOCKER-002", "INFRA-DOCKER-003", "INFRA-DOCKER-004", "INFRA-DOCKER-005"], ["dockerfile", "multi-stage", "root user", "healthcheck", "dockerignore"]),
    "no-iac": (["INFRA-IAC-001"], ["infrastructure as code", "iac", "terraform", "pulumi", "ansible", "cloudformation"]),
    "no-lockfile": (["INFRA-DEPS-001"], ["lockfile", "lock file", "pinned", "pinning", "versioni non bloccate"]),
    "secrets-in-config": (["INFRA-CONFIG-001", "INFRA-CONFIG-002"], [".env", "env file", "config secret", "credenziali in config"]),
    "no-monitoring": (["INFRA-MON-001"], ["monitoring", "monitoraggio", "logging", "observab", "health check"]),
    "no-env-example": (["INFRA-ENVEXAMPLE-001"], [".env.example"]),
    # architecture
    "flat-structure": (["ARCH-STRUCT-001"], ["struttura", "structure", "flat", "organizzazione", "layout"]),
    "circular-imports": (["ARCH-COUPLING-001"], ["circular", "circolar", "ciclic"]),
    "high-coupling": (["ARCH-COUPLING-002"], ["coupling", "accoppiamento", "fan-out", "fan out"]),
    "large-files": (["ARCH-SCALE-001"], ["file grandi", "large file", "god class", "troppo lungo", "> 500", "loc"]),
    "no-tests": (["ARCH-TEST-001"], ["no test", "nessun test", "senza test", "missing test", "test assenti", "test coverage"]),
    "no-migrations": (["ARCH-DB-001"], ["migration", "migrazion", "alembic", "flyway"]),
    # security
    "vulnerable-deps": (["SEC-DEPS-001", "SEC-DEPS-CVE-001"], ["cve", "vulnerab", "outdated", "obsolet"]),
    "no-auth": (["SEC-AUTH-001"], ["authentication", "autenticazione", "auth"]),
    "http-urls": (["SEC-HTTPS-001"], ["http://", "non cifrat", "plain http", "https"]),
    "permissive-cors": (["SEC-CORS-001"], ["cors"]),
    "sql-injection": (["SEC-SQL-001"], ["sql injection", "sql concat", "query string"]),
    "hardcoded-secrets": (["SEC-SECRETS-CODE-001"], ["hardcoded secret", "secret", "api key", "password in", "token in", "credenzial"]),
    "security-headers": (["SEC-HEADERS-001"], ["security header", "helmet", "csp", "hsts"]),
    "weak-crypto": (["SEC-CRYPTO-001"], ["md5", "sha1", "sha-1", "weak crypto", "crittografia debole", "des", "rc4"]),
    # quality
    "no-readme": (["QUAL-DOC-001"], ["readme"]),
    "poor-docs": (["QUAL-DOC-002"], ["docstring", "documentazione inline", "comment", "jsdoc", "documentation"]),
    "no-linter": (["QUAL-LINT-001"], ["lint", "formatter", "ruff", "eslint", "black", "prettier"]),
    "no-typing": (["QUAL-TYPING-001"], ["type check", "typing", "mypy", "typescript strict", "tipizzazione"]),
    "complexity": (["QUAL-COMPLEXITY-001"], ["complex", "nesting", "annidat", "cyclomatic"]),
    "duplication": (["QUAL-DUP-001"], ["duplicat", "copy-paste", "copia"]),
    "no-precommit": (["QUAL-PRECOMMIT-001"], ["pre-commit", "husky", "hook"]),
    "project-hygiene": (["QUAL-EDITORCONFIG-001", "QUAL-CONTRIBUTING-001", "QUAL-CHANGELOG-001"], ["editorconfig", "contributing", "changelog"]),
    # provenance
    "no-license": (["PROV-LICENSE-001"], ["no license", "nessuna licenza", "license file", "missing license", "copyright notice"]),
    "copyleft-deps": (["PROV-COPYLEFT-001", "PROV-COPYLEFT-002"], ["gpl", "agpl", "lgpl", "copyleft", "mpl", "sspl"]),
    "commercial-deps": (["PROV-COMMERCIAL-001"], ["commercial license", "licenza commerciale", "see license in", "proprietary dep", "unlicensed"]),
    "vendored-code": (["PROV-VENDORED-001"], ["vendor", "third_party", "third-party code", "vendoriz", "copied code", "codice copiato"]),
    "copyright-holders": (["PROV-COPYRIGHT-001"], ["copyright holder", "titolar", "copyright di terzi", "multiple copyright"]),
    "readme-claims": (["PROV-CLAIMS-001"], ["readme claim", "dichiar", "aspirational", "not backed", "non riscontr", "claims"]),
    "no-sbom": (["PROV-SBOM-001"], ["sbom", "bill of materials", "cyclonedx", "spdx"]),
    # team
    "bus-factor": (["TEAM-BUSFACTOR-001"], ["bus factor", "truck factor", "single contributor", "unico autore", "un solo autore", "key person", "concentrat"]),
    "inactive-repo": (["TEAM-ACTIVITY-001", "TEAM-ACTIVITY-002"], ["inactive", "inattiv", "stale", "no commits", "fermo", "abandoned", "last commit"]),
    "compressed-history": (["TEAM-HISTORY-001", "TEAM-HISTORY-002"], ["history", "storico", "code dump", "single commit", "import iniziale", "squash"]),
    "no-releases": (["TEAM-RELEASE-001"], ["release", "tag", "version"]),
    "commit-quality": (["TEAM-MSGQUAL-001"], ["commit message", "messaggi di commit", "wip"]),
}

RULE_TO_CATEGORY: dict[str, str] = {
    rule: cat for cat, (rules, _kw) in CATEGORY_MAP.items() for rule in rules
}

LAYER_MAP = {
    "infra": "infrastructure",
    "architecture": "architecture",
    "security": "security",
    "quality": "quality",
    "provenance": "provenance",
    "team": "team",
}

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

DEAL_FLAG_RULES = {
    "deal_flag_ip": {"PROV-COPYLEFT-001", "PROV-COPYRIGHT-001", "PROV-COMMERCIAL-001"},
    "deal_flag_team": {"TEAM-BUSFACTOR-001", "TEAM-ACTIVITY-001"},
    "deal_flag_secrets": {"SEC-SECRETS-CODE-001", "INFRA-CONFIG-001", "INFRA-CONFIG-002"},
}


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

def _build_prompt(due_diligence: bool) -> str:
    categories = ", ".join(CATEGORY_MAP.keys())
    if due_diligence:
        return CC_PROMPT_TEMPLATE.format(
            dd_layers=DD_LAYERS_TEXT,
            dd_layer_names="|provenance|team",
            categories=categories,
            dd_questions=DD_QUESTIONS_TEXT,
            dd_layer_scores=',\n    "provenance": 60,\n    "team": 50',
            dd_answers=DD_ANSWERS_JSON,
        )
    return CC_PROMPT_TEMPLATE.format(
        dd_layers="", dd_layer_names="", categories=categories,
        dd_questions="", dd_layer_scores="", dd_answers="",
    )


def cmd_scan(repo_path: str, due_diligence: bool = False) -> None:
    """Esegue CTO Audit Agent e stampa il prompt per l'LLM."""
    import subprocess

    repo = Path(repo_path).resolve()
    if not repo.is_dir():
        print(f"Errore: {repo} non e una directory")
        sys.exit(1)

    output_file = Path(f"cto_result_{repo.name}.json")
    cmd = [sys.executable, "-m", "cto_audit", "scan", str(repo), "--auto-approve", "--offline", "-o", str(output_file)]
    if due_diligence:
        cmd += ["--scoring", "due-diligence"]

    print(f"Esecuzione CTO Audit Agent su: {repo}" + (" (profilo due-diligence)" if due_diligence else ""))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Errore nell'esecuzione:\n{result.stderr}")
        sys.exit(1)

    print(f"Risultato salvato in: {output_file}")
    print()
    print("=== PASSO SUCCESSIVO ===")
    print()
    print("1. Apri Claude Code (o un altro LLM con accesso al repo) sulla stessa repo")
    print("2. Incolla il prompt seguente, 2-3 volte in sessioni separate:")
    print()
    print(_build_prompt(due_diligence))
    print()
    print(f"3. Salva ogni output JSON (es. llm_{repo.name}_1.json, llm_{repo.name}_2.json)")
    print(f"4. Esegui: python validate.py compare {output_file} llm_{repo.name}_1.json llm_{repo.name}_2.json --repo {repo}")


# ---------------------------------------------------------------------------
# compare
# ---------------------------------------------------------------------------

def _tool_findings(tool_data: dict) -> list[dict]:
    out = []
    for layer_key, layer_data in tool_data.get("health_score", {}).get("layer_scores", {}).items():
        for f in layer_data.get("findings", []):
            if f.get("severity", "") == "info":
                continue
            out.append({
                "layer": LAYER_MAP.get(layer_key, layer_key),
                "severity": f.get("severity", ""),
                "rule_id": f.get("rule_id", ""),
                "category": RULE_TO_CATEGORY.get(f.get("rule_id", ""), f.get("rule_id", "").lower()),
                "title": f.get("title", ""),
            })
    return out


def _classify_llm_finding(f: dict) -> str:
    """Riconduce un finding dell'LLM a una categoria: usa CATEGORY se valida, altrimenti le parole chiave."""
    cat = (f.get("category") or f.get("rule_id") or "").strip().lower()
    if cat in CATEGORY_MAP:
        return cat
    text = " ".join(str(f.get(k, "")) for k in ("category", "rule_id", "title", "description")).lower()
    best, best_hits = None, 0
    for name, (_rules, keywords) in CATEGORY_MAP.items():
        hits = sum(1 for kw in keywords if kw in text)
        if hits > best_hits:
            best, best_hits = name, hits
    return best or (cat or "uncategorized")


def _llm_findings(llm_data: dict) -> list[dict]:
    out = []
    for f in llm_data.get("findings", []):
        if str(f.get("severity", "")).lower() == "info":
            continue
        evidence = f.get("evidence", [])
        if isinstance(evidence, str):
            evidence = [] if evidence.strip().lower() in ("", "none", "n/a") else [evidence]
        out.append({
            "layer": str(f.get("layer", "")).lower(),
            "severity": str(f.get("severity", "")).lower(),
            "category": _classify_llm_finding(f),
            "title": f.get("title", ""),
            "evidence": [str(e) for e in evidence],
        })
    return out


def _evidence_rate(llm_findings: list[dict], repo: Path | None) -> tuple[float | None, list[str]]:
    """Quota di finding LLM con almeno un file di evidenza esistente nel repo."""
    if repo is None:
        return None, []
    ok = 0
    missing: list[str] = []
    for f in llm_findings:
        paths = [p.split(":")[0].strip().lstrip("./") for p in f["evidence"]]
        if paths and any((repo / p).exists() for p in paths):
            ok += 1
        else:
            missing.append(f"{f['category']}: {f['title'][:60]}" + (f" [{', '.join(paths[:2])}]" if paths else " [nessuna evidenza]"))
    return (ok / len(llm_findings) if llm_findings else None), missing


def _jaccard(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if (a | b) else 1.0


def cmd_compare(tool_file: str, llm_files: list[str], repo_path: str | None = None) -> None:
    tool_path = Path(tool_file)
    if not tool_path.exists():
        print(f"Errore: {tool_path} non trovato")
        sys.exit(1)
    tool_data = json.loads(tool_path.read_text(encoding="utf-8"))

    runs: list[dict] = []
    for lf in llm_files:
        p = Path(lf)
        if not p.exists():
            print(f"Errore: {p} non trovato")
            sys.exit(1)
        data = _extract_json(p.read_text(encoding="utf-8"))
        if data is None:
            print(f"Errore: impossibile parsare {p} come JSON")
            sys.exit(1)
        runs.append(data)

    repo = Path(repo_path).resolve() if repo_path else None
    tool_f = _tool_findings(tool_data)
    tool_cats = Counter(f["category"] for f in tool_f)
    tool_cat_set = set(tool_cats)

    print("=" * 64)
    print("  CONFRONTO CTO AUDIT AGENT vs LLM")
    print("=" * 64)

    # --- Stabilita dell'LLM tra esecuzioni ---
    if len(runs) >= 2:
        cat_sets = [set(f["category"] for f in _llm_findings(r)) for r in runs]
        scores = [r.get("overall_score", 0) for r in runs]
        jac = [_jaccard(a, b) for a, b in combinations(cat_sets, 2)]
        print()
        print(f"  Stabilita LLM ({len(runs)} esecuzioni):")
        print(f"    Score: {', '.join(f'{s:.0f}' for s in scores)}  (range {max(scores) - min(scores):.0f} punti)")
        print(f"    Jaccard categorie tra esecuzioni: {sum(jac) / len(jac):.0%} (media)")
        print("    Un Jaccard sotto il 50% dice che l'LLM da solo non e una ground truth stabile.")

    # Confronto principale: unione delle esecuzioni LLM (un finding conta se almeno una run lo trova)
    llm_union: dict[str, dict] = {}
    for r in runs:
        for f in _llm_findings(r):
            llm_union.setdefault(f["category"], f)
    llm_f = list(llm_union.values())
    llm_cat_set = set(llm_union)
    primary = runs[0]

    # --- Score ---
    tool_score = tool_data.get("health_score", {}).get("overall_score", 0)
    llm_scores = [r.get("overall_score", 0) for r in runs]
    llm_score = sum(llm_scores) / len(llm_scores)
    print()
    print(f"  Score Tool:        {tool_score:.0f}/100")
    print(f"  Score LLM:         {llm_score:.0f}/100" + (f" (media di {len(runs)})" if len(runs) > 1 else ""))
    print(f"  Distanza:          {abs(tool_score - llm_score):.1f} punti")

    # --- Layer ---
    print()
    print("  Score per layer:")
    tool_layers = tool_data.get("health_score", {}).get("layer_scores", {})
    for tool_key, llm_key in LAYER_MAP.items():
        if tool_key not in tool_layers:
            continue
        t = tool_layers[tool_key].get("score", 0)
        vals = [r.get("layer_scores", {}).get(llm_key) for r in runs]
        vals = [v for v in vals if isinstance(v, (int, float))]
        if vals:
            l = sum(vals) / len(vals)
            print(f"    {llm_key:<14} Tool: {t:>3.0f}  LLM: {l:>3.0f}  Delta: {abs(t - l):>3.0f}")
        else:
            print(f"    {llm_key:<14} Tool: {t:>3.0f}  LLM: -")

    # --- Finding per categoria ---
    common = tool_cat_set & llm_cat_set
    tool_only = tool_cat_set - llm_cat_set
    llm_only = llm_cat_set - tool_cat_set
    print()
    print(f"  Categorie in comune:        {len(common)}")
    print(f"  Solo nel Tool (FP?):        {len(tool_only)}")
    print(f"  Solo nell'LLM (FN?):        {len(llm_only)}")
    for label, items in (("Concordano su", common), ("Solo nel Tool", tool_only), ("Solo nell'LLM", llm_only)):
        if items:
            print(f"    {label}: {', '.join(sorted(items))}")

    precision = len(common) / len(tool_cat_set) if tool_cat_set else None
    recall = len(common) / len(llm_cat_set) if llm_cat_set else None
    print()
    print(f"  Precision (categorie): {precision:.0%}" if precision is not None else "  Precision: N/A")
    print(f"  Recall (categorie):    {recall:.0%}" if recall is not None else "  Recall: N/A")

    # --- Per layer: precision/recall ---
    print()
    print("  Precision / Recall per layer:")
    for tool_key, llm_key in LAYER_MAP.items():
        t_cats = {f["category"] for f in tool_f if f["layer"] == llm_key}
        l_cats = {f["category"] for f in llm_f if f["layer"] == llm_key}
        if not t_cats and not l_cats:
            continue
        c = t_cats & l_cats
        p = f"{len(c) / len(t_cats):.0%}" if t_cats else "-"
        r = f"{len(c) / len(l_cats):.0%}" if l_cats else "-"
        print(f"    {llm_key:<14} P: {p:>4}  R: {r:>4}  (tool {len(t_cats)}, llm {len(l_cats)}, comuni {len(c)})")

    # --- Severita sui finding in comune ---
    if common:
        exact = near = 0
        for cat in common:
            t_sev = max((SEVERITY_RANK.get(f["severity"], 0) for f in tool_f if f["category"] == cat), default=0)
            l_sev = SEVERITY_RANK.get(llm_union[cat]["severity"], 0)
            if t_sev == l_sev:
                exact += 1
            if abs(t_sev - l_sev) <= 1:
                near += 1
        print()
        print(f"  Severita sui finding comuni: identica {exact}/{len(common)}, entro un livello {near}/{len(common)}")

    # --- Evidence rate dell'LLM ---
    rate, missing = _evidence_rate(llm_f, repo)
    print()
    if rate is None:
        print("  Evidence rate LLM: N/A (passa --repo per verificare i file citati)")
    else:
        print(f"  Evidence rate LLM: {rate:.0%} dei finding citano almeno un file esistente nel repo")
        if missing:
            print("    Finding LLM senza evidenza verificabile:")
            for m in missing[:10]:
                print(f"      - {m}")

    # --- Deal flag (solo due diligence) ---
    dd = primary.get("due_diligence")
    if isinstance(dd, dict):
        tool_rules = {f["rule_id"] for f in tool_f}
        print()
        print("  Deal flag (due diligence):")
        agree = 0
        for flag, rules in DEAL_FLAG_RULES.items():
            tool_ans = "yes" if tool_rules & rules else "no"
            llm_ans = str((dd.get(flag) or {}).get("answer", "n/d")).lower()
            llm_ans = "yes" if llm_ans in ("yes", "si", "sì", "true") else ("no" if llm_ans in ("no", "false") else "n/d")
            mark = "OK" if tool_ans == llm_ans else ("?" if llm_ans == "n/d" else "DIVERGE")
            if tool_ans == llm_ans:
                agree += 1
            print(f"    {flag:<18} Tool: {tool_ans:<3} LLM: {llm_ans:<3} {mark}")
        print(f"    Accordo: {agree}/{len(DEAL_FLAG_RULES)}")

    print()
    print("=" * 64)
    print("  Lettura: precision bassa = regole del tool da rivedere; recall bassa = coperture da aggiungere;")
    print("  evidence rate basso = l'LLM afferma cose che il repo non mostra; Jaccard basso = LLM instabile.")
    print("=" * 64)


def _extract_json(text: str) -> dict | None:
    """Estrae un oggetto JSON dal testo (gestisce markdown code blocks)."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"```(?:json)?\s*\n(.*?)\n```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    start = text.find("{")
    if start >= 0:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break
    return None


def main() -> None:
    args = [a for a in sys.argv[1:]]
    if not args:
        print("Uso:")
        print("  python validate.py scan /path/to/repo [--due-diligence]")
        print("  python validate.py compare tool.json llm_1.json [llm_2.json ...] [--repo /path/to/repo]")
        sys.exit(1)

    cmd = args[0]
    if cmd == "scan":
        dd = "--due-diligence" in args or "--dd" in args
        targets = [a for a in args[1:] if not a.startswith("--")]
        if not targets:
            print("Errore: indica il percorso della repo")
            sys.exit(1)
        cmd_scan(targets[0], due_diligence=dd)
    elif cmd == "compare":
        repo = None
        rest = args[1:]
        if "--repo" in rest:
            i = rest.index("--repo")
            repo = rest[i + 1] if i + 1 < len(rest) else None
            rest = rest[:i] + rest[i + 2:]
        files = [a for a in rest if not a.startswith("--")]
        if len(files) < 2:
            print("Errore: servono il JSON del tool e almeno un JSON dell'LLM")
            sys.exit(1)
        cmd_compare(files[0], files[1:], repo_path=repo)
    else:
        print(f"Comando sconosciuto: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
