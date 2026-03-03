"""
CC Validation Script — Confronto CTO Audit Agent vs Claude Code.

Workflow:
1. Esegue `cto-audit scan` su una repo e salva il JSON
2. Genera un prompt strutturato per Claude Code
3. L'utente esegue CC manualmente e salva l'output in un file
4. Lo script confronta: finding in comune, falsi positivi, falsi negativi

Uso:
    python validate.py scan /path/to/repo
    python validate.py compare result.json cc_output.txt
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


CC_PROMPT_TEMPLATE = """Analizza questo codebase come un CTO esperto. Produci un report strutturato con:

1. SCORE COMPLESSIVO (0-100)

2. SCORE PER LAYER (0-100 ciascuno):
   - Infrastructure: CI/CD, Docker, IaC, monitoraggio
   - Architecture: struttura progetto, separazione layer, dipendenze
   - Security: secrets, SQL injection, XSS, dipendenze vulnerabili, auth
   - Quality: test, linting, documentazione, complessita

3. FINDING (lista di problemi trovati):
   Per ogni finding indica:
   - LAYER: infrastructure|architecture|security|quality
   - SEVERITY: critical|high|medium|low|info
   - RULE_ID: un identificativo breve (es. "no-ci-cd", "hardcoded-secrets")
   - TITLE: titolo breve
   - DESCRIPTION: descrizione

4. GIUDIZIO COMPLESSIVO (2-3 righe)

Rispondi in formato JSON con questa struttura:
{{
  "overall_score": 75,
  "layer_scores": {{
    "infrastructure": 70,
    "architecture": 80,
    "security": 65,
    "quality": 85
  }},
  "findings": [
    {{
      "layer": "security",
      "severity": "high",
      "rule_id": "hardcoded-secrets",
      "title": "Secrets hardcoded nel codice",
      "description": "..."
    }}
  ],
  "summary": "..."
}}
"""


def cmd_scan(repo_path: str) -> None:
    """Esegue CTO Audit Agent e salva il risultato."""
    import subprocess

    repo = Path(repo_path).resolve()
    if not repo.is_dir():
        print(f"Errore: {repo} non e una directory")
        sys.exit(1)

    output_file = Path(f"cto_result_{repo.name}.json")

    print(f"Esecuzione CTO Audit Agent su: {repo}")
    result = subprocess.run(
        [
            sys.executable, "-m", "cto_audit",
            "scan", str(repo),
            "--auto-approve", "--offline",
            "-o", str(output_file),
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(f"Errore nell'esecuzione:\n{result.stderr}")
        sys.exit(1)

    print(f"Risultato salvato in: {output_file}")
    print()
    print("=== PASSO SUCCESSIVO ===")
    print()
    print("1. Apri Claude Code sulla stessa repo")
    print("2. Incolla il prompt seguente:")
    print()
    print(CC_PROMPT_TEMPLATE)
    print()
    print(f"3. Salva l'output JSON di CC in un file (es. cc_result_{repo.name}.json)")
    print(f"4. Esegui: python validate.py compare {output_file} cc_result_{repo.name}.json")


def cmd_compare(tool_file: str, cc_file: str) -> None:
    """Confronta il risultato del tool con quello di Claude Code."""
    tool_path = Path(tool_file)
    cc_path = Path(cc_file)

    if not tool_path.exists():
        print(f"Errore: {tool_path} non trovato")
        sys.exit(1)
    if not cc_path.exists():
        print(f"Errore: {cc_path} non trovato")
        sys.exit(1)

    tool_data = json.loads(tool_path.read_text(encoding="utf-8"))
    cc_text = cc_path.read_text(encoding="utf-8")

    # Cerca di parsare il JSON di CC (potrebbe avere testo intorno)
    cc_data = _extract_json(cc_text)
    if cc_data is None:
        print("Errore: impossibile parsare l'output di CC come JSON")
        print("Assicurati che il file contenga il JSON strutturato richiesto")
        sys.exit(1)

    # --- Score comparison ---
    tool_score = tool_data.get("health_score", {}).get("overall_score", 0)
    cc_score = cc_data.get("overall_score", 0)

    print("=" * 60)
    print("  CONFRONTO CTO AUDIT AGENT vs CLAUDE CODE")
    print("=" * 60)
    print()
    print(f"  Score Tool:        {tool_score:.0f}/100")
    print(f"  Score CC:          {cc_score:.0f}/100")
    print(f"  Distanza:          {abs(tool_score - cc_score):.1f} punti")
    print()

    # --- Layer scores ---
    print("  Score per Layer:")
    tool_layers = tool_data.get("health_score", {}).get("layer_scores", {})
    cc_layers = cc_data.get("layer_scores", {})

    layer_map = {
        "infra": "infrastructure",
        "architecture": "architecture",
        "security": "security",
        "quality": "quality",
    }

    for tool_key, cc_key in layer_map.items():
        tool_ls = tool_layers.get(tool_key, {}).get("score", "-")
        cc_ls = cc_layers.get(cc_key, "-")
        if isinstance(tool_ls, (int, float)) and isinstance(cc_ls, (int, float)):
            delta = abs(tool_ls - cc_ls)
            print(f"    {cc_key:<16} Tool: {tool_ls:>3.0f}  CC: {cc_ls:>3.0f}  Delta: {delta:.0f}")
        else:
            print(f"    {cc_key:<16} Tool: {tool_ls}  CC: {cc_ls}")
    print()

    # --- Finding comparison ---
    tool_findings = set()
    for layer_data in tool_layers.values():
        for f in layer_data.get("findings", []):
            if f.get("severity", "") != "info":
                tool_findings.add(f.get("rule_id", ""))

    cc_findings = set()
    for f in cc_data.get("findings", []):
        if f.get("severity", "") != "info":
            cc_findings.add(f.get("rule_id", ""))

    common = tool_findings & cc_findings
    tool_only = tool_findings - cc_findings
    cc_only = cc_findings - tool_findings

    print(f"  Finding in comune:         {len(common)}")
    print(f"  Solo nel Tool (FP?):       {len(tool_only)}")
    print(f"  Solo in CC (FN?):          {len(cc_only)}")
    print()

    if common:
        print("  Concordano su:")
        for r in sorted(common):
            print(f"    - {r}")
        print()

    if tool_only:
        print("  Solo nel Tool (possibili falsi positivi):")
        for r in sorted(tool_only):
            print(f"    - {r}")
        print()

    if cc_only:
        print("  Solo in CC (possibili falsi negativi):")
        for r in sorted(cc_only):
            print(f"    - {r}")
        print()

    # --- Metriche ---
    total_tool = len(tool_findings)
    total_cc = len(cc_findings)

    if total_tool > 0:
        precision = len(common) / total_tool
        print(f"  Precision: {precision:.0%} ({len(common)}/{total_tool})")
    else:
        print("  Precision: N/A (nessun finding nel tool)")

    if total_cc > 0:
        recall = len(common) / total_cc
        print(f"  Recall:    {recall:.0%} ({len(common)}/{total_cc})")
    else:
        print("  Recall:    N/A (nessun finding in CC)")

    print()
    print("=" * 60)


def _extract_json(text: str) -> dict | None:
    """Estrae un oggetto JSON dal testo (gestisce markdown code blocks)."""
    # Prova parsing diretto
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Prova a estrarre da code block ```json ... ```
    import re
    match = re.search(r"```(?:json)?\s*\n(.*?)\n```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # Prova a trovare il primo { ... } bilanciato
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
    """Entry point CLI."""
    if len(sys.argv) < 2:
        print("Uso:")
        print("  python validate.py scan /path/to/repo")
        print("  python validate.py compare tool_result.json cc_result.json")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "scan" and len(sys.argv) >= 3:
        cmd_scan(sys.argv[2])
    elif cmd == "compare" and len(sys.argv) >= 4:
        cmd_compare(sys.argv[2], sys.argv[3])
    else:
        print(f"Comando non riconosciuto: {cmd}")
        print("Usa 'scan' o 'compare'")
        sys.exit(1)


if __name__ == "__main__":
    main()
