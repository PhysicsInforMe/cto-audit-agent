"""
Due Diligence Report — Report Markdown per chi valuta il codice di un terzo.

Destinatario: investitore, acquirente, partner, o il consulente che lavora
per loro. Non e il board report (rivolto a chi possiede il codice): qui la
domanda e "cosa compro, di chi e, cosa rischio, quanto costa sistemarlo".

Sezioni:
1. Perimetro e metodo (cosa e stato analizzato, cosa NON si puo verificare dal codice)
2. Sintesi (score, deal flag, confidence)
3. Inventario dell'asset (fatti: stack, dimensioni, storico, licenze)
4. Red flag (critical/high) con rischio business dalla KB
5. Yellow flag (medium)
6. Dichiarazioni vs evidenze (claims del README, certificazioni)
7. Costo stimato di remediation (somma effort dalla KB)
8. Domande per il management (generate dalle regole scattate)
9. Compliance (se profili attivi)
10. Score per layer ed evidence chain

Deterministico: funziona senza LLM. Se la pipeline remediation ha prodotto
un executive summary (LLM o template), lo include nella sintesi.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from cto_audit.core.models import (
    LAYER_ORDER,
    AuditResult,
    Finding,
    GitSummary,
    Severity,
)
from cto_audit.remediation.loader import RemediationLoader


LAYER_NAMES: dict[str, str] = {
    "infra": "Infrastruttura",
    "architecture": "Architettura",
    "security": "Sicurezza",
    "quality": "Qualita Codice",
    "provenance": "Provenienza & IP",
    "team": "Team & Continuita",
}

# Domande per il management, per regola scattata. Deterministiche.
MANAGEMENT_QUESTIONS: dict[str, str] = {
    "PROV-COPYLEFT-001": "Quali dipendenze GPL/AGPL sono in produzione, in quale modalita (distribuzione, SaaS, linking) e con quale parere legale?",
    "PROV-COMMERCIAL-001": "Potete fornire i contratti di licenza dei componenti commerciali, con durata, seat e clausola di cessione?",
    "PROV-COPYRIGHT-001": "Chi sono i titolari di copyright presenti nei sorgenti e quali contratti di cessione o licenza coprono quel codice?",
    "PROV-VENDORED-001": "Da dove proviene il codice nelle directory vendor/third_party, con quale licenza, ed e stato modificato?",
    "PROV-LICENSE-001": "Chi detiene formalmente i diritti sul codice? Esistono contratti di cessione con tutti i dipendenti e i fornitori che vi hanno contribuito?",
    "PROV-CLAIMS-001": "Il README dichiara capacita non presenti nel repository: dove vivono (altro repo, infrastruttura esterna) e possiamo vederle?",
    "PROV-CERT-INFO": "Potete fornire certificati e report di audit per le conformita dichiarate, con data di validita?",
    "TEAM-BUSFACTOR-001": "Chi, oltre al primo contributore, e in grado di mantenere il sistema oggi? Che contratti e clausole di permanenza esistono per le persone chiave?",
    "TEAM-ACTIVITY-001": "Perche il repository e fermo da oltre sei mesi? Lo sviluppo e proseguito altrove?",
    "TEAM-ACTIVITY-002": "A cosa e dovuta la pausa degli ultimi tre mesi?",
    "TEAM-HISTORY-001": "La maggior parte del codice e arrivata in pochi commit: dove e stata sviluppata prima, da chi, e con quale storico?",
    "TEAM-HISTORY-002": "Il repository ha uno storico minimo: dove e stato sviluppato il codice prima?",
    "TEAM-AIGEN-INFO": "Quale processo di revisione umana e previsto per il codice generato con assistenti AI e come viene gestita la paternita dell'IP?",
    "SEC-SECRETS-CODE-001": "I secret trovati nel codice sono stati ruotati? Da quando erano esposti e chi ha avuto accesso al repository?",
    "SEC-DEPS-CVE-001": "Esiste un processo di aggiornamento delle dipendenze con CVE note? Con quale SLA?",
    "SEC-AUTH-001": "Come e protetto l'accesso alle API? Esiste un meccanismo di autenticazione fuori dal codice analizzato?",
    "ARCH-TEST-001": "Come viene verificato il software prima del rilascio, in assenza di test automatizzati?",
    "INFRA-CICD-001": "Come avviene il deploy in produzione e chi puo eseguirlo?",
    "INFRA-CONFIG-001": "Il file .env committato contiene credenziali di produzione? Sono state ruotate?",
    "INFRA-CONFIG-002": "I secret nei file di configurazione sono di produzione? Sono stati ruotati?",
}

_SCORE_LABELS = [(80, "Buono"), (60, "Attenzione"), (40, "Insufficiente"), (0, "Critico")]


def _score_label(score: float) -> str:
    for threshold, label in _SCORE_LABELS:
        if score >= threshold:
            return label
    return "Critico"


def _sev_tag(sev: Severity) -> str:
    return {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW", "info": "INFO"}[sev.value]


class DueDiligenceReporter:
    """Genera il report di due diligence in Markdown."""

    def __init__(self, kb_loader: RemediationLoader | None = None, now: datetime | None = None) -> None:
        self._kb = kb_loader
        self._now = now or datetime.now(timezone.utc)

    # --- API ---

    def report(self, result: AuditResult) -> str:
        findings = self._all_findings(result)
        sections = [
            self._header(result),
            self._scope(result),
            self._summary(result, findings),
            self._asset_inventory(result),
            self._flags(findings, (Severity.CRITICAL, Severity.HIGH), "Red flag", "Nessun red flag rilevato."),
            self._flags(findings, (Severity.MEDIUM,), "Yellow flag", "Nessun yellow flag rilevato."),
            self._triage(result),
            self._claims(findings),
            self._remediation_cost(findings),
            self._management_questions(findings),
            self._compliance(result),
            self._score_details(result),
            self._footer(result),
        ]
        return "\n".join(s for s in sections if s)

    def save(self, result: AuditResult, output_path: Path) -> None:
        output_path.write_text(self.report(result), encoding="utf-8")

    # --- Helpers ---

    @staticmethod
    def _all_findings(result: AuditResult) -> list[Finding]:
        out: list[Finding] = []
        for ls in result.health_score.layer_scores.values():
            out.extend(ls.findings)
        return out

    @staticmethod
    def _triggered(findings: list[Finding]) -> set[str]:
        return {f.rule_id for f in findings if f.severity != Severity.INFO}

    # --- Sezioni ---

    def _header(self, result: AuditResult) -> str:
        meta = result.metadata
        lines = [
            "# Technical Due Diligence — Report",
            "",
            f"**Target:** `{meta.target_path}`  ",
            f"**Data analisi:** {meta.timestamp.strftime('%Y-%m-%d %H:%M')}  ",
            f"**Profilo di scoring:** {meta.scoring_profile}  ",
            f"**Layer analizzati:** {', '.join(LAYER_NAMES.get(l, l) for l in meta.active_layers) or 'n/d'}  ",
            f"**Modalita rete:** {'offline (nessun dato uscito dalla macchina)' if meta.offline_mode else ('con consenso rete' if meta.network_consented else 'rete rifiutata, solo analisi locale')}",
            "",
        ]
        return "\n".join(lines)

    def _scope(self, result: AuditResult) -> str:
        lines = [
            "## 1. Perimetro e metodo",
            "",
            "L'analisi e statica e deterministica: il codice del target non viene eseguito. "
            "Ogni punteggio e tracciabile a una regola, un peso e una fonte (sezione 10). "
            "Lo storico git, se disponibile, e letto solo in forma aggregata: nel report non "
            "compaiono nomi ne email degli autori.",
            "",
            "**Cosa questo report non puo verificare dal codice** e va richiesto in data room:",
            "",
            "- contratti di cessione dei diritti con dipendenti e fornitori;",
            "- licenze commerciali effettivamente acquistate e la loro trasferibilita;",
            "- certificazioni (SOC 2, ISO 27001, ecc.) e i relativi report di audit;",
            "- infrastruttura di produzione, dati e accessi che vivono fuori dal repository;",
            "- qualita del prodotto percepita dagli utenti, metriche di business, pipeline commerciale.",
            "",
        ]
        git = result.git_summary
        if git is not None and not git.available:
            lines.append(f"> Storico git non disponibile ({git.reason}): il layer Team non e valutabile. "
                         "Richiedere accesso al repository con storico completo.")
            lines.append("")
        elif git is not None and git.is_shallow:
            lines.append("> Storico git troncato (clone shallow): le metriche di team sono parziali.")
            lines.append("")
        return "\n".join(lines)

    def _summary(self, result: AuditResult, findings: list[Finding]) -> str:
        hs = result.health_score
        crit = [f for f in findings if f.severity == Severity.CRITICAL]
        high = [f for f in findings if f.severity == Severity.HIGH]
        med = [f for f in findings if f.severity == Severity.MEDIUM]

        lines = ["## 2. Sintesi", ""]
        lines.append(f"**Score complessivo: {hs.overall_score:.0f}/100** ({_score_label(hs.overall_score)}), "
                     f"confidence {hs.overall_confidence:.0%}.")
        lines.append("")

        # Deal flag: regole che toccano la cedibilita o la continuita dell'asset
        deal_rules = {
            "PROV-COPYLEFT-001", "PROV-COPYRIGHT-001", "PROV-COMMERCIAL-001",
            "TEAM-BUSFACTOR-001", "TEAM-ACTIVITY-001", "SEC-SECRETS-CODE-001",
        }
        deal_flags = [f for f in findings if f.rule_id in deal_rules and f.severity != Severity.INFO]
        if deal_flags:
            lines.append("**Deal flag** (temi da chiudere prima del closing o da riflettere nel prezzo):")
            lines.append("")
            for f in deal_flags:
                lines.append(f"- [{_sev_tag(f.severity)}] {f.title} (`{f.rule_id}`)")
            lines.append("")
        else:
            lines.append("Nessun deal flag: nessuna regola su cedibilita dell'IP, continuita del team o secret esposti e scattata.")
            lines.append("")

        lines.append(f"Finding: {len(crit)} critici, {len(high)} alti, {len(med)} medi, "
                     f"{len([f for f in findings if f.severity == Severity.LOW])} bassi.")
        lines.append("")

        remediation = result.remediation
        if remediation is not None and remediation.executive_summary:
            if remediation.llm_used:
                origin = " (generato da LLM, approvato dal revisore)"
            else:
                origin = " (template deterministico)"
            lines.append("**Executive summary" + origin + ":**")
            lines.append("")
            lines.append(remediation.executive_summary.strip())
            lines.append("")
            if remediation.llm_skipped_reason:
                lines.append(f"*Nota: {remediation.llm_skipped_reason}.*")
                lines.append("")
        return "\n".join(lines)

    def _asset_inventory(self, result: AuditResult) -> str:
        stack = result.stack_info
        total_files = len(result.classifications)
        total_loc = sum(c.file_info.lines_of_code for c in result.classifications)
        test_files = sum(
            1 for c in result.classifications
            if any(part in ("tests", "test", "__tests__", "spec", "specs") for part in c.file_info.path.replace("\\", "/").split("/")[:-1])
            or c.file_info.path.rsplit("/", 1)[-1].startswith("test_")
        )

        lines = ["## 3. Inventario dell'asset", ""]
        lines.append("| Voce | Valore |")
        lines.append("|------|--------|")
        if stack.languages:
            langs = ", ".join(f"{l.capitalize()} {p:.0%}" for l, p in sorted(stack.languages.items(), key=lambda x: -x[1])[:5])
            lines.append(f"| Linguaggi | {langs} |")
        if stack.frameworks:
            lines.append(f"| Framework | {', '.join(stack.frameworks[:8])} |")
        if stack.infra_type:
            lines.append(f"| Infrastruttura rilevata | {', '.join(stack.infra_type[:8])} |")
        lines.append(f"| File analizzati | {total_files:,} |")
        lines.append(f"| Righe di codice | {total_loc:,} |")
        lines.append(f"| File di test | {test_files:,} |")
        if result.metadata.project_type:
            conf = result.metadata.project_type_confidence
            lines.append(f"| Tipo progetto | {result.metadata.project_type}" + (f" (confidence {conf:.0%})" if conf is not None else "") + " |")

        git = result.git_summary
        if git is not None and git.available:
            age_days = (self._now - git.first_commit).days if git.first_commit else None
            last_days = (self._now - git.last_commit).days if git.last_commit else None
            lines.append(f"| Commit totali | {git.total_commits:,}" + (" (storico troncato)" if git.is_shallow else "") + " |")
            if git.first_commit:
                lines.append(f"| Primo commit | {git.first_commit.date().isoformat()}" + (f" ({age_days} giorni fa)" if age_days is not None else "") + " |")
            if git.last_commit:
                lines.append(f"| Ultimo commit | {git.last_commit.date().isoformat()}" + (f" ({last_days} giorni fa)" if last_days is not None else "") + " |")
            lines.append(f"| Commit ultimi 90 / 180 / 365 giorni | {git.commits_90d} / {git.commits_180d} / {git.commits_365d} |")
            lines.append(f"| Autori distinti (totale / ultimi 12 mesi) | {git.authors_total} / {git.authors_365d} |")
            lines.append(f"| Quota commit del primo autore (12 mesi) | {git.top_author_share_365d:.0%} |")
            lines.append(f"| Tag di release | {git.tags_total} |")
            if git.ai_coauthored_commits:
                lines.append(f"| Commit con co-autore AI dichiarato | {git.ai_coauthored_commits} ({git.ai_coauthored_commits / max(git.total_commits, 1):.0%}) |")

        if result.dependency_licenses:
            by_cat: dict[str, int] = {}
            for dl in result.dependency_licenses:
                by_cat[dl.get("category", "unknown")] = by_cat.get(dl.get("category", "unknown"), 0) + 1
            lines.append(
                f"| Dipendenze dichiarate | {len(result.dependency_licenses)} "
                f"(permissive {by_cat.get('permissive', 0)}, copyleft forte {by_cat.get('strong_copyleft', 0)}, "
                f"copyleft debole {by_cat.get('weak_copyleft', 0)}, commerciali/non std {by_cat.get('nonstandard', 0)}, "
                f"ignote {by_cat.get('unknown', 0)}) |"
            )
        lines.append("")

        if git is not None and git.available and git.commits_by_month:
            lines.append("**Attivita ultimi 12 mesi (commit per mese):**")
            lines.append("")
            lines.append("| " + " | ".join(git.commits_by_month.keys()) + " |")
            lines.append("|" + "---|" * len(git.commits_by_month))
            lines.append("| " + " | ".join(str(v) for v in git.commits_by_month.values()) + " |")
            lines.append("")
        return "\n".join(lines)

    def _flags(self, findings: list[Finding], severities: tuple[Severity, ...], title: str, empty: str) -> str:
        section_no = "4" if Severity.CRITICAL in severities else "5"
        lines = [f"## {section_no}. {title}", ""]
        flagged = [f for f in findings if f.severity in severities]
        if not flagged:
            lines.append(empty)
            lines.append("")
            return "\n".join(lines)
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2}
        # A parita di severita, prima i finding con probabilita di sfruttamento (EPSS) piu alta
        flagged.sort(key=lambda f: (
            order.get(f.severity, 9),
            -float((f.extra.get("epss") or {}).get("max_epss", -1.0)),
            f.layer.value,
        ))
        for f in flagged:
            lines.append(f"### [{_sev_tag(f.severity)}] {f.title}")
            lines.append("")
            lines.append(f"`{f.rule_id}` · layer {LAYER_NAMES.get(f.layer.value, f.layer.value)} · confidence {f.confidence:.0%}"
                         + (f" · {f.framework_ref}" if f.framework_ref else ""))
            lines.append("")
            epss = f.extra.get("epss") if f.extra else None
            if epss:
                lines.append(
                    f"**Probabilita di sfruttamento (FIRST EPSS, {epss.get('date', 'n/d')}):** "
                    f"CVE piu esposta {epss.get('max_cve')} al {float(epss.get('max_epss', 0)):.0%} "
                    f"({float(epss.get('max_percentile', 0)):.0%} percentile), "
                    f"{epss.get('scored_cves', 0)} CVE con punteggio. Dato informativo, non pesa sullo score."
                )
                lines.append("")
            lines.append(f.description.strip())
            lines.append("")
            kb = self._kb.get(f.rule_id) if self._kb else None
            if kb:
                lines.append(f"**Rischio per l'acquirente:** {kb.risk_business.strip()}")
                lines.append("")
                lines.append(f"**Effort stimato di remediation:** {kb.effort_range.min_hours}-{kb.effort_range.max_hours} ore ({kb.effort_range.t_shirt})")
                lines.append("")
        return "\n".join(lines)

    def _triage(self, result: AuditResult) -> str:
        if not result.triage:
            return ""
        labels = {"confirmed": "Confermato", "downgraded": "Declassato", "dismissed": "Scartato"}
        lines = ["## 5.1 Revisione del consulente", ""]
        counts = {k: sum(1 for d in result.triage if d.verdict.value == k) for k in labels}
        lines.append(
            f"{len(result.triage)} finding rivisti a mano: {counts['confirmed']} confermati, "
            f"{counts['downgraded']} declassati, {counts['dismissed']} scartati. "
            "Le decisioni non modificano lo score: indicano quali finding il revisore ritiene rilevanti "
            "per questa operazione."
        )
        lines.append("")
        lines.append("| Regola | Severita | Decisione | Nota |")
        lines.append("|--------|----------|-----------|------|")
        for d in result.triage:
            lines.append(f"| {d.rule_id} | {d.severity} | {labels.get(d.verdict.value, d.verdict.value)} | {(d.note or '').replace('|', '/')} |")
        lines.append("")
        return "\n".join(lines)

    def _claims(self, findings: list[Finding]) -> str:
        lines = ["## 6. Dichiarazioni vs evidenze", ""]
        claim_findings = [f for f in findings if f.rule_id in ("PROV-CLAIMS-001", "PROV-CERT-INFO", "TEAM-AIGEN-INFO", "PROV-LICENSE-INFO")]
        if not claim_findings:
            lines.append("Nessuna dichiarazione del README da riscontrare, oppure il layer Provenienza non e attivo.")
            lines.append("")
            return "\n".join(lines)
        for f in claim_findings:
            lines.append(f"- **{f.title}** (`{f.rule_id}`)")
            lines.append("")
            lines.append("  " + f.description.strip().replace("\n", "\n  "))
            lines.append("")
        return "\n".join(lines)

    def _remediation_cost(self, findings: list[Finding]) -> str:
        lines = ["## 7. Costo stimato di remediation", ""]
        if not self._kb:
            lines.append("Knowledge base di remediation non caricata.")
            lines.append("")
            return "\n".join(lines)
        rows: list[tuple[str, str, int, int, int]] = []
        min_total = max_total = 0
        for rule_id in sorted(self._triggered(findings)):
            kb = self._kb.get(rule_id)
            if not kb:
                continue
            rows.append((rule_id, kb.effort_range.t_shirt, kb.effort_range.min_hours, kb.effort_range.max_hours, kb.priority_tier))
            min_total += kb.effort_range.min_hours
            max_total += kb.effort_range.max_hours
        if not rows:
            lines.append("Nessuna regola con stima di effort e scattata.")
            lines.append("")
            return "\n".join(lines)
        rows.sort(key=lambda r: (r[4], -r[3]))
        lines.append("| Regola | Priorita | Taglia | Ore min | Ore max |")
        lines.append("|--------|----------|--------|---------|---------|")
        for rule_id, tee, mn, mx, tier in rows:
            lines.append(f"| {rule_id} | {tier} | {tee} | {mn} | {mx} |")
        lines.append(f"| **Totale** | | | **{min_total}** | **{max_total}** |")
        lines.append("")
        lines.append(
            f"Stima complessiva: **{min_total}-{max_total} ore** di lavoro tecnico per chiudere tutti i finding "
            "con una voce in knowledge base. Le ore non includono attivita legali (licenze, cessioni) "
            "ne la verifica delle dichiarazioni in data room. Priorita 1 = prima del closing."
        )
        lines.append("")
        return "\n".join(lines)

    def _management_questions(self, findings: list[Finding]) -> str:
        lines = ["## 8. Domande per il management", ""]
        rule_ids = {f.rule_id for f in findings}
        questions = [(rid, q) for rid, q in MANAGEMENT_QUESTIONS.items() if rid in rule_ids]
        if not questions:
            lines.append("Nessuna domanda generata dai finding.")
            lines.append("")
            return "\n".join(lines)
        for idx, (rid, q) in enumerate(questions, 1):
            lines.append(f"{idx}. {q} *(`{rid}`)*")
        lines.append("")
        return "\n".join(lines)

    def _compliance(self, result: AuditResult) -> str:
        results = result.health_score.compliance_results
        if not results:
            return ""
        lines = ["## 9. Compliance", ""]
        for cr in results:
            lines.append(f"**{cr.profile_name}:** {cr.checks_satisfied}/{cr.checks_total} controlli soddisfatti, "
                         f"{cr.checks_partial} parziali, {cr.checks_not_satisfied} non soddisfatti.")
            lines.append("")
            failed = [d for d in cr.details if d.get("status") in ("failed", "partial")]
            if failed:
                lines.append("| Controllo | Riferimento | Stato | Regole scattate |")
                lines.append("|-----------|-------------|-------|-----------------|")
                for d in failed:
                    lines.append(f"| {d.get('title', '')} | {d.get('article_ref', '')} | {d.get('status', '')} | {', '.join(d.get('triggered_rules', []))} |")
                lines.append("")
        return "\n".join(lines)

    def _score_details(self, result: AuditResult) -> str:
        hs = result.health_score
        lines = ["## 10. Score per layer ed evidence chain", ""]
        lines.append("| Layer | Score | Confidence | Finding |")
        lines.append("|-------|-------|------------|---------|")
        for layer_name in LAYER_ORDER:
            if layer_name not in hs.layer_scores:
                continue
            ls = hs.layer_scores[layer_name]
            non_info = len([f for f in ls.findings if f.severity != Severity.INFO])
            lines.append(f"| {LAYER_NAMES.get(layer_name, layer_name)} | {ls.score:.0f}/100 | {ls.confidence:.0%} | {non_info} |")
        lines.append("")
        lines.append("| Rule ID | Layer | Weight | Penalty | Framework |")
        lines.append("|---------|-------|--------|---------|-----------|")
        for layer_name in LAYER_ORDER:
            if layer_name not in hs.layer_scores:
                continue
            for ev in hs.layer_scores[layer_name].evidence_chain:
                if ev.weight == 0 and ev.penalty == 0:
                    continue
                lines.append(f"| {ev.rule_id} | {LAYER_NAMES.get(layer_name, layer_name)} | {ev.weight:.2f} | {ev.penalty:.1f} | {ev.framework_ref or '-'} |")
        lines.append("")
        return "\n".join(lines)

    def _footer(self, result: AuditResult) -> str:
        meta = result.metadata
        return (
            "---\n\n"
            f"*Report di due diligence generato da CTO Audit Agent v{meta.tool_version} il "
            f"{meta.timestamp.strftime('%Y-%m-%d %H:%M')}. Analisi statica: il codice non e stato eseguito. "
            "Le stime di effort provengono dalla knowledge base e vanno validate sul contesto.*\n"
        )
