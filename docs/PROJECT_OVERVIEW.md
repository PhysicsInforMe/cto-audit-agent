# CTO Audit Agent — Project Overview

> Executive summary per stakeholder, investitori e decision-maker.

---

## Il Problema

Quando un fractional CTO o Head of Engineering entra in un'azienda, servono **4 settimane** per produrre un assessment iniziale: leggere codice, navigare repository, capire l'infrastruttura, mappare i rischi. Nessun tool esistente offre una visione CTO-centric: SonarQube e CodeClimate analizzano il codice riga per riga (prospettiva developer), Snyk si concentra sulle vulnerabilita delle dipendenze, e nessuno di questi produce un report esecutivo con scoring tracciabile, verifica di compliance normativa e piano d'azione prioritizzato.

## La Soluzione

**CTO Audit Agent** analizza una codebase come farebbe un CTO esperto al primo giorno: parte dall'infrastruttura, risale all'architettura, poi sicurezza, poi qualita del codice. In **3 ore** (anziche 4 settimane) produce un report strutturato con scoring tracciabile fino alla letteratura scientifica, gap di compliance (NIS2, GDPR), e roadmap di remediation con stime di effort.

Tutto funziona offline, senza server da configurare, con un gate di privacy Human-in-the-Loop che garantisce che nessun dato sensibile lasci la macchina del cliente senza consenso esplicito.

Ogni audit viene salvato automaticamente e al run successivo il tool mostra il delta: cosa e migliorato, cosa persiste, cosa e peggiorato. L'accesso alla rete per il check CVE e una scelta informata dell'utente, non un flag binario.

---

## Target Market e Use Case

| Segmento | Use Case | Valore |
|----------|----------|--------|
| **Fractional CTO / Consulenti tecnici** | Assessment rapido al primo ingresso in azienda | Da 4 settimane a 3 ore |
| **Venture Capital / PE** | Due diligence tecnica pre-investimento | Profilo `vc-diligence` dedicato |
| **PMI senza CTO full-time** | Autodiagnostica della maturita tecnica | Self-service, nessun esperto richiesto |
| **Compliance Officer** | Verifica NIS2/GDPR sulla codebase | Profili compliance integrati |
| **Team Lead / Engineering Manager** | Monitoraggio tech debt e rischio operativo | Report periodici con confronto |

---

## Differenziatori Competitivi

| Aspetto | SonarQube / CodeClimate | Snyk | CTO Audit Agent |
|---------|------------------------|------|-----------------|
| **Prospettiva** | Developer (bug, smell) | Security (CVE) | CTO/Executive (rischio business) |
| **Scoring** | Proprietario, opaco | Severity CVE | Tracciabile, literature-backed |
| **Compliance** | Nessuna | Parziale (license) | NIS2, GDPR integrati |
| **Report** | Per developer | Per developer | Per board, CTO, investitori |
| **Remediation** | "Fix this line" | "Update this dep" | Piano d'azione + rischio business + effort |
| **Privacy** | Invia tutto al server | Cloud-only | HITL gate, 4 livelli privacy |
| **Setup** | Server da configurare | SaaS cloud | `pip install && scan` |
| **Costo** | $150-450/mese (team) | $98-498/mese | Open source / self-hosted |
| **Context-awareness** | Nessuna | Nessuna | Project type detection + confidence score |

### Posizionamento

CTO Audit Agent non e un linter ne uno scanner di vulnerabilita. E un **auditor tecnico automatizzato** che pensa come un CTO: valuta infrastruttura, architettura, sicurezza e qualita come layer interdipendenti, pesati per conseguenza business, non per frequenza di occorrenza.

---

## Value Proposition per Stakeholder

### Per il CTO / Consulente Tecnico
- **3x piu veloce** nell'assessment iniziale
- Scoring difendibile con catena di evidenze (finding → regola → peso → fonte)
- Report pronto per il board senza riscrittura manuale

### Per il Venture Capital / Investitore
- Profilo `vc-diligence` con pesi ottimizzati per due diligence
- Rischio security enfatizzato (un breach pre-investimento e deal-breaker)
- Compliance NIS2/GDPR verificata automaticamente

### Per il Compliance Officer
- Mapping automatico regole → articoli normativi (NIS2 Art.21, GDPR Art.32)
- 3 modalita operative: cross-cutting, standalone, hybrid
- Report di compliance separato con status per controllo

---

## Metriche Chiave

| Metrica | Valore |
|---------|--------|
| **Test automatizzati** | 733 test (31 file) |
| **Repository validate** | 29 (20 reali + 9 sintetiche) |
| **Precision/Recall sintetico** | 100% / 100% su 9 scenari |
| **Score medio su 20 repo reali** | 78.3/100 (range: 56-94) |
| **Linguaggi supportati** | 13+ (Python, JS/TS, Java, Go, Rust, Ruby, PHP, C#, C/C++, Kotlin, Swift, Scala, Elixir) |
| **Regole di analisi** | 36 (10 infra + 7 architettura + 9 security + 10 quality) |
| **Regole di scoring** | 43 (37 penalizzanti + 6 informative) |
| **Knowledge Base remediation** | 37 entry con effort, rischio business, step per linguaggio |
| **Profili di scoring** | 2 (default, vc-diligence) |
| **Profili di compliance** | 2 (NIS2, GDPR) |
| **Tempo di scansione** | 0.1s - 19s (dipende dalla dimensione repo) |
| **Storico audit** | Delta automatico tra run, salvato in `.cto-audit/history/` |

---

## Modello di Business (Potenziale)

### Open Core
- **Core open source**: CLI, 4 analyzer, scoring engine, 2 profili
- **Premium**: profili compliance aggiuntivi (AI Act, SOC2, PCI-DSS), report PDF professionale, integrazione CI/CD, dashboard storica

### Consulting Amplificato
- Il tool genera il report, il consulente aggiunge l'interpretazione esperta
- "Il mio tool ha trovato 12 problemi e 5 violazioni NIS2 — ecco il piano d'azione"

### SaaS (futuro)
- Scansione periodica con trend analysis
- Multi-repo dashboard
- Team management e alerting

---

## Roadmap Sintetica

| Fase | Focus | Stato |
|------|-------|-------|
| **Fase 1** — MVP | CLI, 4 analyzer, scoring, compliance NIS2/GDPR, remediation pipeline, storico audit, consenso rete | Completata |
| **Fase 2** — Deep Analysis | Profili OWASP Top 10, NIST CSF, tree-sitter AST, cross-layer correlation | In corso |
| **Fase 3** — Multi-Source | GitRemoteSource, MultiSource, report PDF, GitHub Action, Ollama | Pianificata |
| **Fase 4** — Intelligence | Trend analysis avanzata, custom rules, MCP server | Pianificata |
| **Fase 5** — Enterprise | Compliance aggiuntivi, multi-repo, i18n, container/API security | Pianificata |

> Roadmap dettagliata con patent safety e mapping open core: [ROADMAP.md](ROADMAP.md)

---

## Stack Tecnico

- **Linguaggio**: Python 3.11+
- **CLI**: Typer + Rich
- **Modelli dati**: Pydantic v2
- **Scoring/Compliance**: YAML-driven (zero codice per nuovi profili)
- **LLM**: Ollama (opzionale, graceful degradation)
- **NLP**: TF-IDF (stdlib) + Sentence-BERT opzionale per project type detection
- **Report**: Terminal, Markdown, HTML, JSON, PDF (con confidence score per layer)
- **Test**: pytest (733 test, 31 file)

---

## Patent Risk

**BASSO**. Analisi dettagliata in [PATENT_ANALYSIS.md](PATENT_ANALYSIS.md).

Il tool si differenzia dai brevetti esistenti (US10275600B2 e simili) per:
- Approccio CTO-centric vs developer-centric
- Scoring literature-backed vs proprietary
- Privacy HITL gate (unico nel settore)
- Compliance normativa integrata (NIS2, GDPR)
- Architettura plugin (profili YAML, zero codice)

---

## Documenti Correlati

Per una guida di lettura top-down di tutta la documentazione, vedi [READING_ORDER.md](READING_ORDER.md).
