# CTO Audit Agent — Development Roadmap

> Roadmap dettagliata con annotazioni patent safety e mapping open core.
> Per l'overview del progetto vedi [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md).

---

## Principi Guida

Ogni feature futura rispetta questi vincoli architetturali:

1. **Static analysis only** — non eseguiamo mai il codice del target
2. **Deterministic scoring** — formula trasparente `max(0, 100 - sum(penalty * weight))`, zero LLM nel core
3. **Offline-first** — nessuna dipendenza da servizi cloud o API esterne nel core
4. **Any codebase** — nessuna restrizione a settore o linguaggio specifico
5. **Rule-based compliance** — mapping deterministico finding → controllo normativo, zero NLP

### Confini Patent Espliciti: cosa NON faremo MAI

Per mantenere massima distanza dal patent US Provisional (vedi [PATENT_ANALYSIS.md](PATENT_ANALYSIS.md)):

- **NO** Market/Financial Agent (analisi team, funding, competitors da fonti esterne)
- **NO** Legal Document NLP (parsing NLP di documenti legali)
- **NO** Sandboxed Code Execution (esecuzione codice in container)
- **NO** Adversarial Testing (FGSM, model inversion, bias audit)
- **NO** Probabilistic Ratings (rating A-F con confidence score e LLM fusion)
- **NO** AI Washing Detection, Certification Labels
- **NO** External API Integration (Salesforce, Tableau, Crunchbase)

---

## Fase 1 — MVP (COMPLETATA)

**Obiettivo**: CLI funzionante con analisi su 4 layer, scoring tracciabile, compliance NIS2/GDPR.

| Componente | Dettaglio |
|------------|-----------|
| Regole di analisi | 36 (10 infra + 7 architettura + 9 security + 10 quality) |
| Test automatizzati | 932 test su 52 file |
| Repository validate | 29 (20 reali + 9 sintetiche) |
| Precision/Recall | 100% / 100% su scenari sintetici |
| Score medio | 78.3/100 (range: 56-94) su 20 repo reali |
| Profili di scoring | 2 (default, vc-diligence) |
| Profili compliance | 2 (NIS2, GDPR) |
| Report | Terminal, Markdown, HTML, JSON, PDF, Board Report |
| Remediation KB | 37 entry con effort, rischio business, step per linguaggio |
| What-If Simulator | Calcolo impatto remediation su score |
| Privacy | HITL gate con 4 livelli, classificazione file automatica |
| Storico Audit | Salvataggio automatico in `.cto-audit/history/`, delta tra audit, visualizzazione in tutti i reporter |
| Consenso Rete | Pannello trasparente pre-CVE check, scelta informata HITL |
| Project Type Detection | Auto-rilevamento tipo progetto (rule-based + TF-IDF + BERT opzionale) |
| Confidence Score | Confidence per layer basata su coverage regole e tipo progetto |

---

## Fase 2 — Deep Analysis (Q2-Q3 2026)

**Obiettivo**: analisi piu profonda con AST, copertura OWASP completa, nuovo framework compliance.

### 2.1 OWASP Top 10 — Copertura Completa
- 15+ nuove regole security mappate a OWASP Top 10 2021
- SQL Injection pattern (A03), XSS sink detection (A03), SSRF pattern (A10)
- Hardcoded secrets avanzato (regex per JWT, API key, connection string)
- Insecure deserialization (A08), broken access control pattern (A01)
- **Patent safety**: prior art — OWASP fondato 2001, Top 10 dal 2003, SonarQube dal 2007

### 2.2 tree-sitter AST Analysis
- Cyclomatic complexity profonda (oltre heuristica lineare attuale)
- Dead code detection (funzioni non chiamate, import non usati)
- Call graph statico (profondita catena di chiamate)
- Anti-pattern detection (god class, feature envy, long parameter list)
- **Patent safety**: static analysis pura — McCabe 1976, Halstead 1977, nessuna esecuzione

### 2.3 NIST CSF Compliance Profile
- Nuovo file `compliance-profiles/nist-csf.yml`
- Mapping regole esistenti + nuove a NIST CSF v2.0 (Govern, Identify, Protect, Detect, Respond, Recover)
- Stesso engine rule-based dei profili NIS2/GDPR
- **Patent safety**: rule-based mapping deterministico, zero NLP — NIST CSF e prior art (2014)

### 2.4 Cross-Layer Correlation
- Finding security che impatta score architettura (es. SQL injection in monolite = rischio amplificato)
- Formula matematica: `correlation_penalty = base_penalty * exposure_factor`
- Exposure factor calcolato da metriche statiche (LOC, coupling, layer score)
- **Patent safety**: formula matematica trasparente, non LLM fusion — CVSS environmental score (2005)

---

## Fase 2.5 — Due Diligence (COMPLETATA, ottobre 2026)

**Obiettivo**: usare il tool per conto di un terzo (investitore, acquirente, partner) che deve capire cosa compra.

| Componente | Dettaglio |
|------------|-----------|
| Layer Provenance (IP & licenze) | 8 regole + 2 info: licenza/copyright, dipendenze copyleft e commerciali, codice vendorizzato, copyright di terzi, claims del README, certificazioni dichiarate, SBOM |
| Layer Team (continuita) | 7 regole + 2 info: bus factor, inattivita, storico compresso, storico minimo, tag, messaggi di commit, commit co-firmati da AI |
| GitHistoryCollector | Solo metadati git aggregati, nessun nome ne email nel risultato |
| LicenseChecker | KB offline verificata sui registri + lookup PyPI/npm dietro consenso rete |
| Profilo `due-diligence` | 6 layer, pesi per conseguenza sul deal |
| Report di due diligence | Deal flag, inventario asset, red/yellow flag, claims vs evidenze, costo di remediation, domande per il management |
| Bug fix | `.gitignore` con pattern annidati e ancorati in `LocalRepoSource` |

**Patent safety**: il layer Team legge solo lo storico git del repository analizzato (metadati locali, prior art: `git log`), nessuna fonte esterna su team, funding o mercato, quindi resta fuori dal confine "Market/Financial Agent". Il bus factor applica una metrica pubblicata (Avelino et al., ICPC 2016). Il check licenze e deterministico (classificazione per stringa SPDX, prior art: license scanner). Nessun LLM nel core.

---

## Fase 3 — Multi-Source & Ecosystem (Q3-Q4 2026)

**Obiettivo**: fonti multiple, report professionali, integrazioni CI/CD.

### 3.1 Source Connectors (COMPLETATO)
- ~~`cto-audit scan --git https://github.com/org/repo`~~ → Implementato con auto-detection URL
- `cto-audit scan https://github.com/owner/repo` — GitHub, GitLab, Azure DevOps, Bitbucket, Archive
- `--source-type`, `--token` (env var `CTO_AUDIT_TOKEN`), `--branch`
- Clone shallow in temp dir, context manager per cleanup automatico
- 6 connettori: `GitHubSource`, `GitLabSource`, `AzureDevOpsSource`, `BitbucketSource`, `ArchiveSource` + `SourceFactory`
- **Patent safety**: git clone e prior art universale, nessun sandbox

### 3.2 PDF Report Professionale
- Cover page con branding, indice, chart score (radar/bar)
- Executive summary, finding dettagliati, compliance, evidence chain
- WeasyPrint (gia in deps) con CSS professionale
- **Patent safety**: generazione report e prior art — ogni tool di analisi genera report

### 3.3 CI/CD Integrations (Consumer-Side)
- GitHub Action: `uses: cto-audit/scan@v1` nel workflow del consumatore
- GitLab CI: template `.gitlab-ci.yml` pronto
- Jenkins: Jenkinsfile template
- Output JSON parsabile per quality gate (exit code non-zero se score < soglia)
- **Patent safety**: CI/CD integration e prior art — SonarQube Scanner dal 2007, ogni linter ha CI integration

### 3.4 Ollama Enhancement
- Structured prompt per executive summary piu accurato
- Delta audit: confronto due scan in linguaggio naturale
- Sempre opzionale, graceful degradation se Ollama non disponibile
- **Patent safety**: LLM opzionale per presentazione, non nel core scoring

---

## Fase 4 — Intelligence & Customization (Q1-Q2 2027)

**Obiettivo**: storico, personalizzazione, integrazioni IDE.

### 4.1 Audit History & Trend (Parzialmente implementato in Fase 1)
- ~~Database SQLite locale (zero cloud) per storico scan~~ → Implementato con JSON files (SQLite eventualmente in futuro)
- ~~`cto-audit history` — tabella con score nel tempo~~ → Delta automatico al run successivo
- `cto-audit diff` — confronto due audit con delta per regola
- Grafici trend in report HTML/PDF
- **Patent safety**: database locale per storico — git log, SonarQube history sono prior art dal 2007

### 4.2 Custom Rules Engine
- Regole YAML user-defined: pattern, severita, layer, peso
- Esempio: `{id: CUSTOM-001, pattern: "eval(", severity: high, layer: security}`
- Validazione schema con Pydantic, zero ML
- **Patent safety**: regole user-authored in YAML, non ML-generated — ESLint custom rules dal 2013

### 4.3 MCP Server
- Model Context Protocol per IDE AI (Cursor, Windsurf, Claude Code)
- Espone scan, score, finding come tool MCP
- IDE puo chiedere "analizza questo file" o "score corrente del progetto"
- **Patent safety**: IDE integration protocollo aperto — LSP dal 2016, MCP e standard Anthropic

### 4.4 Industry-Specific Scoring Profiles
- `scoring-profiles/fintech.yml` — pesi security elevati, compliance PCI-DSS ready
- `scoring-profiles/healthtech.yml` — privacy, audit trail, HIPAA ready
- `scoring-profiles/govtech.yml` — compliance stringente, documentazione
- Stesso engine YAML-driven, zero codice aggiuntivo
- **Patent safety**: profili YAML configurabili — prior art: SonarQube quality profiles dal 2007

---

## Fase 5 — Enterprise & Scale (Q3 2027+)

**Obiettivo**: compliance enterprise, multi-repo, internazionalizzazione.

### 5.1 Compliance Frameworks Aggiuntivi
- AI Act (EU): mapping articoli rilevanti per sistemi AI
- SOC2: Trust Services Criteria (security, availability, processing integrity)
- PCI-DSS: requisiti tecnici per payment processing
- ISO 27001: controlli Annex A mappati a regole
- HIPAA: requisiti tecnici per dati sanitari
- **Patent safety**: rule-based mapping deterministico per ogni framework — compliance tools sono prior art

### 5.2 Multi-Repo Dashboard (COMPLETATO)
- ~~`cto-audit dashboard --repos repo1/ repo2/ repo3/`~~ → Implementato come Dashboard Dash + `cto-audit project config.yml`
- Dashboard interattiva con Dash + Plotly, tema dark "intelligence style"
- `cto-audit ui` per avvio dashboard, `cto-audit project config.yml` per audit multi-repo
- Multi-source aggregation: media pesata per LOC su N repository
- 8 componenti: overview, layers, findings, remediation, compliance, history, source picker, project view
- Agent mode: `cto-audit agent /path -o report.json` per output JSON headless
- Eseguibile standalone: PyInstaller .exe con `sys._MEIPASS` frozen mode
- Container Docker: `Dockerfile` + `docker-compose.yml`
- **Patent safety**: dashboard locale, non SaaS — prior art: SonarQube dashboard locale

### 5.3 Report Internationalization
- Lingue: EN, IT, DE, FR, ES
- File di traduzione YAML per label, descrizioni, remediation
- Selezione lingua via `--lang en`
- **Patent safety**: i18n e prior art universale in software

### 5.4 Container Security Rules
- 20+ regole per Dockerfile best practices
- Kubernetes manifest validation (resource limits, security context, network policies)
- Docker Compose security (no privileged, no host network)
- **Patent safety**: Dockerfile linting e prior art — hadolint (2016), Checkov (2019)

### 5.5 API Security Rules
- OpenAPI spec validation (schema completeness, auth definition)
- Rate limiting configuration detection
- Input validation pattern detection
- CORS misconfiguration detection
- **Patent safety**: API security analysis e prior art — OWASP API Security Top 10 (2019)

---

## LLM Value Map

Il principio: **l'LLM trasforma dati strutturati in narrativa**. L'analisi la fanno le regole deterministiche. L'LLM comunica i risultati a lettori non tecnici.

| Use Case | Input (strutturato) | Output LLM | Valore | Stato |
|----------|---------------------|------------|--------|-------|
| Executive Summary | Score + findings + context | 3-5 righe per board | ALTO | Implementato (Fase 1) |
| Risk Narrative | Top findings + KB risks | Bullet list rischi business | ALTO | Implementato (Fase 1) |
| Delta Narrative | Nuovi/risolti/persistenti + giorni | Evoluzione del progetto in linguaggio naturale | ALTO | Implementato (Fase 1) |
| Finding Explanation | Finding + stack + KB entry | Spiegazione contestualizzata per progetto | MEDIO | Roadmap Fase 2 |
| Remediation Priority | What-if + effort + context | Raccomandazioni prioritizzate | MEDIO | Roadmap Fase 2 |
| Compliance Gap | Control FAIL + testo normativa | Spiegazione gap normativo | BASSO | Roadmap Fase 3 |

---

## Matrice Patent Safety

Riepilogo della distanza dal patent per ogni feature pianificata.

| Feature | Approccio | Distanza dal Patent | Prior Art |
|---------|-----------|-------------------|-----------|
| OWASP Top 10 rules | Pattern matching statico su AST/testo | **MASSIMA** — prior art | OWASP 2003, SonarQube 2007 |
| tree-sitter AST | Analisi statica, no execution | **MASSIMA** — prior art | McCabe 1976, Halstead 1977 |
| NIST CSF profile | Rule-based mapping YAML | **MASSIMA** — prior art | NIST CSF 2014 |
| Cross-layer correlation | Formula matematica deterministica | **ALTA** — no LLM fusion | CVSS environmental score 2005 |
| Source Connectors | git clone + scan statico, 6 provider | **MASSIMA** — prior art | Git 2005 |
| Multi-Source | Aggregazione LOC-weighted, YAML config | **MASSIMA** — prior art | SonarQube multi-project |
| Dashboard UI | Dash + Plotly locale, zero cloud | **MASSIMA** — prior art | SonarQube dashboard 2007 |
| Agent Mode | JSON headless output | **MASSIMA** — prior art | CLI tool output |
| Executable | PyInstaller, frozen mode | **MASSIMA** — prior art | PyInstaller 2005 |
| Container | Dockerfile, docker-compose | **MASSIMA** — prior art | Docker 2013 |
| PDF report | HTML → PDF con WeasyPrint | **MASSIMA** — prior art | Ogni tool genera report |
| CI/CD integrations | GitHub Action/GitLab CI template | **MASSIMA** — prior art | SonarQube Scanner 2007 |
| Ollama enhancement | LLM opzionale, non nel core | **ALTA** — graceful degradation | ChatGPT API 2023 |
| Audit history | JSON file locale, zero cloud | **MASSIMA** — prior art | SonarQube history 2007 |
| Network consent | HITL gate pre-network, consenso informato | **MASSIMA** — prior art | Privacy HITL e prior art |
| Delta narrative | LLM opzionale su dati strutturati | **ALTA** — graceful degradation | ChatGPT API 2023 |
| Custom rules | YAML user-defined, zero ML | **MASSIMA** — prior art | ESLint custom rules 2013 |
| MCP server | Protocollo IDE aperto | **MASSIMA** — prior art | LSP 2016, MCP 2024 |
| Industry profiles | YAML scoring configurabile | **MASSIMA** — prior art | SonarQube quality profiles 2007 |
| Compliance aggiuntivi | Rule-based mapping per framework | **MASSIMA** — prior art | Compliance tools pre-2020 |
| Multi-repo dashboard | Dash + Plotly locale, zero SaaS | **ALTA** — no cloud dashboard | SonarQube multi-project |
| i18n | File traduzione YAML | **MASSIMA** — prior art | Universale |
| Container rules | Dockerfile/K8s linting | **MASSIMA** — prior art | hadolint 2016, Checkov 2019 |
| API security | OpenAPI validation, OWASP API | **MASSIMA** — prior art | OWASP API Top 10 2019 |

---

## Mapping Open Core

Strategia di monetizzazione: core open source + feature premium.

### Core Open Source (Gratuito)

| Componente | Fase |
|------------|------|
| CLI completa (`cto-audit scan`) | 1 (completata) |
| 4 analyzer (infra, architecture, security, quality) | 1 (completata) |
| Scoring engine deterministico | 1 (completata) |
| Profilo default | 1 (completata) |
| Report Terminal, Markdown, JSON | 1 (completata) |
| Remediation KB (37 entry) | 1 (completata) |
| OWASP Top 10 regole | 2 |
| tree-sitter AST analysis | 2 |
| Source Connectors (GitHub, GitLab, Azure, Bitbucket, Archive) | 3 (completata) |
| Multi-Source Aggregation (project YAML) | 3 (completata) |
| Dashboard UI (Dash + Plotly) | 3 (completata) |
| Agent Mode (JSON headless) | 3 (completata) |
| Container Docker (Dockerfile, docker-compose) | 3 (completata) |
| Eseguibile standalone (PyInstaller) | 3 (completata) |
| CI/CD templates (GitHub Action, GitLab CI) | 3 |
| Custom rules engine | 4 |
| Container security rules | 5 |
| API security rules | 5 |

### Premium (License)

| Componente | Fase | Target |
|------------|------|--------|
| Profilo `vc-diligence` | 1 (completata) | VC/PE |
| Compliance NIS2, GDPR | 1 (completata) | Compliance Officer |
| Report HTML, PDF, Board Report | 1 (completata) | CTO, Board |
| What-If Simulator | 1 (completata) | Consulenti |
| NIST CSF compliance | 2 | Enterprise |
| Cross-layer correlation | 2 | CTO senior |
| PDF report professionale (chart, branding) | 3 | Enterprise |
| Ollama enhancement | 3 | Power user |
| Audit history & trend | 1 (completata parzialmente) | Enterprise |
| MCP server (IDE integration) | 4 | Developer |
| Industry-specific profiles (fintech, healthtech, govtech) | 4 | Verticali |
| AI Act, SOC2, PCI-DSS, ISO 27001, HIPAA | 5 | Enterprise |
| Multi-repo dashboard | 3 (completata) | Enterprise |
| Report i18n (EN, IT, DE, FR, ES) | 5 | Internazionale |

---

## Timeline Visuale

```
2026 Q2    2026 Q3    2026 Q4    2027 Q1    2027 Q2    2027 Q3+
  |          |          |          |          |          |
  ├── Fase 2 ──────────┤          |          |          |
  |  OWASP, AST,       |          |          |          |
  |  NIST CSF,          |          |          |          |
  |  cross-layer        ├── Fase 3 ──────────┤          |
  |                     |  GitRemote, PDF,   |          |
  |                     |  CI/CD, Ollama     |          |
  |                     |                    ├── Fase 4 ──────────┤
  |                     |                    |  History, custom   |
  |                     |                    |  rules, MCP,       |
  |                     |                    |  industry profiles |
  |                     |                    |                    ├── Fase 5 ──>
  |                     |                    |                    |  Compliance+,
  |                     |                    |                    |  multi-repo,
  |                     |                    |                    |  i18n, container,
  |                     |                    |                    |  API security
```

---

*Ultimo aggiornamento: Ottobre 2026*
*Per l'analisi patent dettagliata vedi [PATENT_ANALYSIS.md](PATENT_ANALYSIS.md)*
