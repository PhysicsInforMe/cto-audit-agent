# CTO Audit Agent — Documentazione Codice
# v9.0 — Dashboard + Source Connectors + Multi-Source + Agent Mode + Executable

Documento aggiornato progressivamente blocco per blocco.
Descrive cosa fa ogni componente, le scelte implementative, e come i pezzi si collegano.

> **Stato**: 932 test, 52 test files, 7 scenari E2E + 3 scenari board report.
> Validato su **29 repo** (20 reali, media 78.3/100 + 9 sintetiche, 100% precision/recall).
> Tutti e 4 gli analyzer implementati: Infra (10), Architecture (7), Security (9), Quality (10).
> Compliance engine implementato (NIS2, GDPR).
> Scoring difendibile con citation (IBM/Ponemon 2025, DORA 2024, Boehm 1981, OWASP).
> 2 scoring profiles: default + vc-diligence. 43 regole scoring (37 penalizzanti + 6 info).
> --detailed flag, context-aware Docker check.
> **Remediation Pipeline**: Knowledge Base YAML (37 entry), What-If Simulator,
> Context Collector, Board Report deterministico, LLM Provider (Ollama via httpx),
> Interpretation Agent con HITL gate. CLI: `--board-report --no-llm --detailed`.
> Graceful degradation: funziona 100% senza LLM.
> **Audit History**: salvataggio automatico in `.cto-audit/history/`, delta tra audit,
> visualizzazione in tutti i reporter. **Network Consent**: pannello HITL pre-CVE check.
> **Delta Narrative**: LLM opzionale per narrativa evoluzione progetto.
> **Source Connectors**: GitHub, GitLab, Azure DevOps, Bitbucket, Archive (ZIP/tar.gz).
> **Multi-Source**: aggregazione score su N repo con media pesata per LOC.
> **Dashboard**: UI dark Dash + Plotly con 8 componenti (overview, layers, findings,
> remediation, compliance, history, source picker, project view).
> **Agent Mode**: output JSON headless per container e CI/CD.
> **Executable**: PyInstaller .exe con supporto `sys._MEIPASS` frozen mode.
> **Due Diligence (Blocco 17)**: layer Provenance e Team, profilo `due-diligence` a 6 layer,
> GitHistoryCollector, LicenseChecker, report lato acquirente. 1.053 test (58 file).

---

## Struttura Progetto

```
cto-audit/
├── pyproject.toml                  # Dipendenze, metadata, entry point CLI
├── scoring-profiles/               # Profili YAML per lo scoring (peso regole)
│   ├── default.yml                 # Profilo CTO bilanciato
│   └── vc-diligence.yml            # Profilo VC due-diligence
├── compliance-profiles/            # Profili YAML per compliance normativa
│   ├── nis2.yml                    # NIS2 Directive mapping
│   └── gdpr.yml                    # GDPR mapping
│
├── src/cto_audit/
│   ├── __init__.py                 # Package root, espone __version__
│   ├── cli.py                      # Entry point CLI (Typer) — Blocco 6
│   │
│   ├── core/                       # Nucleo del sistema
│   │   ├── models.py               # Tutti i modelli Pydantic v2
│   │   ├── config.py               # Configurazione runtime (Pydantic Settings)
│   │   ├── source.py               # Protocol AuditSource — Blocco 2
│   │   └── orchestrator.py         # Coordinamento flusso — Blocco 10
│   │
│   ├── sources/                    # Implementazioni AuditSource
│   │   ├── __init__.py             # Export di tutte le classi
│   │   ├── local.py                # LocalRepoSource (MVP) — Blocco 2
│   │   ├── base.py                 # TempDirSourceMixin — context manager per temp dir
│   │   ├── github.py               # GitHubSource — clone via git, supporto PAT
│   │   ├── gitlab.py               # GitLabSource — cloud e self-hosted
│   │   ├── azure_devops.py         # AzureDevOpsSource — URL format Azure DevOps
│   │   ├── bitbucket.py            # BitbucketSource — cloud e server
│   │   ├── archive.py              # ArchiveSource — ZIP/tar.gz, stdlib only
│   │   └── factory.py              # SourceFactory — auto-detection e routing
│   │
│   ├── collectors/                 # Raccolta dati dal codebase
│   │   ├── scanner.py              # FileScanner — Blocco 3
│   │   ├── stack.py                # StackDetector — Blocco 3
│   │   └── privacy.py              # PrivacyClassifier — Blocco 4
│   │
│   ├── hitl/                       # Human-in-the-Loop
│   │   ├── reviewer.py             # Review interattivo — Blocco 5
│   │   └── persistence.py          # Persistenza classificazione — Blocco 5
│   │
│   ├── analyzers/                  # Analisi per layer
│   │   ├── base.py                 # BaseAnalyzer interface — Blocco 7
│   │   ├── infra.py                # InfraAnalyzer — Blocco 7
│   │   ├── architecture.py         # ArchitectureAnalyzer — Blocco 8
│   │   ├── security.py             # SecurityAnalyzer — 9 check: secrets, SQL injection, XSS, crypto, headers, HTTPS, CORS, auth, CVE
│   │   └── quality.py              # QualityAnalyzer — 10 check: docs, linting, typing, complexity, duplicates, precommit, editorconfig, contributing, changelog
│   │
│   ├── scoring/                    # Scoring engine pluggable
│   │   ├── engine.py               # ScoringEngine — Blocco 9
│   │   ├── profile.py              # Caricamento profili YAML — Blocco 9
│   │   └── models.py               # Modelli scoring — Blocco 9
│   │
│   ├── compliance/                 # Compliance engine modulare [IMPLEMENTATO]
│   │   ├── engine.py               # ComplianceEngine — mapping finding→requisiti normativi
│   │   ├── profile.py              # Caricamento profili YAML (NIS2, GDPR)
│   │   └── models.py               # Modelli compliance (ComplianceResult, RequirementStatus)
│   │
│   ├── remediation/                # Remediation Pipeline [IMPLEMENTATO]
│   │   ├── models.py               # EffortRange, RemediationEntry, WhatIfResult, RemediationPipelineResult
│   │   ├── loader.py               # RemediationLoader — carica KB YAML + stack merging
│   │   ├── simulator.py            # WhatIfSimulator — simula impatto risoluzione regole
│   │   └── context.py              # ContextCollector — inferisce contesto progetto
│   │
│   ├── history/                     # Storico Audit [IMPLEMENTATO]
│   │   ├── __init__.py
│   │   └── storage.py              # AuditHistoryStorage — save/load/delta
│   │
│   ├── llm/                        # Integrazione LLM [IMPLEMENTATO]
│   │   ├── provider.py             # LLMProvider Protocol + LLMConfig + LLMResponse
│   │   ├── local.py                # OllamaProvider — Ollama via httpx /api/generate
│   │   ├── router.py               # LLMRouter — fallback tra provider
│   │   └── agent.py                # InterpretationAgent — genera executive summary
│   │
│   ├── core/
│   │   ├── project.py              # Modelli multi-source (ProjectConfig, AggregatedResult)
│   │   └── project_orchestrator.py # ProjectOrchestrator — audit multi-repo con aggregazione
│   │
│   ├── dashboard/                  # Dashboard UI (Dash + Plotly) [IMPLEMENTATO]
│   │   ├── __init__.py
│   │   ├── app.py                  # Dash app factory, create_app()
│   │   ├── layout.py               # Layout con sidebar navigation + dcc.Store
│   │   ├── theme.py                # Tema CYBORG + CSS dark (#0d1117, accenti neon)
│   │   ├── callbacks.py            # Callback: scan trigger, navigation, filtri
│   │   └── components/
│   │       ├── __init__.py
│   │       ├── overview.py         # Gauge health score, card layer, stack badges
│   │       ├── layers.py           # Tab per layer, findings, evidence chain
│   │       ├── findings.py         # DataTable filtrabile per severity/layer
│   │       ├── remediation.py      # Priority actions, what-if slider
│   │       ├── compliance.py       # Ring chart NIS2/GDPR, progress
│   │       ├── history.py          # Line chart trend, delta finding
│   │       ├── source_picker.py    # Dropdown sorgente, campi condizionali
│   │       └── project_view.py     # Vista multi-repo, score aggregato
│   │
│   ├── _data.py                    # Risoluzione data dir (dev/frozen/installed)
│   ├── exe_entry.py                # Entry point PyInstaller: dashboard + browser
│   │
│   └── reporters/                  # Generazione report
│       ├── terminal.py             # Output Rich — Blocco 10
│       ├── markdown.py             # Report Markdown — Blocco 10
│       ├── board.py                # Board Report deterministico [IMPLEMENTATO]
│       ├── html.py                 # Report HTML self-contained
│       ├── json_export.py          # Report JSON export
│       ├── comparison.py           # Report comparison (planned)
│       └── pdf.py                  # Report PDF (planned)
│
├── Dockerfile                      # Immagine Docker (python:3.12-slim)
├── docker-compose.yml              # Agent + Dashboard services
├── cto-audit.spec                  # PyInstaller spec file
├── scripts/
│   └── build_exe.py                # Script build eseguibile
│
├── remediation-kb/                 # Knowledge Base remediation [IMPLEMENTATO]
│   └── default.yml                 # 31 entry, 1 per regola penalizzante
│
└── tests/                          # 932 test in 52 file
    ├── test_models.py              # Test modelli Pydantic
    ├── test_source_base.py         # Test TempDirSourceMixin
    ├── test_source_github.py       # Test GitHubSource
    ├── test_source_gitlab.py       # Test GitLabSource
    ├── test_source_azure_devops.py # Test AzureDevOpsSource
    ├── test_source_bitbucket.py    # Test BitbucketSource
    ├── test_source_archive.py      # Test ArchiveSource
    ├── test_source_factory.py      # Test SourceFactory
    ├── test_source_integration.py  # Test source → orchestrator
    ├── test_cli_sources_integration.py # Test CLI + sources
    ├── test_project_models.py      # Test ProjectConfig, AggregatedResult
    ├── test_project_orchestrator.py # Test ProjectOrchestrator
    ├── test_project_integration.py # Test multi-repo E2E
    ├── test_dashboard_theme.py     # Test tema e colori
    ├── test_dashboard_components.py # Test componenti Dash
    ├── test_dashboard_callbacks.py # Test callback
    ├── test_dashboard_app_integration.py # Test app factory
    ├── test_exe_entry.py           # Test entry point exe
    ├── test_data_frozen.py         # Test _data.py frozen mode
    ├── test_exe_integration.py     # Test exe import chain
    ├── test_agent_mode.py          # Test comando agent
    ├── test_agent_integration.py   # Test agent E2E
    ├── test_e2e_full_product.py    # Suite E2E completa (7 scenari)
    ├── test_remediation_kb.py      # Test KB + cross-validazione
    ├── test_whatif.py              # Test What-If Simulator
    ├── test_context.py             # Test Context Collector
    ├── test_board_report.py        # Test Board Report
    ├── test_llm.py                 # Test LLM Provider/Router
    ├── test_llm_agent.py           # Test Interpretation Agent
    ├── test_history.py             # Test History Storage + AuditDelta
    ├── test_integration_remediation.py  # Test E2E pipeline
    ├── test_realistic_scenarios.py # 5 scenari realistici
    └── ...                         # Altri test esistenti
```

---

## Blocco 1 — Scaffolding + Core Models

### Cosa è stato fatto

Creata l'intera struttura directory del progetto con tutti i package Python e i moduli
placeholder. Implementati i modelli dati fondamentali e la configurazione runtime.

### `core/models.py` — Modelli dati Pydantic v2

Questo file è il cuore del sistema dati. Ogni componente del progetto usa questi modelli
per comunicare. Sono tutti immutabili, validati, e serializzabili.

#### Enumerazioni

| Enum | Valori | Uso |
|------|--------|-----|
| `PrivacyCategory` | `safe`, `local_llm`, `sensitive`, `excluded` | Classificazione privacy dei file |
| `Severity` | `critical`, `high`, `medium`, `low`, `info` | Gravità dei finding |
| `Layer` | `infra`, `architecture`, `security`, `quality` | I 4 layer di analisi CTO |
| `ComplianceMode` | `cross-cutting`, `standalone`, `hybrid` | Modalità compliance engine |

#### Modelli principali

| Modello | Campi chiave | Scopo |
|---------|-------------|-------|
| `FileInfo` | path, size, extension, lines_of_code | Info base di un file scansionato |
| `FileClassification` | file_info, category, reason, confidence | Classificazione privacy con motivo |
| `StackInfo` | languages (dict %), frameworks, infra_type | Stack tecnologico rilevato |
| `Finding` | id, layer, severity, rule_id, title, description, file_path, line_number, confidence, framework_ref | Singolo problema rilevato — unità atomica dell'analisi |
| `EvidenceChain` | finding_id, rule_id, weight, penalty, framework_ref | Tracciabilità: finding → regola → peso → penalità |
| `LayerScore` | layer, score (0-100), findings, evidence_chain | Score di un layer con tutte le prove |
| `ComplianceResult` | profile_name, checks_total/satisfied/partial/not_satisfied | Risultato per un profilo compliance |
| `HealthScore` | overall_score (0-100), layer_scores, compliance_results | Score complessivo dell'audit |
| `FileTree` / `FileTreeEntry` | root, entries (path, is_dir, size) | Albero file di una sorgente |
| `SourceMetadata` | name, total_files, total_loc, source_type | Metadati della sorgente dati |
| `AuditMetadata` | timestamp, target_path, tool_version, scoring_profile, compliance_profiles, offline_mode | Metadati dell'esecuzione |
| `AuditResult` | health_score, stack_info, classifications, metadata | Risultato finale completo |

#### Validazioni notevoli

- `FileInfo.size` e `lines_of_code`: devono essere >= 0
- `FileClassification.reason`: non può essere vuota
- `FileClassification.confidence`: deve essere tra 0.0 e 1.0
- `StackInfo.languages`: ogni percentuale deve essere tra 0.0 e 1.0
- `Finding.line_number`: se presente, deve essere >= 1
- `EvidenceChain.penalty`: deve essere <= 0 (è sempre una penalità)
- `LayerScore.score` e `HealthScore.overall_score`: devono essere tra 0 e 100
- `ComplianceResult.checks_satisfied`: non può superare `checks_total`

### `core/config.py` — Configurazione runtime

`AuditConfig` usa Pydantic Settings con prefisso env `CTO_AUDIT_`.
Ogni opzione CLI corrisponde a un campo.

| Campo | Default | Descrizione |
|-------|---------|-------------|
| `target_path` | (obbligatorio) | Percorso del codebase — validato: deve esistere ed essere directory |
| `output_format` | `"terminal"` | Formato output: terminal, markdown, html, json |
| `output_path` | `None` | Percorso file output (se non terminale) |
| `scoring_profile` | `"default"` | Profilo scoring YAML da usare |
| `compliance_profiles` | `[]` | Profili compliance attivi (es. `["nis2", "gdpr"]`) |
| `compliance_mode` | `hybrid` | Modalità compliance: cross-cutting, standalone, hybrid |
| `offline_mode` | `False` | Se True, nessun dato esce dalla macchina |
| `reuse_classification` | `False` | Se True, riusa classificazione da run precedente |
| `auto_approve` | `False` | Se True, salta il gate HITL |
| `focus` | `None` | Se impostato, esegue solo quel layer (infra/architecture/security/quality) |

### Test — 58/58 passed

- **test_models.py** (50 test): istanziazione valida di tutti i modelli, rifiuto dati invalidi
  (severity sbagliate, score fuori range, percentuali invalide, reason vuota, etc.)
- **test_config.py** (10 test): default corretti, validazione path, tutti i formati e modi
- **test_structure.py** (4 test): import di tutti i package e moduli

---

## Blocco 2 — AuditSource Interface + LocalRepoSource

### Cosa è stato fatto

Implementata l'interfaccia astratta per le sorgenti dati (`AuditSource` Protocol) e la
prima implementazione concreta che legge da filesystem locale (`LocalRepoSource`).

### `core/source.py` — Protocol AuditSource

Definisce il contratto che tutte le sorgenti dati devono rispettare. Usa `typing.Protocol`
con `runtime_checkable` per consentire `isinstance()` a runtime.

| Metodo | Signature | Scopo |
|--------|-----------|-------|
| `get_file_tree()` | `-> FileTree` | Restituisce l'albero completo dei file |
| `read_file(path)` | `-> str` | Legge il contenuto testuale di un file |
| `get_metadata()` | `-> SourceMetadata` | Restituisce metadati (nome, file, LOC) |

Qualsiasi classe che implementa questi 3 metodi è automaticamente un `AuditSource`,
senza bisogno di ereditarietà. Questo permette di aggiungere nuove sorgenti
(GitRemoteSource, MultiSource) senza toccare il codice esistente.

### `sources/local.py` — LocalRepoSource

Implementazione MVP di `AuditSource` che legge un codebase locale.

**Costruttore**: riceve un `Path` o `str`, verifica che esista e sia directory,
carica `.gitignore` se presente.

**get_file_tree()**: scansione ricorsiva con `os.walk`. Caratteristiche:
- Esclude sempre `.git/`
- Se presente `.gitignore`, ne rispetta le regole (directory con `/`, pattern glob, estensioni)
- Normalizza tutti i percorsi con `/` (anche su Windows)
- Entry ordinate per percorso
- Ogni file ha la dimensione reale dal filesystem

**read_file(path)**: lettura con gestione encoding:
- Prima prova UTF-8
- Fallback a latin-1 per file con encoding legacy
- Rileva file binari (byte null nel contenuto) → `ValueError`
- `FileNotFoundError` se il file non esiste
- `PermissionError` se non leggibile

**get_metadata()**: calcola on-the-fly:
- Nome directory root
- Conteggio file (esclusi quelli ignorati da .gitignore)
- LOC totali (solo file testuali leggibili)
- `source_type = "local"`

**_is_ignored(rel_path)**: logica di matching gitignore:
- `.git/` e' sempre hardcoded come ignorata
- **Whitelist NEVER_IGNORE_FILES**: file critici per l'analisi (requirements.txt, Dockerfile,
  package.json, manage.py, etc.) non vengono mai ignorati anche se matchano un pattern
  gitignore (es. `*.txt` che escluderebbe requirements.txt)
- Pattern con `/` finale → matcha solo directory
- Pattern glob (es. `*.log`) → matcha su nome file
- Matcha anche su percorso completo per pattern con path

### Test — 30/30 passed

- **TestAuditSourceProtocol** (2): isinstance check e metodi presenti
- **TestLocalRepoSourceInit** (4): path valido/stringa, errori per path inesistente e file
- **TestGetFileTree** (5): struttura corretta, dimensioni, tipo, directory vuota, normalizzazione path
- **TestGitignore** (7): node_modules, __pycache__, dist, *.log, .git, file mantenuti, senza gitignore
- **TestReadFile** (7): UTF-8, latin-1, binario rifiutato, file inesistente, vuoto, path non-file
- **TestGetMetadata** (5): conteggio corretto, directory vuota, LOC, binari ignorati, rispetto gitignore

### Fixture di test

Tre fixture riusabili definite in `test_source.py`:
- `repo_base`: 6 file (Python, JS, Dockerfile, .env, README)
- `repo_con_gitignore`: con node_modules, __pycache__, dist, .git e regole gitignore
- `repo_con_encoding`: file UTF-8, latin-1, binario

---

## Blocco 3 — File Scanner + Stack Detector

### Cosa è stato fatto

Implementati i due collector della pipeline di scansione: il FileScanner che produce
la lista di FileInfo e lo StackDetector che analizza linguaggi, framework e infrastruttura.

### `collectors/scanner.py` — FileScanner

Primo step della pipeline post-source. Riceve un `AuditSource`, itera il file tree,
e produce una lista di `FileInfo` filtrata.

**Logica principale (`scan()`)**:
1. Ottiene il file tree dalla sorgente
2. Per ogni file (non directory), verifica se è in una directory esclusa
3. Salta file generati dal tool stesso (EXCLUDED_TOOL_FILES: `.cto-audit-classification.yml`)
4. Calcola estensione e LOC (leggendo il file)
5. Restituisce lista ordinata per path

**Directory escluse** (`EXCLUDED_DIRECTORIES`): set di 20+ directory note come irrilevanti
per l'audit: `node_modules`, `vendor`, `.git`, `__pycache__`, `.venv`, `venv`, `dist`,
`build`, `target`, `.idea`, `.vscode`, `.mypy_cache`, `.pytest_cache`, `.tox`, etc.

| Metodo | Scopo |
|--------|-------|
| `scan()` | Scansiona e restituisce `list[FileInfo]` |
| `_is_in_excluded_dir(path)` | Controlla ogni componente del percorso contro la lista |
| `_get_extension(path)` | Estrae estensione con `os.path.splitext`, lowercase |
| `_count_lines(path)` | Legge il file dalla sorgente e conta righe; 0 se non leggibile |

**Nota**: lo scanner esclude solo directory. L'esclusione per estensione, dimensione e
lockfile è responsabilità del PrivacyClassifier (Blocco 4).

### `collectors/stack.py` — StackDetector

Analizza i file scansionati per determinare lo stack tecnologico completo.

**Rilevamento linguaggi** (`_detect_languages`):
- Mapping estensione → linguaggio per 30+ estensioni
- Percentuali calcolate per LOC (righe di codice per linguaggio)
- Linguaggi supportati: Python, JavaScript, TypeScript, Java, Go, Rust, C#, Ruby, PHP,
  C/C++, Swift, Kotlin, Scala, Dart, Shell, HTML, CSS, SQL, Elixir, Erlang, Lua, R, Zig

**Rilevamento framework** (`_detect_frameworks`):
- Per ogni file marker trovato, legge il contenuto e passa a un detector specifico
- Detector per linguaggio che cercano nomi noti nelle dipendenze

| File Marker | Linguaggio | Framework rilevabili |
|-------------|-----------|---------------------|
| `requirements.txt`, `pyproject.toml`, `Pipfile`, `setup.py` | Python | FastAPI, Django, Flask, SQLAlchemy, Celery, pytest, NumPy, pandas, PyTorch, etc. |
| `package.json` | JS/TS | React, Next.js, Vue.js, Angular, Express, NestJS, Jest, Prisma, Tailwind, etc. |
| `pom.xml`, `build.gradle` | Java | Spring Boot, Quarkus, Micronaut, Hibernate, JUnit, etc. |
| `go.mod` | Go | Gin, Fiber, Echo, Gorilla Mux, GORM |
| `Cargo.toml` | Rust | Actix Web, Axum, Rocket, Tokio, Diesel, Serde |
| `Gemfile` | Ruby | Rails, Sinatra, RSpec, Sidekiq |
| `composer.json` | PHP | Laravel, Symfony, Slim, PHPUnit |
| `*.csproj` | C# | ASP.NET Core, Entity Framework Core, xUnit, Blazor |

**Rilevamento infrastruttura** (`_detect_infra`):
- Controlla presenza di file/directory marker nel file tree

| Categoria | Marker |
|-----------|--------|
| CI/CD | `.github/workflows`, `.gitlab-ci.yml`, `Jenkinsfile`, `azure-pipelines.yml`, `.circleci`, `.travis.yml` |
| Container | `Dockerfile`, `docker-compose.yml` |
| Kubernetes | `k8s/`, `kubernetes/`, `Chart.yaml` (Helm) |
| IaC | `terraform/`, `main.tf`, `cloudformation/`, `ansible/`, `Pulumi.yaml` |
| Serverless | `serverless.yml`, `vercel.json`, `netlify.toml` |
| Monitoring | `prometheus.yml`, `grafana/`, `datadog.yaml` |

### Test — 40/40 passed

- **test_scanner.py** (12 test): conteggio file, esclusione directory, estensioni, LOC,
  file binari, dimensioni, repo vuota, ordinamento, pattern esclusi
- **test_stack.py** (28 test):
  - Linguaggi (5): solo Python, solo JS, mista, vuota, senza framework
  - Framework (11): Python (FastAPI, Pydantic, pytest), JS (React, Express, Jest),
    mista, Go (Gin), Rust (Actix, Serde, Tokio), Ruby (Rails, RSpec), PHP (Laravel),
    C# (ASP.NET, EF Core), nessun framework, repo vuota
  - Infra (10): Docker, Compose, GitHub Actions, Terraform, nessuna, vuota,
    GitLab CI, Jenkins, Kubernetes+Helm, Vercel
  - Integrazione (2): pipeline completa, file esclusi non influenzano stack

---

## Blocco 4 — Privacy Classifier

### Cosa è stato fatto

Implementato il classificatore automatico di privacy che assegna a ogni file una delle
4 categorie definite nel doc 03-hitl-flow.md. Questo è il cuore del sistema
"privacy by design" del tool.

### `collectors/privacy.py` — PrivacyClassifier

Riceve la lista di `FileInfo` dal FileScanner e la sorgente dati per leggere i contenuti.
Produce una `FileClassification` per ogni file.

**Ordine di valutazione** (deterministico, un file entra nella prima categoria che matcha):
1. EXCLUDED → 2. SENSITIVE → 3. SAFE

La categoria LOCAL_LLM non è mai assegnata automaticamente: è riservata all'override
umano nel gate HITL (Blocco 5).

#### Regole EXCLUDED (⚫)

| Tipo | Regola | Esempi |
|------|--------|--------|
| Directory | 9 directory hardcoded | `node_modules/`, `vendor/`, `.git/`, `__pycache__/`, `.venv/`, `dist/`, `build/`, `target/` |
| Estensione | 16 estensioni binarie/inutili | `.png`, `.jpg`, `.exe`, `.dll`, `.pyc`, `.sqlite`, `.woff`, etc. |
| Dimensione | > 1 MB | Qualsiasi file oltre il limite |
| Lockfile | 8 lockfile noti | `package-lock.json`, `yarn.lock`, `poetry.lock`, `Cargo.lock`, etc. |

#### Regole SENSITIVE (🔴)

| Tipo | Regola | Esempi |
|------|--------|--------|
| Filename | 14 pattern fnmatch | `.env`, `.env.*`, `*.pem`, `*.key`, `secrets.*`, `credentials.*`, `id_rsa`, `.htpasswd`, etc. |
| Path | 4 pattern di percorso | `*/config/prod*`, `*/deploy/prod*`, `*/.ssh/*`, `*/vault/*` |
| Contenuto regex | 9 pattern compilati | `password=`, `api_key=`, `aws_access_key_id`, `-----BEGIN PRIVATE KEY-----`, `database_url`, etc. |
| Entropia Shannon | soglia >= 5.0 | Stringhe ad alta casualita' in assegnazioni (API key, token generati) |

#### Filtri anti-falsi-positivi (aggiunti post-validazione)

| Tipo | Logica | Esempi |
|------|--------|--------|
| Placeholder values | Ignora valori noti non-secrets dopo `=` o `:` | `none`, `null`, `changeme`, `your_api_key_here`, `xxx`, `placeholder` |
| Type annotations | Ignora annotazioni di tipo Python | `api_key: str`, `password: Optional[str]`, `secret: Union[str, None]` |

#### Entropia Shannon (`_shannon_entropy`)

Funzione standalone che calcola l'entropia di una stringa: `H = -Σ(p(x) * log2(p(x)))`.
Valori tipici:
- Stringa costante: 0.0
- Parola normale: 2.5-3.5
- Codice sorgente: 3.5-4.5
- API key / token: 5.0-6.0

La soglia e' stata alzata da 4.5 a **5.0** dopo validazione su repo reali (4.5 produceva
troppi falsi positivi su codice normale con alta varieta' di caratteri).

L'entropia è calcolata solo su righe che contengono `=` o `:` con valore >= 16 caratteri,
per evitare falsi positivi su codice normale. URL e path sono esclusi dal check.

#### Logica `_check_content_sensitive`

1. Legge il file dalla sorgente (skip se non leggibile)
2. Applica i 9 regex pattern sul contenuto completo
3. Per ogni match, estrae il valore dopo `=` o `:` e verifica:
   - Se e' un valore placeholder (es. `none`, `changeme`) → ignora
   - Se e' un'annotazione di tipo Python (es. `str`, `Optional[str]`) → ignora
4. Se nessun regex matcha, cerca righe con alta entropia (soglia 5.0)
5. Il motivo include: tipo di pattern, numero riga, e testo matchato (troncato)

### Test — 52/52 passed

- **TestSensitiveFilename** (9): `.env`, `.env.production`, `*.pem`, `*.key`, `id_rsa`, `secrets.*`, `credentials.*`, `.htpasswd`, `*.keystore`
- **TestSensitiveContent** (8): private key PEM, RSA key, password, API key, AWS credentials, database URL, connection string, docker-compose con password
- **TestSensitiveEntropy** (2): API key ad alta entropia, bassa entropia non sensibile
- **TestSensitivePath** (2): `config/prod/`, `deploy/prod/`
- **TestExcludedExtension** (5): `.png`, `.jpg`, `.exe`, `.pyc`, `.sqlite`
- **TestExcludedLockfile** (6): package-lock, yarn.lock, poetry.lock, Cargo.lock, Pipfile.lock, Gemfile.lock
- **TestExcludedSize** (2): file > 1MB escluso, file = 1MB non escluso
- **TestExcludedDirectory** (2): `node_modules/`, `vendor/`
- **TestSafe** (6): routes.py, Dockerfile, docker-compose senza password, README, Python source, GitHub Actions
- **TestReasonPresente** (2): motivo non vuoto, confidenza valida
- **TestShannonEntropy** (6): vuota, costante, bilanciata, API key, parola normale, codice Python
- **TestIntegrazionePipeline** (2): pipeline completa, conteggi per categoria

---

## Blocco 5 — HITL Gate (Review Interattivo)

### Cosa è stato fatto

Implementati i due componenti del gate Human-in-the-Loop: la persistenza delle
classificazioni su file YAML e il reviewer interattivo con interfaccia Rich.

### `hitl/persistence.py` — ClassificationPersistence

Gestisce salvataggio e caricamento delle classificazioni su `.cto-audit-classification.yml`.

| Metodo | Scopo |
|--------|-------|
| `save(classifications, overrides)` | Serializza su YAML con stats, classificazioni, e override |
| `load()` | Ricostruisce la lista di `FileClassification` dal YAML |
| `load_overrides()` | Carica solo la lista degli override manuali |
| `diff(current_files)` | Confronta file attuali con classificazione salvata |
| `exists()` / `delete()` | Verifica esistenza / elimina file |

**Formato YAML salvato**:
```yaml
version: 1
timestamp: "2024-..."
stats: {total_files: N, safe: N, local_llm: N, sensitive: N, excluded: N}
classifications:
  - {path: "...", size: N, extension: "...", category: "safe", reason: "...", confidence: 1.0}
overrides:
  - {file: "...", from: "safe", to: "local_llm", reason: "..."}
```

**DiffResult**: rileva file nuovi, modificati (size diversa), rimossi, invariati.
Proprietà `has_changes` e `summary` per uso rapido.

### `hitl/reviewer.py` — HITLReviewer

Interfaccia interattiva terminale con Rich per la review delle classificazioni.
L'I/O è disaccoppiato tramite `input_fn` iniettabile per il testing.

**Flusso principale** (`review()`):
1. Mostra pannello summary (totali per categoria, file SENSITIVE in dettaglio)
2. Entra nel loop del menu azioni
3. L'utente può navigare, modificare, o confermare
4. Mostra riepilogo finale e chiede conferma
5. Restituisce `(ReviewResult, classificazioni_finali, overrides)`

**Menu azioni**:
| Tasto | Azione |
|-------|--------|
| C | Conferma classificazione e procedi |
| V | Visualizza tutti i file SAFE |
| S | Visualizza dettaglio file SENSITIVE |
| X | Visualizza file ESCLUSI |
| E | Modifica classificazione di un singolo file |
| A | Sposta TUTTO a SENSITIVE (analisi 100% locale) |
| Q | Annulla audit |

**Override SENSITIVE → SAFE**: richiede digitazione esatta di "CONFERMO" per procedere.
Mostra i pattern sensibili trovati e avvisa che dati transiterebbero su server esterni.

**Override in altre direzioni**: non richiedono conferma speciale.

**Move All to Sensitive**: sposta tutti i SAFE e LOCAL_LLM a SENSITIVE in batch,
generando un override per ciascuno.

### Test — 29/29 passed

**Persistence** (13 test):
- Save: crea file, include overrides
- Load: ricostruisce classificazioni, preserva categorie, errore se file mancante, delete
- Diff: file nuovi, rimossi, modificati, nessun cambiamento, senza file salvato, summary

**Reviewer** (13 test con mock I/O):
- Conferma: diretta, con "si", rifiuto+annulla
- Annullamento: Q esce senza modifiche
- Visualizzazione: SAFE, SENSITIVE, EXCLUDED poi conferma
- Override SENSITIVE→SAFE: con CONFERMO (accettato), senza CONFERMO (rifiutato)
- Override altre direzioni: SAFE→SENSITIVE, SAFE→LOCAL_LLM (nessun CONFERMO richiesto)
- Move all: tutti SAFE/LOCAL_LLM → SENSITIVE
- Stack info: review con StackInfo senza errori

**Integrazione** (3 test):
- Pipeline completa: scan → classify → review → persist → reload
- Riuso classificazione precedente
- Diff dopo modifica file (nuovi + modificati rilevati)

---

## Blocco 6 — CLI Base + Integrazione Fasi 1-3

### Cosa è stato fatto

Implementato l'entry point CLI con Typer che collega tutte le fasi 1-3 della pipeline:
Collection → Scan + Classificazione → HITL Gate. Tutte le opzioni documentate nel concept
sono disponibili come flag CLI.

### `cli.py` — Entry point CLI

App Typer con callback e un singolo comando `scan`. La `Console` Rich è creata all'interno
di `scan()` (non a livello di modulo) per garantire compatibilità con `CliRunner` nei test.

**Opzioni del comando `scan`**:

| Opzione | Tipo | Default | Descrizione |
|---------|------|---------|-------------|
| `TARGET` | Argument | (obbligatorio) | Percorso del codebase da analizzare |
| `--focus / -f` | str | None | Layer specifico: infra, architecture, security, quality |
| `--compliance / -c` | str | None | Profili compliance separati da virgola (es. nis2,gdpr) |
| `--compliance-mode` | str | hybrid | Modalità: cross-cutting, standalone, hybrid |
| `--scoring / -s` | str | default | Profilo scoring (es. nist-csf, owasp-asvs) |
| `--offline` | bool | False | Nessun dato esce dalla macchina |
| `--reuse-classification` | bool | False | Riusa classificazione da run precedente |
| `--output / -o` | str | None | Percorso file output |
| `--auto-approve` | bool | False | Salta gate HITL, approva automaticamente |

**Flusso di esecuzione**:

1. **Validazione** — Verifica che il target esista ed sia una directory, che focus e
   compliance_mode siano valori ammessi
2. **Fase 1 (Collection)** — Mostra pannello CTO AUDIT AGENT con parametri, crea `LocalRepoSource`
3. **Fase 2 (Scan + Classificazione)** — `FileScanner` → `StackDetector` → `PrivacyClassifier`;
   mostra pannello STACK RILEVATO con linguaggi, framework, infra
4. **Fase 3 (HITL Gate)** — Tre percorsi alternativi:
   - `--reuse-classification` con file esistente → carica da YAML
   - `--auto-approve` → salva e prosegue senza interazione
   - Default → `HITLReviewer` interattivo con possibilità di override

**Helper functions**:

| Funzione | Scopo |
|----------|-------|
| `_show_stack_summary(console, stack_info, total_files)` | Pannello Rich con linguaggi (%), framework, infra |
| `_show_classification_summary(console, classifications)` | Riga riepilogo SAFE/LOCAL_LLM/SENSITIVE/EXCLUDED |

**Note implementative**:
- `@app.callback()` necessario per preservare il comportamento multi-comando di Typer
  (senza callback, Typer con un singolo comando collassa il subcomando)
- `from __future__ import annotations` rimosso perché incompatibile con Typer
  (le annotazioni lazy impediscono a Typer di ispezionare i tipi dei parametri)
- Console creata dentro `scan()` per compatibilità con CliRunner che sostituisce
  `sys.stdout` a runtime

### Test — 22/22 passed

- **TestHelp** (2): help root mostra cto-audit/analizza, help scan mostra tutte le opzioni
- **TestErrori** (4): path inesistente (exit 1), file non directory (exit 1),
  focus invalido (exit 1), compliance-mode invalido (exit 1)
- **TestAutoApprove** (3): completa fasi 1-3, salva classificazione YAML,
  classificazione corretta (.env=SENSITIVE, logo.png=EXCLUDED, src/app.py=SAFE)
- **TestReuseClassification** (2): riuso da file precedente, fallback a scan senza file
- **TestOffline** (2): flag accettato, mostrato nel pannello
- **TestFocus** (4): infra, architecture, security, quality tutti accettati
- **TestCompliance** (2): singolo (nis2), multiplo (nis2,gdpr)
- **TestEndToEnd** (3): repo completa (pannello CTO AUDIT, stack, fasi completate),
  directory vuota (messaggio "nessun file"), tutte le opzioni contemporaneamente

**Fixture di test** (`repo_test`): repo sintetica con Python (Flask), JS (React), Dockerfile,
.github/workflows, .env, package.json, logo.png, README — simula un progetto realistico.

---

## Blocco 7 — Infra Analyzer (Layer 1)

### Cosa è stato fatto

Implementata l'interfaccia base per tutti gli analyzer (`BaseAnalyzer` Protocol) e il
primo layer di analisi: `InfraAnalyzer`, che verifica la qualità dell'infrastruttura
con check deterministici (pattern matching, file existence, contenuto).

### `analyzers/base.py` — BaseAnalyzer Protocol

Interfaccia comune per tutti i layer analyzer, usando `typing.Protocol` con `runtime_checkable`.

| Metodo | Signature | Scopo |
|--------|-----------|-------|
| `analyze()` | `(source, stack_info, classifications) -> list[Finding]` | Analizza il codebase e restituisce finding per il layer |

Parametri:
- `source: AuditSource` — per leggere file dal codebase
- `stack_info: StackInfo` — stack tecnologico rilevato
- `classifications: list[FileClassification]` — classificazioni privacy (correlazione)

### `analyzers/infra.py` — InfraAnalyzer

Analyzer per il Layer 1 (Infrastruttura), il primo che un CTO guarda.
Infra-agnostico: non assume quale tipo di infra troverà — rileva e poi valuta.

**Check implementati e regole prodotte**:

| Area | Rule ID | Severità | Condizione |
|------|---------|----------|------------|
| **CI/CD** | INFRA-CICD-001 | High | Nessun CI/CD trovato (GH Actions, GitLab CI, Jenkins, Azure, CircleCI, Travis) |
| | INFRA-CICD-INFO | Info | CI/CD rilevato (informativo) |
| **Container** | INFRA-DOCKER-001 | Medium | Nessuna containerizzazione — solo per progetti deployable (context-aware) |
| | INFRA-DOCKER-INFO | Info | Nessuna containerizzazione (non richiesta per questo tipo di progetto) |
| | INFRA-DOCKER-002 | Low | .dockerignore mancante |
| | INFRA-DOCKER-003 | Medium | Dockerfile senza multi-stage build |
| | INFRA-DOCKER-004 | Medium | Dockerfile esegue come root (no USER non-root) |
| | INFRA-DOCKER-005 | Low | Dockerfile senza HEALTHCHECK |
| **IaC** | INFRA-IAC-001 | High | Nessun IaC (Terraform, CloudFormation, Ansible, Pulumi) |
| **Dipendenze** | INFRA-DEPS-001 | High | File manifesto presente ma nessun lockfile |
| **Config** | INFRA-CONFIG-001 | High | File .env con dati sensibili nel repo |
| | INFRA-CONFIG-002 | High | Secrets in chiaro in file di configurazione |
| **Monitoring** | INFRA-MON-001 | Medium | Nessun monitoraggio né health check rilevato |

**Lockfile detection**: supportati 17 tipi di lockfile (package-lock.json, yarn.lock, pnpm-lock.yaml, Pipfile.lock, poetry.lock, requirements.txt, Cargo.lock, go.sum, Gemfile.lock, composer.lock, pubspec.lock, uv.lock, bun.lock, deno.lock, gradle.lockfile, packages.lock.json, paket.lock).

**Framework reference**: i finding critici includono riferimenti a framework/normative:
- INFRA-CICD-001 → NIST PR.DS-6
- INFRA-DEPS-001 → NIS2 Art.21(2)(d)
- INFRA-MON-001 → NIS2 Art.21(2)(c)

**Correlazione con Privacy Classifier**: il check `_check_secrets()` legge le classificazioni
privacy (Blocco 4) per rilevare file .env e config con secrets già classificati come SENSITIVE.

**Filtro documentazione/CI**: i file README, CONTRIBUTING, CHANGELOG, AUTHORS, file .md/.rst,
e file CI workflow (.github/workflows/) sono esclusi dal check secrets (`_is_documentation_or_ci`)
per evitare falsi positivi su esempi di configurazione nella documentazione.

**Marker riconosciuti**:
- CI/CD: `.github/workflows`, `.gitlab-ci.yml`, `Jenkinsfile`, `azure-pipelines.yml`, `.circleci`, `.travis.yml`, `bitbucket-pipelines.yml`
- Container: `Dockerfile`, `docker-compose.yml/yaml`, `compose.yml/yaml`, `k8s/`, `kubernetes/`, `Chart.yaml`, `kustomization.yaml`
- IaC: `terraform/`, `main.tf`, `cloudformation/`, `ansible/`, `Pulumi.yaml`
- Monitoring: `prometheus.yml`, `grafana/`, `datadog.yaml`, `sentry.properties`, `.sentryclirc`, `newrelic.yml`
- Health check: pattern regex su `/health`, `/healthz`, `/readyz`, `HEALTHCHECK`

### Test — 37/37 passed

- **TestBaseAnalyzer** (3): Protocol runtime_checkable, restituisce list[Finding], tutti layer=infra
- **TestCICD** (5): nessun CI/CD (critico), GitHub Actions (info, no critico), framework_ref NIST, GitLab CI
- **TestContainer** (9): nessun container (critico), Dockerfile singolo stage/root/no dockerignore,
  multi-stage con best practices (nessun finding negativo), HEALTHCHECK
- **TestIaC** (3): nessun IaC (high), Terraform ok, Ansible ok
- **TestDipendenze** (4): manifest senza lockfile (high), con lockfile ok, senza manifest nessun finding, framework_ref NIS2
- **TestConfig** (3): .env sensibile (high), senza .env ok, secrets in config.yml
- **TestMonitoraggio** (4): nessun monitoring (medium), health check endpoint ok, Sentry ok, framework_ref NIS2
- **TestIntegrazione** (6): repo vuota (multipli critici), ben strutturata (nessun critico/high),
  finding info presenti, ID univoci, rule_id con prefisso INFRA-, conteggio repo minima

---

## Blocco 8 — Architecture Analyzer (Layer 2)

### Cosa è stato fatto

Implementato il secondo layer di analisi: `ArchitectureAnalyzer`, che valuta
la struttura del progetto con check deterministici su organizzazione directory,
coupling tra moduli, file grandi, test, e gestione database.

### `analyzers/architecture.py` — ArchitectureAnalyzer

Analyzer per il Layer 2 (Architettura), il secondo in ordine di priorità CTO.
Language-agnostic con import extraction via regex per Python e JS/TS.

**Check implementati e regole prodotte**:

| Area | Rule ID | Severita' | Condizione |
|------|---------|----------|------------|
| **Struttura** | ARCH-STRUCT-001 | Medium | Struttura flat: >70% dei file in root (min 5 file) |
| | ARCH-STRUCT-INFO | Info | Pattern MVC, layered/Clean Arch, o feature-based rilevato |
| **Coupling** | ARCH-COUPLING-001 | High | Import circolari rilevati (con dettaglio cicli) |
| | ARCH-COUPLING-002 | Medium | Fan-out eccessivo: modulo importa >10 moduli interni (normalizzato) |
| | ARCH-COUPLING-INFO | Info | Fan-out elevato oltre il cap normalizzato (visibile, 0 penalita') |
| **Scalabilita'** | ARCH-SCALE-001 | Medium | File con >500 LOC (normalizzato per dimensione progetto) |
| | ARCH-SCALE-INFO | Info | File grande oltre il cap normalizzato (visibile, 0 penalita') |
| **Test** | ARCH-TEST-001 | Critical | Nessuna directory o file di test trovati |
| **Database** | ARCH-DB-001 | Medium | ORM rilevato nei framework ma nessuna directory migrazioni |

**Rilevamento pattern architetturale**:
- **MVC/MTV**: directory `models/`, `views/`, `controllers/`, `templates/`, `static/`
- **Layered/Clean**: directory `domain/`, `application/`, `infrastructure/`, `core/`, `services/`, `repositories/`, `usecases/`, `entities/`, `adapters/`
- **Feature-based**: directory `features/`, `modules/`, `apps/`
- **Flat**: >70% dei file nella root → warning

**Import extraction e cycle detection**:
- Python: regex su `from X import Y` e `import X` → grafo moduli interni → DFS per cicli
- JS/TS: regex su `import ... from './X'` e `require('./X')` → risoluzione path relativi
- Solo import interni al progetto (ignora librerie esterne)
- Fan-out: soglia >10 moduli interni importati da un singolo modulo

**Normalizzazione per dimensione progetto** (ARCH-SCALE-001 e ARCH-COUPLING-002):
Le penalita' sono proporzionate alla percentuale di file problematici, non al numero assoluto.
I file/moduli peggiori (per LOC o per fan-out) vengono penalizzati per primi (MEDIUM);
quelli oltre il cap sono riportati come INFO (visibili nel report ma 0 penalita').
Il cap e' calcolato con: `min(max_cap, max(3, round(ratio * fattore)))`.
Esempio: django-cms ha 72 file >500 LOC su 1665 totali (4.3%) → solo 3 penalizzati.

**Filtro file non-sorgente** (ARCH-SCALE-001):
- Estensioni escluse: `.po`, `.mo`, `.pot` (traduzioni), `.csv`, `.tsv`, `.map`, `.lock`, `.svg`, `.min.js`, `.min.css`, `.xml`, `.resx`, `.sql`, `.json`, `.yaml`, `.yml`, `.proto`, `.graphql`, `.xaml`, `.csproj`
- Nomi file esclusi: LICENSE, CHANGELOG, CONTRIBUTORS, AUTHORS, `.cto-audit-classification.yml`
- **LARGE_FILE_SKIP_DIRS**: directory vendored escluse (vendor/, node_modules/, third_party/, extern/, etc.)
- File EXCLUDED (privacy) sono filtrati prima dell'analisi

**Marker database/migrazioni riconosciuti**:
`migrations/`, `alembic/`, `db/migrate/`, `prisma/migrations/`, `sequelize/migrations/`, `flyway/`, `liquibase/`
I marker sono cercati a qualsiasi livello di sottodirectory (es. `cms/migrations/` matcha).

**ORM riconosciuti nei framework**:
SQLAlchemy, Django ORM, Tortoise ORM, Peewee, Prisma, Sequelize, TypeORM,
Hibernate, Entity Framework, ActiveRecord, GORM, Diesel, Mongoose

### Test — 24/24 passed

- **TestBaseAnalyzer** (4): Protocol, layer=architecture, ID univoci, rule_id ARCH-*
- **TestStruttura** (4): repo flat (medium), MVC (info, no struct finding), layered (info)
- **TestCoupling** (4): import circolari (high), cicli descritti, senza cicli ok, fan-out eccessivo
- **TestFileGrandi** (3): file >500 LOC (medium), file piccoli ok, file_path impostato
- **TestDirectoryTest** (3): senza test (high), con dir tests ok, con file test_*.py ok
- **TestDatabase** (3): ORM senza migrazioni (medium), con alembic ok, senza ORM ok
- **TestIntegrazione** (3): repo MVC (nessun critico), repo problematica (multipli finding), repo layered (info)

---

## Blocco 9 — Scoring Engine Pluggable

### Cosa è stato fatto

Implementato lo scoring engine pluggable basato su profili YAML. Il sistema calcola
score tracciabili per ogni layer con catena di evidenze completa, aggregandoli in
un HealthScore complessivo con media pesata.

### Architettura Scoring

Il flusso di scoring è:

```
Finding[] → ScoringEngine.calculate() → HealthScore
                  ↓
         ScoringProfile (YAML)
                  ↓
  Per ogni finding:
    1. Cerca rule_id nel profilo
    2. Se trovata: usa weight/penalty dal profilo
    3. Se non trovata: usa default_rule_weight + penalità per severità
    4. Penalità effettiva = |penalty| × weight
    5. Crea EvidenceChain per tracciabilità
                  ↓
  LayerScore = 100 - sum(penalità), min 0
                  ↓
  HealthScore = media pesata dei LayerScore con layer_weights
```

### `scoring/profile.py` — ScoringProfile

Caricamento e validazione profili YAML con Pydantic v2.

#### RuleConfig

| Campo | Tipo | Vincoli | Descrizione |
|-------|------|---------|-------------|
| `severity` | str | critical/high/medium/low/info | Severità della regola |
| `weight` | float | 0.0–1.0 | Peso della regola nel layer |
| `penalty` | float | ≤ 0 | Penalità in punti (sempre negativa o zero) |
| `framework_ref` | str\|None | — | Riferimento framework/normativa |
| `description` | str | — | Descrizione della regola |

#### ScoringProfile

| Campo | Tipo | Vincoli | Descrizione |
|-------|------|---------|-------------|
| `name` | str | min_length=1 | Nome del profilo |
| `description` | str | — | Descrizione del profilo |
| `layer_weights` | dict[str, float] | somma = 1.0, layer validi | Pesi per layer |
| `default_rule_weight` | float | 0.0–1.0, default 0.5 | Peso fallback per regole non nel profilo |
| `rules` | dict[str, RuleConfig] | — | Regole di scoring |

**Validazioni**:
- `layer_weights`: solo layer validi (infra, architecture, security, quality), ogni peso 0–1, somma = 1.0 (tolleranza 0.01)
- Regole con `severity=info` devono avere `penalty=0` (model_validator)
- `load_profile()`: carica YAML, valida con Pydantic, errori chiari per file non trovato / YAML malformato / validazione fallita

### `scoring/engine.py` — ScoringEngine

Engine di calcolo score con supporto pluggable via profili.

#### ScoringEngine

| Metodo | Signature | Scopo |
|--------|-----------|-------|
| `__init__(profile)` | `ScoringProfile → None` | Inizializza con profilo |
| `score_layer(layer, findings)` | `Layer, list[Finding] → LayerScore` | Score per un layer |
| `calculate(all_findings)` | `list[Finding] → HealthScore` | Score complessivo |

**Formula score layer**: `score = max(0, 100 - Σ(|penalty_i| × weight_i))`

**Gestione regole mancanti**: se un finding ha un `rule_id` non presente nel profilo,
il sistema usa `default_rule_weight` come peso e penalità default per severità:

| Severità | Penalità default |
|----------|-----------------|
| critical | -20 |
| high | -10 |
| medium | -5 |
| low | -2 |
| info | 0 |

**Framework reference**: usa il `framework_ref` della regola nel profilo; se assente,
usa quello del finding stesso (fallback).

**HealthScore**: media pesata dei layer score con `layer_weights` del profilo.
Layer senza finding → score 100.

### `scoring/models.py` — Re-export

Re-esporta `EvidenceChain`, `LayerScore`, `HealthScore` da `core/models.py`
per comodità di import dal package `scoring`.

### `scoring-profiles/default.yml` — Profilo CTO default

Profilo bilanciato con pesi CTO:

| Layer | Peso |
|-------|------|
| security | 0.30 |
| architecture | 0.25 |
| infra | 0.25 |
| quality | 0.20 |

Contiene 31+ regole coprendo tutti i finding dei Blocchi 7-8 + Security + Quality (incluse regole INFO per normalizzazione):

| Regola | Severita' | Weight | Penalty | Framework |
|--------|----------|--------|---------|-----------|
| INFRA-CICD-001 | high | 0.9 | -20 | NIST PR.DS-6 |
| INFRA-CICD-INFO | info | 0.0 | 0 | — |
| INFRA-DOCKER-001 | medium | 0.5 | -8 | — |
| INFRA-DOCKER-INFO | info | 0.0 | 0 | — |
| INFRA-DOCKER-002 | low | 0.3 | -3 | — |
| INFRA-DOCKER-003 | medium | 0.5 | -5 | — |
| INFRA-DOCKER-004 | medium | 0.6 | -8 | — |
| INFRA-DOCKER-005 | low | 0.3 | -3 | — |
| INFRA-IAC-001 | high | 0.7 | -10 | — |
| INFRA-DEPS-001 | high | 0.80 | -12 | NIS2 Art.21(2)(d) |
| INFRA-CONFIG-001 | high | 0.80 | -15 | — |
| INFRA-CONFIG-002 | high | 0.80 | -15 | — |
| INFRA-MON-001 | medium | 0.5 | -8 | NIS2 Art.21(2)(c) |
| ARCH-STRUCT-001 | medium | 0.5 | -8 | — |
| ARCH-STRUCT-INFO | info | 0.0 | 0 | — |
| ARCH-COUPLING-001 | high | 0.8 | -15 | — |
| ARCH-COUPLING-002 | medium | 0.5 | -5 | — |
| **ARCH-COUPLING-INFO** | info | 0.0 | 0 | — |
| ARCH-SCALE-001 | medium | 0.4 | -3 | — |
| **ARCH-SCALE-INFO** | info | 0.0 | 0 | — |
| ARCH-TEST-001 | critical | 1.0 | -22 | — |
| ARCH-DB-001 | medium | 0.5 | -8 | — |
| SEC-SECRETS-CODE-001 | critical | 1.0 | -25 | — |
| SEC-SQL-001 | high | 0.9 | -18 | — |
| SEC-HTTPS-001 | medium | 0.5 | -5 | — |
| SEC-HEADERS-001 | low | 0.3 | -3 | — |
| SEC-CRYPTO-001 | medium | 0.6 | -8 | — |
| SEC-XSS-001 | high | 0.8 | -15 | — |
| QUAL-DOC-002 | low | 0.3 | -3 | — |
| QUAL-LINT-001 | medium | 0.5 | -8 | — |
| QUAL-TYPING-001 | low | 0.3 | -3 | — |
| QUAL-COMPLEXITY-001 | medium | 0.5 | -7 | — |
| QUAL-DUP-001 | low | 0.3 | -3 | — |

> **Nota**: Profilo aggiuntivo `vc-diligence.yml` disponibile per due-diligence VC (pesi diversi, soglie piu' aggressive).
> **Rationale literature-backed**: i pesi e le penalita' sono calibrati su fonti industriali (IBM/Ponemon Cost of Data Breach, DORA metrics, Boehm's Software Engineering Economics, OWASP Risk Rating).

### Test — 44/44 passed

- **TestScoringProfile** (12): profilo valido, layer_weights somma 1.0, layer invalido,
  peso negativo, severità invalida, penalty positiva, weight fuori range,
  info con penalty non-zero, get_rule esistente/non-esistente, default_rule_weight, nome vuoto
- **TestLoadProfile** (6): carica profilo default reale, profilo custom da YAML,
  profilo non trovato, YAML malformato, YAML non dizionario, campi mancanti
- **TestScoringEngineLayer** (6): score 100 senza finding, un finding, finding critico,
  info non penalizza, score minimo zero, multipli finding
- **TestScoringEngineDefault** (4): finding senza regola usa default, critical senza regola,
  info senza regola, framework_ref da finding
- **TestEvidenceChain** (3): catena completa, framework fallback, ordine corretto
- **TestHealthScore** (5): 100/100 senza finding, con finding (media pesata verificata),
  multipli layer, tutti i layer presenti, basso con molti critici
- **TestScoringModels** (3): re-export EvidenceChain, LayerScore, HealthScore
- **TestProfiloDefault** (5): layer_weights sommano a 1.0, regole infra presenti,
  regole arch presenti, pesi CTO corretti, scoring end-to-end con profilo reale

---

## Blocco 10 — Orchestrator + Report + Integrazione End-to-End

### Cosa è stato fatto

Implementato il coordinatore del flusso completo (`AuditOrchestrator`), i reporter
terminale e Markdown, e aggiornata la CLI per collegare l'intera pipeline.
Il comando `cto-audit scan` ora funziona end-to-end: dalla scansione al report finale.

### `core/orchestrator.py` — AuditOrchestrator

Coordinatore principale che esegue la pipeline completa in sequenza:

```
Source → FileScanner → StackDetector → PrivacyClassifier → HITL → Analyzers → ScoringEngine → Report
```

| Parametro | Tipo | Descrizione |
|-----------|------|-------------|
| `source` | AuditSource | Sorgente dati (LocalRepoSource) |
| `target_path` | Path | Percorso del codebase |
| `scoring_profile` | str | Nome profilo YAML (default: "default") |
| `focus` | Layer\|None | Se impostato, esegue solo quel layer |
| `offline` | bool | Modalità offline |
| `auto_approve` | bool | Salta il gate HITL |
| `reuse_classification` | bool | Riusa classificazione precedente |
| `console` | Console\|None | Console Rich per output |

| Metodo | Scopo |
|--------|-------|
| `run()` | Esegue l'intero flusso e restituisce `AuditResult` |
| `_run_analyzers()` | Esegue tutti e 4 gli analyzer: InfraAnalyzer, ArchitectureAnalyzer, SecurityAnalyzer, QualityAnalyzer |
| `_empty_result()` | Costruisce un AuditResult vuoto (nessun file o audit annullato) |

**Gestione focus**: se `--focus infra`, solo `InfraAnalyzer` viene eseguito.
Gli altri layer avranno score 100 con zero finding.

**Gestione repo vuota**: se FileScanner non trova file, restituisce AuditResult
con HealthScore 100/100 e nessun finding.

**Analyzer disponibili**: InfraAnalyzer (Layer.INFRA), ArchitectureAnalyzer (Layer.ARCHITECTURE), SecurityAnalyzer (Layer.SECURITY), QualityAnalyzer (Layer.QUALITY).

**Flag CLI aggiuntivi**:

| Flag | Descrizione |
|------|-------------|
| `--detailed` | Mostra tutti i finding inclusi INFO (default: INFO capped) |
| `--board-report` | Genera board report con remediation pipeline |
| `--no-llm` | Disabilita LLM (board report deterministico) |
| `--output FILE` | Salva report su file (Markdown, HTML, JSON) |

**Reporter disponibili**: TerminalReporter, MarkdownReporter, BoardReporter, HTMLReporter (self-contained), JSONExporter.

### `reporters/terminal.py` — TerminalReporter

Output Rich formattato che riproduce il mock del doc 01-concept:

| Sezione | Contenuto |
|---------|-----------|
| Header | Stack, framework, infra, file analizzati, profilo scoring |
| Health Score | Score complessivo con colore e etichetta (BUONO/ATTENZIONE/INSUFFICIENTE/CRITICO) |
| Layer Scores | Tabella con score, stato e count finding per ogni layer |
| Top 5 Azioni | Finding con penalità più alta, ordinati per impatto, con file e framework ref |
| Evidence Chain | (opzionale) Tabella dettagliata per layer: rule_id, weight, penalty, framework |

**Colori score**: verde (≥80), giallo (≥60), arancione (≥40), rosso (<40).

**Top 5 azioni**: raccolte da tutti i layer, ordinate per penalità effettiva decrescente.
Per ogni azione: severità, titolo, file coinvolto, riferimento framework.

### `reporters/markdown.py` — MarkdownReporter

Report completo in formato Markdown con 7 sezioni:

1. **Header**: stack, framework, infra, file analizzati, profilo scoring, target
2. **Health Score**: score complessivo con etichetta
3. **Score per Layer**: tabella con score, stato, count finding
4. **Top 5 Azioni Prioritarie**: lista numerata con severità, titolo, descrizione, framework
5. **Dettaglio Finding**: tabella per layer con severità, rule_id, titolo, file
6. **Catena di Evidenze**: tabella per layer con rule_id, weight, penalty, framework
7. **Footer**: versione tool e timestamp

| Metodo | Scopo |
|--------|-------|
| `report(result)` | Genera il Markdown come stringa |
| `save(result, path)` | Genera e salva su file |

### `cli.py` — Aggiornamento

La CLI è stata semplificata: ora delega tutto all'orchestrator e mostra il report.

**Flusso aggiornato**:
1. Validazione input (percorso, focus, compliance mode)
2. Pannello iniziale con configurazione
3. Connessione sorgente (LocalRepoSource)
4. `AuditOrchestrator.run()` — esegue l'intera pipeline
5. Se `--output report.md`: MarkdownReporter.save()
6. Altrimenti: TerminalReporter.report()

**Rimossi**: import di FileScanner, StackDetector, PrivacyClassifier, HITLReviewer,
ClassificationPersistence (ora gestiti dall'orchestrator).

### Test — 27/27 passed (+ 22 CLI aggiornati)

- **TestAuditOrchestrator** (8): flusso completo repo sana, repo problematica,
  score sana > problematica, focus infra/architecture, repo vuota (100/100),
  catena evidenze presente, metadata completa
- **TestTerminalReporter** (5): report completo con health score/layer/azioni,
  mostra azioni, evidence chain, report repo sana, nessuna azione su repo vuota
- **TestMarkdownReporter** (5): sezioni complete, contiene stack, salvataggio su file,
  contiene finding, contiene evidenze
- **TestCLIEndToEnd** (9): e2e repo sana, repo problematica, --focus infra,
  --output report.md produce Markdown, repo vuota, scoring default, tutte opzioni,
  path inesistente, focus invalido

**Fixture di test**:
- `repo_sana`: struttura layered (src/core/services), CI/CD, Docker multi-stage con
  USER + HEALTHCHECK, lockfile, IaC Terraform, directory test, Sentry monitoring
- `repo_problematica`: flat structure, no CI/CD, no Docker, no test, no lockfile,
  .env con secrets, secrets in config.py, no IaC

### Test totali progetto — 640/640 passed

Inclusi 7 scenari realistici E2E (`test_realistic_scenarios.py`).
Validato su 29 repo: 20 reali (media 78.3/100, 10 linguaggi) + 9 sintetiche (100% precision/recall).

---

## Post-validazione — Bug fix e miglioramenti

### Modifiche al PrivacyClassifier (`collectors/privacy.py`)
- Soglia entropia alzata da 4.5 a **5.0** (riduce falsi positivi)
- Aggiunto set `PLACEHOLDER_VALUES` (~25 valori) per filtrare assegnazioni non-secrets
- Aggiunto filtro annotazioni tipo Python (`api_key: str`, `password: Optional[str]`)

### Modifiche al FileScanner (`collectors/scanner.py`)
- Aggiunto `EXCLUDED_TOOL_FILES` per escludere `.cto-audit-classification.yml`

### Modifiche al LocalRepoSource (`sources/local.py`)
- Aggiunto `NEVER_IGNORE_FILES` (~25 file) per impedire al .gitignore di escludere
  file critici come `requirements.txt`, `Dockerfile`, `manage.py`

### Modifiche all'InfraAnalyzer (`analyzers/infra.py`)
- Aggiunto `_is_documentation_or_ci()` per escludere README, .md, .rst, file CI,
  file .po/.pot e directory locale/i18n dal check secrets (evita falsi positivi)
- `_check_dependencies()`: ricerca manifest e lockfile per **basename** (non path esatto),
  rileva correttamente `web/requirements.txt`, `frontend/package.json`, etc.

### Modifiche all'ArchitectureAnalyzer (`analyzers/architecture.py`)
- Aggiunto `LARGE_FILE_SKIP_EXTENSIONS` e `LARGE_FILE_SKIP_NAMES` per escludere
  file non-sorgente (traduzioni .po, LICENSE, CHANGELOG, etc.) dal check file grandi
- Filtro file EXCLUDED (privacy) prima dell'analisi architetturale
- Fix rilevamento migrazioni: cerca in sottodirectory (es. `cms/migrations/`)
- **Normalizzazione per dimensione progetto**: cap le penalita' per file grandi
  (ARCH-SCALE-001) e fan-out (ARCH-COUPLING-002) in base alla percentuale,
  non al numero assoluto. I peggiori offendenti sono MEDIUM, il resto e' INFO.

### Modifiche al profilo scoring (`scoring-profiles/default.yml`)
- Aggiunte regole INFO: `ARCH-SCALE-INFO`, `ARCH-COUPLING-INFO` (peso 0, penalita' 0)
- Totale regole: 31+ (da 19)

### Lockfile detection espanso
- Supportati 17 tipi di lockfile (aggiunto uv.lock, bun.lock, deno.lock, gradle.lockfile, packages.lock.json, paket.lock)

### Context-aware Docker check
- Metodo `_is_deployable()` nell'InfraAnalyzer: verifica se il progetto e' deployable (web framework, API, microservice)
- Set `DEPLOYABLE_FRAMEWORK_NAMES`: Flask, Django, FastAPI, Express, Rails, Spring Boot, etc.
- Se non deployable: emette INFRA-DOCKER-INFO (Info) invece di INFRA-DOCKER-001 (Medium)

### Large file filtering migliorato
- `LARGE_FILE_SKIP_DIRS`: filtra directory vendored (vendor/, node_modules/, third_party/, extern/, bower_components/, etc.)
- Estensioni skip ampliate: aggiunto .xml, .resx, .sql, .json, .yaml, .proto, .graphql, .xaml, .csproj

### --detailed flag
- In modalita' default: finding INFO cappati (non mostrati tutti)
- Con `--detailed`: tutti i finding mostrati, inclusi INFO

### Literature-backed scoring
- Pesi e penalita' calibrati su fonti industriali: IBM/Ponemon Cost of Data Breach, DORA metrics, Boehm's Software Engineering Economics, OWASP Risk Rating
- Commenti rationale nei file YAML del profilo scoring

---

## Fase NEXT — Remediation Pipeline + LLM Integration

### Cosa e' stato fatto

Implementata la pipeline completa di remediation che trasforma lo score deterministico in un piano d'azione prioritizzato con effort, impatto business, e proiezione score. Il sistema funziona 100% senza LLM (graceful degradation) e opzionalmente usa Ollama per generare executive summary.

### Architettura Remediation Pipeline

```
AuditResult (score + findings)
    │
    ├── RemediationLoader (KB YAML → 31 entry con risk_business, steps, effort)
    │       │
    │       └── stack-specific merging (Python/JS/Go override steps)
    │
    ├── ContextCollector (inferisce maturity, team size, infra flags da finding)
    │       │
    │       └── MaturityLevel: PROTOTYPE | MVP | PRODUCTION
    │
    ├── WhatIfSimulator (per ogni regola: rimuovi finding → ricalcola → delta)
    │       │
    │       └── ordina per impact_effort_ratio (delta / avg_hours)
    │
    ├── InterpretationAgent (opzionale, richiede Ollama)
    │       │
    │       ├── LLM disponibile → prompt strutturato → executive summary
    │       ├── LLM non disponibile → fallback deterministico da KB
    │       └── HITL gate → approvazione output LLM (opzionale)
    │
    └── BoardReporter (Markdown deterministico)
            │
            ├── Header (stack, maturity, team size)
            ├── Executive Summary (template o LLM)
            ├── Azioni Prioritarie (top 5 what-if + KB remediation steps)
            ├── Red Flags (critical/high con risk_business)
            ├── Punti di Forza (layer a 100, best practice)
            ├── Score Details (layer scores + evidence chain)
            └── Footer
```

#### Diagramma Mermaid (versione renderizzabile)

```mermaid
flowchart TD
    AR["AuditResult\n(score + findings)"] --> KB["RemediationLoader\n(KB YAML, 31 entry)"]
    AR --> CC["ContextCollector\n(maturity, team size)"]
    AR --> WI["WhatIfSimulator\n(delta score per regola)"]

    KB --> IA["InterpretationAgent"]
    CC --> IA
    WI --> IA

    IA -->|LLM disponibile| LLM["Ollama\n(executive summary)"]
    IA -->|LLM non disponibile| DET["Fallback deterministico\n(template da KB)"]

    LLM --> BR["BoardReporter"]
    DET --> BR

    BR --> Header["Header + Executive Summary"]
    BR --> Actions["Top 5 Azioni Prioritarie"]
    BR --> Flags["Red Flags + Punti di Forza"]
    BR --> Score["Score Details + Evidence"]

    style AR fill:#2563eb,color:white
    style BR fill:#22c55e,color:white
    style IA fill:#7c3aed,color:white
```

### Componenti Nuovi

#### 1. Remediation Knowledge Base (`remediation-kb/default.yml`)
- 31 entry, 1 per ogni regola penalizzante nel profilo scoring default
- Ogni entry contiene: `risk_business` (non-tecnico), `remediation_steps`, `effort_range` (min/max ore + t-shirt), `priority_tier` (1-3), `stack_specific` (override per linguaggio), `references` (NIST, NIS2)
- Cross-validazione automatica nei test: ogni regola penalizzante ha entry nella KB

#### 2. RemediationLoader (`remediation/loader.py`)
- Carica KB da YAML con validazione Pydantic
- `get(rule_id)`: lookup diretto
- `get_for_stack(rule_id, stack_info)`: restituisce entry con steps risolti per lo stack primario

#### 3. WhatIfSimulator (`remediation/simulator.py`)
- Per ogni rule_id: rimuove i finding, ricalcola con `ScoringEngine.calculate()`, misura delta
- Ordina per `impact_effort_ratio = delta / avg_hours`
- Non reimplementa la math dello scoring — riusa `engine.calculate()`

#### 4. ContextCollector (`remediation/context.py`)
- Inferisce: `MaturityLevel` (prototype/mvp/production), `estimated_team_size`, `primary_language/framework`
- Infra signals dai finding: se `INFRA-CICD-001` NON triggered → `has_ci_cd=True`
- Zero accesso filesystem, tutto da `AuditResult`

#### 5. BoardReporter (`reporters/board.py`)
- Report Markdown deterministico per board/management
- 7 sezioni: Header, Executive Summary, Azioni Prioritarie, Red Flags, Punti di Forza, Score Details, Footer
- Funziona 100% senza LLM; se `executive_summary_override` presente, lo usa

#### 6. LLM Provider Abstraction (`llm/`)
- `LLMProvider` Protocol con `generate()`, `is_available()`, `provider_name`
- `OllamaProvider`: httpx → Ollama `/api/generate`, model mapping per `TaskComplexity` (LOW/MEDIUM/HIGH)
- `LLMRouter`: prova provider in ordine, fallback, `generate()` restituisce `None` se nessuno disponibile
- Temperature: LOW=0.0, MEDIUM=0.1, HIGH=0.2

#### 7. InterpretationAgent (`llm/agent.py`)
- Prompt strutturato con contesto, score, top 5 finding critici, top 5 what-if
- Fallback deterministico se LLM non disponibile
- HITL gate opzionale (injectable `hitl_input_fn`, stesso pattern di `HITLReviewer`)

### Modifiche a file esistenti

#### `core/models.py`
- Aggiunto campo `remediation: Any = None` a `AuditResult` (backward compatible)

#### `core/orchestrator.py`
- Aggiunti parametri `board_report` e `no_llm` al costruttore
- Aggiunto metodo `_run_remediation_pipeline()` eseguito dopo lo scoring se `board_report=True`

#### `cli.py`
- Aggiunte opzioni `--board-report` e `--no-llm`
- Se `--board-report` e output specificato, usa `BoardReporter` invece di `MarkdownReporter`

### Design Decisions
1. **Backward compatible**: `remediation=None` di default, tutti i test pre-esistenti invariati
2. **Graceful degradation**: senza Ollama, board report funziona 100% con template KB
3. **ScoringEngine reuse**: What-If non reimplementa la math, usa `engine.calculate()`
4. **KB completeness**: test cross-validazione scoring-profile <-> remediation-kb
5. **HITL per LLM**: opzionale, stesso pattern di HITLReviewer (injectable input_fn)
6. **No nuove dipendenze**: httpx gia' presente, tutto il resto e' pydantic+pyyaml+rich+typer
7. **Temperatura bassa**: LOW=0.0, MEDIUM=0.1, HIGH=0.2 (ripetibilita')

### Test
- `test_remediation_kb.py`: 25 test (modelli, loader, cross-validazione KB <-> profilo)
- `test_whatif.py`: 9 test (simulazione, ordinamento, ratio, profilo default)
- `test_context.py`: 12 test (prototype/mvp/production, team size, linguaggio, info findings)
- `test_board_report.py`: 20 test (sezioni, template vs override, 5 scenari)
- `test_llm.py`: 23 test (config, OllamaProvider mock, LLMRouter fallback)
- `test_llm_agent.py`: 8 test (LLM, fallback, HITL accept/reject, prompt building)
- `test_integration_remediation.py`: 10 test (pipeline E2E, orchestrator, scenari board)
- **Totale nuovi test: 107** (fase remediation/LLM, da 394 a 501)

> **Nota**: Security e Quality analyzer implementati con test dedicati.
> Compliance engine (NIS2, GDPR) implementato con profili YAML e test.
> Scoring profiles: default + vc-diligence, entrambi con citation dalla letteratura.
> Benchmark: 20 repo reali (media 78.3/100) + 9 sintetiche (100% precision/recall).

---

## Blocco 11 — Source Connectors

### Cosa e stato fatto

Implementati 6 source connector per analizzare codice da qualsiasi sorgente. Tutti seguono lo stesso pattern: **clone in temp dir → wrappa in LocalRepoSource → delega i 3 metodi Protocol**.

### `sources/base.py` — TempDirSourceMixin

Context manager che gestisce il ciclo di vita della directory temporanea:
- `__enter__`: crea temp dir, chiama `_materialize()` (abstract), wrappa in `LocalRepoSource`
- `__exit__`: rimuove temp dir con `shutil.rmtree(ignore_errors=True)`
- Se `_materialize()` fallisce, cleanup immediato in `__enter__` (non serve `__exit__`)
- Delega `get_file_tree()`, `read_file()`, `get_metadata()` al `LocalRepoSource` interno

### Source Connectors

| Classe | File | URL Auth Format | Note |
|--------|------|----------------|------|
| `GitHubSource` | `github.py` | `{token}@github.com/...` | Verifica `git` su PATH |
| `GitLabSource` | `gitlab.py` | `oauth2:{token}@gitlab.com/...` | Cloud e self-hosted |
| `AzureDevOpsSource` | `azure_devops.py` | `{token}@dev.azure.com/...` | URL format Azure |
| `BitbucketSource` | `bitbucket.py` | `x-token-auth:{token}@` (cloud), `{token}@` (server) | Flag `server=True` |
| `ArchiveSource` | `archive.py` | N/A | `zipfile`/`tarfile` stdlib, path traversal protection |

Tutti usano `--depth 1` (shallow clone) e supportano branch/tag selection.

### `sources/factory.py` — SourceFactory

Factory con auto-detection dal formato dell'input:
- `github.com` → `GitHubSource`
- `gitlab.com` → `GitLabSource`
- `dev.azure.com` / `visualstudio.com` → `AzureDevOpsSource`
- `bitbucket.org` → `BitbucketSource`
- `.zip`, `.tar.gz`, `.tgz`, `.tar.bz2` → `ArchiveSource`
- Default → `LocalRepoSource`

### Test — 91 test

- `test_source_base.py` (9): context manager, cleanup, materialize failure
- `test_source_github.py` (13): clone args, shallow, branch, tag, token URL rewriting
- `test_source_gitlab.py` (8): URL format `oauth2:{token}@`
- `test_source_azure_devops.py` (8): URL format Azure DevOps
- `test_source_bitbucket.py` (6): cloud e server URL format
- `test_source_archive.py` (10): ZIP/tar.gz reali, estrazione, cleanup
- `test_source_factory.py` (22): routing per tipo, auto-detection, parametri
- `test_source_integration.py` (14): source → FileScanner → StackDetector E2E
- `test_cli_sources_integration.py` (10): CLI + source factory E2E

---

## Blocco 12 — Multi-Source Aggregation

### Cosa e stato fatto

Supporto per audit aggregati su N repository (scenari consulenza: 15 microservizi in 15 repo).

### `core/project.py` — Modelli Pydantic

| Modello | Scopo |
|---------|-------|
| `ProjectSourceConfig` | Configurazione singola sorgente (name, source_type, path_or_url, token_env, branch) |
| `ProjectConfig` | Configurazione progetto (name, sources[]) — parsata da YAML |
| `SourceResult` | Risultato singola sorgente (name, audit_result, loc, error) |
| `AggregatedResult` | Score aggregato con media pesata per LOC, breakdown per repo |

### `core/project_orchestrator.py` — ProjectOrchestrator

- Itera le sorgenti dalla `ProjectConfig`
- Per ciascuna: crea source via `SourceFactory`, esegue `AuditOrchestrator`, raccoglie risultato
- Aggregazione: `score_aggregato = sum(score_i * loc_i) / sum(loc_i)`
- Error handling: se una sorgente fallisce, le altre continuano — errori in `failed_sources`
- Token letti da env var (`token_env` nel YAML config)

### CLI `project` command

```
cto-audit project config.yml [--offline] [-o output.json]
```

### Test — 18 test

- `test_project_models.py` (9): validazione Pydantic, serializzazione YAML
- `test_project_orchestrator.py` (5): aggregazione, error handling, media pesata
- `test_project_integration.py` (4): YAML → orchestrator → risultato E2E

---

## Blocco 13 — Dashboard UI

### Cosa e stato fatto

Dashboard interattiva dark "intelligence style" costruita con Dash + Plotly + dash-bootstrap-components.

### Architettura Dashboard

```
create_app() → Dash app
  ├── layout.py → sidebar navigation + content area + 4 dcc.Store
  ├── callbacks.py → URL routing, scan trigger, deserializzazione
  └── components/ → 8 componenti modulari
```

### Tema (`theme.py`)

- Base: `dbc.themes.CYBORG` (dark bootstrap)
- Sfondo: `#0d1117` (GitHub dark)
- Accenti: `#00ff41` (verde hacker), `#ff3333` (critical), `#f0b400` (warning)
- `score_color(score)`: restituisce il colore in base alla soglia (75+/50+/25+/sotto)
- CSS custom con `@media print` per stampa

### Componenti

| Componente | File | Cosa fa |
|-----------|------|---------|
| Overview | `overview.py` | Gauge health score (`plotly.Indicator`), card layer, stack badges, maturity |
| Layers | `layers.py` | Tab per layer, findings list, evidence chain table |
| Findings | `findings.py` | `DataTable` filtrabile/ordinabile per severity, layer, rule_id |
| Remediation | `remediation.py` | Executive summary card, what-if slider |
| Compliance | `compliance.py` | Ring chart (`plotly.Pie` con hole), compliance card |
| History | `history.py` | Delta score, finding nuovi/risolti |
| Source Picker | `source_picker.py` | Dropdown tipo sorgente, campi condizionali, bottone "Avvia Audit" |
| Project View | `project_view.py` | Score aggregato multi-repo, bar chart per repo |

### Flusso operativo

1. Utente apre la dashboard (`cto-audit ui` o doppio click su exe)
2. Source picker: seleziona tipo sorgente, compila campi, clicca "Avvia Audit"
3. Callback `_run_audit()` esegue scan con `AuditOrchestrator`
4. Risultato salvato in `dcc.Store` (JSON serializzato da Pydantic)
5. Navigazione tra le tab per esplorare risultati

### Test — 43 test

- `test_dashboard_theme.py` (11): colori, soglie, CSS
- `test_dashboard_components.py` (17): ogni componente con dati mock
- `test_dashboard_callbacks.py` (6): logica callback isolata
- `test_dashboard_app_integration.py` (9): app factory, layout, store

---

## Blocco 14 — Executable Standalone + Frozen Mode

### Cosa e stato fatto

Supporto per build eseguibile standalone (.exe/.app) con PyInstaller.

### `exe_entry.py` — Entry point

```python
def main(port=8050):
    app = create_app(title="CTO Audit Agent")
    threading.Timer(1.5, lambda: webbrowser.open(f"http://localhost:{port}")).start()
    app.run(host="127.0.0.1", port=port, debug=False)
```

### `_data.py` — Risoluzione data directory

Cerca le directory dati (scoring-profiles, remediation-kb, compliance-profiles) in 3 percorsi:
1. **Frozen mode**: `sys._MEIPASS / subdir` (PyInstaller)
2. **Installed mode**: `importlib.resources`
3. **Dev mode**: risale dal file fino alla root del repo

### `cto-audit.spec` — PyInstaller spec

- `console=False` — nessuna finestra terminale
- `collect_data_files('dash')`, `collect_data_files('plotly')`, `collect_data_files('dash_bootstrap_components')`
- Include YAML data dirs via `datas`
- Hidden imports per tutti i moduli dinamici

### Test — 11 test

- `test_exe_entry.py` (2): `main()` crea app e chiama `app.run`
- `test_data_frozen.py` (3): `sys._MEIPASS` mockato, fallback
- `test_exe_integration.py` (6): import chain completa, YAML data trovati

---

## Blocco 15 — Agent Mode + Container

### Cosa e stato fatto

Comando `agent` per output JSON headless + Dockerfile per deployment containerizzato.

### CLI `agent` command

```
cto-audit agent <target> [-o output.json] [--offline]
```

- Auto-approve implicito (non chiede conferma)
- JSON su stdout (default) o file (`-o`)
- Log su stderr (non inquina stdout)
- Exit code 0 su successo, 1 su errore

### Dockerfile

- Base: `python:3.12-slim`
- Installa `git` per clone remoti
- Utente non-root (`ctoaudit`)
- `EXPOSE 8050` per dashboard mode

### docker-compose.yml

```yaml
services:
  agent:   # Audit headless con output JSON
    volumes: [./test-repo:/audit:ro, ./output:/output]
    command: agent /audit -o /output/report.json
  dashboard:   # UI interattiva
    ports: ["8050:8050"]
    command: ui --port 8050 --no-browser
```

### Test — 11 test

- `test_agent_mode.py` (7): help, stdout, file, campi attesi, path inesistente, exit code
- `test_agent_integration.py` (4): flusso completo → AuditResult deserializzabile

---

## Blocco 16 — Test End-to-End Completi

### `test_e2e_full_product.py` — 11 test

Suite E2E che verifica l'intero prodotto come lo userebbe un utente:

1. **CLI classica invariata**: `cto-audit scan /repo --auto-approve` con tutte le opzioni
2. **CLI con sorgente remota**: mock subprocess → clone → audit → risultato
3. **Multi-source project**: YAML config con 2 sorgenti → aggregazione
4. **Dashboard lifecycle**: `create_app()` → tutti i componenti renderizzano
5. **Agent mode**: `cto-audit agent /repo -o report.json` → JSON completo
6. **Frozen mode simulation**: mock `sys._MEIPASS` → data dir corretti
7. **Backward compatibility**: import, LocalRepoSource, AuditOrchestrator invariati

### Totale complessivo progetto: 932 test (52 test files)

| Gruppo | Test | File |
|--------|------|------|
| Core (modelli, config, struttura) | 64 | 3 |
| Collectors + HITL | 120 | 6 |
| Analyzers (4 layer) | 105 | 5 |
| Scoring + Compliance | 86 | 5 |
| Remediation + LLM | 107 | 7 |
| Source Connectors | 91 | 9 |
| Multi-Source | 18 | 3 |
| Dashboard | 43 | 4 |
| Executable + Frozen | 11 | 3 |
| Agent Mode | 11 | 2 |
| E2E | 11 | 1 |
| Scenari realistici + Benchmark | 165 | 4 |

---

## Blocco 17 — Due Diligence: layer Provenance e Team

### Cosa e stato fatto

Il tool nasce per il CTO che entra in azienda. La due diligence per conto di un
terzo (investitore, acquirente) pone domande diverse: di chi e il codice, si puo
cedere, c'e un team dietro, e vivo. Nessuno dei 4 layer storici le copriva.
Questo blocco aggiunge due layer, un profilo di scoring, un report dedicato e
un collector git, senza cambiare il comportamento dei profili esistenti.

### `core/models.py` — Layer, GitSummary, AuditResult

- `Layer` passa da 4 a 6 valori: `PROVENANCE` e `TEAM`.
- `LAYER_ORDER` (lista ordinata dei layer) e `CORE_LAYERS` (i 4 storici) sostituiscono
  le liste hardcoded nei reporter.
- `GitSummary`: riepilogo aggregato dello storico git. Per scelta non contiene
  nomi ne email: solo conteggi, quote e finestre temporali.
- `AuditResult` guadagna `git_summary` e `dependency_licenses` (opzionali, default vuoti).
- `AuditMetadata.active_layers`: quali layer sono stati effettivamente analizzati.

### `collectors/git_history.py` — GitHistoryCollector

Esegue `git log --all` (con `--numstat` in una seconda passata) e `git tag` sulla
root della sorgente, con cap a 20.000 commit e timeout 120 s. Calcola: commit
totali e merge, primo/ultimo commit, autori distinti (per email, mai esportati),
commit a 90/180/365 giorni, quota del primo autore (storico intero e ultimi 12
mesi), tag, commit con trailer `Co-Authored-By` di un assistente AI, messaggi
generici, quota di righe inserite dai 3 commit piu grandi, commit per mese.
Degradazione graziosa: git assente, directory non repo, repo vuoto → `available=False`
con `reason`. Clone shallow → `is_shallow=True`.

### `collectors/license_checker.py` — LicenseChecker

Classifica la licenza di ogni dipendenza (riusa `parse_dependencies` del CVE checker)
in cinque categorie: copyleft forte (GPL, AGPL, SSPL), copyleft debole (LGPL, MPL,
EPL, GPL con linking exception), permissiva, non standard/commerciale
("SEE LICENSE IN", "Commercial", URL, UNLICENSED), ignota. Offline usa una KB
curata (`OFFLINE_LICENSE_KB`, verificata sui registri PyPI e npm il 2026-10-06);
online interroga `pypi.org/pypi/<pkg>/json` e `registry.npmjs.org/<pkg>/latest`
inviando solo il nome del pacchetto, dietro lo stesso consenso rete del CVE check.

### `analyzers/provenance.py` — ProvenanceAnalyzer (Layer 5)

| Regola | Severita | Cosa rileva |
|---|---|---|
| PROV-LICENSE-001 | medium | Nessun LICENSE/COPYING/NOTICE e nessuna nota di copyright nel README |
| PROV-OWNLICENSE-INFO | info | Classificazione della licenza del repository stesso (permissiva, copyleft, non standard) |
| PROV-COPYLEFT-001 | high | Dipendenze GPL/AGPL/SSPL |
| PROV-COPYLEFT-002 | low | Dipendenze LGPL/MPL/EPL |
| PROV-COMMERCIAL-001 | medium | Dipendenze con licenza commerciale o non standard |
| PROV-LICENSE-INFO | info | Inventario licenze: quante classificate, quante ignote |
| PROV-VENDORED-001 | medium | File sorgente in vendor/, third_party/, external/... |
| PROV-COPYRIGHT-001 | medium | Header di copyright con 2+ titolari diversi nei sorgenti (progetto senza licenza OSS riconosciuta) |
| PROV-COPYRIGHT-002 | low | Stesso caso in un progetto open source riconosciuto: titolari multipli attesi |
| PROV-CLAIMS-001 | low | README dichiara Dockerfile/Helm chart/IaC/CI/test senza riscontro nel repo (le istruzioni d'uso come `docker run` non contano) |
| PROV-CERT-INFO | info | README dichiara SOC 2, ISO 27001, HIPAA, PCI DSS... (non verificabili dal codice) |
| PROV-SBOM-001 | low | Nessun file SBOM (CycloneDX/SPDX); framework_ref NIS2 Art.21(2)(d) |

### `analyzers/team.py` — TeamAnalyzer (Layer 6)

Riceve il `GitSummary` dall'orchestrator (nessun accesso al filesystem).

| Regola | Severita | Soglia |
|---|---|---|
| TEAM-GIT-INFO | info | Storico non disponibile o shallow (su clone shallow si valuta solo l'attivita recente) |
| TEAM-BUSFACTOR-001 | high | Autore unico con >=10 commit, oppure primo autore >=80% con >=20 commit (finestra 12 mesi se popolata, altrimenti storico intero) |
| TEAM-ACTIVITY-001 | high | Ultimo commit >180 giorni fa |
| TEAM-ACTIVITY-002 | medium | Ultimo commit tra 90 e 180 giorni fa |
| TEAM-HISTORY-001 | medium | I 3 commit piu grandi coprono >=60% delle righe inserite |
| TEAM-HISTORY-002 | low | Meno di 5 commit (storia non valutabile; valutazione si ferma qui) |
| TEAM-RELEASE-001 | low | Nessun tag con >=100 commit |
| TEAM-MSGQUAL-001 | low | >=40% di messaggi generici su >=20 commit |
| TEAM-AIGEN-INFO | info | Quota di commit con co-autore AI dichiarato |

Riferimento per il bus factor: Avelino, Passos, Hora, Valente, *A Novel Approach
for Estimating Truck Factors*, ICPC 2016 (arXiv:1604.06766).

### Scoring e orchestrator

- `scoring/profile.py`: i layer validi derivano dall'enum `Layer`, non da una lista fissa.
- `scoring/engine.py`: un layer entra in `layer_scores` solo se pesato dal profilo
  o se ha prodotto finding. Con `default` e `vc-diligence` l'output e identico a prima.
  `LAYER_RULES` include le regole dei due layer nuovi per il calcolo della confidence.
- `core/orchestrator.py`: carica il profilo prima degli analyzer e lancia solo i layer
  pesati (`_active_layers`, che rispetta anche `--focus`). Se Team o Provenance sono
  attivi, esegue `GitHistoryCollector` una volta sola sulla root (locale o clone
  temporaneo, `_resolve_root`). Il pannello di consenso rete elenca anche i registri
  PyPI/npm quando Provenance e attivo.
- `scoring-profiles/due-diligence.yml`: 6 layer, pesi security 0.25, provenance 0.20,
  team 0.15, architecture 0.15, quality 0.15, infra 0.10; 63 regole.
- `cli.py`: con layer Team attivo (profilo due-diligence o `--focus team`) le sorgenti remote
  vengono clonate con storico completo (`shallow=False`), altrimenti bus factor e storico
  sarebbero artefatti del clone.
- `remediation-kb/due-diligence.yml`: 16 entry (9 PROV + 7 TEAM). `RemediationLoader.load_all()`
  unisce tutte le KB della directory; `from_yaml("default")` resta invariata (37 entry).

### `reporters/due_diligence.py` — DueDiligenceReporter

Report Markdown lato acquirente, deterministico, dieci sezioni: perimetro e limiti,
sintesi con deal flag (regole su cedibilita, continuita, secret esposti), inventario
dell'asset (incluso storico git e inventario licenze), red flag e yellow flag con il
rischio dalla KB, dichiarazioni vs evidenze, costo di remediation in ore (somma degli
effort KB per regola scattata), domande per il management (template per regola),
compliance, evidence chain. CLI: `cto-audit scan <target> --due-diligence --output dd.md`
(il flag imposta il profilo `due-diligence` se non specificato e attiva la pipeline
remediation per le stime di effort).

### Gate HITL obbligatorio sull'output LLM

Prima di questo blocco l'orchestrator costruiva `InterpretationAgent(router, kb)` senza
`hitl_enabled`: il testo di Ollama finiva nel board report senza approvazione, in
contrasto con quanto documentato. Ora `_run_remediation_pipeline`:

- con `--no-llm` non interpella l'LLM (motivo registrato in `llm_skipped_reason`);
- con `--auto-approve` (nessun revisore: CI, agent mode) non interpella l'LLM, perche
  l'output richiederebbe un'approvazione che nessuno puo dare;
- altrimenti interpella l'LLM con `hitl_enabled=True` e mostra l'output in un pannello
  (`_llm_approval_input`); solo la risposta `s`/`si`/`y`/`yes` lo inserisce nel report,
  EOF o interruzione valgono come rifiuto e si torna al template deterministico.

`RemediationPipelineResult` registra `llm_hitl_approved` e `llm_skipped_reason`; il report
di due diligence etichetta l'executive summary come "generato da LLM, approvato dal
revisore" oppure "template deterministico" e spiega il motivo. Il router e iniettabile
(`AuditOrchestrator(llm_router=...)`) per i test (`test_llm_hitl.py`, 8 test).

### Reporter esistenti

`terminal`, `markdown`, `html`, `board`, `comparison`: le liste hardcoded dei 4 layer
sono sostituite da `LAYER_ORDER`; le mappe dei nomi includono i due layer nuovi. Con i
profili a 4 layer non cambia nulla, perche i layer assenti vengono saltati.

### Bug fix collaterale — `.gitignore` in `sources/local.py`

I pattern con path (`benchmarks/repos/`), ancorati (`/dist`) o con glob su path
(`docs/*.tmp`) venivano confrontati con il singolo componente del percorso e non
escludevano nulla. Lo scan della repo del tool stesso leggeva 36.000 file dei clone
di benchmark (oltre 5 minuti); dopo il fix ne legge 172 (1 secondo). Inoltre i file
"mai ignorati" (`setup.py`, `requirements.txt`, ...) ora restano esclusi se stanno
dentro una directory ignorata.

### Test — 1.053 totali (58 file; 121 nuovi in 6 file)

I 43 test della dashboard richiedono `dash` installato (`pip install cto-audit[ui]`); gli altri 1.010 girano nel venv base.

| File | Test | Cosa copre |
|---|---|---|
| `test_git_history.py` | 13 | Collector su repo git reali in tmp_path; assenza di PII nel summary; parsing |
| `test_team.py` | 19 | Ogni regola del TeamAnalyzer su GitSummary sintetici |
| `test_provenance.py` | 54 | classify_license, LicenseChecker offline/online (MockTransport), ogni regola |
| `test_due_diligence.py` | 23 | Profilo, engine a 4 e 6 layer, orchestrator end-to-end, report, CLI |
| `test_gitignore_nested.py` | 4 | Regressione pattern annidati, ancorati, con path |
| `test_llm_hitl.py` | 8 | Gate di approvazione sull'output LLM: approva, rifiuta, headless, --no-llm, etichette nel report |
