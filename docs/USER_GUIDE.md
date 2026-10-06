# CTO Audit Agent — User Guide

Guida pratica per interpretare i risultati, personalizzare i profili e ottenere il massimo dall'audit.

## Indice

1. [Prerequisiti e Setup](#prerequisiti-e-setup)
2. [Quick Start](#quick-start)
3. [Come funziona lo scoring](#come-funziona-lo-scoring)
4. [Confidence Score](#confidence-score)
5. [Project Type Detection](#project-type-detection)
6. [Interpretare il punteggio](#interpretare-il-punteggio)
7. [I 4 layer di analisi](#i-4-layer-di-analisi)
8. [Leggere il report](#leggere-il-report)
9. [Profili di scoring](#profili-di-scoring)
10. [Creare un profilo personalizzato](#creare-un-profilo-personalizzato)
11. [Compliance NIS2 e GDPR](#compliance-nis2-e-gdpr)
12. [Board Report e Remediation](#board-report-e-remediation)
13. [Formati di output](#formati-di-output)
14. [Source Connectors (sorgenti remote)](#source-connectors)
15. [Audit Multi-Repo](#audit-multi-repo)
16. [Dashboard Interattiva](#dashboard-interattiva)
17. [Agent Mode e Container](#agent-mode-e-container)
18. [Eseguibile Standalone](#eseguibile-standalone)
19. [Scenari d'uso comuni](#scenari-duso-comuni)
20. [FAQ](#faq)
21. [Storico Audit e Delta](#storico-audit-e-delta)
22. [Accesso alla Rete](#accesso-alla-rete)

---

## Prerequisiti e Setup

### Cosa serve

1. **Python 3.11 o superiore** — scaricalo da [python.org](https://www.python.org/downloads/). Durante l'installazione su Windows, spunta **"Add Python to PATH"**.
2. **Un terminale** — e la finestra dove digiti i comandi. Vedi sotto come aprirlo.
3. **Il codice da analizzare** — una cartella sul tuo computer contenente il progetto.

### Come aprire il terminale

| Sistema Operativo | Come fare |
|---|---|
| **Windows** | Premi `Win + R`, scrivi `cmd`, premi Invio. Oppure cerca "Prompt dei comandi" nel menu Start. In alternativa usa PowerShell o Windows Terminal. |
| **macOS** | Apri Spotlight (`Cmd + Spazio`), scrivi `Terminal`, premi Invio. |
| **Linux** | Premi `Ctrl + Alt + T` oppure cerca "Terminal" tra le applicazioni. |
| **VS Code** | Se usi VS Code, apri il terminale integrato con `` Ctrl + ` `` (backtick). |

### Installazione passo-passo

Apri il terminale e digita questi comandi uno alla volta, premendo Invio dopo ciascuno:

```bash
# 1. Verifica che Python sia installato
python --version
```

Dovresti vedere qualcosa come `Python 3.12.x`. Se da errore, Python non e installato o non e nel PATH.

```bash
# 2. Clona e installa CTO Audit Agent
git clone https://github.com/PhysicsInforMe/cto-audit-agent.git
cd cto-audit-agent
pip install -e .
```

Aspetta che finisca (puo richiedere 1-2 minuti). Vedrai del testo scorrere — e normale.

```bash
# 3. Verifica che funzioni
cto-audit --help
```

Se vedi il menu di aiuto, sei pronto.

### Nota sui percorsi

Nei comandi sotto, `/path/to/codebase` e un segnaposto — sostituiscilo col percorso reale della cartella del progetto da analizzare. Esempi:

| Sistema | Esempio percorso |
|---|---|
| Windows | `C:\Users\mario\progetti\mio-progetto` |
| macOS/Linux | `/home/mario/progetti/mio-progetto` |
| Cartella corrente | `.` (un punto — significa "la cartella in cui mi trovo adesso") |

---

## Quick Start

Apri il terminale e digita:

```bash
# Audit base — output nel terminale
cto-audit scan /path/to/codebase

# Report Markdown dettagliato
cto-audit scan /path/to/codebase --detailed -o report.md

# Report HTML (si apre nel browser)
cto-audit scan /path/to/codebase -o report.html

# Report PDF (richiede: pip install cto-audit[pdf])
cto-audit scan /path/to/codebase -o report.pdf
```

Dove trovare il report generato: nella cartella da cui hai lanciato il comando (la "cartella corrente" del terminale). Per sapere quale sia, digita `cd` (Windows) o `pwd` (macOS/Linux).

---

## Come funziona lo scoring

### Formula

Lo **Health Score** (0-100) e una media pesata dei punteggi dei 4 layer:

```
Health Score = security × 0.30 + architecture × 0.25 + infra × 0.25 + quality × 0.20
```

Ogni **layer score** parte da 100 e viene decrementato per ogni finding rilevato:

```
Layer Score = max(0, 100 - somma(|penalty| × weight))
```

Dove:
- **penalty**: punti sottratti per la regola (es. -20 per niente CI/CD)
- **weight**: peso della regola nel profilo (0.0-1.0)

### Catena di evidenza

Ogni punto perso e tracciabile fino alla sua origine:

```
Finding (es. "Nessun CI/CD rilevato")
  → Regola (INFRA-CICD-001, penalty: -20, weight: 0.9)
    → Layer Score (Infra: 82/100)
      → Health Score (85/100)
        → Fonte (Google DORA State of DevOps 2024)
```

### Perche questi pesi?

I pesi dei layer sono basati sulla **conseguenza** (costo/tempo di riparazione), non sulla frequenza:

| Layer | Peso | Rationale |
|---|---|---|
| **Security** | 0.30 | Conseguenza massima: breach avg $4.44M (IBM/Ponemon 2025), sanzioni GDPR fino a 4% fatturato, 241 giorni per contenere |
| **Architecture** | 0.25 | Costo che cresce esponenzialmente nel tempo (Fowler). $1.52T in tech debt accumulato (CISQ 2022) |
| **Infrastructure** | 0.25 | Importante ma recuperabile. DORA 2024: elite teams MTTR <1h. CI/CD si aggiunge in settimane |
| **Quality** | 0.20 | Amplificatore: defect in produzione costa 10-100x (Boehm 1981). 42% del tempo dev su tech debt (Stripe 2018) |

---

## Confidence Score

Ogni layer score include una **confidence** (0.0-1.0) che indica quanto il tool e sicuro del punteggio assegnato. Un Security 100/100 con confidence 30% significa che il tool ha verificato poco — conviene approfondire manualmente.

### Come viene calcolata

La confidence di ogni layer si basa su:
1. **Coverage** (70%): quante regole del layer sono state effettivamente verificate rispetto a quelle applicabili
2. **Finding confidence** (30%): media della confidence dei finding rilevati

### Come leggerla

| Confidence | Badge | Significato |
|---|---|---|
| >= 0.7 | alta | Il tool ha verificato la maggior parte delle regole applicabili |
| 0.4 - 0.69 | media | Verifica parziale, alcune regole non controllabili |
| < 0.4 | bassa | Il tool ha verificato poco, il punteggio potrebbe non essere rappresentativo |

### Context-awareness

La confidence tiene conto del **tipo di progetto**: per una libreria Python, le regole web-specific (SEC-AUTH-001, SEC-CORS-001, SEC-HEADERS-001, SEC-SQL-001) vengono escluse dal calcolo, alzando la confidence. Senza questa correzione, una libreria avrebbe confidence artificialmente bassa perche le regole web non sono verificabili.

Lo **Health Score complessivo** ha una `overall_confidence` calcolata come media pesata delle confidence dei layer (con gli stessi pesi dei layer).

---

## Project Type Detection

Il tool rileva automaticamente il **tipo di progetto** per rendere l'analisi context-aware.

### Tipi supportati

| Tipo | Descrizione | Esempio |
|---|---|---|
| `web_app` | Backend API / web service | Flask, Django, Express, FastAPI |
| `frontend` | Frontend SPA senza backend | React, Vue, Angular |
| `full_stack` | Frontend + Backend | Django + React, Next.js |
| `library` | Pacchetto/libreria riusabile | pip package, npm module |
| `cli_tool` | Tool da riga di comando | click, argparse, typer |
| `data_pipeline` | ETL, ML, data processing | pandas, sklearn, torch |
| `prototype` | Piccolo, sperimentale | <20 file, no CI, no test |
| `unknown` | Non classificabile | Nessun segnale forte |

### Come funziona

Il rilevamento usa 3 livelli in cascata:

1. **Rule-based** (sempre attivo): analizza file tree, dipendenze e framework per classificare il progetto
2. **TF-IDF** (opzionale): analizza il README con TF-IDF per migliorare la confidence (nessuna dipendenza esterna)
3. **Sentence-BERT** (opzionale): usa `sentence-transformers` per classificazione piu accurata (richiede `pip install cto-audit[nlp]`)

Il sistema funziona al 100% senza NLP. I livelli 2 e 3 migliorano solo la confidence del rilevamento.

### Impatto sull'analisi

Il tipo di progetto influenza:
- **Confidence score**: le regole non applicabili vengono escluse dal calcolo
- **Report**: il tipo rilevato e la sua confidence vengono mostrati nell'header del report

---

## Interpretare il punteggio

### Scala di riferimento

| Range | Giudizio | Significato |
|---|---|---|
| **90-100** | Eccellente | Pratiche mature, rischio minimo. Team di esperienza |
| **75-89** | Buono | Solida base con alcune aree di miglioramento |
| **60-74** | Sufficiente | Funziona ma accumula tech debt. Interventi necessari |
| **40-59** | Insufficiente | Rischi significativi. Remediation urgente su piu fronti |
| **0-39** | Critico | Rischio operativo elevato. Intervento immediato necessario |

### Come leggere i layer score

Non guardare solo lo Health Score complessivo. I layer score individuali raccontano la storia:

- **Infra 45, Security 90**: il team sa fare security ma non ha automatizzato il deploy. Rischio operativo ma non di breach.
- **Security 40, resto 80+**: rischio critico. Un singolo incidente puo essere esistenziale. Priorita assoluta.
- **Quality 50, Architecture 50**: tech debt accumulato. Il team rallenta e ogni change rischia regressioni.

### Cosa NON misura il punteggio

- **Correttezza funzionale**: l'audit non esegue il codice, non sa se fa quello che deve
- **Performance runtime**: non misura latenza, throughput o scalabilita a runtime
- **Business logic**: non valuta se il prodotto e valido dal punto di vista business
- **Skill del team**: misura gli artefatti, non le persone

---

## I 4 layer di analisi

### Layer 1: Infrastructure (peso: 0.25)

Misura la maturita operativa del progetto.

| Regola | Severity | Penalty | Cosa rileva |
|---|---|---|---|
| INFRA-CICD-001 | high | -20 | Nessuna CI/CD pipeline (GitHub Actions, GitLab CI, Jenkins...) |
| INFRA-DOCKER-001 | medium | -8 | Nessuna containerizzazione (solo per progetti deployable) |
| INFRA-DOCKER-INFO | info | 0 | Docker assente in progetto non-deployable (nessuna penalita) |
| INFRA-DOCKER-002 | low | -3 | .dockerignore mancante |
| INFRA-DOCKER-003 | medium | -5 | Dockerfile senza multi-stage build |
| INFRA-DOCKER-004 | medium | -8 | Dockerfile che esegue come root |
| INFRA-DOCKER-005 | low | -3 | Dockerfile senza HEALTHCHECK |
| INFRA-IAC-001 | high | -10 | Nessun Infrastructure as Code (Terraform, CloudFormation...) |
| INFRA-DEPS-001 | high | -12 | Nessun lockfile (package-lock.json, Pipfile.lock...) |
| INFRA-CONFIG-001 | high | -15 | File .env con dati sensibili nel repository |
| INFRA-CONFIG-002 | high | -15 | Secrets in file di configurazione (.yml, .ini, .conf) |
| INFRA-MON-001 | medium | -8 | Nessun monitoraggio (Sentry, Datadog, Prometheus...) |
| INFRA-ENVEXAMPLE-001 | medium | -5 | `.env` in .gitignore ma nessun `.env.example` o `.env.sample` |

**Context-aware**: INFRA-DOCKER-001 non scatta per librerie, CLI tool o scraper. Solo i progetti "deployable" (web framework rilevato) vengono penalizzati per l'assenza di Docker. I progetti non-deployable ricevono INFRA-DOCKER-INFO (informativo, 0 penalty).

### Layer 2: Architecture (peso: 0.25)

Misura la sostenibilita e manutenibilita nel tempo.

| Regola | Severity | Penalty | Cosa rileva |
|---|---|---|---|
| ARCH-STRUCT-001 | medium | -8 | Struttura directory piatta o caotica |
| ARCH-COUPLING-001 | high | -15 | Import circolari (Python e JS/TS) |
| ARCH-COUPLING-002 | medium | -5 | Fan-out eccessivo (un file importa troppi moduli) |
| ARCH-SCALE-001 | medium | -3 | File con piu di 500 righe di codice (normalizzato) |
| ARCH-TEST-001 | critical | -22 | Nessuna directory o file di test |
| ARCH-DB-001 | medium | -8 | ORM presente ma nessuna gestione migrazioni |

### Layer 3: Security (peso: 0.30)

Misura il rischio di breach e la compliance normativa. 9 regole totali.

| Regola | Severity | Penalty | Cosa rileva |
|---|---|---|---|
| SEC-SECRETS-CODE-001 | critical | -25 | Secrets hardcodati nel codice sorgente e config (.properties, .yml, .ini) |
| SEC-SQL-001 | high | -18 | Possibile SQL Injection via string concatenation |
| SEC-AUTH-001 | high | -15 | Nessun framework di autenticazione |
| SEC-DEPS-CVE-001 | high | -15 | CVE note trovate nelle dipendenze (fonte: Google OSV, richiede rete) |
| SEC-DEPS-001 | high | -12 | Dipendenze con versioni notoriamente vulnerabili (check statico) |
| SEC-CRYPTO-001 | medium | -8 | Pattern crittografici deboli (MD5, SHA1, DES, RC4) |
| SEC-HTTPS-001 | medium | -5 | URL HTTP non cifrati nel codice |
| SEC-CORS-001 | medium | -5 | CORS permissivo (`*` origins) |
| SEC-HEADERS-001 | low | -3 | Nessun middleware per security headers |

**SEC-DEPS-CVE-001** interroga l'API OSV di Google per CVE note nelle dipendenze. Richiede connessione a internet. In modalita `--offline`, questo check viene saltato. Supporta 7 ecosistemi: PyPI, npm, crates.io, Go, RubyGems, Maven, Packagist.

### Layer 4: Quality (peso: 0.20)

Misura l'igiene del codice e la velocita di iterazione. 10 regole totali.

| Regola | Severity | Penalty | Cosa rileva |
|---|---|---|---|
| QUAL-DOC-001 | medium | -8 | Nessun README nella root |
| QUAL-LINT-001 | medium | -8 | Nessun linter o formatter configurato |
| QUAL-COMPLEXITY-001 | medium | -7 | Codice eccessivamente annidato (nesting profondo) |
| QUAL-DOC-002 | low | -3 | Documentazione inline insufficiente |
| QUAL-TYPING-001 | low | -3 | Nessun type checking configurato |
| QUAL-DUP-001 | low | -3 | File con nome identico in directory diverse (copy-paste) |
| QUAL-PRECOMMIT-001 | medium | -5 | Nessun pre-commit hook (pre-commit, husky, lefthook) |
| QUAL-EDITORCONFIG-001 | low | -2 | Nessun `.editorconfig` nella root |
| QUAL-CONTRIBUTING-001 | low | -2 | Nessun `CONTRIBUTING.md` nella root |
| QUAL-CHANGELOG-001 | low | -2 | Nessun `CHANGELOG.md` (o `CHANGES.md`, `HISTORY.md`) |

---

## Leggere il report

### Severity dei finding

| Severity | Significato | Azione |
|---|---|---|
| **critical** | Rischio immediato, potenzialmente esistenziale | Fix immediato |
| **high** | Rischio significativo per operativita o sicurezza | Fix entro sprint corrente |
| **medium** | Problema reale ma gestibile | Pianificare nel backlog |
| **low** | Miglioramento consigliato, non urgente | Nice-to-have |
| **info** | Osservazione informativa, nessuna penalita | Solo per contesto |

### Report standard vs dettagliato

Il report **standard** (senza `--detailed`) mostra:
- Health Score e layer score
- Solo i finding con severity critical, high e medium
- Limita il numero di finding INFO mostrati

Il report **dettagliato** (`--detailed`) aggiunge:
- Tutti i finding, inclusi INFO e low
- Catena di evidenza completa per ogni finding
- Statistiche dettagliate per layer

---

## Profili di scoring

CTO Audit Agent include 2 profili di scoring:

### Profilo `default`

Bilanciato, adatto alla maggior parte degli audit tecnici.

```
layer_weights:
  security: 0.30
  architecture: 0.25
  infra: 0.25
  quality: 0.20
```

### Profilo `vc-diligence`

Per due diligence pre-investimento. Enfatizza security e compliance.

```
layer_weights:
  security: 0.35      # Un breach pre-investimento e deal-breaker
  architecture: 0.25   # Tech debt = costo nascosto post-investimento
  quality: 0.20        # Velocita iterazione team
  infra: 0.20          # Recuperabile post-investimento
```

Differenze chiave:
- Security pesa 0.35 (vs 0.30): un breach pre-investimento puo far saltare il deal
- Infra pesa 0.20 (vs 0.25): recuperabile post-investimento
- Penalita SEC-* aumentate del 20-30%: rischio compliance per l'investitore

```bash
# Usare il profilo VC
cto-audit scan /path/to/codebase --scoring vc-diligence
```

---

## Creare un profilo personalizzato

Puoi creare profili di scoring personalizzati copiando e modificando un profilo esistente.

### Struttura di un profilo YAML

```yaml
name: my-profile
description: "Il mio profilo personalizzato"

# Pesi layer — devono sommare a 1.0
layer_weights:
  security: 0.40      # Enfatizzare security
  architecture: 0.20
  infra: 0.20
  quality: 0.20

# Peso default per regole non elencate
default_rule_weight: 0.5

# Regole
rules:
  INFRA-CICD-001:
    severity: high
    weight: 0.9        # 0.0 = irrilevante, 1.0 = massimo peso
    penalty: -20        # Punti sottratti dal layer score
    description: "Nessun CI/CD pipeline rilevato"

  # Per disabilitare una regola: weight 0.0 e penalty 0
  INFRA-DOCKER-001:
    severity: info
    weight: 0.0
    penalty: 0
    description: "Docker non rilevante per questo contesto"
```

### Come personalizzare

1. **Copia** un profilo esistente da `scoring-profiles/`
2. **Modifica** i `layer_weights` per riflettere le tue priorita
3. **Aggiusta** le penalty delle singole regole
4. **Salva** nella directory `scoring-profiles/`
5. **Usa** con `--scoring nome-profilo`

### Regole per la personalizzazione

- I `layer_weights` **devono sommare a 1.0**
- Le `penalty` sono numeri negativi (es. -20 sottrae 20 punti dal layer)
- Il `weight` va da 0.0 (regola ignorata) a 1.0 (peso massimo)
- Per **disabilitare** una regola: imposta `weight: 0.0` e `penalty: 0`
- I `severity` validi sono: `critical`, `high`, `medium`, `low`, `info`

---

## Compliance NIS2 e GDPR

CTO Audit Agent include profili di compliance per la Direttiva NIS2 (UE 2022/2555) e il GDPR.

### Come funziona

Il motore di compliance mappa le regole dell'audit ai controlli normativi:

```
Regola INFRA-CICD-001 → NIS2 Art. 21(2)(b) "Gestione degli incidenti"
Regola SEC-SECRETS-CODE-001 → GDPR Art. 32(1)(a) "Crittografia dei dati personali"
```

Se una regola mappata a un controllo produce un finding, il controllo risulta **NON SODDISFATTO**.

### Modalita operative

```bash
# Cross-cutting: compliance come overlay sull'audit standard
cto-audit scan /path --compliance nis2,gdpr --compliance-mode cross-cutting

# Standalone: solo i controlli compliance, senza scoring
cto-audit scan /path --compliance nis2 --compliance-mode standalone

# Hybrid (default): entrambi
cto-audit scan /path --compliance nis2,gdpr
```

### Cosa copre

**NIS2 Art. 21(2)** — 10 controlli mappati:
- (a) Analisi dei rischi e politiche di sicurezza
- (b) Gestione degli incidenti
- (c) Continuita operativa
- (d) Sicurezza della catena di approvvigionamento
- (e) Sicurezza di rete e sistemi informativi
- (f) Valutazione dell'efficacia delle misure
- (g) Pratiche di base di igiene informatica
- (h) Politiche sull'uso della crittografia
- (i) Sicurezza delle risorse umane
- (j) Autenticazione multi-fattore

**GDPR** — 5 controlli mappati (focalizzati su sicurezza tecnica):
- Art. 25 Privacy by design
- Art. 32(1)(a) Crittografia
- Art. 32(1)(b) Riservatezza e integrita
- Art. 32(1)(c) Ripristino accesso ai dati
- Art. 32(1)(d) Verifica e valutazione regolare

---

## Board Report e Remediation

Il board report e pensato per stakeholder non tecnici: CTO, board, investitori.

```bash
cto-audit scan /path/to/codebase --board-report -o board.md
```

### Cosa contiene

1. **Executive Summary**: punteggio complessivo e giudizio sintetico
2. **Risk Assessment**: le aree di rischio piu critiche
3. **What-If Analysis**: simulazione dell'impatto delle correzioni
4. **Remediation Roadmap**: piano d'azione prioritizzato con stime di effort

### What-If Simulator

Il simulatore calcola quanto migliorerebbe il punteggio correggendo ogni finding:

```
Se correggi SEC-SECRETS-CODE-001:
  Score attuale: 62 → Score proiettato: 69 (+7 punti)
  Effort stimato: 4-16 ore (T-shirt: M)
  Impatto/Effort ratio: 1.75
```

Le correzioni sono ordinate per **impatto/effort ratio**: massimo miglioramento col minimo sforzo.

### Knowledge Base

La KB contiene 37 entry, una per ogni regola penalizzante, con:
- **risk_business**: perche questa debolezza e un rischio per il business
- **remediation_steps**: passi concreti per la correzione
- **effort_range**: stima ore (min-max) e T-shirt size (XS/S/M/L/XL)
- **stack_specific**: istruzioni specifiche per linguaggio (Python, Node.js, etc.)
- **references**: fonti normative e best practice

---

## Formati di output

| Formato | Estensione | Comando | Note |
|---|---|---|---|
| Terminal | - | `cto-audit scan /path` | Output colorato con Rich |
| Markdown | `.md` | `-o report.md` | Adatto a commit nel repo |
| HTML | `.html` | `-o report.html` | Con stili CSS integrati |
| PDF | `.pdf` | `-o report.pdf` | Richiede `pip install cto-audit[pdf]` |
| JSON | `.json` | `-o report.json` | Per integrazione programmatica |

### Board Report

Il board report e un formato separato, non dipende dall'estensione:

```bash
# Board report in Markdown
cto-audit scan /path --board-report -o board.md

# Board report nel terminale
cto-audit scan /path --board-report
```

---

## Source Connectors

CTO Audit Agent puo analizzare codice da sorgenti diverse, non solo directory locali.

### Sorgenti supportate

| Sorgente | Esempio | Auto-detect |
|---|---|---|
| **Locale** | `cto-audit scan /path/to/repo` | Default |
| **GitHub** | `cto-audit scan https://github.com/owner/repo` | `github.com` nell'URL |
| **GitLab** | `cto-audit scan https://gitlab.com/owner/repo` | `gitlab.com` nell'URL |
| **Azure DevOps** | `cto-audit scan https://dev.azure.com/org/project/_git/repo` | `dev.azure.com` nell'URL |
| **Bitbucket** | `cto-audit scan https://bitbucket.org/owner/repo` | `bitbucket.org` nell'URL |
| **Archivio** | `cto-audit scan /path/to/code.zip` | Estensione `.zip`/`.tar.gz` |

### Auto-detection

Il tipo di sorgente viene rilevato automaticamente dall'input. Puoi forzarlo con `--source-type`:

```bash
cto-audit scan https://github.com/owner/repo --source-type github
```

### Autenticazione per repo private

Usa `--token` o la variabile d'ambiente `CTO_AUDIT_TOKEN`:

```bash
# Via flag
cto-audit scan https://github.com/owner/private-repo --token ghp_xxxxx

# Via env var
export CTO_AUDIT_TOKEN=ghp_xxxxx
cto-audit scan https://github.com/owner/private-repo
```

Il token non viene mai loggato o persistito. Viene usato solo per il clone e rimosso dalla memoria.

### Branch e tag

```bash
# Clone di un branch specifico
cto-audit scan https://github.com/owner/repo --branch develop

# Clone di un tag
cto-audit scan https://github.com/owner/repo --branch v2.0.0
```

### Come funziona

Tutte le sorgenti remote seguono lo stesso pattern:
1. Clone shallow (`--depth 1`) in directory temporanea
2. Wrap in `LocalRepoSource` (stessa logica di analisi)
3. Cleanup automatico al termine (`__exit__` del context manager)

Requisito: `git` deve essere installato e nel PATH per le sorgenti Git.

---

## Audit Multi-Repo

Per scenari di consulenza con N repository (es. 15 microservizi), puoi creare un file YAML di configurazione:

### Formato config

```yaml
# project.yml
name: "Acme Platform"
sources:
  - name: "backend-api"
    source_type: "github"
    path_or_url: "https://github.com/acme/api"
    token_env: "GITHUB_TOKEN"     # legge il token da questa env var
    branch: "main"
  - name: "frontend"
    source_type: "local"
    path_or_url: "/path/to/frontend"
  - name: "shared-libs"
    source_type: "zip"
    path_or_url: "/path/to/libs.zip"
```

### Esecuzione

```bash
cto-audit project project.yml -o aggregated.json
cto-audit project project.yml --offline -o aggregated.json
```

### Output

Il JSON di output contiene:
- `project_name`: nome del progetto
- `aggregated_score`: score complessivo (media pesata per LOC)
- `source_results`: risultato individuale per ogni sorgente
- `aggregated_layer_scores`: score per layer aggregato
- `total_loc`: LOC totali del progetto
- `failed_sources`: sorgenti che hanno fallito (le altre continuano)

### Come funziona l'aggregazione

Lo score aggregato e una **media pesata per LOC** (Lines of Code):

```
score_aggregato = sum(score_i * loc_i) / sum(loc_i)
```

Un repository con 50.000 LOC pesa 10x rispetto a uno con 5.000 LOC.

---

## Dashboard Interattiva

La dashboard offre un'interfaccia visuale dark "intelligence style" per navigare i risultati dell'audit.

### Prerequisiti

```bash
pip install cto-audit[ui]
```

### Avvio

```bash
# Apre il browser automaticamente
cto-audit ui

# Porta personalizzata
cto-audit ui --port 9000

# Senza aprire il browser (utile in container)
cto-audit ui --no-browser
```

### Sezioni della dashboard

| Sezione | Cosa mostra |
|---|---|
| **Overview** | Gauge health score, card per ogni layer, stack badges, maturity |
| **Layers** | Tab per layer con findings dettagliati e evidence chain |
| **Findings** | Tabella filtrabile e ordinabile per severity, layer, rule_id |
| **Remediation** | Azioni prioritarie, scatter chart effort vs impatto, what-if slider |
| **Compliance** | Ring chart per profilo NIS2/GDPR con progress e stato controlli |
| **History** | Trend score nel tempo, delta finding nuovi/risolti |
| **Source Picker** | Seleziona sorgente (locale/remota), compila campi, avvia audit dalla UI |
| **Project View** | Vista multi-repo con score aggregato e breakdown per repo |

### Flusso operativo

1. Apri la dashboard (`cto-audit ui`)
2. Nella sezione **Source Picker**, seleziona il tipo di sorgente
3. Compila il percorso/URL e eventuali opzioni
4. Clicca "Avvia Audit"
5. Naviga tra le tab per esplorare i risultati

---

## Agent Mode e Container

Il comando `agent` produce output JSON puro, ideale per CI/CD e container Docker.

### Agent mode

```bash
# JSON su file
cto-audit agent /path/to/repo -o report.json --offline

# JSON su stdout (per piping)
cto-audit agent /path/to/repo --offline | jq '.health_score.overall_score'
```

Caratteristiche:
- Auto-approve implicito (non chiede conferma)
- Log su stderr (non inquina stdout)
- Exit code 0 su successo, 1 su errore
- Output JSON deserializzabile in `AuditResult`

### Container Docker

```bash
# Build
docker build -t cto-audit .

# Audit con volume mount (codice read-only)
docker run -v /code:/audit:ro -v /out:/output cto-audit agent /audit -o /output/report.json

# Dashboard in container
docker run -p 8050:8050 cto-audit ui --port 8050 --no-browser
```

Il codice e montato read-only. Solo il report JSON esce dal container. Il cliente puo ispezionare l'immagine Docker.

### docker-compose

```yaml
services:
  agent:
    build: .
    volumes:
      - ./test-repo:/audit:ro
      - ./output:/output
    command: agent /audit -o /output/report.json

  dashboard:
    build: .
    ports:
      - "8050:8050"
    command: ui --port 8050 --no-browser
```

---

## Eseguibile Standalone

L'utente non-tecnico scarica l'exe, doppio click, si apre la dashboard nel browser. Zero Python, zero pip, zero terminale.

### Build

```bash
pip install cto-audit[build]
python scripts/build_exe.py
# → dist/cto-audit.exe (Windows) o dist/cto-audit (macOS/Linux)
```

### Cosa include l'exe

- Dashboard completa con tutti i componenti
- Tutti i profili YAML (scoring, compliance, remediation KB)
- Asset Dash/Plotly/Bootstrap
- Git deve essere installato separatamente per le sorgenti remote

---

## Scenari d'uso comuni

### Audit rapido prima di un merge

```bash
cto-audit scan . --offline --auto-approve
```

Nessuna connessione, nessuna interazione. Mostra il risultato nel terminale.

### Due diligence tecnica per investitore

```bash
cto-audit scan /path \
  --scoring vc-diligence \
  --compliance nis2,gdpr \
  --board-report \
  --detailed \
  -o diligence-report.html
```

Usa il profilo VC, attiva compliance, genera board report dettagliato in HTML.

### Audit solo security

```bash
cto-audit scan /path --focus security -o security-audit.md
```

Analizza solo il layer security, utile per review mirate.

### Report per il management

```bash
cto-audit scan /path --board-report --no-llm -o board.md
```

Board report senza LLM (usa solo template deterministici dalla KB).

### Confronto tra versioni

Esegui due audit su commit diversi e confronta i JSON:

```bash
git checkout v1.0
cto-audit scan . --auto-approve --offline -o v1.json

git checkout v2.0
cto-audit scan . --auto-approve --offline -o v2.json
```

### Export per integrazione CI/CD

```bash
cto-audit scan . --auto-approve --offline -o audit.json
# Poi parsare audit.json nel CI per gate di qualita
```

### Audit di un repo GitHub privato

```bash
export CTO_AUDIT_TOKEN=ghp_xxxxx
cto-audit scan https://github.com/acme/private-api --auto-approve -o report.json
```

### Audit multi-repo per consulenza

```bash
# Crea project.yml con le sorgenti
cto-audit project project.yml --offline -o audit-acme.json
```

### Audit in container Docker

```bash
docker run -v /cliente/codice:/audit:ro -v ./out:/output cto-audit agent /audit -o /output/report.json
```

Il codice resta read-only, solo il JSON esce.

### Dashboard per presentazione

```bash
pip install cto-audit[ui]
cto-audit ui --port 8050
# Apri nel browser, naviga tra le tab, screenshot per la presentazione
```

---

## Storico Audit e Delta

Ogni volta che esegui un audit, il risultato viene salvato automaticamente in `.cto-audit/history/` dentro la directory del progetto scansionato. Al run successivo, il tool carica l'ultimo risultato e mostra il **delta**:

- **Score trend**: come e cambiato il punteggio complessivo e per layer
- **Finding nuovi**: problemi emersi dopo l'ultimo audit
- **Finding risolti**: problemi che il team ha corretto
- **Finding persistenti**: problemi ancora presenti
- **Giorni trascorsi**: tempo dall'ultimo audit

Il delta viene mostrato in tutti i formati di output (terminale, Markdown, HTML, JSON).

### Esempio di workflow

```bash
# Primo audit (nessun delta)
cto-audit scan /path/to/project --auto-approve --offline

# ... il team corregge alcuni problemi ...

# Secondo audit (mostra delta)
cto-audit scan /path/to/project --auto-approve --offline
```

Il secondo run mostrera automaticamente il confronto con il primo.

### File salvati

I risultati vengono salvati come file JSON in:
```
/path/to/project/.cto-audit/history/YYYYMMDD_HHMMSS.json
```

Puoi aggiungere `.cto-audit/` al tuo `.gitignore` se non vuoi committare lo storico.

---

## Accesso alla Rete

Il tool accede alla rete **solo** per il check CVE delle dipendenze, tramite l'API OSV di Google.

### Cosa succede senza `--offline`

Quando il tool arriva alla fase di security analysis, mostra un **pannello informativo** che spiega:
- **Cosa viene inviato**: nome e versione dei pacchetti (es. "requests 2.31.0")
- **A chi**: Google OSV (https://osv.dev)
- **Cosa NON viene inviato**: codice sorgente, percorsi file, nomi progetto, dati personali

L'utente puo **acconsentire** (il check CVE viene eseguito) o **rifiutare** (lo scan continua senza CVE). Nessun dato viene inviato senza consenso esplicito.

### Comportamento dei flag

| Situazione | Comportamento |
|---|---|
| Nessun flag | Mostra pannello consenso, l'utente sceglie |
| `--offline` | Nessun accesso alla rete, nessuna domanda |
| `--auto-approve` | Consenso implicito, CVE check attivo |
| `--auto-approve --offline` | Nessun accesso alla rete, nessuna domanda |

---

## FAQ

### Il punteggio 75/100 e buono o cattivo?

Dipende dal contesto. 75 per una startup early-stage e ottimo. 75 per un sistema che processa dati finanziari in produzione potrebbe non essere sufficiente, soprattutto se il layer Security e basso.

### Perche il mio progetto prende penalita per Docker se e una libreria?

Non dovrebbe. Il check Docker e **context-aware**: se il tool non rileva web framework nel progetto, emette un finding INFO (senza penalita) invece che un finding MEDIUM. Se il tuo progetto e una libreria e prende penalita Docker, potrebbe avere file che suggeriscono un web framework (es. `manage.py`, `app.py` con Flask/Django import).

### Posso disabilitare una regola specifica?

Si. Crea un profilo personalizzato e imposta la regola con `weight: 0.0` e `penalty: 0`. Vedi la sezione [Creare un profilo personalizzato](#creare-un-profilo-personalizzato).

### Il tool invia dati all'esterno?

Con `--offline`, nessun dato esce dalla macchina. Senza `--offline`, il tool mostra un pannello informativo prima del check CVE e chiede il consenso esplicito. Se acconsenti, vengono inviati solo nome, versione ed ecosistema delle dipendenze (es. "django 4.2 PyPI") all'API OSV di Google, **mai il codice sorgente**. Se rifiuti, lo scan continua senza CVE.

### Come funziona il gate HITL?

Prima dell'analisi, i file vengono classificati in 4 categorie di privacy:
- **SAFE**: file di configurazione, manifest, CI/CD
- **LOCAL_LLM**: codice sorgente analizzabile con LLM locale
- **SENSITIVE**: file con potenziali dati sensibili
- **EXCLUDED**: file esclusi dall'analisi

Il gate HITL chiede conferma prima di procedere. Con `--auto-approve` viene saltato.

### Quali linguaggi sono supportati?

L'analisi funziona su qualsiasi codebase. Il rilevamento stack e ottimizzato per:
Python, JavaScript/TypeScript, Java, Go, Rust, Ruby, PHP, C#/.NET, C/C++, Swift, Kotlin, Scala, Dart, Elixir.

Il check CVE delle dipendenze supporta 7 ecosistemi: PyPI, npm, crates.io, Go, RubyGems, Maven, Packagist.

### Come si confronta con SonarQube?

SonarQube analizza il codice riga per riga (lint, bug pattern, code smell). CTO Audit Agent analizza il progetto dal punto di vista di un CTO: infrastruttura, architettura, sicurezza operativa, compliance. Sono complementari, non alternativi.
