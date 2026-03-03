# CTO Audit Agent — Guida per il Tester

Hai ricevuto questo tool da testare e non sai da dove partire? Questa guida e per te.

## Cos'e questo tool

CTO Audit Agent e un tool da riga di comando che **analizza un codebase come farebbe un CTO esperto**. Non e un linter (non guarda le singole righe di codice), ma analizza il progetto dall'alto:

- **Ha una CI/CD pipeline?** (GitHub Actions, GitLab CI, Jenkins...)
- **Ha test?** (directory test/, file *_test.py, etc.)
- **Ci sono secrets esposti?** (chiavi API hardcoded, .env nel repo)
- **L'architettura e sana?** (import circolari, file giganti, coupling eccessivo)
- **La security e ok?** (SQL injection, dipendenze vulnerabili, CORS aperto)
- **La qualita del codice?** (README, linter, type checking, documentazione, pre-commit, editorconfig, contributing, changelog)

Produce un **punteggio da 0 a 100** con **confidence score** per ogni layer e un report dettagliato con i problemi trovati. Rileva automaticamente il **tipo di progetto** (web app, libreria, CLI tool, ecc.) per rendere l'analisi context-aware.

## Requisiti

- **Python 3.11+** — scaricalo da [python.org](https://www.python.org/downloads/). Su Windows, durante l'installazione spunta **"Add Python to PATH"**.
- **~50 MB di spazio disco** per l'installazione
- **Git** (opzionale) — serve solo se vuoi scaricare repo open source da testare (Test 2). Scaricalo da [git-scm.com](https://git-scm.com/downloads).

## Dove si eseguono i comandi?

Tutti i comandi di questa guida (quelli nei riquadri grigi) vanno digitati in un **terminale**, cioe una finestra testuale dove scrivi comandi e premi Invio.

**Come aprire il terminale:**

| Sistema | Come fare |
|---|---|
| **Windows** | Premi `Win + R`, scrivi `cmd`, premi Invio. Oppure cerca "Prompt dei comandi" o "PowerShell" nel menu Start. |
| **macOS** | Premi `Cmd + Spazio`, scrivi `Terminal`, premi Invio. |
| **Linux** | Premi `Ctrl + Alt + T` oppure cerca "Terminal" tra le applicazioni. |
| **VS Code** | Apri il terminale integrato con `` Ctrl + ` `` (il tasto backtick, sopra Tab). |

**Come funzionano i percorsi:**

Nei comandi vedrai `/path/to/progetto` — e un segnaposto. Sostituiscilo col percorso reale della cartella. Esempi:

- Windows: `C:\Users\mario\progetti\mio-app`
- macOS/Linux: `/home/mario/progetti/mio-app`
- Cartella corrente: `.` (un punto = "qui dove mi trovo adesso")

Per sapere in quale cartella ti trovi, digita `cd` (Windows) o `pwd` (macOS/Linux).

## Installazione (2 minuti)

Hai ricevuto la cartella del progetto CTO Audit Agent (via zip, chiavetta, cartella condivisa, ecc.). Apri il terminale e segui questi passi **uno alla volta**, premendo Invio dopo ciascuno.

### Passo 1: Entra nella cartella del progetto

```bash
# Sostituisci con il percorso reale della cartella che hai ricevuto.
# Esempio Windows:
cd C:\Users\mario\Desktop\progetto-CTOAgent

# Esempio Mac/Linux:
cd ~/Desktop/progetto-CTOAgent
```

### Passo 2: Crea un ambiente Python isolato

Questo crea una copia locale di Python dentro la cartella, cosi le dipendenze non interferiscono col resto del sistema.

```bash
python -m venv .venv
```

### Passo 3: Attiva l'ambiente

Scegli il comando giusto per il tuo sistema:

```bash
# Windows (Prompt dei comandi):
.venv\Scripts\activate

# Windows (PowerShell):
.venv\Scripts\Activate.ps1

# Mac/Linux:
source .venv/bin/activate
```

Se ha funzionato, vedrai `(.venv)` comparire all'inizio della riga nel terminale.

### Passo 4: Installa le dipendenze

```bash
pip install -e ".[dev]"
```

Aspetta che finisca (1-2 minuti, vedrai del testo scorrere — e normale).

### Passo 5: Verifica

```bash
cto-audit --help
```

Se vedi il menu di aiuto, sei pronto. Se da errore tipo "comando non trovato", verifica che l'ambiente sia attivo (punto 3).

**Nota importante**: ogni volta che apri un nuovo terminale per usare il tool, devi prima ripetere il punto 1 (entrare nella cartella) e il punto 3 (attivare l'ambiente). L'installazione (punti 2 e 4) si fa una volta sola.

## Il tuo primo audit (1 minuto)

Prova subito su un progetto che hai sul tuo computer:

```bash
cto-audit scan /path/to/un/tuo/progetto --auto-approve --offline
```

Sostituisci `/path/to/un/tuo/progetto` con un percorso reale, per esempio:
- Windows: `cto-audit scan C:\Users\mario\progetti\mio-sito --auto-approve --offline`
- macOS: `cto-audit scan ~/progetti/mio-sito --auto-approve --offline`

Vedrai un output colorato con:
- **Health Score**: il punteggio complessivo (0-100)
- **Layer Score**: punteggio per ognuno dei 4 layer (Infra, Architecture, Security, Quality)
- **Finding**: lista dei problemi trovati, con severity e descrizione

---

## Riferimento Opzioni

Questa e la lista completa delle opzioni disponibili. Le puoi vedere anche digitando `cto-audit scan --help`.

Il formato base e sempre: `cto-audit scan PERCORSO [OPZIONI]`

### Tutte le opzioni

| Opzione | Abbreviazione | Cosa fa | Valori possibili |
|---|---|---|---|
| `--offline` | | Disabilita le chiamate di rete senza fare domande. Senza questo flag, il tool mostra un pannello informativo prima del check CVE e chiede il consenso. Con `--offline` tutto funziona al 100% senza internet e senza interazione. | |
| `--auto-approve` | | Salta la schermata interattiva di classificazione privacy. Normalmente il tool mostra quali file ha trovato e chiede conferma prima di procedere. Con questa opzione procede direttamente. | |
| `--output` | `-o` | Salva il report su file invece di mostrarlo nel terminale. Il formato dipende dall'estensione del file. | `.md` `.html` `.json` `.pdf` |
| `--detailed` | | Mostra tutti i finding nel report, inclusi quelli informativi e a bassa severita. Senza questa opzione il report mostra solo i problemi importanti. | |
| `--focus` | `-f` | Analizza solo uno dei 4 layer invece di tutti. | `security` `architecture` `infra` `quality` |
| `--scoring` | `-s` | Cambia il profilo di scoring (i pesi delle regole). | `default` `vc-diligence` |
| `--compliance` | `-c` | Attiva la verifica di compliance normativa. Puoi attivare piu profili separandoli con virgola. | `nis2` `gdpr` `nis2,gdpr` |
| `--compliance-mode` | | Come integrare la compliance nell'analisi. | `hybrid` (default) `cross-cutting` `standalone` |
| `--board-report` | | Genera un report pensato per il management: executive summary, risk assessment, what-if analysis, piano di remediation. | |
| `--no-llm` | | Disabilita l'integrazione con Ollama (LLM locale). Il report usa solo template deterministici dalla Knowledge Base. Utile se non hai Ollama installato. | |
| `--reuse-classification` | | Riusa la classificazione privacy di un run precedente invece di rifarla da zero. | |

### Combinazioni consigliate per il test

Queste sono le combinazioni piu utili da provare. In tutti gli esempi, sostituisci `/path/to/project` col percorso reale.

| # | Comando | Cosa testa | Output atteso |
|---|---|---|---|
| 1 | `cto-audit scan /path/to/project --auto-approve --offline` | Audit base, risultato nel terminale | Score + finding colorati nel terminale |
| 2 | `cto-audit scan /path/to/project --auto-approve --offline -o report.md` | Report Markdown | File `report.md` nella cartella corrente |
| 3 | `cto-audit scan /path/to/project --auto-approve --offline -o report.html` | Report HTML | File `report.html` (aprilo nel browser) |
| 4 | `cto-audit scan /path/to/project --auto-approve --offline -o report.json` | Export JSON | File `report.json` (dati strutturati) |
| 5 | `cto-audit scan /path/to/project --auto-approve --offline --detailed -o detailed.md` | Report con tutti i finding | File `detailed.md` (piu lungo del report base) |
| 6 | `cto-audit scan /path/to/project --auto-approve --offline --focus security` | Solo layer security | Score e finding solo di sicurezza |
| 7 | `cto-audit scan /path/to/project --auto-approve --offline --focus infra` | Solo layer infrastruttura | Score e finding solo di infrastruttura |
| 8 | `cto-audit scan /path/to/project --auto-approve --offline --focus architecture` | Solo layer architettura | Score e finding solo di architettura |
| 9 | `cto-audit scan /path/to/project --auto-approve --offline --focus quality` | Solo layer qualita | Score e finding solo di qualita |
| 10 | `cto-audit scan /path/to/project --auto-approve --offline --scoring vc-diligence -o vc.md` | Profilo VC (pesi diversi) | Score diverso dal default (security pesa di piu) |
| 11 | `cto-audit scan /path/to/project --auto-approve --offline --compliance nis2,gdpr -o compliance.md` | Compliance NIS2 + GDPR | Report con sezione compliance (controlli PASS/FAIL) |
| 12 | `cto-audit scan /path/to/project --auto-approve --offline --compliance nis2 --compliance-mode standalone` | Solo compliance NIS2 | Solo controlli NIS2, senza scoring generale |
| 13 | `cto-audit scan /path/to/project --auto-approve --no-llm --board-report -o board.md` | Board report senza LLM | Report per management con remediation e what-if |
| 14 | `cto-audit scan /path/to/project --auto-approve --offline --scoring vc-diligence --compliance nis2,gdpr --board-report --detailed -o full.html` | Tutto insieme | Report completo: VC scoring + compliance + board + dettagliato |
| 15 | `cto-audit scan /path/to/project --auto-approve` | Con check CVE online | Come #1 ma interroga anche l'API Google OSV per vulnerabilita note nelle dipendenze |
| 16 | `cto-audit scan /path/to/project --auto-approve` | Consenso rete interattivo | Pannello che chiede consenso per check CVE — rifiutare e verificare che lo scan continui senza CVE |

**Nota**: `--auto-approve` e `--offline` si usano quasi sempre durante il test per comodita. In un uso reale potresti voler togliere `--auto-approve` (per vedere la classificazione privacy e il consenso rete) e `--offline` (per avere il check CVE con consenso informato).

---

## Scenari di Test

### Test 1: Il tuo progetto personale

Lancia il comando #1 della tabella sopra su un tuo progetto e chiediti:
- Il punteggio ha senso? Un progetto ben curato dovrebbe stare sopra 75.
- I finding rilevati sono veri? Se dice "nessun test", guarda se hai effettivamente test.
- Ci sono falsi positivi? Problemi segnalati che non sono reali?
- Manca qualcosa di ovvio? Problemi noti del tuo progetto che il tool non ha rilevato?

### Test 2: Un progetto open source noto

Scarica un progetto open source e auditalo. Puoi farlo in due modi:

**Opzione A — con Git** (se lo hai installato):
```bash
git clone https://github.com/tiangolo/full-stack-fastapi-template.git
cto-audit scan full-stack-fastapi-template --auto-approve --offline -o report.md
```

**Opzione B — senza Git** (scarica lo zip dal browser):
1. Vai su https://github.com/tiangolo/full-stack-fastapi-template
2. Clicca il bottone verde "Code" → "Download ZIP"
3. Estrai lo zip in una cartella
4. Lancia l'audit su quella cartella:
```bash
cto-audit scan /path/to/cartella-estratta --auto-approve --offline -o report.md
```

Apri `report.md` (con un editor di testo o VS Code) e verifica che il report sia leggibile e coerente.

### Test 3: Confronta profilo default vs VC

Lancia il comando #1 e poi il #10 sullo stesso progetto. Il punteggio dovrebbe essere diverso perche il profilo VC pesa di piu la security (35% vs 30%).

### Test 4: Compliance

Lancia il comando #11. Il report dovra contenere una sezione "Compliance" con una lista di controlli NIS2 e GDPR, ciascuno con stato PASS, PARTIAL o FAIL.

### Test 5: Board report

Lancia il comando #13. Questo genera un report pensato per un non-tecnico. Verifica che sia leggibile e che contenga: executive summary, what-if analysis ("se correggi X, il punteggio sale a Y"), piano di remediation.

### Test 6: Progetto vuoto / minimale

Crea una cartella con un solo file Python e auditala:

```bash
# Mac/Linux:
mkdir /tmp/empty-project
echo "print('hello')" > /tmp/empty-project/main.py
cto-audit scan /tmp/empty-project --auto-approve --offline

# Windows (Prompt dei comandi):
mkdir %TEMP%\empty-project
echo print('hello') > %TEMP%\empty-project\main.py
cto-audit scan %TEMP%\empty-project --auto-approve --offline
```

Un progetto minimale dovrebbe avere un punteggio basso (40-60). Verifica che non crashi.

### Test 7: Progetto grande

Se hai accesso a un monorepo o progetto con 1000+ file, lancia il comando #1. Dovrebbe completare in meno di 2-3 minuti per ~5000 file.

### Test 8: Tutto insieme

Lancia il comando #14. E il test piu completo: combina profilo VC, compliance NIS2+GDPR, board report, report dettagliato, output HTML. Verifica che il file HTML si apra nel browser e contenga tutte le sezioni.

### Test 9: Storico audit e delta

Lancia lo stesso audit due volte sullo stesso progetto:

```bash
# Primo run
cto-audit scan /path/to/project --auto-approve --offline

# Secondo run (stessa cartella)
cto-audit scan /path/to/project --auto-approve --offline
```

Il secondo run dovrebbe mostrare un pannello "DELTA RISPETTO ALL'ULTIMO AUDIT" con:
- Score precedente → score attuale (e la differenza)
- Giorni dall'ultimo audit
- Finding nuovi, risolti e persistenti

Verifica anche che la directory `.cto-audit/history/` sia stata creata nel progetto scansionato, con file JSON al suo interno.

### Test 10: Consenso rete

Lancia il tool senza `--offline` e senza `--auto-approve`:

```bash
cto-audit scan /path/to/project
```

Dopo la classificazione privacy, dovrebbe apparire un pannello "ACCESSO ALLA RETE" che spiega cosa viene inviato e chiede conferma. Prova entrambi i casi:

1. **Rifiuta** (digita "n"): lo scan deve continuare, ma senza check CVE
2. **Accetta** (digita "s"): lo scan include il check CVE delle dipendenze

### Test 11: Confidence score

Lancia un audit e verifica che ogni layer score abbia un **badge di confidence** accanto:

```bash
cto-audit scan /path/to/project --auto-approve --offline
```

L'output dovrebbe mostrare per ogni layer qualcosa come:
```
  Security:       100/100  [confidence: bassa]
  Infrastructure:  67/100  [confidence: alta]
```

Verifica che:
- La confidence sia tra 0% e 100%
- Un progetto con poche regole verificabili (es. una libreria senza web framework) abbia confidence bassa nel layer Security
- Un progetto completo (web app con CI/CD, test, Docker, ecc.) abbia confidence alta

### Test 12: Project type detection

Lancia un audit e verifica che l'header del report mostri il **tipo di progetto rilevato**:

```bash
cto-audit scan /path/to/project --auto-approve --offline
```

L'output dovrebbe indicare il tipo (es. "web_app", "library", "cli_tool") con la confidence del rilevamento.

Prova con diversi tipi di progetto:
- Un progetto **Flask/Django/FastAPI** dovrebbe essere rilevato come `web_app`
- Un progetto con solo **setup.py/pyproject.toml** senza web framework dovrebbe essere `library`
- Un progetto con **React/Vue/Angular** dovrebbe essere `frontend`
- Un progetto molto piccolo (pochi file, no CI, no test) dovrebbe essere `prototype`

### Test 13: Nuove regole quality

Crea una cartella di test senza i file di quality e verifica che vengano segnalati:

```bash
mkdir /tmp/test-quality
echo "print('hello')" > /tmp/test-quality/main.py
echo "# My Project" > /tmp/test-quality/README.md
cto-audit scan /tmp/test-quality --auto-approve --offline --focus quality
```

Dovrebbero comparire finding per:
- **QUAL-PRECOMMIT-001**: nessun pre-commit hook
- **QUAL-EDITORCONFIG-001**: nessun `.editorconfig`
- **QUAL-CONTRIBUTING-001**: nessun `CONTRIBUTING.md`
- **QUAL-CHANGELOG-001**: nessun `CHANGELOG.md`

### Test 14: Regola INFRA-ENVEXAMPLE-001

Crea un progetto con `.gitignore` che ignora `.env` ma senza `.env.example`:

```bash
mkdir /tmp/test-env
echo "print('hello')" > /tmp/test-env/main.py
echo ".env" > /tmp/test-env/.gitignore
cto-audit scan /tmp/test-env --auto-approve --offline --focus infra
```

Dovrebbe comparire il finding **INFRA-ENVEXAMPLE-001**. Poi aggiungi un `.env.example` e riscansiona — il finding dovrebbe sparire:

```bash
echo "DB_URL=" > /tmp/test-env/.env.example
cto-audit scan /tmp/test-env --auto-approve --offline --focus infra
```

### Test 15: Secrets in file di configurazione (.properties, .yml, .ini)

Crea un progetto con un file `.properties` con password hardcodata:

```bash
mkdir -p /tmp/test-secrets/src/main/resources
echo "spring.datasource.password=petclinic" > /tmp/test-secrets/src/main/resources/application-mysql.properties
echo "print('hello')" > /tmp/test-secrets/app.py
cto-audit scan /tmp/test-secrets --auto-approve --offline --focus security
```

Dovrebbe comparire **SEC-SECRETS-CODE-001** con menzione del file `.properties`. Verifica che i placeholder vengano correttamente ignorati:

```bash
echo "spring.datasource.password=\${DB_PASSWORD}" > /tmp/test-secrets/src/main/resources/application-mysql.properties
cto-audit scan /tmp/test-secrets --auto-approve --offline --focus security
```

Con `${DB_PASSWORD}` il finding **NON** dovrebbe comparire. Stessa cosa con `ENC(...)`, valori vuoti, o file che contengono "test" nel nome.

---

## Come riportare problemi

Quando trovi un problema, segnalalo con queste informazioni:

1. **Comando esatto** che hai lanciato (copia-incolla dal terminale)
2. **Output** (o screenshot) del problema
3. **Cosa ti aspettavi** vs cosa e successo
4. **Sistema operativo** (Windows/Mac/Linux)
5. **Versione Python** (`python --version`)

### Categorie di problemi da cercare

| Categoria | Esempio |
|---|---|
| **Crash** | Il tool si blocca o da errore Python |
| **Falso positivo** | Segnala un problema che non esiste |
| **Falso negativo** | Non rileva un problema evidente |
| **Punteggio assurdo** | Score 95 per un progetto pessimo, o 20 per uno ottimo |
| **Report illeggibile** | Testo troncato, formattazione rotta, dati mancanti |
| **Lentezza** | >3 minuti per <5000 file |
| **UX** | Messaggi confusi, output non chiaro |

---

## Cosa NON fa il tool

Per evitare aspettative sbagliate:

- **Non esegue il codice**: analisi puramente statica
- **Non verifica la correttezza funzionale**: non sa se il codice fa quello che deve
- **Non e un linter**: non segnala variabili inutilizzate o stile del codice
- **Non analizza performance runtime**: non misura latenza o memory
- **Non accede a servizi cloud**: non controlla la configurazione AWS/GCP
- **Non legge i commit**: analizza solo lo stato attuale dei file

---

## Linguaggi supportati

L'analisi funziona su qualsiasi codebase. Il rilevamento stack e ottimizzato per:
Python, JavaScript/TypeScript, Java, Go, Rust, Ruby, PHP, C#/.NET, C/C++, Swift, Kotlin, Scala, Dart, Elixir.

---

## Struttura del punteggio

```
Health Score (0-100) = media pesata dei 4 layer:
  - Security (30%): rischio breach e compliance
  - Architecture (25%): sostenibilita nel tempo
  - Infrastructure (25%): maturita operativa
  - Quality (20%): igiene del codice

Ogni layer parte da 100 e perde punti per ogni problema trovato.
Ogni layer ha un confidence score (0-100%) che indica
quanto il tool e sicuro del punteggio assegnato.
```

| Range | Giudizio |
|---|---|
| 90-100 | Eccellente |
| 75-89 | Buono |
| 60-74 | Sufficiente |
| 40-59 | Insufficiente |
| 0-39 | Critico |

---

## Hai problemi?

- Il tool non si installa? Verifica Python 3.11+ e che il virtual environment sia attivo (vedi sezione Installazione).
- Crash su un progetto specifico? Prova con `--offline` e `--auto-approve`.
- Output vuoto? Il progetto potrebbe essere troppo piccolo o avere solo file binari.
- Domande? Contatta chi ti ha mandato il tool.
