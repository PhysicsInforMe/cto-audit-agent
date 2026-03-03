# CTO Audit Agent — Human-in-the-Loop Classification Flow
# v8.0 — Defensible Scoring + Full Benchmark Validation

> **Stato (v0.4.0)**: Il flusso HITL e' **completamente implementato** e testato (733 test).
> Il PrivacyClassifier classifica automaticamente in 3 categorie (EXCLUDED, SENSITIVE, SAFE).
> La categoria LOCAL_LLM esiste nel modello ma viene assegnata solo tramite override HITL.
> Il Compliance Engine e' **implementato** con profili NIS2 e GDPR in modalita' ibrida.
> Tutti e 4 gli analyzer sono **operativi** (Infra 10, Architecture 7, Security 9, Quality 10 regole).
> L'integrazione LLM e' **implementata** (Ollama provider, InterpretationAgent) per
> generazione executive summary nei board report.
> **Post-validazione**: soglia entropia alzata a 5.0, aggiunto filtro placeholder/annotazioni
> tipo, aggiunta whitelist NEVER_IGNORE_FILES per impedire al .gitignore di escludere
> file critici (requirements.txt, Dockerfile, etc.).
> Validato su 29 repo (20 reali + 9 sintetiche).

## Principio

**Nessun byte di codice lascia la macchina del cliente senza consenso esplicito.**

La classificazione automatica è un suggerimento. L'umano ha l'ultima parola.
Sempre. Sia in modalità consulente che in modalità self-service.

---

## Flusso Completo

```
FASE 1: SCAN              FASE 2: CLASSIF.         FASE 3: REVIEW UMANO          FASE 4: ANALISI
(automatica)               (automatica)              (interattiva)                 (automatica)

┌──────────┐              ┌──────────────┐          ┌─────────────────┐           ┌──────────────┐
│ Scan     │              │ Classificatore│         │ REVIEW UMANO    │           │ 4 Layer      │
│ file     │─────────────▶│ Privacy       │────────▶│                 │──────────▶│ + Compliance │
│ system   │              │               │         │ Conferma/       │           │ + Scoring    │
│          │              │ Ogni file →   │         │ Correggi/       │           │              │
│ Stack    │              │ 🟢🟡🔴⚫     │         │ Override        │           │ Tutto rispetta│
│ detect   │              │               │         │                 │           │ la classif.  │
└──────────┘              └──────────────┘          └─────────────────┘           └──────────────┘
                                                           │
                                                    ██████████████████
                                                    █  GATE DI STOP  █
                                                    █  Nulla procede █
                                                    █  senza OK      █
                                                    ██████████████████
```

Le 4 categorie:
- 🟢 **SAFE** → LLM Cloud (qualità massima)
- 🟡 **LOCAL LLM** → Ollama locale (qualità media)
- 🔴 **SENSITIVE** → Solo analisi locale, no LLM (qualità ridotta)
- ⚫ **ESCLUSO** → File ignorato

**Importante**: i check di compliance rispettano la classificazione privacy. Se un check GDPR richiede analisi LLM su un file SENSITIVE, il check viene eseguito in modalita' deterministica (qualita' ridotta) oppure via Ollama locale se disponibile.

> **Stato attuale**: La classificazione privacy e' operativa e influenza il routing
> dell'analisi. I file EXCLUDED vengono filtrati e non analizzati. I file SENSITIVE
> vengono segnalati e analizzati solo con check deterministici. Security e Quality
> analyzer sono implementati con check deterministici. L'integrazione LLM (Ollama)
> e' attiva per la generazione dell'executive summary nei board report.

---

## Comportamento in Base alla Modalità

| Aspetto | Modalità Consulente | Modalità Self-service |
|---------|--------------------|-----------------------|
| HITL gate | **Obbligatorio** | Obbligatorio, skippabile con `--auto-approve` |
| Default classificazione | Conservativo | Standard |
| Spostamento SENSITIVE→SAFE | Richiede `CONFERMO` | Richiede `CONFERMO` |

---

## Fase 3 in Dettaglio: La Review Interattiva

### Step 1 — Presentazione del Summary

```
╔══════════════════════════════════════════════════════════════╗
║           📋 CLASSIFICATION REVIEW — Progetto X             ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Scansionati: 312 file | 45,231 LOC                         ║
║  Stack rilevato: Python (FastAPI) + JavaScript (React)       ║
║  Infra rilevata: Docker + GitHub Actions                     ║
║                                                              ║
║  🟢 SAFE (LLM cloud):             280 file                  ║
║  🟡 LOCAL LLM (Ollama):             0 file                  ║
║  🔴 SENSITIVE (solo locale):        25 file                  ║
║  ⚫ ESCLUSI (vendor/binari/gen.):     7 file                 ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  FILE CLASSIFICATI COME 🔴 SENSITIVE:                        ║
║                                                              ║
║   #  File                          Motivo                    ║
║  ─────────────────────────────────────────────────────────── ║
║   1  .env                          Variabili ambiente        ║
║   2  .env.production               Variabili ambiente        ║
║   3  config/database.yml           Connection string         ║
║   4  config/secrets.yml            Nome file sospetto        ║
║   5  src/auth/keys.py              API key rilevata          ║
║   6  deploy/prod-config.ini        Credenziali server        ║
║   7  certs/server.pem              Certificato               ║
║   8  certs/private.key             Chiave privata            ║
║   9  src/payments/stripe.py        Token di pagamento        ║
║  10  docker-compose.prod.yml       Password nel file         ║
║  ... (altri 15 file)                                         ║
║                                                              ║
║  FILE 🟢 SAFE — CAMPIONE (i più rilevanti):                 ║
║   1  src/api/routes.py             Route definitions         ║
║   2  src/models/user.py            Data model                ║
║   3  Dockerfile                    Container config          ║
║   4  .github/workflows/ci.yml      CI/CD pipeline            ║
║  ... (altri 276 file)                                        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

### Step 2 — Azioni Disponibili

```
Cosa vuoi fare?

  [C] ✅ Conferma classificazione e procedi
  [V] 👁️  Visualizza tutti i file SAFE (280)
  [S] 👁️  Visualizza dettaglio file SENSITIVE (25)
  [X] 👁️  Visualizza file ESCLUSI
  [E] ✏️  Modifica classificazione di un file
  [A] 🔒 Sposta TUTTO a SENSITIVE (analisi 100% locale)
  [Q] ❌ Annulla audit

  Scelta: _
```

### Step 3 — Modifica Classificazione (SAFE → altro)

```
  Inserisci numero file o path: 3

  📄 src/services/order.py
  Classificazione attuale: 🟢 SAFE
  Motivo auto: Nessun pattern sensibile rilevato

  Nuova classificazione:
  [1] Mantieni 🟢 SAFE → LLM cloud (qualità massima)
  [2] Sposta a 🟡 LOCAL LLM → Ollama locale (qualità media)
  [3] Sposta a 🔴 SENSITIVE → solo locale (qualità ridotta)
  [4] Sposta a ⚫ ESCLUDI → ignorato

  Scelta: 2

  ⚠️  NOTA: L'analisi via LLM locale è meno accurata.
  I finding (inclusi quelli di compliance) potrebbero essere meno precisi.
  Confermi? [s/N]: s

  ✅ src/services/order.py → 🟡 LOCAL LLM
```

### Step 3b — Spostamento SENSITIVE → SAFE

```
  📄 docker-compose.prod.yml
  Classificazione attuale: 🔴 SENSITIVE
  Motivo auto: Password rilevata (riga 23: POSTGRES_PASSWORD=...)

  ⛔ ATTENZIONE: Questo file contiene pattern sensibili:
     Riga 23: POSTGRES_PASSWORD=mysecretpassword123
     Riga 31: REDIS_AUTH=redis_token_abc
  
  Inviando questo file al LLM cloud, questi dati transiteranno
  su server esterni (Anthropic/Google). 
  
  Sei sicuro? Digita 'CONFERMO' per procedere: _
```

### Step 4 — Riepilogo Finale e Conferma

```
╔══════════════════════════════════════════════════════════════╗
║              📋 RIEPILOGO CLASSIFICAZIONE FINALE             ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  🟢 SAFE → LLM Cloud:        277 file                       ║
║  🟡 LOCAL LLM → Ollama:        3 file                       ║
║  🔴 SENSITIVE → Solo locale:   22 file                       ║
║  ⚫ ESCLUSI:                    10 file                       ║
║                                                              ║
║  Modifiche manuali: 5                                        ║
║  ⚠️  3 file analizzati con qualità ridotta (Ollama)          ║
║  ⚠️  10 file ignorati                                        ║
║                                                              ║
║  Procedi con l'analisi? [s/N]: _                             ║
╚══════════════════════════════════════════════════════════════╝
```

---

## Regole del Classificatore Automatico

### 🔴 SENSITIVE automaticamente:

```python
SENSITIVE_RULES = {
    "filename_patterns": [
        ".env", ".env.*",
        "*.pem", "*.key", "*.cert", "*.p12",
        "secrets.*", "credentials.*",
        "*secret*", "*credential*",
        "id_rsa", "id_ed25519",
        ".htpasswd", ".pgpass",
        "*.keystore", "*.jks",
    ],
    "content_patterns": [
        r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+",
        r"(?i)(api[_-]?key|apikey)\s*[=:]\s*\S+",
        r"(?i)(secret[_-]?key|client[_-]?secret)\s*[=:]",
        r"(?i)(access[_-]?token|auth[_-]?token)\s*[=:]",
        r"(?i)(aws_access_key_id|aws_secret)",
        r"(?i)(database_url|db_password|db_pass)",
        r"(?i)(private[_-]?key)\s*[=:]",
        r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
        r"(?i)connection[_-]?string\s*[=:]",
    ],
    "entropy_threshold": 5.0,  # Alzata da 4.5 dopo validazione su repo reali
    "path_patterns": [
        "*/config/prod*", "*/deploy/prod*",
        "*/.ssh/*", "*/vault/*",
    ],
    # Filtri anti-falsi-positivi (aggiunti post-validazione):
    "placeholder_values": [
        "none", "null", "nil", "undefined", "false", "true",
        "your_api_key_here", "your_key_here", "changeme", "change_me",
        "example", "test", "dummy", "placeholder", "sample", "xxx",
    ],
    "skip_type_annotations": True,  # Ignora "api_key: str", "password: Optional[str]"
}
```

### ⚫ ESCLUSO automaticamente:

```python
EXCLUDED_RULES = {
    "directories": [
        "node_modules/", "vendor/", ".git/", "__pycache__/",
        ".venv/", "venv/", "dist/", "build/", "target/",
    ],
    "extensions": [
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
        ".woff", ".woff2", ".ttf", ".eot",
        ".zip", ".tar", ".gz", ".exe", ".dll", ".so",
        ".pyc", ".class", ".o", ".sqlite", ".db",
    ],
    "size_limit": 1_048_576,  # > 1MB
    "lockfiles": [
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "poetry.lock", "Pipfile.lock", "Cargo.lock",
        "composer.lock", "Gemfile.lock",
    ],
}
```

### Whitelist NEVER_IGNORE_FILES

Alcuni file sono critici per l'analisi (detection stack, dipendenze) e non devono
mai essere ignorati dal `.gitignore`, anche se un pattern li matcherebbe (es. `*.txt`
che escluderebbe `requirements.txt`). Questi file sono sempre inclusi:

```python
NEVER_IGNORE_FILES = {
    "requirements.txt", "setup.py", "setup.cfg", "pyproject.toml",
    "package.json", "pom.xml", "build.gradle", "go.mod", "go.sum",
    "Cargo.toml", "Gemfile", "composer.json",
    "Makefile", "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "Jenkinsfile", ".gitignore", "manage.py",
}
```

### 🟢 SAFE: tutto ciò che non matcha SENSITIVE o EXCLUDED.

---

## Persistenza della Review

```yaml
# .cto-audit-classification.yml
version: 1
stats:
  total_files: 312
  safe: 277
  local_llm: 3
  sensitive: 22
  excluded: 10

overrides:
  - file: src/services/order.py
    from: safe
    to: local_llm
    reason: "Logica proprietaria"

excluded_dirs:
  - node_modules/
  - vendor/
  - .git/
```

Se il file esiste al prossimo run:
```
  [U] Usa classificazione precedente (skip review)
  [R] Riesegui da zero
  [M] Rivedi solo file nuovi/modificati
```

---

## Interazione con Scoring e Compliance

### Scoring Engine [IMPLEMENTATO]

Lo Scoring Engine riceve i finding **dopo** che l'analisi e' completata, quindi **dopo** il gate HITL. Lo scoring e' literature-backed con pesi e soglie derivati da standard di settore.

La classificazione privacy impatta la **qualita'** dei finding:

- Finding da file SAFE (analisi LLM cloud): alta confidence
- Finding da file LOCAL_LLM (Ollama): media confidence
- Finding da file SENSITIVE (solo locale): bassa confidence
- File EXCLUDED: non analizzati

### Compliance Engine [IMPLEMENTATO]

Il Compliance Engine e' operativo con profili NIS2 e GDPR in modalita' ibrida
(check deterministici + LLM dove disponibile).

I check di compliance rispettano le regole di privacy:

- Check su file SAFE: prompt inviato al cloud
- Check su file SENSITIVE: solo check deterministici (regex, file existence, pattern)
- Check su file LOCAL_LLM: prompt inviato a Ollama locale

---

## Edge Cases

### Repo enorme (1000+ file)
Summary aggregato per directory. Solo i SENSITIVE in dettaglio.

### Zero file SENSITIVE
```
✅ Nessun file sensibile rilevato. Tutti i file via LLM cloud.
   Vuoi comunque rivedere? [s/N]: _
```

### Tutti i file SENSITIVE
```
⚠️ Tutti i 45 file sono SENSITIVE. Analisi interamente locale.
   I check di compliance LLM-based saranno degradati a deterministici.
   [C] Procedi | [E] Rivedi | [O] Configura Ollama
```

### Ollama non disponibile
```
⚠️ Ollama non rilevato. I file LOCAL_LLM analizzati come SENSITIVE.
   I check di compliance per quei file saranno solo deterministici.
   [C] Procedi senza Ollama | [Q] Annulla
```

### Modalità --offline
Tutti i file → 🔴 SENSITIVE o ⚫ ESCLUSO. HITL avviene comunque.
I check di compliance funzionano solo in modalità deterministica.

### File modificati tra due run
```
  23 file cambiati: 8 nuovi, 12 modificati, 3 rimossi
  [M] Rivedi solo nuovi/modificati | [R] Da zero | [U] Auto-classifica nuovi
```

---

## Documenti Correlati

- **[docs/PROJECT_OVERVIEW.md](docs/PROJECT_OVERVIEW.md)** — Overview strategico (stile YC pitch)
- **01-concept.md** — L'idea, i 4+1 layer, il piano completo
- **02-architecture.md** — Architettura, scoring engine, compliance engine
- **04-due-diligence.md** — Analisi di investibilita
- **[docs/READING_ORDER.md](docs/READING_ORDER.md)** — Guida di lettura top-down
