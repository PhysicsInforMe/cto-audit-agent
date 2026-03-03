# CTO Audit Agent — Metodologia di Validazione

> Come validare l'accuratezza del tool usando Claude Code come ground truth.

---

## Il Principio

CTO Audit Agent analizza un codebase con 36 regole deterministiche, producendo un punteggio tracciabile. Ma come sappiamo che le conclusioni sono corrette?

**Claude Code (CC)** analizza lo stesso codebase come un CTO con miliardi di parametri, senza regole predefinite — arriva alle stesse conclusioni per strade diverse (LLM code-specific). L'output di CC e la **ground truth**: se il tool e CC concordano, il tool e accurato.

## Cosa NON e

- **Non e un workflow utente**: chi ha accesso a CC non ha bisogno del tool per l'analisi
- **Non e un test automatico**: CC richiede esecuzione manuale
- **Non sostituisce i test unitari**: i 733 test verificano correttezza interna, CC verifica allineamento con giudizio esperto
- **Non e un vincolo a runtime**: e un processo di validazione offline, da eseguire periodicamente

## Cosa E

Un **asset di credibilita** per pitch e fundraising: "abbiamo validato contro un LLM state-of-the-art e il nostro tool raggiunge l'X% di allineamento".

---

## Metriche di Allineamento

Per ogni repository campione, si misurano:

### 1. Finding Agreement

Per ogni finding del tool, CC concorda che e un problema reale?

```
Precision = Finding concordati / Finding totali del tool
```

Un finding del tool che CC non considera un problema e un **falso positivo**.

### 2. Finding Coverage

Per ogni problema che CC identifica, il tool lo rileva?

```
Recall = Problemi CC rilevati dal tool / Problemi CC totali
```

Un problema CC che il tool non rileva e un **falso negativo**.

### 3. Score Alignment

Quanto e vicino lo score del tool al giudizio di CC?

```
Score Distance = |Score Tool - Score CC| (su scala 0-100)
```

### 4. Layer Agreement

Per ogni layer, CC concorda con la valutazione del tool?

```
Layer Agreement = Layer con valutazione simile / 4 layer totali
```

---

## Processo di Validazione

### Step 1: Selezione Repository

Scegliere 5-10 repository rappresentative:
- Diverse per linguaggio (Python, JS/TS, Go, Java, Rust)
- Diverse per qualita (eccellente, buono, mediocre, scarso)
- Diverse per dimensione (piccolo, medio, grande)

### Step 2: Esecuzione CTO Audit Agent

```bash
cto-audit scan /path/to/repo --auto-approve --offline -o result.json
```

### Step 3: Esecuzione Claude Code

Eseguire CC sulla stessa repo con un prompt strutturato che richiede la stessa analisi (4 layer, score, finding). Il prompt e incluso nello script `benchmarks/cc_validation/validate.py`.

### Step 4: Confronto

Lo script `validate.py` confronta i due output e produce metriche di allineamento.

### Step 5: Iterazione

I falsi positivi e negativi guidano il miglioramento delle regole del tool.

---

## Frequenza

- **Pre-release**: su almeno 5 repository prima di ogni release
- **Post-modifica regole**: quando si aggiungono o modificano regole
- **Periodica**: ogni 2-3 mesi su repository aggiornate

---

## Limitazioni

1. **CC non e infallibile**: e un LLM, puo avere allucinazioni o bias
2. **Soggettivita**: la valutazione CTO ha componenti soggettive
3. **Costo**: eseguire CC su molte repo richiede tempo e accesso
4. **Riproducibilita**: l'output di CC puo variare tra esecuzioni

Per mitigare: usare sempre lo stesso prompt strutturato, eseguire CC 2-3 volte per repo, concentrarsi sui finding (binari) piuttosto che sullo score (continuo).

---

## Documenti Correlati

- [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) — Overview del progetto
- [benchmarks/cc_validation/README.md](../benchmarks/cc_validation/README.md) — Istruzioni per il tester
