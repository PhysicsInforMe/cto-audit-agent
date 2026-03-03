# CC Validation — CTO Audit Agent vs Claude Code

Questo framework confronta i risultati di CTO Audit Agent con l'analisi di Claude Code (CC), usato come ground truth.

## Prerequisiti

- CTO Audit Agent installato (`pip install -e ".[dev]"`)
- Accesso a Claude Code
- Una o piu repository da analizzare

## Workflow

### Step 1: Esegui il tool sulla repo

```bash
python validate.py scan /path/to/repo
```

Questo:
- Esegue `cto-audit scan --auto-approve --offline -o result.json`
- Stampa il prompt da usare con Claude Code

### Step 2: Esegui Claude Code

1. Apri Claude Code nella stessa repo
2. Incolla il prompt stampato dallo script
3. Salva l'output JSON di CC in un file (es. `cc_result_reponame.json`)

### Step 3: Confronta

```bash
python validate.py compare cto_result_reponame.json cc_result_reponame.json
```

Lo script produce:
- **Score comparison**: distanza tra score tool e CC
- **Layer comparison**: delta per ogni layer
- **Finding comparison**: finding in comune, falsi positivi, falsi negativi
- **Precision/Recall**: metriche di allineamento

## Interpretazione Risultati

| Metrica | Target | Significato |
|---------|--------|-------------|
| Score Distance | < 15 punti | Tool e CC valutano in modo simile |
| Precision | > 80% | Pochi falsi positivi |
| Recall | > 70% | Pochi falsi negativi |
| Finding Agreement | > 60% | Buon allineamento sui problemi |

## Note

- Il confronto sui **rule_id** e approssimativo: CC usa ID diversi dal tool
- Concentrarsi sulla **tipologia** di finding piuttosto che sull'ID esatto
- Eseguire CC 2-3 volte per ridurre la variabilita dell'LLM
- I risultati servono per migliorare le regole del tool, non come test pass/fail

## Struttura File

```
cc_validation/
├── README.md          # Questo file
└── validate.py        # Script di validazione
```

## Documenti Correlati

- [docs/VALIDATION_METHODOLOGY.md](../../docs/VALIDATION_METHODOLOGY.md) — Metodologia completa
- [benchmarks/results/benchmark_report.md](../results/benchmark_report.md) — Benchmark su 20 repo reali
