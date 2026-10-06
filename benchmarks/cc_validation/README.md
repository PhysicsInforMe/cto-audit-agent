# CC Validation — CTO Audit Agent vs Claude Code

Questo framework confronta i risultati di CTO Audit Agent con l'analisi di Claude Code (CC), usato come ground truth.

## Prerequisiti

- CTO Audit Agent installato (`pip install -e ".[dev]"`)
- Accesso a Claude Code
- Una o piu repository da analizzare

## Workflow

### Step 1: Esegui il tool sulla repo

```bash
python validate.py scan /path/to/repo                  # profilo default (4 layer)
python validate.py scan /path/to/repo --due-diligence  # profilo due-diligence (6 layer)
```

Esegue `cto-audit scan --auto-approve --offline -o cto_result_<repo>.json` e stampa il prompt
per l'LLM. Il prompt chiede, per ogni finding, una CATEGORY presa da un elenco chiuso (lo stesso
usato per mappare i rule_id del tool) e una EVIDENCE: il file del repo che dimostra il finding.
In modalita due diligence chiede anche tre risposte si/no sui deal flag (IP, team, secret).

### Step 2: Esegui l'LLM, piu volte

Apri Claude Code (o un altro LLM con accesso al repo), incolla il prompt in 2-3 sessioni
separate e salva ogni output JSON (`llm_<repo>_1.json`, `llm_<repo>_2.json`, ...). Le
esecuzioni multiple servono a misurare quanto l'LLM e stabile prima di usarlo come riferimento.

### Step 3: Confronta

```bash
python validate.py compare cto_result_<repo>.json llm_<repo>_1.json llm_<repo>_2.json --repo /path/to/repo
```

## Metriche

| Metrica | Cosa misura | Lettura |
|---------|-------------|---------|
| Score distance | Distanza tra score complessivo tool e media LLM | Sotto 15 punti: valutazione simile |
| Layer delta | Stessa distanza, per ogni layer (inclusi provenance e team) | Isola il layer dove i due divergono |
| Precision (categorie) | Quota di categorie trovate dal tool che anche l'LLM trova | Bassa: regole del tool da rivedere |
| Recall (categorie) | Quota di categorie trovate dall'LLM che anche il tool trova | Bassa: coperture da aggiungere |
| Precision / Recall per layer | Le stesse due metriche, layer per layer | Dice quale analyzer sbaglia |
| Severity agreement | Sui finding comuni: quanti hanno la stessa severita, quanti entro un livello | Il tool pesa come un umano? |
| Evidence rate | Quota di finding LLM che citano un file esistente nel repo (`--repo`) | Basso: l'LLM afferma cose che il repo non mostra |
| Stabilita LLM | Range degli score e Jaccard medio delle categorie tra esecuzioni | Jaccard sotto 50%: l'LLM da solo non e una ground truth |
| Deal flag agreement | Solo due diligence: accordo sulle tre risposte si/no (IP, team, secret) | Il livello che conta per un investitore |

Il confronto avviene per **categoria**, non per rule_id: il tool mappa i suoi rule_id a
categorie (`CATEGORY_MAP` in `validate.py`), l'LLM dichiara la categoria o viene
classificato dalle parole chiave di titolo e descrizione. L'unione delle esecuzioni LLM e
usata come riferimento: un finding conta se almeno una esecuzione lo trova.

## Interpretazione

- Precision e recall vanno letti insieme all'evidence rate: un finding LLM senza file di
  evidenza non e un falso negativo del tool finche non viene verificato a mano.
- Il tool e deterministico: due esecuzioni danno lo stesso risultato. L'LLM no, e la
  stabilita misurata e il limite superiore della sua affidabilita come riferimento.
- I risultati servono a migliorare le regole del tool (soglie, parole chiave, coperture),
  non come test pass/fail.

## Struttura File

```
cc_validation/
├── README.md          # Questo file
└── validate.py        # Script di validazione (scan, compare)
```

## Documenti Correlati

- [docs/VALIDATION_METHODOLOGY.md](../../docs/VALIDATION_METHODOLOGY.md) — Metodologia completa
- [benchmarks/results/benchmark_report.md](../results/benchmark_report.md) — Benchmark su 20 repo reali
