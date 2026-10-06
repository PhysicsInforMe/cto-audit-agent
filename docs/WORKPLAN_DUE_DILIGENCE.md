# Piano di lavoro — Due Diligence, validazione e stima di rischio locale

> Stato al 2026-10-06. Documento operativo: cosa fare, in che ordine, con quali criteri di uscita.
> Per la roadmap di prodotto vedi [ROADMAP.md](ROADMAP.md); per i vincoli brevettuali [PATENT_ANALYSIS.md](PATENT_ANALYSIS.md).

## Decisioni prese

| Data | Decisione | Motivo |
|---|---|---|
| 2026-10-06 | Il tool opera in due modalita: `default` (CTO che entra in azienda, 4 layer) e `due-diligence` (per conto di terzi, 6 layer) | Due domande diverse: "quanto e ben fatto" e "di chi e, si puo cedere, c'e un team" |
| 2026-10-06 | Nessun testo generato da LLM entra in un report senza approvazione umana esplicita | Report destinati a investitori; il template deterministico e il fallback |
| 2026-10-06 | Niente modelli chiusi a pagamento (Jev di TypeSafe AI escluso): solo API aperte e modelli che girano in locale | Offline-first, costi, controllo |
| 2026-10-06 | Una eventuale probabilita per finding resta fuori dallo score deterministico | Confine brevettuale: lo scoring probabilistico e tra gli elementi del patent da cui il tool si distingue |
| 2026-10-06 | Il codice dei clienti non viene inviato a LLM cloud per etichettare | Coerente con il gate privacy (solo file SAFE verso cloud, e solo con consenso); le etichette da LLM si raccolgono su repository open source |

## Fase A — Validazione dei layer nuovi (prima di usarli su un cliente)

Obiettivo: misurare precision e recall dei layer Provenance e Team contro un riferimento esterno, su repository con storico completo.

1. Riclonare le 20 repository di benchmark con storico completo (`git clone` senza `--depth`), in `benchmarks/repos-full/`, ignorato da git. Senza storico il layer Team valuta solo l'attivita.
2. Eseguire `benchmarks/cc_validation/validate.py scan <repo> --due-diligence` su un primo campione di 5 repository (una per linguaggio: Python, JS, Go, Java, Ruby).
3. Eseguire Claude Code sulle stesse 5 repository con il prompt generato, 3 volte ciascuna, in sessioni separate. Salvare i JSON.
4. `validate.py compare` con `--repo`: leggere evidence rate e Jaccard prima di precision e recall. Una categoria trovata dall'LLM senza file di evidenza non e un falso negativo del tool finche non e verificata a mano.
5. Per ogni divergenza: decidere se e una regola da aggiungere, una soglia da spostare (costanti in testa a `analyzers/team.py` e `analyzers/provenance.py`) o un errore dell'LLM. Annotare la decisione in `benchmarks/results/due_diligence_benchmark.md`.
6. Estendere alle altre 15 repository solo se il campione ha mostrato divergenze sistematiche.

Criterio di uscita: precision per layer sopra l'80% e nessuna divergenza non spiegata sui deal flag, sul campione.

## Fase B — EPSS per i finding CVE

Obiettivo: dare una probabilita di sfruttamento ai finding `SEC-DEPS-CVE-001` usando un dato pubblico gia calibrato, senza modelli propri.

1. Collector `collectors/epss.py`: per ogni CVE trovata dal check OSV, interrogare `https://api.first.org/epss/` (dato gratuito, API e CSV pubblici, mantenuto dallo EPSS SIG di FIRST). Stesso consenso rete del check CVE; offline: nessuna chiamata, campo vuoto.
2. Il finding CVE guadagna due campi informativi: `epss_probability` (probabilita di sfruttamento nei 30 giorni successivi) e `epss_percentile`, con data di lettura. Lo score non cambia.
3. Nei report (terminale, Markdown, due diligence) le CVE vengono ordinate per EPSS decrescente e la probabilita compare accanto alla CVE.
4. Test con client httpx finto (stesso pattern di `test_provenance.py`).

Criterio di uscita: una CVE con EPSS alto compare in cima alla lista red flag con la probabilita indicata; con `--offline` il report e identico a oggi.

## Fase C — Raccolta etichette

Obiettivo: costruire il dataset che manca per qualsiasi stima di rischio appresa. Due sorgenti, con pesi diversi.

### C1. Etichette oro: decisioni del revisore (HITL)

1. Nuovo passo opzionale `--triage` (attivo di default in modalita due diligence, disattivabile): dopo lo scoring, il tool mostra i finding critical/high/medium uno per uno e il revisore risponde `conferma`, `declassa`, `scarta`, con una nota facoltativa.
2. Ogni decisione viene salvata in `.cto-audit/decisions.jsonl` dentro il repository analizzato, piu una copia aggregata e anonimizzata in una directory di lavoro del consulente (configurabile, es. `~/.cto-audit/labels/`): rule_id, layer, severita, tipo progetto, linguaggi, dimensioni, confidence del finding, decisione, data. Mai percorsi di file, mai snippet, mai nome del cliente.
3. Lo score del report non cambia con il triage: le decisioni servono al dataset e a una sezione "Finding rivisti dal consulente" nel report di due diligence.

### C2. Etichette argento: LLM su repository open source

1. Usare Claude (via Claude Code o API) solo su repository open source, mai su codice di clienti.
2. Per ogni finding del tool, chiedere all'LLM un giudizio strutturato: `confermato` / `non rilevante` / `non determinabile`, con il file di evidenza. Tre esecuzioni per finding; l'etichetta argento e la maggioranza, con la dispersione registrata.
3. Un campione del 10% delle etichette argento viene rivisto a mano da Luigi. L'accordo tra Luigi e l'LLM su quel campione e la misura di quanto le etichette argento valgono: sotto l'80% di accordo non si usano per addestrare, solo per cercare regole mancanti.

Perche due sorgenti: le etichette dell'LLM costano poco e arrivano subito, ma misurano l'opinione di un modello, non un esito. Le decisioni del revisore sono poche e lente, ma sono il giudizio che il report deve riprodurre. Il modello della fase D si addestra sulle argento e si valuta solo sulle oro.

Criterio di uscita: almeno 300 finding etichettati oro (soglia di progetto, da rivedere con i dati) e accordo Luigi-LLM misurato sul campione.

## Fase D — Stimatore locale di conferma

Obiettivo: per ogni finding, una probabilita calibrata che un revisore lo confermi, calcolata in locale, senza LLM a runtime.

1. Feature: solo dati strutturati gia presenti nel finding e nel contesto (rule_id, layer, severita, confidence, tipo progetto, linguaggi, LOC, numero di file coinvolti, maturity level). Niente testo libero, niente embedding nella prima versione.
2. Modello: regressione logistica o gradient boosting con scikit-learn (da aggiungere come extra `ml`, opzionale), con calibrazione isotonica o Platt su un fold separato. Pesa pochi KB, gira offline, si spiega.
3. Valutazione sulle etichette oro: Brier score, curva di affidabilita, AUC. Un modello che non batte la baseline "probabilita media per rule_id" non viene rilasciato.
4. Output: campo `confirmation_probability` sul finding, con versione del modello e data di addestramento. Usato per ordinare i finding nel report e per un badge "da verificare per primo". Lo score deterministico resta identico: e la condizione del confine brevettuale.
5. Riaddestramento: comando `cto-audit labels train` sulla directory delle etichette; il modello e un file locale versionato.

Criterio di uscita: Brier score migliore della baseline per rule_id sulle etichette oro, e un report in cui l'ordine dei finding cambia in modo che il revisore riconosce come sensato.

## Fase E — Packaging e pubblicazione

1. Allineare `pyproject.toml` (oggi `version = "0.1.0"`) alla versione documentata.
2. Verificare che il wheel includa `scoring-profiles/`, `remediation-kb/`, `compliance-profiles/` nel percorso che `_data.py` cerca in modalita installata; test di installazione da wheel in un venv pulito.
3. Workflow GitHub Actions di release con trusted publishing verso PyPI (il nome `cto-audit` risulta libero al 2026-10-06). Il caricamento richiede le credenziali di Luigi.

## Fase F — Sito

Allineare la scheda del progetto su luigisimeone.com (oggi 36 regole, 4 layer) al profilo due-diligence e ai 6 layer, con link al report di benchmark.

## Ordine consigliato e dipendenze

```
A (validazione) ──> C2 (etichette argento usa lo stesso harness)
B (EPSS)          indipendente, breve
C1 (triage HITL)  indipendente, breve: inizia a raccogliere oro da subito
C1 + C2 ────────> D (modello)
E, F              indipendenti
```

Prima settimana: B e C1, perche sono brevi e C1 inizia ad accumulare dati che non si recuperano dopo. Poi A sul campione di 5 repository. D solo quando le etichette oro ci sono.

## Verifiche fatte per questo documento

- Jev / System One Models: post ufficiale TypeSafe AI (API in early access, nessun peso aperto, output a probabilita calibrate).
- EPSS: pagina ufficiale FIRST.org (probabilita di sfruttamento a 30 giorni, dati gratuiti via API e CSV, mantenuto dallo EPSS SIG).
- Confine brevettuale: `docs/PATENT_ANALYSIS.md`, elementi 5 del Claim 1 e 6 del Claim 2 (probabilistic rating engine, probabilistic scoring via LLM).
- Stato del codice: commit `4f848d7` su master, 1.053 test.
- Le soglie numeriche (80% di accordo, 300 etichette) sono scelte di progetto, non valori di letteratura.
