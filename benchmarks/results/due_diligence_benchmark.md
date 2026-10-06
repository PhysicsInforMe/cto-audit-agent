# Benchmark modalita Due Diligence (20 repository reali)

Data: 2026-10-06. Stesse 20 repository del benchmark principale (`benchmark_report.md`), clonate shallow (`--depth 1`) a febbraio 2026. Esecuzione offline, `--auto-approve`, profili `default` e `due-diligence`.

## Regressione del profilo default

Lo score del profilo `default` e stato confrontato con quello prodotto dal codice precedente all'introduzione dei layer di due diligence (commit `9fdb60f`, eseguito da un worktree separato) sulle repository clean-architecture, jekyll, redis, spring-petclinic e ripgrep: identico al centesimo in tutti i casi. Le altre 15 repository coincidono con i risultati salvati in `benchmark_results.json` dove il confronto e univoco. I quattro scostamenti di 7,5 punti rispetto ai risultati di febbraio (clean-architecture, jekyll, redis, spring-petclinic) sono quindi precedenti a questo lavoro e non dipendono dai layer nuovi ne dal fix del `.gitignore`.

## Score per repository

| Repository | Default | Due diligence | File | Provenance | Team | Tempo DD |
|---|---:|---:|---:|---:|---:|---:|
| black | 69.9 | 72.6 | 451 | 98 | 78 | 2.9s |
| clean-architecture | 80.5 | 83.1 | 309 | 99 | 78 | 0.7s |
| express | 72.5 | 73.6 | 213 | 98 | 78 | 0.8s |
| fastapi-users | 78.4 | 82.0 | 150 | 99 | 78 | 0.5s |
| fastify | 68.7 | 70.4 | 380 | 99 | 78 | 2.2s |
| fiber | 75.8 | 76.8 | 379 | 99 | 78 | 2.1s |
| ghost | 62.4 | 69.8 | 6,529 | 98 | 78 | 16.5s |
| gin | 81.2 | 81.5 | 130 | 98 | 78 | 0.5s |
| httpie-cli | 81.1 | 84.3 | 265 | 99 | 78 | 0.6s |
| java-design-patterns | 75.3 | 74.7 | 3,564 | 99 | 78 | 5.3s |
| jekyll | 79.0 | 82.2 | 812 | 99 | 78 | 1.0s |
| laravel | 82.8 | 86.4 | 61 | 99 | 78 | 0.2s |
| mastodon | 66.5 | 71.3 | 9,618 | 98 | 78 | 10.1s |
| minio | 71.9 | 74.5 | 1,275 | 98 | 78 | 4.6s |
| redis | 74.2 | 73.4 | 1,744 | 94 | 78 | 2.6s |
| ripgrep | 90.4 | 91.6 | 220 | 99 | 78 | 1.1s |
| sanic | 69.2 | 73.4 | 681 | 99 | 78 | 1.5s |
| scrapy | 75.4 | 75.5 | 611 | 99 | 78 | 2.4s |
| socket.io | 55.8 | 66.5 | 816 | 99 | 78 | 2.5s |
| spring-petclinic | 75.3 | 75.3 | 126 | 99 | 78 | 0.4s |
| **Media** | **74.3** | **77.0** | | | | |

## Finding dei layer nuovi

| Regola | Repository su 20 | Lettura |
|---|---:|---|
| PROV-SBOM-001 | 20 | Atteso: quasi nessun progetto open source committa uno SBOM. Severita bassa. |
| TEAM-GIT-INFO | 20 | Tutti i clone sono shallow: il layer Team valuta solo l'attivita recente e lo dichiara. |
| TEAM-ACTIVITY-001 | 20 | Ultimo commit oltre 180 giorni fa: i clone risalgono a febbraio 2026, quindi il dato descrive lo snapshot del benchmark, non i progetti reali, che sono attivi. |
| PROV-OWNLICENSE-INFO | 19 | Informativo: la licenza del repository viene classificata (MIT/BSD/Apache, AGPL per minio e mastodon, tri-licenza per redis). |
| PROV-LICENSE-INFO | 18 | Informativo: inventario licenze delle dipendenze (KB offline). |
| PROV-COPYRIGHT-002 | 6 | Titolari di copyright multipli in progetti open source: atteso, severita bassa. |
| PROV-CLAIMS-001 | 1 | Dichiarazioni del README senza riscontro nel repository (es. Helm chart citato ma in altro repo). |
| PROV-VENDORED-001 | 1 | Codice di terze parti incorporato (es. `deps/` di redis: lua, jemalloc, hiredis). |

## Limiti di questo benchmark

- Le repository sono clone shallow: bus factor, storico compresso, tag e messaggi di commit non sono valutabili qui. In modalita due diligence il tool clona le sorgenti remote con storico completo.
- Sono progetti open source maturi, non codebase di startup: le regole su licenza del repository e titolari di copyright si comportano come atteso (informative o a severita bassa), ma il valore discriminante dei layer nuovi va misurato su codice proprietario.
- Il check licenze delle dipendenze e stato eseguito offline (solo KB curata): con accesso rete l'inventario copre tutte le dipendenze PyPI e npm.
- Confronto con un LLM: il framework `benchmarks/cc_validation/` e stato esteso ai layer nuovi (categorie, evidence rate, stabilita tra esecuzioni, deal flag). L'esecuzione dell'LLM sulle repository non e stata ancora fatta: richiede sessioni separate di Claude Code per ogni repository.
