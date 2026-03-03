# CTO Audit Agent — Guida di Lettura

Ordine consigliato per comprendere il progetto dall'alto verso il basso.

---

## Per chi ha poco tempo (30 minuti)

Leggi solo i primi 3 documenti per capire cos'e, come si usa e come funziona lo scoring.

## Percorso completo (~2 ore)

| # | Documento | Cosa impari | Tempo |
|---|-----------|-------------|-------|
| 1 | [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) | Cos'e, perche esiste, per chi, metriche chiave, differenziatori | 5 min |
| 2 | [README.md](../README.md) | Quick start, installazione, uso, opzioni CLI | 10 min |
| 3 | [01-cto-audit-concept.md](../01-cto-audit-concept.md) | Concetto, principi fondamentali, decisioni di design, scoring engine | 15 min |
| 4 | [USER_GUIDE.md](USER_GUIDE.md) | Come interpretare i risultati, tabelle penalita per regola, profili | 15 min |
| 5 | [TESTER_GUIDE.md](TESTER_GUIDE.md) | Come testare il tool, scenari di validazione, troubleshooting | 10 min |
| 6 | [02-cto-audit-architecture.md](../02-cto-audit-architecture.md) | Architettura tecnica, regole per analyzer, compliance engine | 20 min |
| 7 | [03-cto-audit-hitl-flow.md](../03-cto-audit-hitl-flow.md) | Privacy, classificazione file, gate Human-in-the-Loop | 10 min |
| 8 | [PATENT_ANALYSIS.md](PATENT_ANALYSIS.md) | Differenziazione dal brevetto, rischio IP | 10 min |
| 9 | [ROADMAP.md](ROADMAP.md) | Roadmap dettagliata, patent safety per feature, mapping open core | 10 min |
| 10 | [ARCHITECTURE.md](../ARCHITECTURE.md) | Dettagli implementativi completi, struttura codice, dipendenze | 30 min |
| 11 | [benchmark_report.md](../benchmarks/results/benchmark_report.md) | Risultati su 20 repository reali, score per linguaggio | 5 min |
| 12 | [VALIDATION_METHODOLOGY.md](VALIDATION_METHODOLOGY.md) | Metodologia di validazione tramite Claude Code come ground truth | 5 min |

---

## Percorsi alternativi

### Sono un investitore / VC
1. PROJECT_OVERVIEW.md — Il pitch
2. README.md — Quick start
3. benchmark_report.md — Validazione empirica
4. PATENT_ANALYSIS.md — Rischio IP

### Sono un CTO che vuole usare il tool
1. README.md — Installazione e uso
2. USER_GUIDE.md — Interpretare i risultati
3. TESTER_GUIDE.md — Come validarlo
4. 01-cto-audit-concept.md — Capire la filosofia

### Sono uno sviluppatore che vuole contribuire
1. README.md — Setup
2. ARCHITECTURE.md — Struttura codice e componenti
3. 02-cto-audit-architecture.md — Design architetturale
4. TESTER_GUIDE.md — Come eseguire i test

### Sono un compliance officer
1. PROJECT_OVERVIEW.md — Overview
2. USER_GUIDE.md — Sezione compliance NIS2/GDPR
3. 03-cto-audit-hitl-flow.md — Privacy e data handling
4. 01-cto-audit-concept.md — Sezione compliance modulare
