"""
EPSS Client — Probabilita di sfruttamento delle CVE (Exploit Prediction Scoring System).

EPSS e mantenuto dallo EPSS Special Interest Group di FIRST e stima, per ogni CVE
pubblicata, la probabilita che venga sfruttata in natura nei 30 giorni successivi.
I dati sono pubblici e gratuiti: API https://api.first.org/data/v1/epss, CSV e
repository GitHub (fonte: https://www.first.org/epss/).

Uso nel tool: arricchisce il finding SEC-DEPS-CVE-001 con un campo informativo
per CVE (probabilita e percentile). Lo score deterministico non cambia: EPSS
serve a ordinare le CVE per urgenza, non a pesarle.

Cosa viene inviato: solo gli identificativi CVE (es. "CVE-2024-3094").
Nessun nome di pacchetto, nessun codice. Stesso consenso rete del check OSV.
Degradazione graziosa: offline o API non raggiungibile -> dizionario vuoto.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_TIMEOUT = 15  # secondi
# Il parametro "cve" accetta ID separati da virgola, massimo 2000 caratteri.
# Un ID CVE occupa al piu 20 caratteri: 80 per richiesta stanno sotto il limite.
EPSS_BATCH_SIZE = 80


@dataclass(frozen=True)
class EPSSScore:
    """Punteggio EPSS per una CVE."""
    cve: str
    epss: float          # probabilita di sfruttamento a 30 giorni, 0.0-1.0
    percentile: float    # posizione rispetto a tutte le CVE, 0.0-1.0
    date: str            # data del punteggio (YYYY-MM-DD)

    def to_dict(self) -> dict[str, Any]:
        return {"cve": self.cve, "epss": self.epss, "percentile": self.percentile, "date": self.date}


def query_epss(cve_ids: list[str], client: httpx.Client | None = None) -> dict[str, EPSSScore]:
    """
    Interroga l'API EPSS per una lista di CVE.

    Args:
        cve_ids: identificativi CVE (gli ID non CVE, es. GHSA-..., vengono ignorati)
        client: client httpx iniettabile (test)

    Returns:
        Dizionario cve -> EPSSScore per le CVE con punteggio. Vuoto se l'API non risponde.
    """
    ids = sorted({c.strip().upper() for c in cve_ids if c and c.strip().upper().startswith("CVE-")})
    if not ids:
        return {}

    scores: dict[str, EPSSScore] = {}
    for i in range(0, len(ids), EPSS_BATCH_SIZE):
        batch = ids[i:i + EPSS_BATCH_SIZE]
        data = _get(client, {"cve": ",".join(batch)})
        if data is None:
            # Un batch fallito non invalida i precedenti: restituisci quanto raccolto
            return scores
        for row in data.get("data", []) or []:
            try:
                cve = str(row["cve"]).upper()
                scores[cve] = EPSSScore(
                    cve=cve,
                    epss=float(row.get("epss", 0.0)),
                    percentile=float(row.get("percentile", 0.0)),
                    date=str(row.get("date") or row.get("created") or "")[:10],
                )
            except (KeyError, TypeError, ValueError):
                continue
    return scores


def _get(client: httpx.Client | None, params: dict[str, str]) -> dict | None:
    try:
        if client is not None:
            resp = client.get(EPSS_API_URL, params=params, timeout=EPSS_TIMEOUT)
        else:
            resp = httpx.get(EPSS_API_URL, params=params, timeout=EPSS_TIMEOUT)
        if resp.status_code != 200:
            return None
        data = resp.json()
        return data if isinstance(data, dict) else None
    except (httpx.HTTPError, ValueError):
        return None


def summarize(scores: dict[str, EPSSScore]) -> dict[str, Any]:
    """Riepilogo serializzabile per il campo `extra` del finding."""
    if not scores:
        return {}
    top = max(scores.values(), key=lambda s: s.epss)
    return {
        "source": "FIRST EPSS",
        "date": top.date,
        "scored_cves": len(scores),
        "max_epss": top.epss,
        "max_percentile": top.percentile,
        "max_cve": top.cve,
        "scores": {cve: {"epss": s.epss, "percentile": s.percentile} for cve, s in scores.items()},
    }
