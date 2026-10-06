"""
Tema dark "intelligence style" per la dashboard.

Colori:
- Background: #0d1117 (GitHub dark)
- Card: #161b22 con bordi sottili
- Verde hacker: #00ff41 per score buoni
- Rosso: #ff3333 per critical
- Warning: #f0b400 per warning
"""

from __future__ import annotations

# Colori principali
BG_DARK = "#0d1117"
CARD_BG = "#161b22"
CARD_BORDER = "#30363d"
TEXT_PRIMARY = "#e6edf3"
TEXT_SECONDARY = "#8b949e"

# Accenti per score
COLOR_GOOD = "#00ff41"      # Verde neon
COLOR_WARNING = "#f0b400"   # Giallo/arancio
COLOR_DANGER = "#ff3333"    # Rosso
COLOR_INFO = "#58a6ff"      # Blu

# Soglie score
SCORE_GOOD = 70
SCORE_WARNING = 40


def score_color(score: float) -> str:
    """Restituisce il colore appropriato per uno score."""
    if score >= SCORE_GOOD:
        return COLOR_GOOD
    if score >= SCORE_WARNING:
        return COLOR_WARNING
    return COLOR_DANGER


CUSTOM_CSS = """
body {
    background-color: #0d1117 !important;
    color: #e6edf3 !important;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
}
.card {
    background-color: #161b22 !important;
    border: 1px solid #30363d !important;
    border-radius: 8px !important;
}
.card-header {
    background-color: #161b22 !important;
    border-bottom: 1px solid #30363d !important;
}
.nav-link {
    color: #8b949e !important;
}
.nav-link.active {
    color: #00ff41 !important;
    border-color: #00ff41 !important;
    background-color: transparent !important;
}
.table {
    color: #e6edf3 !important;
}
code, .monospace {
    font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
}
@media print {
    body { background-color: white !important; color: black !important; }
    .card { border: 1px solid #ccc !important; background: white !important; }
}
"""
