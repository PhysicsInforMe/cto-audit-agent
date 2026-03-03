#!/usr/bin/env python3
"""
Genera il pitch deck CTO Audit Agent in formato PowerPoint (.pptx).

Deck unico generico ~15 slide, funziona per CTO, VC e audit firm.

Uso:
    python pitch/generate_pitchdeck.py

Requisiti:
    pip install python-pptx
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    from pptx import Presentation
    from pptx.util import Inches, Pt, Emu
    from pptx.dml.color import RGBColor
    from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
    from pptx.enum.shapes import MSO_SHAPE
except ImportError:
    print(
        "ERRORE: python-pptx non installato.\n"
        "Installa con: pip install python-pptx",
        file=sys.stderr,
    )
    sys.exit(1)


OUTPUT_DIR = Path(__file__).resolve().parent / "output"

# ---------------------------------------------------------------------------
# Design Tokens
# ---------------------------------------------------------------------------

NAVY = RGBColor(0x0F, 0x17, 0x2A)
DARK_BLUE = RGBColor(0x1E, 0x3A, 0x5F)
GREEN = RGBColor(0x22, 0xC5, 0x5E)
DARK_GREEN = RGBColor(0x16, 0x65, 0x34)
RED = RGBColor(0xEF, 0x44, 0x44)
ORANGE = RGBColor(0xF9, 0x73, 0x16)
YELLOW = RGBColor(0xEA, 0xB3, 0x08)
BLUE = RGBColor(0x3B, 0x82, 0xF6)
GRAY = RGBColor(0x64, 0x74, 0x8B)
LIGHT_GRAY = RGBColor(0x94, 0xA3, 0xB8)
SLATE = RGBColor(0x1E, 0x29, 0x3B)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
BG_LIGHT = RGBColor(0xF8, 0xFA, 0xFC)
BG_GREEN_LIGHT = RGBColor(0xF0, 0xFD, 0xF4)
BG_RED_LIGHT = RGBColor(0xFE, 0xF2, 0xF2)
BORDER_LIGHT = RGBColor(0xE2, 0xE8, 0xF0)

SLIDE_W = Inches(13.333)  # 16:9 widescreen
SLIDE_H = Inches(7.5)

FONT_TITLE = "Segoe UI"
FONT_BODY = "Segoe UI"
FONT_MONO = "Consolas"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _set_slide_bg(slide, color: RGBColor) -> None:
    """Imposta il colore di sfondo di una slide."""
    bg = slide.background
    fill = bg.fill
    fill.solid()
    fill.fore_color.rgb = color


def _add_textbox(slide, left, top, width, height, text: str, *,
                 font_size: int = 14, font_color: RGBColor = NAVY,
                 bold: bool = False, font_name: str = FONT_BODY,
                 alignment: PP_ALIGN = PP_ALIGN.LEFT,
                 anchor: MSO_ANCHOR = MSO_ANCHOR.TOP) -> object:
    """Aggiunge un textbox alla slide e ritorna il text_frame."""
    txbox = slide.shapes.add_textbox(left, top, width, height)
    tf = txbox.text_frame
    tf.word_wrap = True
    tf.auto_size = None
    try:
        txbox.fill.background()
    except Exception:
        pass
    p = tf.paragraphs[0]
    p.text = text
    p.font.size = Pt(font_size)
    p.font.color.rgb = font_color
    p.font.bold = bold
    p.font.name = font_name
    p.alignment = alignment
    return tf


def _add_rich_textbox(slide, left, top, width, height) -> object:
    """Aggiunge un textbox vuoto e ritorna il text_frame per contenuto rich."""
    txbox = slide.shapes.add_textbox(left, top, width, height)
    tf = txbox.text_frame
    tf.word_wrap = True
    tf.auto_size = None
    return tf


def _add_paragraph(tf, text: str, *, font_size: int = 14,
                   font_color: RGBColor = NAVY, bold: bool = False,
                   font_name: str = FONT_BODY,
                   alignment: PP_ALIGN = PP_ALIGN.LEFT,
                   space_before: Pt | None = None,
                   space_after: Pt | None = None) -> object:
    """Aggiunge un paragrafo a un text_frame esistente."""
    p = tf.add_paragraph()
    p.text = text
    p.font.size = Pt(font_size)
    p.font.color.rgb = font_color
    p.font.bold = bold
    p.font.name = font_name
    p.alignment = alignment
    if space_before:
        p.space_before = space_before
    if space_after:
        p.space_after = space_after
    return p


def _add_rect(slide, left, top, width, height, fill_color: RGBColor,
              border_color: RGBColor | None = None) -> object:
    """Aggiunge un rettangolo colorato."""
    shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill_color
    if border_color:
        shape.line.color.rgb = border_color
        shape.line.width = Pt(1)
    else:
        shape.line.fill.background()
    return shape


def _add_rounded_rect(slide, left, top, width, height, fill_color: RGBColor,
                       border_color: RGBColor | None = None) -> object:
    """Aggiunge un rettangolo arrotondato."""
    shape = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height
    )
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill_color
    if border_color:
        shape.line.color.rgb = border_color
        shape.line.width = Pt(1)
    else:
        shape.line.fill.background()
    return shape


def _slide_number(slide, num: int, total: int) -> None:
    """Aggiunge numero slide in basso a destra."""
    _add_textbox(
        slide, Inches(11.5), Inches(7.0), Inches(1.5), Inches(0.4),
        f"{num}/{total}", font_size=10, font_color=LIGHT_GRAY,
        alignment=PP_ALIGN.RIGHT,
    )


def _section_title_bar(slide, title: str, num: int, total: int) -> None:
    """Barra titolo in alto con linea navy sotto."""
    _add_rect(slide, Inches(0), Inches(0), SLIDE_W, Inches(0.06), NAVY)
    _add_textbox(
        slide, Inches(0.7), Inches(0.25), Inches(10), Inches(0.6),
        title, font_size=28, font_color=NAVY, bold=True,
    )
    _slide_number(slide, num, total)


# ---------------------------------------------------------------------------
# Slide builders
# ---------------------------------------------------------------------------

TOTAL_SLIDES = 15


def slide_cover(prs: Presentation) -> None:
    """Slide 1: Cover."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])  # blank
    _set_slide_bg(slide, NAVY)

    # Accent line
    _add_rect(slide, Inches(0), Inches(2.0), SLIDE_W, Inches(0.05), GREEN)

    _add_textbox(
        slide, Inches(1.5), Inches(2.4), Inches(10), Inches(1.2),
        "CTO Audit Agent", font_size=48, font_color=WHITE, bold=True,
        alignment=PP_ALIGN.CENTER,
    )
    _add_textbox(
        slide, Inches(1.5), Inches(3.5), Inches(10), Inches(0.8),
        "Audit tecnico automatizzato per chi prende decisioni",
        font_size=22, font_color=LIGHT_GRAY, alignment=PP_ALIGN.CENTER,
    )

    _add_rect(slide, Inches(5.5), Inches(4.6), Inches(2.3), Inches(0.04), GRAY)

    _add_textbox(
        slide, Inches(2), Inches(4.9), Inches(9), Inches(0.6),
        "Assessment in 3 ore  |  Scoring deterministico  |  Compliance NIS2/GDPR  |  Storico audit  |  Privacy-first",
        font_size=13, font_color=GRAY, alignment=PP_ALIGN.CENTER,
    )

    _add_textbox(
        slide, Inches(2), Inches(6.4), Inches(9), Inches(0.5),
        "info@cto-audit.dev  |  Febbraio 2026",
        font_size=11, font_color=GRAY, alignment=PP_ALIGN.CENTER,
    )


def slide_problem(prs: Presentation) -> None:
    """Slide 2: Il Problema."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _section_title_bar(slide, "Il Problema", 2, TOTAL_SLIDES)

    problems = [
        ("4 settimane per assessment",
         "Leggere codice, navigare repo, capire l'infrastruttura, "
         "mappare i rischi. Tempo enorme, non fatturabile."),
        ("Risultati soggettivi",
         "Due consulenti sullo stesso codice producono valutazioni diverse. "
         "Nessuna tracciabilita, nessuna riproducibilita."),
        ("Report non difendibili",
         "Il board chiede 'perche 65/100?' e non c'e una catena "
         "di evidenze da finding a fonte bibliografica."),
        ("Tech DD costosa e lenta",
         "Due diligence tecnica: $50-150K/deal, 2-4 settimane. "
         "Ritarda il deal flow. Audit compliance: manuale e variabile."),
    ]

    for i, (title, desc) in enumerate(problems):
        row = i // 2
        col = i % 2
        left = Inches(0.7 + col * 6.1)
        top = Inches(1.3 + row * 2.8)

        # Red accent bar
        _add_rect(slide, left, top, Inches(0.08), Inches(2.2), RED)

        _add_textbox(
            slide, left + Inches(0.3), top + Inches(0.1), Inches(5.3), Inches(0.4),
            title, font_size=18, font_color=RED, bold=True,
        )
        _add_textbox(
            slide, left + Inches(0.3), top + Inches(0.6), Inches(5.3), Inches(1.5),
            desc, font_size=13, font_color=GRAY,
        )

    # Stats bar at bottom
    stats = [("4 sett.", "Tempo assessment"), ("$100K+", "Costo tech DD"),
             ("0%", "Riproducibilita"), ("Manuale", "Compliance mapping")]
    for i, (val, label) in enumerate(stats):
        left = Inches(0.7 + i * 3.1)
        _add_rounded_rect(slide, left, Inches(6.6), Inches(2.8), Inches(0.7),
                           BG_RED_LIGHT, BORDER_LIGHT)
        _add_textbox(slide, left + Inches(0.2), Inches(6.62), Inches(1.2), Inches(0.35),
                     val, font_size=16, font_color=RED, bold=True)
        _add_textbox(slide, left + Inches(1.4), Inches(6.68), Inches(1.3), Inches(0.35),
                     label, font_size=10, font_color=GRAY)


def slide_solution(prs: Presentation) -> None:
    """Slide 3: La Soluzione."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _section_title_bar(slide, "La Soluzione", 3, TOTAL_SLIDES)

    features = [
        ("36 regole su 4 layer",
         "Infrastruttura, Architettura, Sicurezza, Qualita. "
         "Analisi come farebbe un CTO esperto al primo giorno."),
        ("Scoring deterministico",
         "Formula trasparente: max(0, 100 - sum(penalty * weight)). "
         "Ogni peso tracciabile fino alla letteratura scientifica."),
        ("Report per il board",
         "Executive summary, score card, compliance NIS2/GDPR, "
         "remediation con effort e rischio business."),
        ("What-If + Storico Audit",
         "Simula l'impatto di una remediation. Storico automatico: "
         "ad ogni run mostra delta score, finding nuovi e risolti."),
    ]

    for i, (title, desc) in enumerate(features):
        top = Inches(1.3 + i * 1.45)
        # Green circle with number
        circle = slide.shapes.add_shape(
            MSO_SHAPE.OVAL, Inches(0.7), top, Inches(0.5), Inches(0.5)
        )
        circle.fill.solid()
        circle.fill.fore_color.rgb = GREEN
        circle.line.fill.background()
        circle.text_frame.paragraphs[0].text = str(i + 1)
        circle.text_frame.paragraphs[0].font.size = Pt(16)
        circle.text_frame.paragraphs[0].font.color.rgb = WHITE
        circle.text_frame.paragraphs[0].font.bold = True
        circle.text_frame.paragraphs[0].alignment = PP_ALIGN.CENTER

        _add_textbox(
            slide, Inches(1.4), top, Inches(5), Inches(0.35),
            title, font_size=16, font_color=NAVY, bold=True,
        )
        _add_textbox(
            slide, Inches(1.4), top + Inches(0.35), Inches(5), Inches(0.9),
            desc, font_size=12, font_color=GRAY,
        )

    # Right side: "Come Funziona" box
    _add_rounded_rect(slide, Inches(7.2), Inches(1.3), Inches(5.5), Inches(5.5),
                       BG_GREEN_LIGHT, GREEN)

    _add_textbox(
        slide, Inches(7.6), Inches(1.5), Inches(4.5), Inches(0.5),
        "Come Funziona", font_size=20, font_color=DARK_GREEN, bold=True,
    )

    steps = [
        "pip install cto-audit",
        "cto-audit scan ./codebase",
        "Report completo in 3 ore (vs 4 settimane)",
        "Score difendibile, pronto per board/investitore",
    ]
    for i, step in enumerate(steps):
        top = Inches(2.3 + i * 1.15)
        step_circle = slide.shapes.add_shape(
            MSO_SHAPE.OVAL, Inches(7.6), top, Inches(0.4), Inches(0.4)
        )
        step_circle.fill.solid()
        step_circle.fill.fore_color.rgb = DARK_GREEN
        step_circle.line.fill.background()
        step_circle.text_frame.paragraphs[0].text = str(i + 1)
        step_circle.text_frame.paragraphs[0].font.size = Pt(13)
        step_circle.text_frame.paragraphs[0].font.color.rgb = WHITE
        step_circle.text_frame.paragraphs[0].font.bold = True
        step_circle.text_frame.paragraphs[0].alignment = PP_ALIGN.CENTER

        _add_textbox(
            slide, Inches(8.2), top + Inches(0.03), Inches(4.2), Inches(0.8),
            step, font_size=14, font_color=NAVY, font_name=FONT_MONO if i < 2 else FONT_BODY,
        )


def slide_demo(prs: Presentation) -> None:
    """Slide 4: Demo — Terminal mockup."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _section_title_bar(slide, "Demo: Output Reale", 4, TOTAL_SLIDES)

    # Terminal background
    _add_rounded_rect(slide, Inches(0.5), Inches(1.2), Inches(12.3), Inches(5.8),
                       NAVY)

    # Terminal title bar
    _add_rect(slide, Inches(0.5), Inches(1.2), Inches(12.3), Inches(0.45), SLATE)

    # Dots
    for i, color in enumerate([RED, YELLOW, GREEN]):
        dot = slide.shapes.add_shape(
            MSO_SHAPE.OVAL,
            Inches(0.8 + i * 0.35), Inches(1.3), Inches(0.2), Inches(0.2)
        )
        dot.fill.solid()
        dot.fill.fore_color.rgb = color
        dot.line.fill.background()

    _add_textbox(
        slide, Inches(2.0), Inches(1.27), Inches(3), Inches(0.35),
        "CTO Audit Agent", font_size=11, font_color=GRAY,
    )

    # Terminal content
    terminal_lines = [
        ("$ cto-audit scan ./client-repo", GREEN),
        ("", WHITE),
        ("Audit precedente trovato: 2026-02-20 14:30", GRAY),
        ("Accesso alla rete: consenso ottenuto (CVE check attivo)", GRAY),
        ("Running 4 analyzers: infra, architecture, security, quality", GRAY),
        ("", WHITE),
        ("=" * 60, GRAY),
        ("  CTO AUDIT REPORT", RGBColor(0x38, 0xBD, 0xF8)),
        ("=" * 60, GRAY),
        ("", WHITE),
        ("  Overall Score          82/100  (Buono)", GREEN),
        ("  Infrastruttura  85    Architettura  74    Sicurezza  88    Qualita  81", RGBColor(0x38, 0xBD, 0xF8)),
        ("", WHITE),
        ("  DELTA: 72 -> 82 (+10.0 MIGLIORATO, 7 giorni)", GREEN),
        ("  Risolti: 3  |  Nuovi: 1  |  Persistenti: 8", YELLOW),
        ("", WHITE),
        ("  Finding: 3 critical, 5 high, 8 medium, 12 low", ORANGE),
        ("  Compliance: NIS2 8/12 PASS | GDPR 6/8 PASS", GREEN),
        ("", WHITE),
        ("  Report salvato: audit_report.html", GRAY),
    ]

    tf = _add_rich_textbox(slide, Inches(0.9), Inches(1.75), Inches(11.5), Inches(5.0))
    tf.paragraphs[0].text = terminal_lines[0][0]
    tf.paragraphs[0].font.size = Pt(12)
    tf.paragraphs[0].font.color.rgb = terminal_lines[0][1]
    tf.paragraphs[0].font.name = FONT_MONO

    for text, color in terminal_lines[1:]:
        p = tf.add_paragraph()
        p.text = text
        p.font.size = Pt(12)
        p.font.color.rgb = color
        p.font.name = FONT_MONO


def slide_four_layers(prs: Presentation) -> None:
    """Slide 5: I 4 Layer di Analisi."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _section_title_bar(slide, "I 4 Layer di Analisi", 5, TOTAL_SLIDES)

    layers = [
        ("Infrastruttura", "10 regole", "CI/CD, Docker, IaC, monorepo, "
         "dipendenze, .env, .env.example, git hygiene",
         RGBColor(0x3B, 0x82, 0xF6), "25%"),
        ("Architettura", "7 regole", "Coupling, coesione, scalabilita, "
         "separation of concerns, layer structure",
         RGBColor(0x8B, 0x5C, 0xF6), "25%"),
        ("Sicurezza", "9 regole", "Credenziali hardcoded, HTTPS, auth, "
         "logging, dependency vulnerabilities, input validation",
         RED, "30%"),
        ("Qualita Codice", "10 regole", "Complessita ciclomatica, "
         "test coverage, linting, documentazione, pre-commit, changelog",
         GREEN, "20%"),
    ]

    for i, (name, rules, desc, color, weight) in enumerate(layers):
        top = Inches(1.3 + i * 1.45)

        # Color bar left
        _add_rect(slide, Inches(0.7), top, Inches(0.12), Inches(1.2), color)

        # Layer name
        _add_textbox(
            slide, Inches(1.1), top, Inches(3), Inches(0.4),
            name, font_size=18, font_color=NAVY, bold=True,
        )
        # Rules count badge
        _add_textbox(
            slide, Inches(3.5), top + Inches(0.05), Inches(1.2), Inches(0.3),
            rules, font_size=11, font_color=color, bold=True,
        )
        # Weight
        _add_textbox(
            slide, Inches(4.6), top + Inches(0.05), Inches(1), Inches(0.3),
            f"peso: {weight}", font_size=10, font_color=LIGHT_GRAY,
        )
        # Description
        _add_textbox(
            slide, Inches(1.1), top + Inches(0.45), Inches(5.5), Inches(0.7),
            desc, font_size=12, font_color=GRAY,
        )

    # Right side: Score formula
    _add_rounded_rect(slide, Inches(7.2), Inches(1.3), Inches(5.5), Inches(5.5),
                       BG_LIGHT, BORDER_LIGHT)

    _add_textbox(
        slide, Inches(7.5), Inches(1.5), Inches(5), Inches(0.5),
        "Scoring Engine", font_size=20, font_color=NAVY, bold=True,
    )

    formula_lines = [
        ("Formula:", True, NAVY),
        ("LayerScore = max(0, 100 - sum(penalty * weight))", False, DARK_GREEN),
        ("", False, NAVY),
        ("Overall = weighted_sum(layer_scores)", False, DARK_GREEN),
        ("", False, NAVY),
        ("Ogni peso e tracciabile:", True, NAVY),
        ("McCabe 1976 (complessita)", False, GRAY),
        ("Martin 1994 (coupling)", False, GRAY),
        ("OWASP Top 10 (sicurezza)", False, GRAY),
        ("CVSS v3.1 (severity)", False, GRAY),
        ("", False, NAVY),
        ("Output: 0-100 deterministico", True, DARK_GREEN),
        ("Stesso input = stesso output. Sempre.", False, GRAY),
    ]

    tf = _add_rich_textbox(slide, Inches(7.5), Inches(2.2), Inches(5), Inches(4.3))
    tf.paragraphs[0].text = formula_lines[0][0]
    tf.paragraphs[0].font.size = Pt(13)
    tf.paragraphs[0].font.color.rgb = formula_lines[0][2]
    tf.paragraphs[0].font.bold = formula_lines[0][1]
    tf.paragraphs[0].font.name = FONT_BODY

    for text, bold, color in formula_lines[1:]:
        p = tf.add_paragraph()
        p.text = text
        p.font.size = Pt(13)
        p.font.color.rgb = color
        p.font.bold = bold
        p.font.name = FONT_MONO if "=" in text or "(" in text else FONT_BODY


def slide_features(prs: Presentation) -> None:
    """Slide 6: Feature Principali."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _section_title_bar(slide, "Feature Principali", 6, TOTAL_SLIDES)

    features = [
        ("Storico Audit e Delta", "Ogni run salvato automaticamente. "
         "Delta: score trend, finding nuovi/risolti.", "STORICO", GREEN),
        ("Consenso Rete", "Pannello trasparente pre-CVE: cosa invia, "
         "a chi, cosa NO. L'utente sceglie.", "PRIVACY", NAVY),
        ("Remediation KB", "37 entry con effort, rischio business, "
         "step per linguaggio", "37 ENTRY", GREEN),
        ("What-If Simulator", "Simula impatto remediation: "
         "'se fixo SQL injection, score sale a 87'", "SIMULAZIONE", ORANGE),
        ("Compliance NIS2/GDPR", "Mapping automatico finding -> articoli "
         "normativi. 3 modalita operative.", "COMPLIANCE", BLUE),
        ("Board Report", "Executive summary + score card + compliance + "
         "roadmap di remediation", "REPORT", BLUE),
        ("Privacy HITL Gate", "4 livelli privacy. Nessun dato esce "
         "dalla macchina senza consenso esplicito.", "HITL", NAVY),
        ("Project Type Detection", "Auto-rileva tipo progetto (web app, "
         "library, CLI, data pipeline). Analisi context-aware.", "SMART", BLUE),
        ("Confidence Score", "Ogni layer score ha confidence 0-100%. "
         "Sai dove il tool ha verificato poco.", "CONFIDENCE", ORANGE),
        ("13+ Linguaggi", "Python, JS/TS, Java, Go, Rust, Ruby, PHP, "
         "C#, C/C++, Kotlin, Swift, Scala, Elixir", "MULTI-LANG", ORANGE),
    ]

    for i, (title, desc, badge, badge_color) in enumerate(features):
        row = i // 2
        col = i % 2
        left = Inches(0.7 + col * 6.2)
        top = Inches(1.3 + row * 1.45)

        _add_rounded_rect(slide, left, top, Inches(5.8), Inches(1.25),
                           BG_LIGHT, BORDER_LIGHT)

        # Badge
        badge_shape = _add_rounded_rect(
            slide, left + Inches(0.15), top + Inches(0.1),
            Inches(1.5), Inches(0.25), badge_color,
        )
        badge_shape.text_frame.paragraphs[0].text = badge
        badge_shape.text_frame.paragraphs[0].font.size = Pt(7)
        badge_shape.text_frame.paragraphs[0].font.color.rgb = WHITE
        badge_shape.text_frame.paragraphs[0].font.bold = True
        badge_shape.text_frame.paragraphs[0].alignment = PP_ALIGN.CENTER

        _add_textbox(
            slide, left + Inches(0.15), top + Inches(0.4), Inches(5.4), Inches(0.3),
            title, font_size=14, font_color=NAVY, bold=True,
        )
        _add_textbox(
            slide, left + Inches(0.15), top + Inches(0.72), Inches(5.4), Inches(0.5),
            desc, font_size=10, font_color=GRAY,
        )


def slide_compliance(prs: Presentation) -> None:
    """Slide 7: Compliance NIS2/GDPR."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _section_title_bar(slide, "Compliance Integrata", 7, TOTAL_SLIDES)

    _add_textbox(
        slide, Inches(0.7), Inches(1.3), Inches(12), Inches(0.5),
        "Mapping automatico: finding tecnico -> controllo normativo. "
        "Rule-based, deterministico, riproducibile.",
        font_size=14, font_color=GRAY,
    )

    # NIS2 column
    _add_rounded_rect(slide, Inches(0.7), Inches(2.1), Inches(5.8), Inches(4.8),
                       BG_LIGHT, BLUE)
    _add_textbox(
        slide, Inches(1.0), Inches(2.2), Inches(5), Inches(0.5),
        "NIS2 Directive — Art. 21", font_size=18, font_color=BLUE, bold=True,
    )
    nis2_controls = [
        "Art.21(a) Risk analysis policies",
        "Art.21(b) Incident handling",
        "Art.21(c) Business continuity",
        "Art.21(d) Supply chain security",
        "Art.21(e) Vulnerability disclosure",
        "Art.21(f) Assessment effectiveness",
        "Art.21(g) Cybersecurity hygiene",
        "Art.21(h) Cryptography policies",
        "Art.21(i) HR security",
        "Art.21(j) Access control",
    ]
    tf = _add_rich_textbox(slide, Inches(1.0), Inches(2.8), Inches(5.2), Inches(3.8))
    tf.paragraphs[0].text = "12 controlli mappati a regole tecniche:"
    tf.paragraphs[0].font.size = Pt(11)
    tf.paragraphs[0].font.color.rgb = NAVY
    tf.paragraphs[0].font.bold = True
    for ctrl in nis2_controls:
        p = tf.add_paragraph()
        p.text = f"  {ctrl}"
        p.font.size = Pt(10)
        p.font.color.rgb = GRAY

    # GDPR column
    _add_rounded_rect(slide, Inches(6.9), Inches(2.1), Inches(5.8), Inches(4.8),
                       BG_LIGHT, DARK_GREEN)
    _add_textbox(
        slide, Inches(7.2), Inches(2.2), Inches(5), Inches(0.5),
        "GDPR — Art. 32", font_size=18, font_color=DARK_GREEN, bold=True,
    )

    gdpr_items = [
        "8 controlli tecnici mappati",
        "Pseudonymization & encryption",
        "Confidentiality & integrity",
        "Availability & resilience",
        "Restore access after incident",
        "Regular testing & assessment",
        "",
        "3 modalita operative:",
        "  Cross-cutting | Standalone | Hybrid",
    ]
    tf2 = _add_rich_textbox(slide, Inches(7.2), Inches(2.8), Inches(5.2), Inches(3.8))
    tf2.paragraphs[0].text = gdpr_items[0]
    tf2.paragraphs[0].font.size = Pt(11)
    tf2.paragraphs[0].font.color.rgb = NAVY
    tf2.paragraphs[0].font.bold = True
    for item in gdpr_items[1:]:
        p = tf2.add_paragraph()
        p.text = f"  {item}" if item and not item.startswith(" ") else item
        p.font.size = Pt(10)
        p.font.color.rgb = GRAY
        if "modalita" in item:
            p.font.bold = True
            p.font.color.rgb = NAVY


def slide_competitors(prs: Presentation) -> None:
    """Slide 8: Confronto Competitor."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _section_title_bar(slide, "Confronto con le Alternative", 8, TOTAL_SLIDES)

    headers = ["", "SonarQube", "Snyk", "Consulente", "CTO Audit Agent"]
    rows = [
        ["Prospettiva", "Developer", "Security (CVE)", "Dipende", "CTO/Executive"],
        ["Tempo setup", "Complesso", "Cloud only", "4 settimane", "3 ore"],
        ["Scoring", "Proprietario", "Severity CVE", "Soggettivo", "Literature-backed"],
        ["Compliance", "Nessuna", "Solo license", "Manuale", "NIS2, GDPR"],
        ["Report board", "No", "No", "Si (manuale)", "Automatico"],
        ["Privacy", "Server", "Cloud", "Locale", "HITL Gate offline"],
        ["Riproducibilita", "Parziale", "Parziale", "Zero", "100%"],
        ["Costo", "$150-450/mo", "$98-498/mo", "Tempo CTO", "Open source"],
    ]

    col_widths = [Inches(1.8), Inches(2.2), Inches(2.2), Inches(2.2), Inches(2.8)]
    start_left = Inches(0.7)
    header_top = Inches(1.3)
    row_h = Inches(0.52)

    # Header row
    left = start_left
    for i, (h, w) in enumerate(zip(headers, col_widths)):
        bg = GREEN if i == 4 else NAVY
        if i == 0:
            bg = SLATE
        _add_rect(slide, left, header_top, w, Inches(0.48), bg)
        _add_textbox(
            slide, left + Inches(0.1), header_top + Inches(0.05),
            w - Inches(0.2), Inches(0.4),
            h, font_size=11, font_color=WHITE, bold=True,
            alignment=PP_ALIGN.CENTER,
        )
        left += w

    # Data rows
    for r, row in enumerate(rows):
        top = header_top + Inches(0.48) + r * row_h
        left = start_left
        bg = WHITE if r % 2 == 0 else BG_LIGHT
        for c, (cell, w) in enumerate(zip(row, col_widths)):
            _add_rect(slide, left, top, w, row_h, bg, BORDER_LIGHT)
            is_last = (c == 4)
            _add_textbox(
                slide, left + Inches(0.1), top + Inches(0.08),
                w - Inches(0.2), row_h - Inches(0.1),
                cell, font_size=10,
                font_color=DARK_GREEN if is_last else (NAVY if c == 0 else GRAY),
                bold=is_last or c == 0,
                alignment=PP_ALIGN.CENTER if c > 0 else PP_ALIGN.LEFT,
            )
            left += w


def slide_validation(prs: Presentation) -> None:
    """Slide 9: Validazione Empirica."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _section_title_bar(slide, "Validazione Empirica", 9, TOTAL_SLIDES)

    metrics = [
        ("733", "Test\nautomatizzati", GREEN),
        ("29", "Repository\nvalidate", BLUE),
        ("100%", "Precision\n& Recall", DARK_GREEN),
        ("78.3", "Score medio\n(range 56-94)", ORANGE),
        ("36", "Regole\ndi analisi", NAVY),
    ]

    for i, (val, label, color) in enumerate(metrics):
        left = Inches(0.5 + i * 2.5)
        _add_rounded_rect(slide, left, Inches(1.4), Inches(2.2), Inches(2.0),
                           BG_GREEN_LIGHT, color)
        _add_textbox(
            slide, left, Inches(1.6), Inches(2.2), Inches(0.7),
            val, font_size=36, font_color=color, bold=True,
            alignment=PP_ALIGN.CENTER,
        )
        _add_textbox(
            slide, left, Inches(2.4), Inches(2.2), Inches(0.8),
            label, font_size=11, font_color=GRAY,
            alignment=PP_ALIGN.CENTER,
        )

    # Repository list
    _add_textbox(
        slide, Inches(0.7), Inches(3.8), Inches(12), Inches(0.4),
        "Repository validate (20 reali + 9 sintetiche):",
        font_size=13, font_color=NAVY, bold=True,
    )

    repos = [
        "FastAPI", "Django", "Express", "Spring PetClinic", "Gin",
        "Fiber", "MinIO", "Mastodon", "Ghost", "Socket.io",
        "Scrapy", "Sanic", "Jekyll", "Ripgrep", "Laravel",
        "nopCommerce", "Java Design Patterns", "Clean Architecture",
        "httpie", "black",
    ]
    _add_textbox(
        slide, Inches(0.7), Inches(4.3), Inches(12), Inches(1.5),
        " | ".join(repos),
        font_size=11, font_color=GRAY,
    )

    # Distribution info
    _add_rounded_rect(slide, Inches(0.7), Inches(5.5), Inches(11.9), Inches(1.2),
                       BG_LIGHT, BORDER_LIGHT)
    _add_textbox(
        slide, Inches(1.0), Inches(5.6), Inches(11), Inches(0.4),
        "Distribuzione score su 20 repo reali: min 56 | Q1 71 | mediana 79 | Q3 86 | max 94",
        font_size=13, font_color=NAVY, bold=True,
    )
    _add_textbox(
        slide, Inches(1.0), Inches(6.1), Inches(11), Inches(0.4),
        "Linguaggi: Python, JavaScript/TypeScript, Java, Go, Rust, Ruby, PHP, C#, C/C++, Kotlin, Swift, Scala, Elixir",
        font_size=11, font_color=GRAY,
    )


def slide_how_different(prs: Presentation) -> None:
    """Slide 10: Perche Diverso (non AI hype)."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _section_title_bar(slide, "Non AI Hype — Deterministico e Tracciabile", 10, TOTAL_SLIDES)

    points = [
        ("Deterministico, non probabilistico",
         "Formula matematica trasparente. Nessun LLM nel core scoring. "
         "Stesso input = stesso output. Sempre."),
        ("Static analysis, non code execution",
         "Non eseguiamo mai il codice del target. Zero sandbox, zero Docker. "
         "Nessun rischio per il sistema analizzato."),
        ("Rule-based compliance, non NLP",
         "Mapping deterministico finding -> controllo normativo. "
         "Nessun modello AI nel loop di compliance. Verificabile."),
        ("Offline-first, non cloud-dependent",
         "Funziona al 100% senza connessione internet. "
         "Nessun dato lascia la macchina. Privacy by design."),
        ("Any codebase, non settore-specifico",
         "13+ linguaggi. Dall'e-commerce al fintech, dal SaaS all'enterprise. "
         "Non limitato a startup AI."),
        ("Evidence chain, non black box",
         "Ogni punto perso e tracciabile: "
         "finding -> regola -> peso -> framework accademico."),
    ]

    for i, (title, desc) in enumerate(points):
        row = i // 2
        col = i % 2
        left = Inches(0.7 + col * 6.2)
        top = Inches(1.3 + row * 1.95)

        # Green check
        _add_textbox(
            slide, left, top + Inches(0.1), Inches(0.4), Inches(0.3),
            "\u2713", font_size=18, font_color=GREEN, bold=True,
        )
        _add_textbox(
            slide, left + Inches(0.4), top, Inches(5.4), Inches(0.35),
            title, font_size=14, font_color=NAVY, bold=True,
        )
        _add_textbox(
            slide, left + Inches(0.4), top + Inches(0.4), Inches(5.4), Inches(1.2),
            desc, font_size=11, font_color=GRAY,
        )


def slide_business_model(prs: Presentation) -> None:
    """Slide 11: Business Model."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _section_title_bar(slide, "Modello di Business — Open Core", 11, TOTAL_SLIDES)

    tiers = [
        ("Open Source", "Gratuito", [
            "CLI completa",
            "4 analyzer, 36 regole",
            "Scoring deterministico",
            "Report Terminal/MD/JSON",
            "Community support",
        ], False, BORDER_LIGHT),
        ("Professional", "Per utente/anno", [
            "Tutto Open Source +",
            "Report HTML/PDF/Board",
            "What-If Simulator",
            "Compliance NIS2/GDPR",
            "Audit history & delta",
            "White-label report",
            "Supporto prioritario",
        ], True, GREEN),
        ("Enterprise", "Su richiesta", [
            "Tutto Professional +",
            "Profili custom (industry)",
            "Compliance aggiuntivi",
            "Multi-repo dashboard",
            "Formazione dedicata",
            "SLA & supporto dedicato",
        ], False, BORDER_LIGHT),
    ]

    for i, (name, price, features, featured, border) in enumerate(tiers):
        left = Inches(0.7 + i * 4.15)
        w = Inches(3.85)

        _add_rounded_rect(slide, left, Inches(1.3), w, Inches(5.6),
                           WHITE if not featured else BG_GREEN_LIGHT, border)

        if featured:
            _add_rounded_rect(slide, left, Inches(1.3), w, Inches(0.35), GREEN)
            _add_textbox(
                slide, left, Inches(1.3), w, Inches(0.35),
                "CONSIGLIATO", font_size=9, font_color=WHITE, bold=True,
                alignment=PP_ALIGN.CENTER,
            )

        name_top = Inches(1.85) if featured else Inches(1.5)
        _add_textbox(
            slide, left + Inches(0.2), name_top, w - Inches(0.4), Inches(0.4),
            name, font_size=18, font_color=NAVY, bold=True,
            alignment=PP_ALIGN.CENTER,
        )
        _add_textbox(
            slide, left + Inches(0.2), name_top + Inches(0.45), w - Inches(0.4), Inches(0.4),
            price, font_size=20, font_color=DARK_GREEN, bold=True,
            alignment=PP_ALIGN.CENTER,
        )

        tf = _add_rich_textbox(
            slide, left + Inches(0.3), name_top + Inches(1.1),
            w - Inches(0.6), Inches(3.5),
        )
        tf.paragraphs[0].text = f"\u2713  {features[0]}"
        tf.paragraphs[0].font.size = Pt(11)
        tf.paragraphs[0].font.color.rgb = GRAY
        for feat in features[1:]:
            p = tf.add_paragraph()
            p.text = f"\u2713  {feat}"
            p.font.size = Pt(11)
            p.font.color.rgb = GRAY
            p.space_before = Pt(4)


def slide_patent_safety(prs: Presentation) -> None:
    """Slide 12: Patent Safety."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _section_title_bar(slide, "Patent Safety — Rischio Basso", 12, TOTAL_SLIDES)

    _add_textbox(
        slide, Inches(0.7), Inches(1.3), Inches(12), Inches(0.6),
        "Analisi del patent US Provisional \"Multi-Agent AI Risk Evaluation System\". "
        "Per violare il Claim 1 servono TUTTI E 6 gli elementi. Ne implementiamo ZERO.",
        font_size=13, font_color=GRAY,
    )

    elements = [
        ("Legal NLP module", "NO", "Noi: rule-based matching"),
        ("Sandbox execution", "NO", "Noi: static analysis only"),
        ("Market risk (API esterne)", "NO", "Noi: solo file locali"),
        ("Multi-agent LLM", "NO", "Noi: analyzer deterministici"),
        ("Probabilistic rating", "NO", "Noi: formula matematica 0-100"),
        ("SaaS dashboards", "PARZIALE", "Noi: report locali MD/HTML"),
    ]

    headers = ["Elemento Patent", "Presente?", "Nostro approccio"]
    col_w = [Inches(3.5), Inches(1.5), Inches(6.2)]
    left_start = Inches(0.7)

    # Header
    left = left_start
    for h, w in zip(headers, col_w):
        _add_rect(slide, left, Inches(2.1), w, Inches(0.45), NAVY)
        _add_textbox(
            slide, left + Inches(0.1), Inches(2.12), w - Inches(0.2), Inches(0.4),
            h, font_size=11, font_color=WHITE, bold=True,
        )
        left += w

    for r, (elem, present, approach) in enumerate(elements):
        top = Inches(2.55) + r * Inches(0.55)
        bg = WHITE if r % 2 == 0 else BG_LIGHT
        left = left_start

        for c, (text, w) in enumerate(zip([elem, present, approach], col_w)):
            _add_rect(slide, left, top, w, Inches(0.5), bg, BORDER_LIGHT)
            color = RED if text == "NO" else (YELLOW if text == "PARZIALE" else GRAY)
            if c == 0:
                color = NAVY
            _add_textbox(
                slide, left + Inches(0.1), top + Inches(0.08),
                w - Inches(0.2), Inches(0.35),
                text, font_size=10, font_color=color,
                bold=(c == 1),
            )
            left += w

    _add_textbox(
        slide, Inches(0.7), Inches(6.0), Inches(12), Inches(0.8),
        "Risultato: 0/6 elementi implementati. Massima distanza dal patent. "
        "Dettagli completi in docs/PATENT_ANALYSIS.md",
        font_size=12, font_color=NAVY, bold=True,
    )


def slide_roadmap(prs: Presentation) -> None:
    """Slide 13: Roadmap."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _section_title_bar(slide, "Roadmap di Sviluppo", 13, TOTAL_SLIDES)

    phases = [
        ("Fase 1 — MVP", "Completata", [
            "36 regole, 733 test",
            "Project type detection",
            "Confidence score per layer",
            "NIS2/GDPR compliance",
            "5 formati report",
        ], GREEN, True),
        ("Fase 2 — Deep", "Q2-Q3 2026", [
            "OWASP Top 10 completo",
            "tree-sitter AST",
            "NIST CSF profile",
            "Cross-layer correlation",
        ], BLUE, False),
        ("Fase 3 — Multi", "Q3-Q4 2026", [
            "GitRemoteSource",
            "PDF professionale",
            "CI/CD integrations",
            "Ollama enhancement",
        ], RGBColor(0x8B, 0x5C, 0xF6), False),
        ("Fase 4 — Intel", "Q1-Q2 2027", [
            "Custom rules YAML",
            "MCP server (IDE AI)",
            "Profili industry",
            "Multi-repo dashboard",
        ], ORANGE, False),
        ("Fase 5 — Scale", "Q3 2027+", [
            "AI Act, SOC2, PCI-DSS",
            "Multi-repo dashboard",
            "Internationalization",
            "Container/API security",
        ], RED, False),
    ]

    # Timeline line
    _add_rect(slide, Inches(0.7), Inches(2.3), Inches(11.9), Inches(0.04), BORDER_LIGHT)

    for i, (name, date, items, color, completed) in enumerate(phases):
        left = Inches(0.5 + i * 2.5)

        # Dot on timeline
        dot = slide.shapes.add_shape(
            MSO_SHAPE.OVAL,
            left + Inches(0.85), Inches(2.15), Inches(0.3), Inches(0.3),
        )
        dot.fill.solid()
        dot.fill.fore_color.rgb = color
        dot.line.fill.background()

        # Phase name
        _add_textbox(
            slide, left, Inches(2.6), Inches(2.3), Inches(0.4),
            name, font_size=13, font_color=NAVY, bold=True,
            alignment=PP_ALIGN.CENTER,
        )
        # Date
        _add_textbox(
            slide, left, Inches(3.0), Inches(2.3), Inches(0.3),
            date, font_size=10,
            font_color=GREEN if completed else LIGHT_GRAY,
            bold=completed,
            alignment=PP_ALIGN.CENTER,
        )

        # Items
        tf = _add_rich_textbox(slide, left + Inches(0.1), Inches(3.5), Inches(2.1), Inches(3.0))
        tf.paragraphs[0].text = f"  {items[0]}"
        tf.paragraphs[0].font.size = Pt(10)
        tf.paragraphs[0].font.color.rgb = GRAY
        for item in items[1:]:
            p = tf.add_paragraph()
            p.text = f"  {item}"
            p.font.size = Pt(10)
            p.font.color.rgb = GRAY
            p.space_before = Pt(2)


def slide_use_cases(prs: Presentation) -> None:
    """Slide 14: Use Case per Audience."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _section_title_bar(slide, "Use Case", 14, TOTAL_SLIDES)

    cases = [
        ("Fractional CTO", "Da 4 settimane a 3 ore",
         "Assessment rapido al primo ingresso. "
         "Report difendibile per il board. "
         "What-If per prioritizzare.",
         BLUE),
        ("Venture Capital / PE", "Due diligence quantitativa",
         "Profilo vc-diligence security-weighted. "
         "Benchmark su 20 repo. "
         "Compliance pre-investimento.",
         GREEN),
        ("Audit / Compliance", "Compliance scalabile",
         "NIS2/GDPR automatico. "
         "Evidence chain tracciabile. "
         "Riproducibile al 100%.",
         ORANGE),
        ("PMI senza CTO", "Autodiagnostica",
         "Self-service, nessun esperto richiesto. "
         "Score comprensibile. "
         "Piano d'azione prioritizzato.",
         RGBColor(0x8B, 0x5C, 0xF6)),
    ]

    for i, (audience, value, desc, color) in enumerate(cases):
        left = Inches(0.5 + i * 3.15)
        top = Inches(1.3)

        _add_rounded_rect(slide, left, top, Inches(2.95), Inches(5.4),
                           WHITE, color)

        # Color header bar
        _add_rect(slide, left, top, Inches(2.95), Inches(0.6), color)
        _add_textbox(
            slide, left + Inches(0.15), top + Inches(0.08), Inches(2.6), Inches(0.5),
            audience, font_size=14, font_color=WHITE, bold=True,
            alignment=PP_ALIGN.CENTER,
        )

        _add_textbox(
            slide, left + Inches(0.2), top + Inches(0.8), Inches(2.5), Inches(0.6),
            value, font_size=13, font_color=NAVY, bold=True,
            alignment=PP_ALIGN.CENTER,
        )

        _add_textbox(
            slide, left + Inches(0.2), top + Inches(1.5), Inches(2.5), Inches(3.5),
            desc, font_size=11, font_color=GRAY,
        )


def slide_cta(prs: Presentation) -> None:
    """Slide 15: Call to Action."""
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, NAVY)

    _add_rect(slide, Inches(0), Inches(2.0), SLIDE_W, Inches(0.05), GREEN)

    _add_textbox(
        slide, Inches(1.5), Inches(2.5), Inches(10), Inches(0.9),
        "Prova CTO Audit Agent", font_size=40, font_color=WHITE, bold=True,
        alignment=PP_ALIGN.CENTER,
    )
    _add_textbox(
        slide, Inches(2), Inches(3.4), Inches(9), Inches(0.8),
        "Assessment tecnico in 3 ore. Scoring deterministico. "
        "Compliance automatica. 100% offline.",
        font_size=18, font_color=LIGHT_GRAY, alignment=PP_ALIGN.CENTER,
    )

    # Command box
    _add_rounded_rect(slide, Inches(3.5), Inches(4.6), Inches(6.3), Inches(0.7),
                       SLATE)
    _add_textbox(
        slide, Inches(3.7), Inches(4.65), Inches(5.9), Inches(0.6),
        "pip install cto-audit && cto-audit scan ./your-repo",
        font_size=16, font_color=GREEN, font_name=FONT_MONO,
        alignment=PP_ALIGN.CENTER,
    )

    _add_rect(slide, Inches(5.5), Inches(5.7), Inches(2.3), Inches(0.04), GRAY)

    _add_textbox(
        slide, Inches(2), Inches(6.0), Inches(9), Inches(0.5),
        "info@cto-audit.dev",
        font_size=13, font_color=GRAY, alignment=PP_ALIGN.CENTER,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    prs = Presentation()

    # Set 16:9 widescreen
    prs.slide_width = SLIDE_W
    prs.slide_height = SLIDE_H

    slide_cover(prs)           # 1
    slide_problem(prs)         # 2
    slide_solution(prs)        # 3
    slide_demo(prs)            # 4
    slide_four_layers(prs)     # 5
    slide_features(prs)        # 6
    slide_compliance(prs)      # 7
    slide_competitors(prs)     # 8
    slide_validation(prs)      # 9
    slide_how_different(prs)   # 10
    slide_business_model(prs)  # 11
    slide_patent_safety(prs)   # 12
    slide_roadmap(prs)         # 13
    slide_use_cases(prs)       # 14
    slide_cta(prs)             # 15

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_path = OUTPUT_DIR / "cto_audit_pitch_deck.pptx"
    prs.save(str(output_path))

    size_kb = output_path.stat().st_size / 1024
    print(f"Pitch deck generato: {output_path} ({size_kb:.0f} KB)")
    print(f"  {TOTAL_SLIDES} slide, formato 16:9 widescreen")
    print(f"  Apri con PowerPoint o LibreOffice Impress per esportare in PDF")


if __name__ == "__main__":
    main()
