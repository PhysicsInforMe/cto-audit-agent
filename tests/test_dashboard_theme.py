"""
Test per il tema della dashboard.
"""

from __future__ import annotations

from cto_audit.dashboard.theme import (
    BG_DARK, CARD_BG, COLOR_GOOD, COLOR_WARNING, COLOR_DANGER,
    CUSTOM_CSS, SCORE_GOOD, SCORE_WARNING, score_color,
)


class TestScoreColor:
    def test_score_buono(self):
        assert score_color(85) == COLOR_GOOD

    def test_score_al_limite_buono(self):
        assert score_color(70) == COLOR_GOOD

    def test_score_warning(self):
        assert score_color(55) == COLOR_WARNING

    def test_score_al_limite_warning(self):
        assert score_color(40) == COLOR_WARNING

    def test_score_danger(self):
        assert score_color(20) == COLOR_DANGER

    def test_score_zero(self):
        assert score_color(0) == COLOR_DANGER

    def test_score_cento(self):
        assert score_color(100) == COLOR_GOOD


class TestThemeConstants:
    def test_bg_dark_hex(self):
        assert BG_DARK.startswith("#")

    def test_card_bg_hex(self):
        assert CARD_BG.startswith("#")

    def test_custom_css_contiene_bg(self):
        assert BG_DARK in CUSTOM_CSS

    def test_custom_css_contiene_print(self):
        assert "@media print" in CUSTOM_CSS
