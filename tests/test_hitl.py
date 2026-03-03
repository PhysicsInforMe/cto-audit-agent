"""
Test per il Blocco 5: HITL Gate (Persistence + Reviewer).

Verifica:
- Persistence: salva e ricarica classificazioni
- Persistence: rileva file aggiunti/rimossi/modificati
- Reviewer: mostra dati corretti (mock I/O)
- Override SENSITIVE→SAFE richiede "CONFERMO"
- Override altri versi non richiede "CONFERMO"
- Annullamento esce senza modificare
- Integrazione: Scanner → PrivacyClassifier → HITL → persistenza
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from rich.console import Console

from cto_audit.collectors.privacy import PrivacyClassifier
from cto_audit.collectors.scanner import FileScanner
from cto_audit.core.models import (
    FileClassification,
    FileInfo,
    PrivacyCategory,
    StackInfo,
)
from cto_audit.hitl.persistence import (
    CLASSIFICATION_FILENAME,
    ClassificationPersistence,
    DiffResult,
    ReloadOption,
)
from cto_audit.hitl.reviewer import (
    HITLReviewer,
    ReviewAction,
    ReviewResult,
)
from cto_audit.sources.local import LocalRepoSource


# --- Helper ---


def _make_classification(
    path: str,
    category: PrivacyCategory,
    reason: str = "Test",
    size: int = 100,
    extension: str = ".py",
) -> FileClassification:
    """Crea una FileClassification di test."""
    return FileClassification(
        file_info=FileInfo(path=path, size=size, extension=extension, lines_of_code=10),
        category=category,
        reason=reason,
        confidence=1.0,
    )


def _make_sample_classifications() -> list[FileClassification]:
    """Crea un set di classificazioni di esempio per i test."""
    return [
        _make_classification("src/app.py", PrivacyCategory.SAFE, "Nessun pattern sensibile"),
        _make_classification("src/models.py", PrivacyCategory.SAFE, "Nessun pattern sensibile"),
        _make_classification("src/utils.py", PrivacyCategory.SAFE, "Nessun pattern sensibile"),
        _make_classification(".env", PrivacyCategory.SENSITIVE, "Variabili ambiente", extension=""),
        _make_classification("config/secrets.yml", PrivacyCategory.SENSITIVE, "Nome file sospetto", extension=".yml"),
        _make_classification("logo.png", PrivacyCategory.EXCLUDED, "Estensione esclusa: .png", extension=".png"),
    ]


# ========== Test Persistence ==========


class TestPersistenceSave:
    """Test per il salvataggio delle classificazioni."""

    def test_salva_e_crea_file(self, tmp_path: Path):
        """save() crea il file .cto-audit-classification.yml."""
        persistence = ClassificationPersistence(tmp_path)
        classifications = _make_sample_classifications()

        persistence.save(classifications)

        assert persistence.exists()
        assert (tmp_path / CLASSIFICATION_FILENAME).exists()

    def test_salva_con_overrides(self, tmp_path: Path):
        """save() include gli override nel file."""
        persistence = ClassificationPersistence(tmp_path)
        classifications = _make_sample_classifications()
        overrides = [{"file": "src/app.py", "from": "safe", "to": "local_llm", "reason": "Test"}]

        persistence.save(classifications, overrides=overrides)

        loaded_overrides = persistence.load_overrides()
        assert len(loaded_overrides) == 1
        assert loaded_overrides[0]["file"] == "src/app.py"


class TestPersistenceLoad:
    """Test per il caricamento delle classificazioni."""

    def test_carica_classificazioni(self, tmp_path: Path):
        """load() ricostruisce le classificazioni dal file YAML."""
        persistence = ClassificationPersistence(tmp_path)
        original = _make_sample_classifications()

        persistence.save(original)
        loaded = persistence.load()

        assert len(loaded) == len(original)
        for orig, load in zip(original, loaded):
            assert orig.file_info.path == load.file_info.path
            assert orig.category == load.category
            assert orig.reason == load.reason
            assert orig.file_info.size == load.file_info.size

    def test_carica_preserva_categorie(self, tmp_path: Path):
        """load() preserva tutte le categorie corrette."""
        persistence = ClassificationPersistence(tmp_path)
        original = _make_sample_classifications()

        persistence.save(original)
        loaded = persistence.load()

        cat_map = {c.file_info.path: c.category for c in loaded}
        assert cat_map["src/app.py"] == PrivacyCategory.SAFE
        assert cat_map[".env"] == PrivacyCategory.SENSITIVE
        assert cat_map["logo.png"] == PrivacyCategory.EXCLUDED

    def test_carica_file_inesistente(self, tmp_path: Path):
        """load() solleva FileNotFoundError se il file non esiste."""
        persistence = ClassificationPersistence(tmp_path)
        with pytest.raises(FileNotFoundError):
            persistence.load()

    def test_exists_false_se_non_salvato(self, tmp_path: Path):
        """exists() ritorna False se non è mai stato salvato."""
        persistence = ClassificationPersistence(tmp_path)
        assert persistence.exists() is False

    def test_delete_rimuove_file(self, tmp_path: Path):
        """delete() rimuove il file di classificazione."""
        persistence = ClassificationPersistence(tmp_path)
        persistence.save(_make_sample_classifications())
        assert persistence.exists()

        persistence.delete()
        assert not persistence.exists()


class TestPersistenceDiff:
    """Test per il rilevamento differenze tra classificazione salvata e file attuali."""

    def test_rileva_file_nuovi(self, tmp_path: Path):
        """diff() rileva file presenti nel codebase ma non nella classificazione."""
        persistence = ClassificationPersistence(tmp_path)
        persistence.save([
            _make_classification("a.py", PrivacyCategory.SAFE),
        ])

        current = [
            FileInfo(path="a.py", size=100, extension=".py"),
            FileInfo(path="b.py", size=200, extension=".py"),  # nuovo
        ]

        diff = persistence.diff(current)
        assert "b.py" in diff.new_files
        assert len(diff.new_files) == 1
        assert diff.has_changes

    def test_rileva_file_rimossi(self, tmp_path: Path):
        """diff() rileva file nella classificazione ma non più nel codebase."""
        persistence = ClassificationPersistence(tmp_path)
        persistence.save([
            _make_classification("a.py", PrivacyCategory.SAFE),
            _make_classification("b.py", PrivacyCategory.SAFE),
        ])

        current = [
            FileInfo(path="a.py", size=100, extension=".py"),
            # b.py rimosso
        ]

        diff = persistence.diff(current)
        assert "b.py" in diff.removed_files
        assert len(diff.removed_files) == 1
        assert diff.has_changes

    def test_rileva_file_modificati(self, tmp_path: Path):
        """diff() rileva file con dimensione diversa."""
        persistence = ClassificationPersistence(tmp_path)
        persistence.save([
            _make_classification("a.py", PrivacyCategory.SAFE, size=100),
        ])

        current = [
            FileInfo(path="a.py", size=500, extension=".py"),  # size diversa
        ]

        diff = persistence.diff(current)
        assert "a.py" in diff.modified_files
        assert len(diff.modified_files) == 1
        assert diff.has_changes

    def test_nessun_cambiamento(self, tmp_path: Path):
        """diff() con file identici → nessun cambiamento."""
        persistence = ClassificationPersistence(tmp_path)
        persistence.save([
            _make_classification("a.py", PrivacyCategory.SAFE, size=100),
        ])

        current = [
            FileInfo(path="a.py", size=100, extension=".py"),
        ]

        diff = persistence.diff(current)
        assert not diff.has_changes
        assert len(diff.unchanged_files) == 1
        assert "a.py" in diff.unchanged_files

    def test_diff_senza_file_salvato(self, tmp_path: Path):
        """diff() senza classificazione precedente → tutti nuovi."""
        persistence = ClassificationPersistence(tmp_path)
        current = [
            FileInfo(path="a.py", size=100, extension=".py"),
            FileInfo(path="b.py", size=200, extension=".py"),
        ]

        diff = persistence.diff(current)
        assert len(diff.new_files) == 2
        assert diff.has_changes

    def test_diff_summary(self, tmp_path: Path):
        """Il summary del diff è leggibile."""
        diff = DiffResult(
            new_files=["c.py"],
            modified_files=["a.py"],
            removed_files=["b.py"],
            unchanged_files=[],
        )
        summary = diff.summary
        assert "3 file cambiati" in summary
        assert "1 nuovi" in summary
        assert "1 modificati" in summary
        assert "1 rimossi" in summary


# ========== Test Reviewer ==========


def _make_reviewer_with_inputs(inputs: list[str]) -> HITLReviewer:
    """Crea un HITLReviewer con input predefiniti (mock)."""
    input_iter = iter(inputs)
    mock_input = lambda prompt: next(input_iter)
    console = Console(file=MagicMock(), force_terminal=True, no_color=True)
    return HITLReviewer(console=console, input_fn=mock_input)


class TestReviewerConfirm:
    """Test per la conferma delle classificazioni."""

    def test_conferma_diretta(self):
        """Scelta C + conferma s → CONFIRMED."""
        reviewer = _make_reviewer_with_inputs(["C", "s"])
        classifications = _make_sample_classifications()

        result, final, overrides = reviewer.review(classifications)

        assert result == ReviewResult.CONFIRMED
        assert len(final) == len(classifications)
        assert overrides == []

    def test_conferma_con_si(self):
        """Scelta C + conferma 'si' → CONFIRMED."""
        reviewer = _make_reviewer_with_inputs(["C", "si"])
        classifications = _make_sample_classifications()

        result, _, _ = reviewer.review(classifications)
        assert result == ReviewResult.CONFIRMED

    def test_rifiuto_conferma_poi_annulla(self):
        """Scelta C + rifiuto (N) → torna al menu, poi Q → CANCELLED."""
        reviewer = _make_reviewer_with_inputs(["C", "N", "Q"])
        classifications = _make_sample_classifications()

        result, _, _ = reviewer.review(classifications)
        assert result == ReviewResult.CANCELLED


class TestReviewerCancel:
    """Test per l'annullamento dell'audit."""

    def test_annullamento(self):
        """Scelta Q → CANCELLED, classificazioni originali invariate."""
        reviewer = _make_reviewer_with_inputs(["Q"])
        classifications = _make_sample_classifications()

        result, final, overrides = reviewer.review(classifications)

        assert result == ReviewResult.CANCELLED
        assert final == classifications  # originali, non modificate
        assert overrides == []


class TestReviewerView:
    """Test per la visualizzazione dei file."""

    def test_visualizza_safe_poi_conferma(self):
        """V (view SAFE) + C + s → CONFIRMED."""
        reviewer = _make_reviewer_with_inputs(["V", "C", "s"])
        classifications = _make_sample_classifications()

        result, _, _ = reviewer.review(classifications)
        assert result == ReviewResult.CONFIRMED

    def test_visualizza_sensitive_poi_conferma(self):
        """S (view SENSITIVE) + C + s → CONFIRMED."""
        reviewer = _make_reviewer_with_inputs(["S", "C", "s"])
        classifications = _make_sample_classifications()

        result, _, _ = reviewer.review(classifications)
        assert result == ReviewResult.CONFIRMED

    def test_visualizza_excluded_poi_conferma(self):
        """X (view EXCLUDED) + C + s → CONFIRMED."""
        reviewer = _make_reviewer_with_inputs(["X", "C", "s"])
        classifications = _make_sample_classifications()

        result, _, _ = reviewer.review(classifications)
        assert result == ReviewResult.CONFIRMED


class TestReviewerEditSensitiveToSafe:
    """Test per l'override SENSITIVE → SAFE (richiede CONFERMO)."""

    def test_sensitive_to_safe_con_confermo(self):
        """Override SENSITIVE→SAFE con digitazione CONFERMO → accettato."""
        # E (edit) → 4 (seleziona .env, 4° nell'ordine editable)
        # → 1 (SAFE) → CONFERMO → C → s
        reviewer = _make_reviewer_with_inputs([
            "E", "4", "1", "CONFERMO", "C", "s"
        ])
        classifications = _make_sample_classifications()

        result, final, overrides = reviewer.review(classifications)

        assert result == ReviewResult.CONFIRMED
        assert len(overrides) == 1
        assert overrides[0]["from"] == "sensitive"
        assert overrides[0]["to"] == "safe"

        # Il file .env ora è SAFE
        env_class = next(c for c in final if c.file_info.path == ".env")
        assert env_class.category == PrivacyCategory.SAFE

    def test_sensitive_to_safe_senza_confermo_rifiutato(self):
        """Override SENSITIVE→SAFE senza CONFERMO → rifiutato."""
        # E → 4 → 1 (SAFE) → "no" (non CONFERMO) → Q
        reviewer = _make_reviewer_with_inputs([
            "E", "4", "1", "no", "Q"
        ])
        classifications = _make_sample_classifications()

        result, final, overrides = reviewer.review(classifications)

        assert result == ReviewResult.CANCELLED
        assert overrides == []
        # .env rimane SENSITIVE
        env_class = next(c for c in final if c.file_info.path == ".env")
        assert env_class.category == PrivacyCategory.SENSITIVE


class TestReviewerEditOtherDirections:
    """Test per override in direzioni che NON richiedono CONFERMO."""

    def test_safe_to_sensitive_no_confermo(self):
        """Override SAFE→SENSITIVE non richiede CONFERMO."""
        # E → 1 (src/app.py) → 3 (SENSITIVE) → C → s
        reviewer = _make_reviewer_with_inputs([
            "E", "1", "3", "C", "s"
        ])
        classifications = _make_sample_classifications()

        result, final, overrides = reviewer.review(classifications)

        assert result == ReviewResult.CONFIRMED
        assert len(overrides) == 1
        assert overrides[0]["from"] == "safe"
        assert overrides[0]["to"] == "sensitive"

        app_class = next(c for c in final if c.file_info.path == "src/app.py")
        assert app_class.category == PrivacyCategory.SENSITIVE

    def test_safe_to_local_llm_no_confermo(self):
        """Override SAFE→LOCAL_LLM non richiede CONFERMO."""
        # E → 1 (src/app.py) → 2 (LOCAL_LLM) → C → s
        reviewer = _make_reviewer_with_inputs([
            "E", "1", "2", "C", "s"
        ])
        classifications = _make_sample_classifications()

        result, final, overrides = reviewer.review(classifications)

        assert result == ReviewResult.CONFIRMED
        assert len(overrides) == 1

        app_class = next(c for c in final if c.file_info.path == "src/app.py")
        assert app_class.category == PrivacyCategory.LOCAL_LLM


class TestReviewerMoveAllSensitive:
    """Test per spostare tutto a SENSITIVE."""

    def test_move_all_to_sensitive(self):
        """Scelta A sposta tutti SAFE e LOCAL_LLM a SENSITIVE."""
        # A → C → s
        reviewer = _make_reviewer_with_inputs(["A", "C", "s"])
        classifications = _make_sample_classifications()

        result, final, overrides = reviewer.review(classifications)

        assert result == ReviewResult.CONFIRMED
        # 3 file SAFE spostati a SENSITIVE
        assert len(overrides) == 3

        for c in final:
            if c.category != PrivacyCategory.EXCLUDED:
                assert c.category == PrivacyCategory.SENSITIVE


class TestReviewerWithStackInfo:
    """Test che la review mostra correttamente le info stack."""

    def test_review_con_stack_info(self):
        """La review accetta e usa stack_info senza errori."""
        reviewer = _make_reviewer_with_inputs(["C", "s"])
        classifications = _make_sample_classifications()
        stack = StackInfo(
            languages={"python": 0.7, "javascript": 0.3},
            frameworks=["FastAPI", "React"],
            infra_type=["Docker", "GitHub Actions"],
        )

        result, _, _ = reviewer.review(classifications, stack_info=stack)
        assert result == ReviewResult.CONFIRMED


# ========== Test Integrazione Completa ==========


class TestIntegrazioneCompleta:
    """Test end-to-end: Scanner → PrivacyClassifier → HITL → Persistenza."""

    def test_pipeline_completa(self, tmp_path: Path):
        """Pipeline completa: scan, classifica, review (auto-confirm), persisti."""
        # Crea repo
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("print('hello')\n", encoding="utf-8")
        (tmp_path / ".env").write_text("PASSWORD=secret\n", encoding="utf-8")
        (tmp_path / "logo.png").write_bytes(b"\x89PNG\x00")

        # Pipeline
        source = LocalRepoSource(tmp_path)
        scanner = FileScanner(source)
        classifier = PrivacyClassifier(source)

        files = scanner.scan()
        classifications = classifier.classify(files)

        # Review con mock (conferma diretta)
        reviewer = _make_reviewer_with_inputs(["C", "s"])
        result, final, overrides = reviewer.review(classifications)
        assert result == ReviewResult.CONFIRMED

        # Persistenza
        persistence = ClassificationPersistence(tmp_path)
        persistence.save(final, overrides=overrides)

        # Ricarica e verifica
        loaded = persistence.load()
        cat_map = {c.file_info.path: c.category for c in loaded}
        assert cat_map["src/app.py"] == PrivacyCategory.SAFE
        assert cat_map[".env"] == PrivacyCategory.SENSITIVE
        assert cat_map["logo.png"] == PrivacyCategory.EXCLUDED

    def test_pipeline_con_reuse(self, tmp_path: Path):
        """Pipeline con riuso della classificazione precedente."""
        (tmp_path / "app.py").write_text("pass\n", encoding="utf-8")

        source = LocalRepoSource(tmp_path)
        scanner = FileScanner(source)
        classifier = PrivacyClassifier(source)
        files = scanner.scan()
        classifications = classifier.classify(files)

        # Primo run: salva
        persistence = ClassificationPersistence(tmp_path)
        persistence.save(classifications)

        # Secondo run: riusa
        assert persistence.exists()
        loaded = persistence.load()
        assert len(loaded) == 1
        assert loaded[0].file_info.path == "app.py"
        assert loaded[0].category == PrivacyCategory.SAFE

    def test_pipeline_diff_dopo_modifica(self, tmp_path: Path):
        """Rileva file nuovi e modificati tra due run."""
        # Primo run
        (tmp_path / "app.py").write_text("pass\n", encoding="utf-8")
        source = LocalRepoSource(tmp_path)
        scanner = FileScanner(source)
        classifier = PrivacyClassifier(source)
        files = scanner.scan()
        classifications = classifier.classify(files)
        persistence = ClassificationPersistence(tmp_path)
        persistence.save(classifications)

        # Aggiungi un file e modifica uno esistente
        (tmp_path / "new.py").write_text("print('new')\n", encoding="utf-8")
        (tmp_path / "app.py").write_text("# modified\npass\npass\n", encoding="utf-8")

        # Secondo run: diff
        source2 = LocalRepoSource(tmp_path)
        scanner2 = FileScanner(source2)
        files2 = scanner2.scan()

        diff = persistence.diff(files2)
        assert "new.py" in diff.new_files
        assert "app.py" in diff.modified_files
        assert diff.has_changes
