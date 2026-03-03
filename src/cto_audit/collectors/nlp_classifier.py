"""
NLP Project Classifier — Classificazione progetto via NLP.

Due livelli opzionali:
  Livello 2: TF-IDF puro (stdlib only, ~60 righe)
  Livello 3: Sentence-BERT embeddings (richiede sentence-transformers)

Entrambi i livelli sono opzionali. Il sistema funziona al 100%
con il solo rule-based detector (livello 1).
"""

from __future__ import annotations

import math
import re
from collections import Counter

from cto_audit.core.models import ProjectType, ProjectTypeResult


# --- Descrizioni di riferimento per ogni tipo di progetto ---

TYPE_DESCRIPTIONS: dict[str, str] = {
    "web_app": (
        "web application REST API server endpoints routes authentication "
        "database middleware request response HTTP backend service deploy "
        "production hosting webhook controller handler"
    ),
    "frontend": (
        "React Vue Angular components UI user interface browser DOM CSS "
        "styling layout responsive design SPA single page application "
        "webpack vite bundler state management"
    ),
    "full_stack": (
        "full stack web application frontend backend API server React Vue "
        "Angular database authentication REST GraphQL deployment Docker "
        "fullstack monorepo client server"
    ),
    "library": (
        "package module pip install import reusable API interface "
        "documentation PyPI npm publish versioning semver SDK wrapper "
        "utility helper toolkit"
    ),
    "cli_tool": (
        "command line interface CLI arguments parser terminal console "
        "output stdin stdout flags options subcommand shell script "
        "executable binary tool"
    ),
    "data_pipeline": (
        "data ETL pipeline preprocessing model training dataset batch "
        "processing machine learning analytics notebook CSV DataFrame "
        "transform feature engineering prediction inference"
    ),
    "prototype": (
        "experiment prototype proof of concept demo exploration notebook "
        "draft sketch idea test quick hack MVP minimal example sample "
        "playground sandbox"
    ),
    "unknown": (
        "project software code application program"
    ),
}

# Stop words per il tokenizer
STOP_WORDS: set[str] = {
    "a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "is", "it", "this", "that", "are", "was",
    "be", "has", "have", "had", "not", "no", "do", "does", "did", "will",
    "can", "could", "should", "would", "may", "might", "shall", "must",
    "if", "then", "else", "when", "where", "how", "what", "which", "who",
    "as", "so", "than", "each", "every", "all", "any", "some", "such",
    "into", "over", "also", "just", "about", "more", "very", "too",
    "up", "out", "its", "your", "our", "their", "my", "we", "you", "he",
    "she", "they", "us", "them", "me", "him", "her",
}

# Word tokenizer
_WORD_RE = re.compile(r"[a-z][a-z0-9_]+")


def _tokenize(text: str) -> list[str]:
    """Tokenizza testo: lowercase, split, rimuovi stop words."""
    words = _WORD_RE.findall(text.lower())
    return [w for w in words if w not in STOP_WORDS and len(w) > 2]


def _compute_tf(tokens: list[str]) -> dict[str, float]:
    """Calcola Term Frequency."""
    counts = Counter(tokens)
    total = len(tokens) if tokens else 1
    return {word: count / total for word, count in counts.items()}


def _compute_idf(documents: list[list[str]]) -> dict[str, float]:
    """Calcola Inverse Document Frequency."""
    n_docs = len(documents)
    idf: dict[str, float] = {}
    all_words: set[str] = set()
    for doc in documents:
        all_words.update(doc)

    for word in all_words:
        doc_count = sum(1 for doc in documents if word in set(doc))
        idf[word] = math.log((n_docs + 1) / (doc_count + 1)) + 1

    return idf


def _tfidf_vector(tf: dict[str, float], idf: dict[str, float]) -> dict[str, float]:
    """Calcola il vettore TF-IDF."""
    return {word: tf_val * idf.get(word, 0) for word, tf_val in tf.items()}


def _cosine_similarity(vec_a: dict[str, float], vec_b: dict[str, float]) -> float:
    """Calcola la cosine similarity tra due vettori sparsi."""
    common_keys = set(vec_a.keys()) & set(vec_b.keys())
    if not common_keys:
        return 0.0

    dot_product = sum(vec_a[k] * vec_b[k] for k in common_keys)
    norm_a = math.sqrt(sum(v * v for v in vec_a.values()))
    norm_b = math.sqrt(sum(v * v for v in vec_b.values()))

    if norm_a == 0 or norm_b == 0:
        return 0.0

    return dot_product / (norm_a * norm_b)


class TFIDFClassifier:
    """
    Classificatore TF-IDF puro (stdlib only).

    Tokenizza il README.md, calcola TF-IDF contro le descrizioni di
    riferimento, e classifica per cosine similarity.
    """

    def __init__(self) -> None:
        # Pre-tokenize reference descriptions
        self._ref_tokens: dict[str, list[str]] = {
            ptype: _tokenize(desc) for ptype, desc in TYPE_DESCRIPTIONS.items()
        }

    def classify(self, readme_content: str) -> ProjectTypeResult:
        """
        Classifica il progetto basandosi sul contenuto del README.

        Args:
            readme_content: Contenuto del README.md

        Returns:
            ProjectTypeResult con tipo rilevato, confidence e metodo "tfidf"
        """
        readme_tokens = _tokenize(readme_content)
        if len(readme_tokens) < 10:
            return ProjectTypeResult(
                detected_type=ProjectType.UNKNOWN,
                confidence=0.2,
                method="tfidf",
                signals=["README too short for TF-IDF classification"],
            )

        # Build document corpus: README + all reference descriptions
        all_docs = [readme_tokens] + list(self._ref_tokens.values())
        idf = _compute_idf(all_docs)

        # Compute TF-IDF for README
        readme_tf = _compute_tf(readme_tokens)
        readme_tfidf = _tfidf_vector(readme_tf, idf)

        # Compute similarities
        similarities: list[tuple[str, float]] = []
        for ptype, ref_tokens in self._ref_tokens.items():
            ref_tf = _compute_tf(ref_tokens)
            ref_tfidf = _tfidf_vector(ref_tf, idf)
            sim = _cosine_similarity(readme_tfidf, ref_tfidf)
            similarities.append((ptype, sim))

        # Sort by similarity descending
        similarities.sort(key=lambda x: x[1], reverse=True)
        best_type, best_score = similarities[0]

        # Map string to ProjectType
        try:
            detected = ProjectType(best_type)
        except ValueError:
            detected = ProjectType.UNKNOWN

        # Confidence: scale similarity (0-1) with a minimum threshold
        confidence = min(0.85, max(0.3, best_score))

        signals = [
            f"TF-IDF best match: {best_type} (similarity: {best_score:.3f})",
        ]
        if len(similarities) > 1:
            second_type, second_score = similarities[1]
            signals.append(f"Runner-up: {second_type} (similarity: {second_score:.3f})")

        return ProjectTypeResult(
            detected_type=detected,
            confidence=round(confidence, 2),
            method="tfidf",
            signals=signals,
        )


# --- Livello 3: Sentence-BERT (opzionale) ---

try:
    from sentence_transformers import SentenceTransformer  # type: ignore[import-untyped]
    import numpy as np  # type: ignore[import-untyped]
    _BERT_AVAILABLE = True
except ImportError:
    _BERT_AVAILABLE = False


def bert_available() -> bool:
    """Controlla se sentence-transformers è disponibile."""
    return _BERT_AVAILABLE


class BERTClassifier:
    """
    Classificatore basato su Sentence-BERT.

    Usa all-MiniLM-L6-v2 (22MB, veloce) per encoding del README
    e delle descrizioni tipo. Cosine similarity per classificazione.

    Richiede: pip install sentence-transformers
    """

    def __init__(self) -> None:
        if not _BERT_AVAILABLE:
            raise ImportError(
                "sentence-transformers non disponibile. "
                "Installa con: pip install cto-audit[nlp]"
            )
        self._model = SentenceTransformer("all-MiniLM-L6-v2")
        # Pre-encode reference descriptions
        self._ref_embeddings: dict[str, object] = {}
        for ptype, desc in TYPE_DESCRIPTIONS.items():
            self._ref_embeddings[ptype] = self._model.encode(desc)

    def classify(self, readme_content: str) -> ProjectTypeResult:
        """
        Classifica il progetto usando BERT embeddings.

        Args:
            readme_content: Contenuto del README.md

        Returns:
            ProjectTypeResult con tipo, confidence e metodo "bert"
        """
        if len(readme_content.strip()) < 50:
            return ProjectTypeResult(
                detected_type=ProjectType.UNKNOWN,
                confidence=0.2,
                method="bert",
                signals=["README too short for BERT classification"],
            )

        # Truncate to first 2000 chars (BERT has token limit)
        readme_text = readme_content[:2000]
        readme_embedding = self._model.encode(readme_text)

        # Compute cosine similarities
        similarities: list[tuple[str, float]] = []
        for ptype, ref_emb in self._ref_embeddings.items():
            sim = float(np.dot(readme_embedding, ref_emb) / (
                np.linalg.norm(readme_embedding) * np.linalg.norm(ref_emb)
            ))
            similarities.append((ptype, sim))

        similarities.sort(key=lambda x: x[1], reverse=True)
        best_type, best_score = similarities[0]

        try:
            detected = ProjectType(best_type)
        except ValueError:
            detected = ProjectType.UNKNOWN

        # BERT gives higher quality embeddings, so confidence can be higher
        confidence = min(0.95, max(0.4, best_score))

        signals = [
            f"BERT best match: {best_type} (similarity: {best_score:.3f})",
        ]
        if len(similarities) > 1:
            second_type, second_score = similarities[1]
            signals.append(f"Runner-up: {second_type} (similarity: {second_score:.3f})")

        return ProjectTypeResult(
            detected_type=detected,
            confidence=round(confidence, 2),
            method="bert",
            signals=signals,
        )


def enhance_with_nlp(
    rule_result: ProjectTypeResult,
    readme_content: str | None,
) -> ProjectTypeResult:
    """
    Tenta di migliorare il risultato rule-based con NLP.

    Se il rule-based ha confidence bassa e c'è un README, prova
    TF-IDF (e opzionalmente BERT) per una classificazione più precisa.

    Args:
        rule_result: Risultato del ProjectTypeDetector rule-based
        readme_content: Contenuto del README.md (None se assente)

    Returns:
        ProjectTypeResult migliorato (o l'originale se NLP non aiuta)
    """
    # Se non c'è README, non possiamo fare NLP
    if not readme_content or len(readme_content.strip()) < 50:
        return rule_result

    # Se rule-based ha alta confidence, non serve NLP
    if rule_result.confidence >= 0.85:
        return rule_result

    # Prova BERT se disponibile
    if _BERT_AVAILABLE:
        try:
            bert = BERTClassifier()
            bert_result = bert.classify(readme_content)
            if bert_result.confidence > rule_result.confidence:
                # Merge signals
                bert_result.signals = rule_result.signals + bert_result.signals
                return bert_result
        except Exception:
            pass  # Fall through to TF-IDF

    # Prova TF-IDF
    try:
        tfidf = TFIDFClassifier()
        tfidf_result = tfidf.classify(readme_content)
        if tfidf_result.confidence > rule_result.confidence:
            # Merge signals
            tfidf_result.signals = rule_result.signals + tfidf_result.signals
            return tfidf_result
    except Exception:
        pass

    return rule_result
