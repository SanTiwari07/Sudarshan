"""
Corpus path resolution.

The labelled corpus is gitignored, so these tests build synthetic trees rather
than touching the real one - they must pass on a fresh clone that has no APKs.

The double-nesting case is the reason this module exists: the in-repo corpus
sits at ``test apk/test apk/``, and two callers hardcoded the un-nested path
and were silently resolving to a directory that does not exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sudarshan_core.validation.labelled_corpus import (
    CATEGORY_LABELS,
    corpus_search_order,
    find_labelled_corpus_root,
    load_labelled_samples,
    resolve_sample,
)


def _make_corpus(root: Path, categories=("Malware", "Safe")) -> Path:
    for category in categories:
        d = root / category
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{category.replace(' ', '')}Sample.apk").write_bytes(b"PK\x03\x04stub")
    return root


@pytest.fixture
def no_repo_defaults(monkeypatch):
    """
    Blank the in-repo default search paths.

    Needed for the "nothing found" cases: a developer machine that HAS the real
    corpus checked out would otherwise fall through to it and legitimately
    return a root, so those assertions would pass or fail depending on whether
    the person running them holds the malware.
    """
    monkeypatch.setattr(
        "sudarshan_core.validation.labelled_corpus._DEFAULT_CORPUS_DIRS", []
    )


def test_finds_a_flat_corpus(tmp_path, monkeypatch):
    root = _make_corpus(tmp_path / "corpus")
    monkeypatch.setenv("SUDARSHAN_LABELLED_CORPUS_DIR", str(root))
    assert find_labelled_corpus_root() == root


def test_descends_into_a_nested_corpus(tmp_path, monkeypatch):
    """
    The regression: outer dir contains only an inner dir of the same name.

    `test apk/` holds no category folders - only `test apk/`. Resolution must
    descend one level rather than declaring the outer directory the root.
    """
    outer = tmp_path / "test apk"
    inner = _make_corpus(outer / "test apk")
    monkeypatch.setenv("SUDARSHAN_LABELLED_CORPUS_DIR", str(outer))

    assert find_labelled_corpus_root() == inner, "did not descend into the nested corpus"


def test_stale_env_var_falls_through_to_a_real_candidate(tmp_path, monkeypatch):
    """A pointer at a deleted directory must not disable detection."""
    real = _make_corpus(tmp_path / "real")
    monkeypatch.setenv("SUDARSHAN_LABELLED_CORPUS_DIR", str(tmp_path / "gone"))
    assert find_labelled_corpus_root(explicit=real) == real


def test_directory_without_apks_is_not_a_corpus_root(tmp_path, monkeypatch, no_repo_defaults):
    """Empty category folders are a half-populated checkout, not a corpus."""
    (tmp_path / "empty" / "Malware").mkdir(parents=True)
    monkeypatch.setenv("SUDARSHAN_LABELLED_CORPUS_DIR", str(tmp_path / "empty"))
    assert find_labelled_corpus_root() is None


def test_missing_corpus_returns_none_not_raises(tmp_path, monkeypatch, no_repo_defaults):
    """Absence is an ordinary outcome - the corpus is gitignored."""
    monkeypatch.setenv("SUDARSHAN_LABELLED_CORPUS_DIR", str(tmp_path / "nope"))
    assert find_labelled_corpus_root(explicit=tmp_path / "also-nope") is None


def test_search_order_is_reported_for_error_messages(tmp_path, monkeypatch):
    monkeypatch.setenv("SUDARSHAN_LABELLED_CORPUS_DIR", str(tmp_path / "from-env"))
    order = corpus_search_order(explicit=tmp_path / "explicit")
    assert order[0] == tmp_path / "explicit"
    assert tmp_path / "from-env" in order
    assert len(order) == len(set(order)), "search order should not repeat candidates"


def test_samples_are_labelled_and_deterministically_ordered(tmp_path):
    root = _make_corpus(tmp_path / "c", categories=tuple(CATEGORY_LABELS))
    samples = load_labelled_samples(root)

    assert len(samples) == len(CATEGORY_LABELS)
    assert [s.category for s in samples] == sorted(CATEGORY_LABELS)
    assert load_labelled_samples(root) == samples, "ordering must be stable across calls"

    by_category = {s.category: s.label for s in samples}
    assert by_category["Malware"] == "malware"
    # Deliberately insecure is not the same claim as malicious.
    assert by_category["Vulnerable"] == "benign"
    assert by_category["MAS Crackmes"] == "benign"


def test_resolve_sample_finds_a_known_fixture(tmp_path, monkeypatch):
    root = tmp_path / "c"
    (root / "Vulnerable").mkdir(parents=True)
    (root / "Vulnerable" / "InsecureBankv2.apk").write_bytes(b"PK\x03\x04")
    (root / "Malware").mkdir()
    (root / "Malware" / "x.apk").write_bytes(b"PK\x03\x04")
    monkeypatch.setenv("SUDARSHAN_LABELLED_CORPUS_DIR", str(root))

    assert resolve_sample("Vulnerable/InsecureBankv2.apk") == root / "Vulnerable" / "InsecureBankv2.apk"
    assert resolve_sample("Vulnerable/DoesNotExist.apk") is None
