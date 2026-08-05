"""Tests for dynamic validation corpus loader."""

import json
from pathlib import Path

import pytest

from sudarshan_core.validation.corpus import CORPUS_ROOT, load_corpus


def test_manifest_loads():
    entries = load_corpus()
    assert len(entries) >= 10
    ids = {e.id for e in entries}
    assert "insecurebankv2" in ids


def test_optional_missing_marked():
    entries = load_corpus()
    hw = next(e for e in entries if e.id == "hello_world")
    assert hw.optional
    assert hw.missing or hw.apk_path.is_file()


def test_alias_resolves_multi_activity():
    entries = load_corpus()
    bank = next(e for e in entries if e.id == "insecurebankv2")
    multi = next(e for e in entries if e.id == "multi_activity")
    if bank.apk_path.is_file():
        assert multi.apk_path.is_file()
