"""B-3: Gemini Vision captions are opt-in, non-fatal, and presentation-only."""

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

import pytest

from sudarshan_core.engines.agentic import caption_generator as cg
from sudarshan_core.engines.screenshot_manager import UNCLEAR_CAPTION


@pytest.fixture(autouse=True)
def _clear_flag(monkeypatch):
    monkeypatch.delenv("SUDARSHAN_VISION_CAPTIONS", raising=False)


def _png(tmp_path):
    p = tmp_path / "shot.png"
    p.write_bytes(b"\x89PNG\r\n\x1a\n" + b"x" * 64)
    return p


class _FakeResp:
    def __init__(self, text):
        self.text = text


class _FakeClient:
    def __init__(self, text="A login form with username and password fields"):
        self._text = text
        self.calls = 0

    class _Models:
        def __init__(self, outer):
            self._outer = outer

        def generate_content(self, **kw):
            self._outer.calls += 1
            return _FakeResp(self._outer._text)

    @property
    def models(self):
        return self._Models(self)


# ── Off by default ────────────────────────────────────────────────────────────

def test_disabled_by_default(tmp_path):
    assert cg.vision_captions_enabled() is False
    client = _FakeClient()
    assert cg.generate_caption(_png(tmp_path), client=client) == ""
    assert client.calls == 0, "no network call may happen with the flag unset"


def test_should_caption_is_false_when_disabled():
    assert cg.should_caption("OTHER", UNCLEAR_CAPTION) is False


# ── Enabled behaviour ─────────────────────────────────────────────────────────

def test_enabled_returns_model_caption(tmp_path, monkeypatch):
    monkeypatch.setenv("SUDARSHAN_VISION_CAPTIONS", "1")
    client = _FakeClient()
    out = cg.generate_caption(_png(tmp_path), client=client)
    assert out == "A login form with username and password fields"
    assert client.calls == 1


def test_only_ambiguous_reasons_are_eligible(monkeypatch):
    monkeypatch.setenv("SUDARSHAN_VISION_CAPTIONS", "1")
    assert cg.should_caption("OTHER", "anything") is True
    assert cg.should_caption("EXPLORER_ACTION", "x") is True
    # A confident deterministic caption is left alone.
    assert cg.should_caption("OVERLAY", "Overlay window displayed over target app") is False
    # ...unless the table gave up on it.
    assert cg.should_caption("OVERLAY", UNCLEAR_CAPTION) is True


def test_caption_is_length_bounded(tmp_path, monkeypatch):
    monkeypatch.setenv("SUDARSHAN_VISION_CAPTIONS", "1")
    out = cg.generate_caption(_png(tmp_path), client=_FakeClient("word " * 500))
    assert out, "a long reply must still yield a caption"
    assert len(out) <= 200


def test_multiline_reply_is_collapsed(tmp_path, monkeypatch):
    monkeypatch.setenv("SUDARSHAN_VISION_CAPTIONS", "1")
    out = cg.generate_caption(_png(tmp_path), client=_FakeClient("line one\nline two"))
    assert out == "line one line two"


# ── Never fatal ───────────────────────────────────────────────────────────────

def test_model_exception_returns_empty_not_raise(tmp_path, monkeypatch):
    monkeypatch.setenv("SUDARSHAN_VISION_CAPTIONS", "1")

    class _Boom:
        @property
        def models(self):
            raise RuntimeError("API down")

    assert cg.generate_caption(_png(tmp_path), client=_Boom()) == ""


def test_missing_image_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("SUDARSHAN_VISION_CAPTIONS", "1")
    assert cg.generate_caption(tmp_path / "nope.png", client=_FakeClient()) == ""


def test_empty_reply_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("SUDARSHAN_VISION_CAPTIONS", "1")
    assert cg.generate_caption(_png(tmp_path), client=_FakeClient("")) == ""


# ── Manager integration ───────────────────────────────────────────────────────

def test_enrich_is_noop_when_flag_unset():
    from sudarshan_core.engines.screenshot_manager import ScreenshotManager

    mgr = ScreenshotManager.__new__(ScreenshotManager)
    assert mgr.enrich_captions_with_vision() == 0
