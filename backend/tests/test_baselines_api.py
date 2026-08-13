"""VIDE baseline corpus ingestion, cache and admin refresh API."""

import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test_secret_key_for_pytest_minimum_length_32")
os.environ.setdefault("SUDARSHAN_RATE_LIMIT_DISABLED", "true")

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND.parent / "shared"))
sys.path.insert(0, str(BACKEND))

from sudarshan_core.engines.vide.baseline_store import (  # noqa: E402
    SOURCE_CORPUS,
    cache_status,
    get_baselines,
    load_corpus_baselines,
    refresh_baselines,
)
from sudarshan_core.engines.vide.corpus_loader import (  # noqa: E402
    find_corpus_root,
    parse_design_md,
)

CORPUS_PRESENT = find_corpus_root() is not None
requires_corpus = pytest.mark.skipif(
    not CORPUS_PRESENT, reason="apk_details corpus not available"
)


# ── design.md parsing ──────────────────────────────────────────────────────

def test_parse_design_md_extracts_brand_palette():
    md = """
# BRAND AND VISUAL IDENTITY

## Color System

| Token | Value | Confidence | Evidence |
|---|---|---|---|
| primary | `#1B4AA0` (deep blue) | APPROXIMATED | brand blue |
| secondary | `#2E9E4B` (green) | APPROXIMATED | green accent |
| surface | `#FFFFFF` | APPROXIMATED | card surfaces |
| success `#178C4E` / warning `#E8A100` | APPROXIMATED | states |

## Typography
Humanist sans; 700/500/400.

# SCREEN INVENTORY

**MUST IMPLEMENT (3):** `LOGIN`, `MPIN`, `HOME`.
"""
    design = parse_design_md(md)

    assert design.color_tokens["primary"] == "#1b4aa0"
    assert design.color_tokens["secondary"] == "#2e9e4b"
    # Tokens sharing one table row are still paired correctly.
    assert design.color_tokens["success"] == "#178c4e"
    assert design.color_tokens["warning"] == "#e8a100"
    # Neutral surfaces carry no brand identity and must stay out of the palette.
    assert "#ffffff" not in design.brand_palette
    assert design.brand_palette == ["#1b4aa0", "#2e9e4b"]
    assert design.must_implement_screens == ["LOGIN", "MPIN", "HOME"]
    assert "Humanist sans" in design.typography


def test_parse_design_md_empty_is_safe():
    design = parse_design_md("")
    assert design.color_tokens == {}
    assert design.brand_palette == []


# ── corpus ingestion ───────────────────────────────────────────────────────

@requires_corpus
def test_corpus_ingests_all_ten_banks():
    baselines = load_corpus_baselines()
    assert len(baselines) == 10

    for baseline in baselines:
        assert baseline.source == SOURCE_CORPUS
        assert baseline.institution_id.startswith("BASE-")
        assert baseline.bank, f"{baseline.institution_id} missing bank name"
        assert baseline.screens, f"{baseline.institution_id} has no screens"
        assert baseline.design is not None
        # Every bank must contribute an identity-carrying palette, otherwise
        # the colour axis of the confidence score is dead weight.
        assert baseline.design.brand_palette, baseline.institution_id
        assert baseline.profile.strings, baseline.institution_id


@requires_corpus
def test_corpus_screens_carry_structural_signatures():
    baselines = load_corpus_baselines()
    sbi = next(b for b in baselines if b.institution_id == "BASE-01-SBI")

    login = next(s for s in sbi.screens if s.screen_id == "SBI-LOGIN")
    assert login.structural_signature == "AUTH_FORM_VERTICAL_PRIMARY_CTA"
    assert login.region_order == ["HEADER", "PRIMARY_CONTENT", "FOOTER_CTA"]
    assert login.brand_tokens["colorPrimary"] == "#1b4aa0"

    # Assert the shape of the fingerprint, not one literal label: exactStrings
    # are regenerated from the shipped APK (scripts/regenerate_fingerprints.py),
    # so pinning a specific string would break on every legitimate corpus
    # refresh. What must hold is that the login screen carries credential
    # labels at all.
    assert login.exact_strings
    blob = " ".join(login.exact_strings).lower()
    assert any(token in blob for token in ("user", "password", "login", "id"))


@requires_corpus
def test_corpus_navigation_graph_loaded():
    sbi = next(
        b for b in load_corpus_baselines() if b.institution_id == "BASE-01-SBI"
    )
    assert sbi.navigation.get("entry") == "SBI-SPLASH"
    assert len(sbi.navigation.get("nodes") or []) > 5
    assert len(sbi.navigation.get("edges") or []) > 5


# ── cache + refresh ────────────────────────────────────────────────────────

@requires_corpus
def test_cache_is_reused_between_calls():
    refresh_baselines()
    first = get_baselines()
    generation = cache_status()["generation"]

    second = get_baselines()
    # Same object identity proves the hot path did not re-read the corpus.
    assert second is first
    assert cache_status()["generation"] == generation


@requires_corpus
def test_refresh_invalidates_and_reports():
    before = cache_status()["generation"]
    report = refresh_baselines()

    assert report["refreshed"] is True
    assert report["corpus_baselines"] == 10
    assert report["total"] == report["corpus_baselines"] + report["lab_baselines"]
    assert report["generation"] > before
    assert "BASE-01-SBI" in report["institutions"]


def test_missing_corpus_degrades_to_empty(tmp_path, monkeypatch):
    """A missing corpus must not raise - VIDE falls back to lab baselines."""
    monkeypatch.setenv("VIDE_CORPUS_DIR", str(tmp_path / "nope"))
    monkeypatch.setattr(
        "sudarshan_core.engines.vide.corpus_loader._DEFAULT_CORPUS_DIR",
        tmp_path / "also-nope",
    )
    assert load_corpus_baselines() == []


# ── API ────────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_baselines_endpoints_require_auth():
    from httpx import ASGITransport, AsyncClient
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        assert (await ac.get("/api/v1/baselines")).status_code == 401
        assert (await ac.post("/api/v1/baselines/refresh")).status_code == 401


@pytest.mark.anyio
async def test_refresh_is_admin_only():
    """An analyst must not be able to redefine the protected institutions.

    Roles are resolved from the database, not from the token claim, so the
    identity is injected by overriding the auth dependency.
    """
    from httpx import ASGITransport, AsyncClient
    from app.auth.auth import get_current_user
    from app.main import app

    async def _analyst():
        return {"id": 99, "username": "analyst1", "role": "analyst"}

    app.dependency_overrides[get_current_user] = _analyst
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            refresh_resp = await ac.post("/api/v1/baselines/refresh")
            list_resp = await ac.get("/api/v1/baselines")
    finally:
        app.dependency_overrides.pop(get_current_user, None)

    assert refresh_resp.status_code == 403
    # ...but reading the corpus is part of the analyst workflow.
    assert list_resp.status_code == 200


@requires_corpus
@pytest.mark.anyio
async def test_admin_can_list_and_refresh():
    from httpx import ASGITransport, AsyncClient
    from app.auth.auth import create_access_token
    from app.main import app

    token = create_access_token(1, "admin", "admin")
    headers = {"Authorization": f"Bearer {token}"}
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        listing = await ac.get("/api/v1/baselines", headers=headers)
        assert listing.status_code == 200
        body = listing.json()
        assert body["count"] >= 10
        ids = {b["institution_id"] for b in body["baselines"]}
        assert "BASE-01-SBI" in ids

        detail = await ac.get("/api/v1/baselines/BASE-01-SBI", headers=headers)
        assert detail.status_code == 200
        payload = detail.json()
        assert payload["design"]["brand_palette"]
        assert payload["screens"]
        assert payload["navigation"]["entry"] == "SBI-SPLASH"

        missing = await ac.get("/api/v1/baselines/BASE-99-NOPE", headers=headers)
        assert missing.status_code == 404

        refreshed = await ac.post("/api/v1/baselines/refresh", headers=headers)
        assert refreshed.status_code == 200
        assert refreshed.json()["corpus_baselines"] == 10
