#!/usr/bin/env python3
"""End-to-end visual evidence validation against running Sudarshan API."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/apks/categories/sudarshan_artifacts/insecurebankv2_2ebde24e"
APK = ROOT / "backend/test_sample.apk"
SHA = "b18af2a0e44d7634bbcdf93664d9c78a2695e050393fcfbb5e8b91f902d194a4"
BASE = os.environ.get("SUDARSHAN_API", "http://127.0.0.1:8000/api/v1")

# Credentials come from the environment - never from the repository.
CREDS = [
    (os.environ.get("SUDARSHAN_E2E_USER", os.environ.get("ADMIN_USERNAME", "admin")),
     os.environ.get("SUDARSHAN_E2E_PASSWORD", os.environ.get("ADMIN_PASSWORD", ""))),
]


def login(client: httpx.Client) -> str:
    for user, pw in CREDS:
        r = client.post(f"{BASE}/auth/login", json={"username": user, "password": pw})
        if r.status_code == 200:
            return r.json()["access_token"]
    raise SystemExit("Login failed - set SUDARSHAN_E2E_USER / SUDARSHAN_E2E_PASSWORD")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    out: dict = {"steps": [], "table": {}}
    client = httpx.Client(timeout=httpx.Timeout(600.0, connect=30.0))
    token = login(client)
    headers = {"Authorization": f"Bearer {token}"}
    out["steps"].append({"login": "ok"})

    # Unauthenticated manifest
    r = client.get(f"{BASE}/screenshots/{SHA}/manifest")
    out["auth_unauthenticated_manifest"] = r.status_code

    # Case may already exist
    r = client.get(f"{BASE}/cases/{SHA}", headers=headers)
    case_exists = r.status_code == 200
    out["case_exists_before_analyze"] = case_exists

    if not case_exists and APK.is_file():
        out["steps"].append({"analyze": "starting_async"})
        with APK.open("rb") as f:
            files = {"file": ("test_sample.apk", f, "application/vnd.android.package-archive")}
            ar = client.post(f"{BASE}/analyze/async", headers=headers, files=files)
        out["analyze_async_status"] = ar.status_code
        if ar.status_code not in (200, 202):
            out["analyze_async_body"] = ar.text[:500]
        else:
            job_id = ar.json().get("job_id")
            out["job_id"] = job_id
            deadline = time.time() + 3600
            while time.time() < deadline:
                sr = client.get(f"{BASE}/status/{job_id}", headers=headers)
                if sr.status_code != 200:
                    break
                body = sr.json()
                st = body.get("status")
                if st in ("completed", "failed", "error"):
                    out["job_final"] = body
                    break
                time.sleep(15)
            else:
                out["job_final"] = {"status": "timeout"}

    # Resolve artifact dir from case or docker uploads
    r = client.get(f"{BASE}/cases/{SHA}", headers=headers)
    out["case_get_status"] = r.status_code
    artifact_dir = None
    if r.status_code == 200:
        case = r.json()
        dyn = case.get("dynamic_result") or case.get("dynamic_analysis") or {}
        ad = dyn.get("artifact_dir") or case.get("artifact_dir")
        if ad:
            artifact_dir = Path(ad)
        out["package_name"] = case.get("package_name")

    # Docker host path mapping: check uploads in container
    if artifact_dir is None or not artifact_dir.exists():
        uploads_guess = ROOT / "backend/uploads" / SHA[:16]
        for p in [ROOT / "backend/uploads", FIXTURE.parent]:
            pass
        # try fixture copy path used by tests
        if FIXTURE.is_dir():
            out["fixture_available"] = True

    # If local fixture is reference only, exec docker find
    docker_art = os.popen(
        f'docker exec sudarshan-backend sh -c "find /app/uploads -maxdepth 3 -name visual_evidence.json 2>/dev/null | head -5"'
    ).read().strip()
    out["docker_visual_evidence_paths"] = docker_art.splitlines() if docker_art else []

    # Manifest API
    mr = client.get(f"{BASE}/screenshots/{SHA}/manifest", headers=headers, params={"order": "timeline"})
    out["manifest_status"] = mr.status_code
    if mr.status_code == 200:
        manifest = mr.json()
        out["has_visual_evidence"] = manifest.get("has_visual_evidence")
        out["manifest_keys"] = sorted(manifest.keys())
        entries = manifest.get("entries") or manifest.get("screenshots") or []
        out["entry_count"] = len(entries)
        leaked = json.dumps(manifest)
        for bad in ("/app/uploads", "C:\\", "artifact_dir", "docker"):
            if bad.lower() in leaked.lower():
                out.setdefault("path_leaks", []).append(bad)
        if entries:
            e0 = entries[0]
            out["sample_entry_keys"] = sorted(e0.keys())
            png_url = e0.get("png_url", "")
            out["sample_png_url"] = png_url
            if png_url:
                rel = png_url.split(f"/screenshots/{SHA}/")[-1]
                pr = client.get(f"{BASE}/screenshots/{SHA}/{rel}", headers=headers)
                out["png_fetch_status"] = pr.status_code
                out["png_content_type"] = pr.headers.get("content-type")

    # Auth matrix
    out["auth_invalid_filename"] = client.get(
        f"{BASE}/screenshots/{SHA}/../etc/passwd", headers=headers
    ).status_code
    out["auth_missing_png"] = client.get(
        f"{BASE}/screenshots/{SHA}/nonexistent_screenshot.png", headers=headers
    ).status_code

    # Read visual_evidence from docker if present
    for ve_path in out.get("docker_visual_evidence_paths", []):
        raw = os.popen(
            f'docker exec sudarshan-backend cat "{ve_path}"'
        ).read()
        if raw:
            try:
                ve = json.loads(raw)
                out["visual_evidence_meta"] = {
                    k: ve.get(k) for k in ("schema_version", "analysis_id", "package_name")
                }
                records = ve.get("records") or []
                out["visual_evidence_record_count"] = len(records)
                causal = [x for x in records if x.get("correlation_status") == "causal"]
                out["causal_records"] = [
                    {
                        "screenshot_id": c.get("screenshot_id"),
                        "linked_evidence_ids": c.get("linked_evidence_ids"),
                        "claim_type": c.get("claim_type"),
                        "quality": c.get("quality"),
                        "capability_flags": c.get("capability_flags"),
                        "vide_rule_id": c.get("vide_rule_id"),
                        "workflow_stage_label": c.get("workflow_stage_label"),
                    }
                    for c in causal[:3]
                ]
                vide = [x for x in records if x.get("claim_type") == "visual_impersonation"]
                out["vide_records"] = len(vide)
            except json.JSONDecodeError:
                out["visual_evidence_parse_error"] = True
            break
    else:
        out["visual_evidence_in_docker"] = False

    # Linker validation on fixture (reference causal chain, not injected)
    if FIXTURE.is_dir():
        sys.path.insert(0, str(ROOT / "shared"))
        from sudarshan_core.visual_evidence.linker import VisualEvidenceLinker

        records = VisualEvidenceLinker(
            FIXTURE,
            analysis_id="2ebde24e",
            package_name="com.android.insecurebankv2",
        ).link()
        scr1 = next((r for r in records if r.screenshot_id == "SCR-001"), None)
        if scr1:
            out["fixture_linker_scr001"] = {
                "correlation": scr1.correlation_status,
                "evid": scr1.linked_evidence_ids,
                "claim_type": scr1.claim_type,
                "quality": scr1.quality,
            }

    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
