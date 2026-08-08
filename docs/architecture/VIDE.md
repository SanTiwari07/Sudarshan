# VIDE — Visual Impersonation Detection Engine

## Purpose

VIDE is a **deterministic** evidence engine that compares a suspect APK’s UI fingerprint against **lab/hackathon** institution baselines (SBI, HDFC, ICICI). It produces rule **VIDE-F001** and feeds the existing Fraud Risk Score (FRS) / STEI stack. **No LLM determines whether VIDE fires.**

## Pipeline

```
APK → ApktoolEngine → build_static_ui_profile() (layout + assets/*.html)
    → UIProfile
Dynamic → frida_events (WebView loadData / loadDataWithBaseURL) + optional ui_hierarchy_xml
    → merged UIProfile
    → baseline shortlist (min string overlap; no arbitrary banks)
    → compare.py (40% strings / 35% tree / 25% colors, threshold 0.72)
    → VIDE-F001 + CH06 signer registry
    → risk_engine (BT boost, score floors, Critical only with cluster or signer)
    → API `vide` → dashboard; VIDE-F001 lines in `report.evidence` indexed under RAG `risk_engine` (no separate LLM scorer)
```

## Scoring

- **String Jaccard** — 40%
- **View-tree similarity** — 35%
- **Brand color overlap** — 25%
- **Detection** — confidence ≥ 0.72 and (string Jaccard ≥ 0.08 or tree ≥ 0.35)

## Critical escalation (unchanged)

| Condition | Risk band |
|-----------|-------------|
| Visual similarity only | High Risk cap (~75), **not** Critical |
| Visual + static high-risk capability (a11y / overlay / SMS) + confidence ≥ 0.80 | `critical_visual_cluster` → Critical |
| CH06 signer impersonation | Critical |

## Baselines and registry

- UI baselines: `shared/sudarshan_core/data/ui_baselines/*.json` — **demo/lab only**, not production bank authority.
- Signer registry: `shared/sudarshan_core/data/bank_signer_registry.json` — **demo/lab** SHA placeholders.

## Frida

Runtime uses `banking_trojan.bundle.js` (built from `banking_trojan.js` via `npm run build` in `frida_hooks/`). WebView HTML is extracted in Python via `collect_webview_html_from_frida_events()`.

## Status fields

`safe_run_vide_analysis()` sets `available` / `status`: `OK`, `UNAVAILABLE`, or `ERROR` — distinct from “no match.”

## Verification status (engineering)

| Layer | Status |
|-------|--------|
| Static UI + `assets/*.html` via Apktool | **STATIC VERIFIED** (unit + integration tests) |
| Frida hooks + bundle (`loadData` / `loadDataWithBaseURL`) | **DYNAMIC CODE VERIFIED** (source + bundle grep, unit extraction tests) |
| Live emulator WebView → `frida_events` → VIDE | **DYNAMIC DEVICE** — run `scripts/verify_vide_webview_device.md` when frida-server is up |
| UI baselines (SBI/HDFC/ICICI JSON) | **LAB / HACKATHON** — not production bank authority |
| Signer registry | **LAB / DEMO** placeholders |

Do not describe lab baselines as production-authoritative bank data.
