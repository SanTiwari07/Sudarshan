# MASTER_BASELINE_ARCHITECTURE.md

How the 10 prototype applications form a coherent **trusted-baseline library** for
SUDARSHAN's Visual Identity & Deception Engine (VIDE).

---

## 1. Purpose

Provide VIDE with a set of **known-good, fully-documented, deterministic**
banking-UI baselines so that evidence from a *suspect* application can be scored
for visual / structural / flow similarity against a controlled reference — with
full traceability and honest uncertainty.

## 2. System context

```
                 ┌───────────────────────────────────────────────┐
                 │                 SUDARSHAN                      │
                 │        Intelligence Against Digital Threats    │
                 │                                               │
   Suspect APK ─►│  Static │ Dynamic │ Identity │  ┌──────────┐  │
                 │  collectors ...................►│   VIDE   │  │
                 │                                 └────┬─────┘  │
                 │                                      │        │
                 │            Trusted Baseline Library ◄┘        │
                 │            (THIS CORPUS's prototypes)         │
                 └───────────────────────────────────────────────┘
```

VIDE consumes two things:
1. **Baseline profiles** — from this corpus's prototypes (trusted).
2. **Suspect evidence** — from an unknown app under test.

It emits a **similarity signal**, never a standalone verdict.

## 3. Corpus-level design goals

| Goal | Why it matters to VIDE |
|---|---|
| **Cross-app consistency** | Comparable structural/flow features across baselines |
| **Deterministic navigation** | Reproducible traversal → stable dynamic fingerprints |
| **Screen diversity** | Enough distinct screens to test true vs false matches |
| **Mock-data only** | No real data contaminates baselines |
| **Original assets** | Similarity signal reflects *structure/brand-likeness*, not copied binaries |
| **Documented confidence** | VIDE can weight low-confidence baseline regions |

## 4. Baseline library structure

```
baseline-library/
├── BASE-01-SBI/
│   ├── app.meta.json
│   ├── navigation.manifest.json
│   ├── screens/                 ← deterministic screenshots (per screen)
│   ├── fingerprints/            ← semantic screen fingerprints (schema §7)
│   ├── tokens.json              ← design tokens w/ confidence
│   └── source/                  ← prototype source + built APK reference
├── BASE-02-HDFC/
│   └── ...
└── index.json                   ← library manifest of all 10 baselines
```

## 5. What makes each prototype a *valid* baseline

A prototype is admissible into the library only if it passes
`BASELINE_READINESS_REPORT` (see PART 7, Agent 9) confirming:

- unique, schema-conformant screen identifiers;
- deterministic navigation with no dead ends or unreachable MUST-IMPLEMENT screens;
- sufficient screen diversity (≥ the app's MUST-IMPLEMENT set);
- mock data only; **no** network calls to any real endpoint;
- no credential capture path;
- consistent `app.meta.json` metadata;
- documented confidence for approximated tokens/layouts.

## 6. Baseline representations produced

For each baseline, VIDE derives four representations (detail in
`BASELINE_REGISTRATION_PIPELINE.md`):

1. **Visual** — per-screen rendered images (deterministic capture).
2. **Text/OCR** — on-screen functional labels (short, non-copyrighted).
3. **Structural** — semantic hierarchy + structural signature per screen.
4. **Navigation** — screen graph (nodes/edges) from the manifest.

## 7. Similarity model (conceptual)

For a suspect screen `S` vs a baseline screen `B`:

```
sim(S,B) = w_v·visual(S,B) + w_t·text(S,B) + w_s·structural(S,B)
```

and for whole apps, a **flow-graph** similarity over navigation edges.

**Guardrails baked into the architecture:**

- A high `sim` is a **signal**, not a verdict. Generic banking UIs *will*
  resemble each other; the architecture requires corroboration.
- Output is always accompanied by **conflicting evidence** and **limitations**
  fields (see registration pipeline §output).
- Baseline low-confidence regions (APPROXIMATED/UNKNOWN) **down-weight** their
  contribution to `sim`.

## 8. Cross-app comparability matrix

Because all apps share the schema, VIDE can run controlled experiments:

| Experiment | Uses |
|---|---|
| Self-match (baseline vs itself) | sanity: must be highest similarity |
| Sibling public-sector apps | structural overlap without impersonation |
| Copied-flow variant | detect partial screen/flow cloning |
| Generic banking UI | must NOT auto-classify as impersonation |
| Unrelated app | must produce no meaningful match |

Defined fully in `05-validation/TEST_MATRIX.md`.

## 9. Data-flow summary

```
DESIGN SPEC ──► IMPLEMENTATION PLAN ──► PROTOTYPE (React/Capacitor)
                                            │
                                            ▼
                                   BUILD + APK (local)
                                            │
                                            ▼
                         BASELINE REGISTRATION PIPELINE
                                            │
                    ┌───────────┬───────────┼───────────┐
                    ▼           ▼           ▼           ▼
                 visual       text      structural   navigation
                    └───────────┴─────┬─────┴───────────┘
                                      ▼
                             TRUSTED BASELINE PROFILE
                                      │
                                      ▼
                                    VIDE
```

## 10. Non-goals (architecture level)

- Not a malware classifier; VIDE contributes one evidence stream.
- Not a real-time interception or overlay-detection tool.
- Not a store-scraping or bulk-download system.
- Not a producer of distributable look-alike apps.

## 11. Versioning & governance

- **Corpus version** in every `app.meta.json`; bump on schema change.
- Re-run registration when a prototype changes materially.
- Keep a changelog of rebrand-driven baseline updates (BOI Omni Neo, Union ease,
  YONO 2.0) as future work.
