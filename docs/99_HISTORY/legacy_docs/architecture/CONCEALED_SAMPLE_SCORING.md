# Why a banking trojan scored 18/100 "Safe"

Measured on the labelled corpus against a live Android 17 emulator. Every
number below was reproduced by running the code, not read off a design.

---

## The symptom

Anubis (`com.tjmonh.android`, SHA-256 `d17d2f0a…`) scored **18.43 / 100, Safe** —
while the AI summary beside it described accessibility API calls, hardcoded IPs
and AV vendor hits.

```
FRS = 0.25(9.20) + 0.35(27.74) + 0.20(12.11) + 0.20(20.0) = 18.43
STEI = 0.60·CT + 0.20·BT + 0.10·PR + 0.05·OB + 0.05·IR
     = 0.60(0) + 0.20(0) + 0.10(20) + 0.05(94) + 0.05(50) = 9.20
```

The corpus made the real problem obvious. **Eight known banking trojans, none
above 46.28, and benign NewPipe (15.63) sat between two of them.**

---

## Four defects, all logical, none sample-specific

### 1. The sandbox recorded itself as the evader **[FIXED]**

The Frida agent spoofs emulator-identifying `Build` fields at attach time to
conceal the sandbox, and emitted that under `anti_analysis`.
`dynamic_exclusion_reason()` reads any such event as proof the *sample* resisted
observation, and excludes the dynamic axis (weight 0.35, the largest).

All ten stored runs carried **exactly one** anti-analysis event — the same one,
for benign apps and trojans alike. A constant that does not vary with the sample
cannot be evidence about the sample.

Now emitted as `harness_action` / `sandbox.build_fields_spoofed` with
`actor: "harness"`. `sample_attributable_evasion()` filters by actor, category
**and** hook name, so the ten stored runs keep scoring correctly without
re-analysis.

Effect: 4 runs corrected from `EVASION_ONLY` to `NO_BEHAVIOR_OBSERVED`. One
sample (FluBot) had two *genuine* probes and correctly stays `EVASION_ONLY`.
**No score moved** — both reasons exclude the axis. This is an attribution fix,
not a scoring fix.

### 2. A signal every app emits drove the heaviest axis **[FIXED]**

`AccessibilityManager.sendAccessibilityEvent` is dispatched whenever a view
announces a UI change. It was in the `accessibility` category — BFCI weight
0.35, cap 2–3 events — so **one** dispatch scored 50/100 for the component.

Measured live, 300 s runs:

| sample | BFCI | accessibility | fired |
| --- | ---: | ---: | --- |
| Anubis (banking trojan) | 17.5 | 50.0 | `sendAccessibilityEvent` ×1 |
| NewPipe (video player) | 17.5 | 50.0 | `sendAccessibilityEvent` ×1 |

The heaviest-weighted axis could not distinguish a banking trojan from a video
player. Moved to `app_telemetry` (unscored). Real abuse — `onAccessibilityEvent`,
`getText`, `performAction`, `dispatchGesture` — is still scored.

This restores a rule `bfci_scorer` already states: *"A scored category that also
catches ordinary application behaviour is not a weak signal — it is a constant,
and it inflates every verdict equally."*

### 3. STEI scored "we cannot see" as "there is nothing" **[FIXED]**

CT (60% of STEI) and BT (20%) are read from the manifest and string pool. When a
payload is concealed, those describe a stub — the real code is a nested archive
nobody parsed. A 0 there means *blind*, not *clean*.

The result was an inverted metric:

| | STEI | CT | IR | concealed |
| --- | ---: | ---: | ---: | --- |
| Anubis (banking trojan) | **9.20** | 0 | 50 | yes |
| NewPipe (video player) | **24.64** | 25 | 100 | no |

**The benign app scored higher.** NewPipe honestly declares
`SYSTEM_ALERT_WINDOW` for picture-in-picture and ships real endpoints, so it
earns points. Anubis declares four permissions and hides everything, so it earns
zeros. The metric rewarded disclosure and rewarded concealment.

The fix applies the treatment FRS axes already get one level up — *"an excluded
axis is one with no data; it is not scored as benign"*. A visibility-dependent
axis that is **both** blind **and** zero is dropped and the rest renormalised.

Deliberately narrow: a concealed sample that *still* declares accessibility has
told us something real, and that evidence is kept. PR, OB and IR are measured
directly and are never excluded. Nothing is invented — the score is the measured
axes, reweighted.

Anubis: STEI 9.20 → **46.00**, FRS 14.0 Safe → **34.44 Suspicious**.
Every non-concealed sample is byte-identical.

### 4. The launch ladder killed the only attachable process **[FIXED]**

Live run, Anubis:

```
steps 1-5  PID 12966, no foreground window   (headless — that IS the behaviour)
step 6     force_stop_retry -> crashed at 10.8 s
           "Application crashed during step6 - NOT attaching Frida."
status=INSTRUMENTATION_FAILED  hooks=0  events=0
```

Six consecutive steps reported the **same stable PID**. The app runs headless,
which is dropper behaviour, not a launch failure. Step 6 force-stops the package
before retrying — destroying the only observation target — and the ui-less
fallback was gated on `_crash_on_step is None`, so the viable process was
discarded.

Two corrections: step 6 is skipped once a headless process exists, and a crash
on a *later* step no longer vetoes an *earlier* process that is **verified still
alive** (`_resolve_pid()`). A headless run is still flagged `ui_render_failed`
so the dynamic axis reads inconclusive rather than clean.

---

## Result

Live, 300-second runs, all fixes active:

| | FRS | band | BFCI |
| --- | ---: | --- | ---: |
| **Anubis** (banking trojan) | **19.38** | **Suspicious** | 0.0 |
| **NewPipe** (video player) | **12.70** | Safe | 0.0 |

Corpus-wide, real analyzer, all 13 samples:

```
MAL  Teabot     51.44 Susp    MAL  Anubis        34.44 Susp
MAL  FluBot     51.39 Susp    VULN InsecureBank  25.95 Safe
MAL  Octo       48.61 Susp    MAL  Drinik        24.73 Susp
MAL  SharkBot   45.68 Susp    BEN  VLC           23.02 Safe
MAL  Hook       41.04 Susp    BEN  NewPipe       22.58 Safe
MAL  Cerberus   38.74 Susp    BEN  Amaze         14.28 Safe
                              BEN  KeePassDX     13.07 Safe

malware min 24.73 | benign max 23.02 | separation +1.71 | overlap: NONE
```

**8/8 malware Suspicious, 4/4 benign Safe.** No package name, family name or
region is hardcoded anywhere in these changes; every one is conditional on a
measured property (concealment detected, category membership, process liveness).

Tests: **1889 passed**. The 11 failures are all pre-existing — 9 reproduce on a
stashed clean tree, and the other 2 (`test_boundaries::test_invalid_env_override`,
`test_dynamic_pipeline_regression`) are the documented emulator-gated pair,
verified failing on a clean tree with the emulator attached.

---

## What is NOT fixed

* **The dynamic axis still scores 0.0 rather than being excluded when a run
  observes no fraud-relevant behaviour.** Measured cost: Anubis loses ~15 points
  (34.44 static-only → 19.38 with DYN 0.0 at weight 0.35). This is the defect
  `risk_engine`'s own comment names — *"observing nothing scored worse than
  failing to observe"*. Fixing it means excluding the dynamic axis whenever no
  scored category fired, which raises benign samples too (NewPipe 12.70 → 22.58)
  and is a model change needing corpus re-validation. Ordering is correct either
  way; it is the margin that suffers.

* **Anubis clears the Safe band only via the visibility floor.** Its numeric
  score (19.38) is still inside Safe; the concealed-payload floor forces
  Suspicious. If concealment detection ever misses, it reads Safe again.

* **False-positive risk on concealment.** Defect 3 raises any sample with a
  concealed payload. Legitimate apps do sometimes ship nested APKs (plugins,
  split installs). In this corpus 0 of 4 benign samples were concealed, so the
  risk is real but unmeasured. A benign concealed app would gain roughly
  0.25 × 60 = 15 STEI points.

* **`INDIAN_BANK_PACKAGES` is untouched.** BT is still gated on a hardcoded
  21-prefix list that also selects the exploration plan, so non-Indian trojans
  are still explored less thoroughly. This is the largest remaining hardcoded
  schema.

* **Single live run per sample.** Run-to-run variance is unmeasured, and the
  launch ladder behaved differently across three Anubis runs (attach at 23 s,
  then a crash, then success at 94 s).
