# When does a dynamic run count as having observed the sample?

The dynamic axis carries **0.35**, the heaviest weight in FRS. Whether it is
*scored* or *excluded* moves a verdict more than any other single decision, so
the rule that decides it matters more than the score it produces.

---

## The defect

`_MIN_DYNAMIC_EVENTS` is 1. One observed event marks a run conclusive, the fraud
axis is then scored at whatever BFCI says, and BFCI says 0.0 when nothing
fraud-relevant fired.

Measured on a live 300-second Anubis run with the current agent:

```
frida_events   {harness_action: 1, smoke: 1, app_telemetry: 1}
api_calls      ["Activity.onResume", "ContextWrapper.getSharedPreferences"]
bfci           0.0
coverage       25%
```

Three ordinary events — one of them the sandbox's own Build-field spoofing —
were enough to score the fraud axis as a clean zero.

```
axis excluded : FRS 34.44  Suspicious
axis = 0.0    : FRS 19.38  (inside the Safe band)
```

**Fifteen points lost for successfully analysing the sample.** That creates a
perverse incentive: a dropper scores *better* by behaving during the observation
window than by defeating the sandbox, because defeating it excludes the axis
while behaving scores it at zero.

`risk_engine`'s own comment already named this: *"observing nothing scored worse
than failing to observe."*

---

## The wrong fix, and why it was wrong

The obvious correction is to exclude the axis whenever no **BFCI-scored**
category fired — if the fraud axis has no fraud events, it has no data.

That broke 11 tests, including this one, which is deliberate and documented:

```python
def test_conclusive_benign_dynamic_run_may_lower_the_score():
    """
    This is NOT 'dynamic can only ever raise the score'. A well-covered run
    that observes benign behaviour is legitimate evidence and must still be
    able to reduce the verdict.
    """
```

The codebase's position is correct. Driving an app through several activities,
API calls and network requests and seeing no fraud **is** evidence. Excluding
the axis there would make dynamic analysis one-directional — able to convict,
never to acquit.

The discriminator was wrong. The question is not *"were there fraud events"*.
It is **"was the run covered enough for absence to mean anything"**.

---

## The fix

Two buckets hold ordinary behaviour by their own definition, from
`frida_sandbox.collected_events`:

| bucket | definition |
| --- | --- |
| `app_telemetry` | "activity lifecycle, keyboard, generic crypto / prefs / windows" |
| `smoke` | "baseline runtime smoke-test events" |

Every app produces them. They are recorded as evidence but no longer count as
proof that the sandbox *observed* anything — the same treatment
`_EVASION_EVIDENCE_CATEGORIES` and `_HARNESS_EVIDENCE_CATEGORIES` already get,
for the same reason.

Everything that indicates real coverage still counts: `api_calls`,
`network_logs`, `activities_triggered`, `files_accessed`, and every
fraud-category bucket. So the benign-covered-run property survives untouched.

### The double count

Filtering the buckets alone was not enough. `api_calls` is a **flattened,
uncategorised projection of the same hook events**:

```
frida_events   app_telemetry: Activity.onResume
               smoke:         ContextWrapper.getSharedPreferences
api_calls      ["Activity.onResume", "ContextWrapper.getSharedPreferences"]
```

The bucket filter skipped them and `api_calls` let the identical two events
straight back in. They are now subtracted **by exact hook name**, read from the
result's own buckets — no hook-to-category table is introduced, so none can
drift. An API call that never appeared in a discounted bucket still counts.

---

## Nothing is hardcoded

No package name, family, region or magic threshold. The rule keys on:

* bucket membership, defined in `frida_sandbox.collected_events`
* hook names read from the result itself

A test asserts both baseline names exist as real sandbox buckets (so the filter
cannot be silently inert), that neither is a BFCI-scored category (so the fraud
axis cannot be blinded), and that the three discount sets stay disjoint.

---

## Validation

All 13 samples re-run live with the current agent, then scored twice on
identical inputs - once with the rule active, once patched back.

| | before | after |
| --- | ---: | ---: |
| FluBot | 28.91 | **51.39** |
| SharkBot | 25.70 | **45.68** |
| Hook | 23.09 | **41.04** |
| Anubis | 19.38 | **34.44** |
| VLC *(benign)* | 12.95 | 23.02 *(still Safe)* |

Four malware samples rose 15-22 points. One benign sample rose and stayed
Safe. Nothing else moved. Malware overlapping the benign range fell from
`[Anubis, Drinik]` to `[Drinik]`.

### What the corpus also exposed

**Three benign apps never instrumented at all.** Amaze, KeePassDX and NewPipe
returned `INSTRUMENTATION_FAILED` / `NO_UI_RENDERED`; Amaze died with
`SIGABRT: Bad file descriptor` and, decisively, `frida_attach: None` - it
crashed *before* instrumentation, so this is an app/emulator incompatibility on
API 37, not something the harness causes. All eight malware samples instrument
fine.

Those three are floored to Suspicious by `incomplete_exercise`. That is the
honesty mechanism working correctly - the sandbox never exercised them, so it
refuses to certify them Safe - but it means any "malware vs benign separation"
figure computed across all 13 is measuring instrumentation coverage as much as
detection. VLC, the one benign app that did instrument, scores 23.02 Safe.

**Drinik is now the weakest malware result, at 18.29.** Its shell execution IS
detected (BFCI 0.0 -> 10.0, see the code_execution axis), but 10.0 is the
maximum a single 0.10-weighted axis can produce, and including a dynamic axis
at 10.0 against a STEI of 28.52 pulls the total *down* - from 24.73 with the
axis excluded to 18.29 with it included.

This is a pre-existing structural property of BFCI, not new: any single-category
detection maxes out at its own weight. It is now visible because
`code_execution` detects something real for the first time. Raising that weight
would fix Drinik, but exactly one sample in the corpus exercises the axis, which
is not enough evidence to re-tune a weight against.

Regression suites that specifically guard this area all pass:
`test_detection_regressions.py`, `test_risk_engine.py`,
`test_determinism_replay.py`.

---

## Known limits

* **Stored runs cannot validate this.** Every dynamic result in the database
  predates the agent fix that moved `sendAccessibilityEvent` out of the scored
  `accessibility` bucket, so those runs genuinely contain fraud-category events
  and are unaffected by this change. Only re-run data is meaningful here.

* **The two baseline buckets are a judgement.** `app_telemetry` and `smoke` are
  discounted because their own definitions say they hold ordinary behaviour. If
  a genuinely diagnostic hook is ever filed into either, it will stop counting
  as observation. The disjointness and not-BFCI-scored tests catch the worst
  version of that mistake, not all of it.

* **Coverage is still not measured directly.** The real question is "was this
  run thorough enough for silence to mean something", and the proxy is "did
  anything other than ordinary behaviour happen". A run that exercised one
  screen deeply and a run that swept twenty shallowly look the same here.
  `coverage_metrics` exists and is not consulted.
