# Live validation — §28 four-category matrix (Phase 11)

Run on `emulator-5554`, Android 17 / API 37, x86_64, Frida 17.16.4.
Every sample was uninstalled after its run; the device was verified clean
afterwards.

## Results

| # | category | sample | label it claims | perms | Frida events | screenshots | evidence | workflow |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| 1 | legitimate simple | Amaze File Manager | Amaze | 18 | 2 | 9 | 11 | PRECONDITIONS_ONLY |
| 2 | permission-heavy legit | VLC | VLC | 30 | 2 | 8 | 10 | PRECONDITIONS_ONLY |
| 3 | suspicious / unexpected | InsecureBankv2 | InsecureBankv2 | 12 | 1 | 9 | 10 | PRECONDITIONS_ONLY |
| 4 | banking trojan | **Cerberus** | **"Google Update"** | 17 | **98** | 5 | **103** | PRECONDITIONS_ONLY |

All four completed with `dynamic_status = EVENTS_CAPTURED`. No crashes.

## What worked

**The dynamic engine separates the trojan from the legitimate apps by ~50×.**
Cerberus produced 98 runtime events and 103 evidence records against 1-2 events
and 10-11 records for everything else. Its top hooks were
`DevicePolicyManager.isAdminActive` (47) and
`ContextWrapper.getSharedPreferences` (47) - device-admin probing and
preference reads, consistent with a banking trojan checking whether it holds
persistence.

**No false positives.** Zero unexpected-permission findings across the three
legitimate/vulnerable samples, and none of them produced a behavioural workflow
stage. The `PRECONDITIONS_ONLY` result on rows 1-3 is correct: the only stage
recorded is the sandbox's own permission grant, which is exactly what the
precondition split was built to express.

**The static bridge and capability profile behaved.** VLC was correctly
inferred `MEDIA_PLAYER`, InsecureBankv2 `BANKING`.

## What did not work — three findings

### 1. The workflow reconstructor did not fire on the trojan

`PRECONDITIONS_ONLY` on row 4 is a **miss**, not a correct negative. Measured
against the artifact:

```
events matching a workflow rule: 0 / 103
```

Not one of Cerberus's 103 evidence records matched any `trigger_hooks` entry.
The causal-chain engine - the platform's headline "Accessibility + Overlay +
SMS + Network into one reconstructed fraud sequence" capability - **has never
fired on real data in this cycle.**

Two separate causes:

* **9 of 25 rule triggers name hooks the agent never emits.** Comparing
  `banking_trojan.js` (80 emittable hooks) with the rule table:

  | rule expects | agent emits |
  | --- | --- |
  | `DevicePolicyManager.setActiveAdmin` | `DevicePolicyManager.isAdminActive` |
  | `AccessibilityManager.isEnabled` | `AccessibilityManager.sendAccessibilityEvent` |
  | `Settings.canDrawOverlays`, `View.setType/TYPE_APPLICATION_OVERLAY` | — |
  | `HttpURLConnection.connect`, `OkHttpClient.newCall` | — |
  | `Runtime.load`, `AlarmManager.setRepeating`, `PackageManager.queryIntentActivities` | — |

  The other 16 triggers do exist, so the vocabulary is not wholly broken - but
  the device-admin rule in particular is listening for the wrong verb while the
  sample fired the right one 47 times.

* **The payload never activated.** Cerberus gates its behaviour on an
  accessibility service, which was never enabled, so the hooks that *are* wired
  (`AccessibilityService.onAccessibilityEvent`, `SmsMessage.getMessageBody`)
  had nothing to observe.

### 2. The investigation plan is descriptive, not driving

This is the architectural one.

`ACCESSIBILITY_ANALYSIS` **was** in Cerberus's plan - confirmed by rebuilding
the controller from its real static flags (`has_accessibility_abuse: True`):

```
BOOTSTRAP → APP_LAUNCH → INITIAL_OBSERVATION → PERMISSION_ANALYSIS
→ SPECIAL_PERMISSION_ANALYSIS → ACCESSIBILITY_ANALYSIS → ... → COMPLETE
```

The run visited `['BOOTSTRAP', 'PERSISTENCE_ANALYSIS']`.

`InvestigationController.advance()` is only called when `stuck()`. A sample that
keeps producing events is never stuck, so the investigation bounces between
evidence-selected states and never walks the plan it was given. The stage that
would have unlocked the payload was planned and skipped.

The plan currently *describes* what should be investigated. Nothing *executes*
it. Closing that is the next substantive piece of work, and it is what would
turn row 4 from a miss into a chain.

### 3. Incidental accessibility evidence opened branches on clean apps

Rows 1 and 2 both visited `ACCESSIBILITY_ANALYSIS`. Amaze - a file manager with
no accessibility service - spent five iterations in Android Settings, because
`AccessibilityManager.sendAccessibilityEvent` is emitted by *every* app whenever
the UI changes so screen readers can announce it.

**Fixed during this phase** (`INCIDENTAL_CATEGORIES`): `accessibility` and
`network` can no longer open a branch the static signals never planned, though
they can still move the investigation to one that was. Covered by 4 new tests.
The matrix above predates the fix.

## Still not verified

* **The accessibility grant path has still never executed.** Cerberus declares
  `.zWPzgfI` and the manifest parse resolved it correctly, but the run never
  entered the stage that would have granted it. This remains the oldest
  outstanding gap in the cycle.
* **Screenshot counts fall as evidence rises.** Cerberus produced the most
  evidence (103) and the fewest screenshots (5). The capture triggers are not
  keyed to evidence volume.
* **One run per sample.** No repetition, so run-to-run variance is unmeasured.
