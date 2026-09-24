# YARA rules

## Where they live

```
shared/sudarshan_core/engines/yara_rules/
    banking_trojan_behaviour.yar    runtime-string rules
    apk_dropper_packaging.yar       APK container rules
```

`frida_sandbox` resolves this directory absolutely, overridable with
`SUDARSHAN_YARA_RULES_DIR`, and logs whether rules were loaded — so "no YARA
matches" can be told apart from "YARA never ran".

## The finding that shaped the ruleset

Measured across the labelled corpus (8 banking trojans, 9 benign controls), the
trojans are **packed**. Payload API names are absent from the malware and
present in the clean apps:

| indicator | malware | benign |
| --- | --- | --- |
| `AccessibilityNodeInfo` | 2/8 | 8/9 |
| `frida` | 0/8 | 4/9 |
| `test-keys` | 0/8 | 4/9 |
| `onAccessibilityEvent` | 1/8 | 0/9 |

A conventional static string rule over the APK would therefore **flag the clean
apps and miss the trojans**. The dropper only reveals its second stage once it
decrypts it in memory.

That is why the behaviour rules target `YARAScanner.scan_strings()`, which the
Frida agent feeds with strings recovered at runtime, rather than
`scan_file()`. Low static recall on a packed sample is expected, not a bug.

Two things are deliberately **not** re-detected:

* **Concealment.** The static analyser already raises `has_concealed_payload`
  and the risk engine already floors a concealed sample away from "Safe".
* **Anti-analysis probing.** `AntiAnalysisDetector` already emits those events
  at runtime, and every formulation of a probing rule fired on UnCrackable L4 —
  a crackme whose whole purpose is root and instrumentation detection. Probing
  is not malicious on its own.

## Current measurements

```
rule                                    malware   benign
android_accessibility_abuse_runtime       1/8      0/9
android_bot_command_channel               0/8      0/9   runtime-only by construction
android_device_admin_persistence          3/8      0/9
android_in_memory_dex_payload             1/8      0/9
android_overlay_credential_phishing       0/8      0/9   runtime-only by construction
android_sms_otp_interception              1/8      0/9
apk_no_signature_block                    2/8      0/9
apk_payload_disguised_by_extension        3/8      0/9

malware with at least one rule hit : 7/8   (Drinik is the miss — fully packed, 39 entries)
benign with no rule hit at all     : 9/9
total false-positive rule hits     : 0
```

## The rule that governs the rules

**No rule may fire on a benign control.**

A rule that flags VLC is worse than a rule that misses a trojan, because an
analyst who learns to ignore the ruleset gets nothing from any of it.

This is not a stylistic preference. The first draft used the obvious API names —
`AccessibilityServiceInfo`, `dispatchGesture`, `TYPE_APPLICATION_OVERLAY`,
`DexClassLoader` — and produced **10 false positives**, because VLC, KeePassDX,
NewPipe and Amaze bundle framework and plugin code that legitimately references
all of them. Each rule was then narrowed to only the strings measured at 0/9
benign:

| rule | what was removed and why |
| --- | --- |
| accessibility | `AccessibilityServiceInfo`, `AccessibilityNodeInfo`, `ACTION_ACCESSIBILITY_FOCUS`, `findAccessibilityNodeInfosByViewId` — androidx ships them, 8/9 benign |
| overlay | foreground-app polling as the second half — `getRunningAppProcesses` is in 3/9 benign; now requires the injection vocabulary, because an overlay is only phishing if something tells it which bank to imitate |
| dex loading | the `DexClassLoader + Cipher` branch — plugin architectures load DEX and also do crypto, so the conjunction carried no information; narrowed to `InMemoryDexClassLoader` |
| device admin | `lockNow` — VLC carries it |
| c2 channel | `sendSMS` — too close to ordinary API naming |

Every rule requires **multiple independent indicators**. Any single one can
occur innocently; the combination is what is diagnostic.

## Validating

```bash
python scripts/validate_yara_rules.py
```

Runs two passes per sample — `match(apk_path)` (what `scan_file` sees) and
`match(data=<decompressed entries>)` (an approximation of what `scan_strings`
sees once Frida has recovered runtime strings). It exits non-zero if any rule
fires on a benign control. **Run it before adding a string.**

The second pass is an approximation and is labelled as one: decompressing an
APK is not running it, so a packed sample's second stage stays encrypted and
this pass under-reports what a live run finds.

`tests/unit/test_yara_scanner.py` is the counterpart that needs no corpus — the
malware samples are gitignored, so it builds its own inputs and asserts the
rules compile, match what they should, and stay silent on ordinary app
vocabulary.

## On family attribution

The corpus holds **one sample per family**, so a rule keyed to a specific asset
directory (`assets/lmafo/`, `assets/junk_clean/`) would encode that one build
rather than the family. Those rules are not shipped. Family attribution is left
to threat intelligence, which already supplies it — `trojan.coper/fakeapp`,
`trojan.sharkbot/andr` and so on come back from the VirusTotal cross-check.

## Two scanner bugs this work fixed

Both presented as "YARA ran and found nothing" rather than as an error:

1. **`match.strings` API break.** The scanner used `s[2].decode()`, the
   pre-4.3 tuple API. yara-python ≥ 4.3 returns `StringMatch` objects, so every
   match raised `TypeError: 'yara.StringMatch' object is not subscriptable` into
   an `except Exception` and was logged as a scan failure. `matched_strings()`
   now accepts both shapes.

2. **Extension glob mismatch.** `frida_sandbox` gates on `*.yar*` and its
   warning names ".yar/.yara", but the scanner globbed `*.yar` only — a
   `.yara`-only directory reported "rules loaded" and then compiled nothing.

A ruleset that fails to compile now says which directory it was loading and
that scanning is disabled for the run, so a compile error cannot read as a
clean scan.
