# 11 — Static Analysis

> **Chapter ID:** `CH11` · **Block:** B (Analysis Craft) · **Status:** Stable
> **Tags:** `#static-analysis` `#mobsf` `#yara` `#capability-extraction` `#taint-analysis` `#automation` `#pipeline`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 04](../security/04-android-security-model.md), [Ch 08](../apk/08-apk-file-format.md), [Ch 10](../reverse-engineering/10-reverse-engineering.md)

---

## Table of Contents

1. [Static analysis vs reverse engineering](#1-static-analysis-vs-reverse-engineering)
2. [The tiered pipeline](#2-the-tiered-pipeline)
3. [Tier 0 — structural](#3-tier-0--structural)
4. [Tier 1 — manifest and capability extraction](#4-tier-1--manifest-and-capability-extraction)
5. [Tier 2 — resource and asset mining](#5-tier-2--resource-and-asset-mining)
6. [Tier 3 — code analysis](#6-tier-3--code-analysis)
7. [Taint analysis](#7-taint-analysis)
8. [MobSF](#8-mobsf)
9. [YARA](#9-yara)
10. [Similarity hashing](#10-similarity-hashing)
11. [What static analysis cannot do](#11-what-static-analysis-cannot-do)
12. [Detection logic for SUDARSHAN](#12-detection-logic-for-sudarshan)
13. [Limitations, edge cases, false positives](#13-limitations-edge-cases-false-positives)
14. [Engineering tips](#14-engineering-tips)
15. [Judge Insights](#15-judge-insights)
16. [Interview Insights](#16-interview-insights)
17. [Cross-references](#17-cross-references)
18. [References](#18-references)

---

## 1. Static analysis vs reverse engineering

Both examine code without running it. The difference is **purpose and scale**.

| | Static Analysis | Reverse Engineering |
|---|---|---|
| Goal | Extract structured facts at scale | Understand specific logic deeply |
| Operator | Automated pipeline | Human analyst |
| Throughput | Thousands/day | Hours per sample |
| Output | Feature vector, findings, score | Narrative, IOCs, YARA rules |
| Handles novelty | Poorly | Well |
| Reproducible | Perfectly | Depends on the analyst |

**Static analysis is what SUDARSHAN does to every sample. Reverse engineering is what a human
does to the few percent that earn it.** [Ch 10](../reverse-engineering/10-reverse-engineering.md)
is the apex tier; this chapter is the base and the middle.

> **⚙️ Engineering Note:** The relationship runs both ways. RE produces the *patterns* (YARA
> rules, API signatures, MITRE mappings) that static analysis then applies at scale. A team
> that does RE without encoding findings back into the static pipeline is doing the same work
> forever. **Every RE session must end with a rule.** → [Ch 10 §12](../reverse-engineering/10-reverse-engineering.md#12-the-re-workflow-end-to-end)

---

## 2. The tiered pipeline

The architecture is driven by one fact: **analysis costs vary by four orders of magnitude.**

```
 TIER 0  STRUCTURAL             ~10 ms    100% of samples
         ZIP layout, DEX headers, checksums, signing        → Ch 07, Ch 08
              │
              ▼
 TIER 1  MANIFEST + CAPABILITY  ~50 ms    100% of samples
         permissions, components, a11y config, targetSdk    → Ch 02, Ch 04
              │
              ├──────── no capability cluster ────────► low-priority queue
              ▼
 TIER 2  RESOURCES + ASSETS     ~500 ms   ~100% (cheap enough)
         strings, locales, target lists, entropy scan       → Ch 08
              │
              ▼
 TIER 3  CODE ANALYSIS          ~10-120 s  ~20% of samples
         decompile, API xrefs, call graph, YARA, taint      → Ch 10
              │
              ▼
 TIER 4  DYNAMIC DETONATION     ~5-15 min  ~5% of samples   → Ch 12
              │
              ▼
 TIER 5  HUMAN RE               hours      <1% of samples   → Ch 10
```

### The gating principle

> **Each tier's job is to decide whether the next tier is worth paying for.** Tier 1 is 1,000×
> cheaper than Tier 3 and answers most triage questions. Design the pipeline so the expensive
> tiers only ever see samples the cheap tiers flagged.

Crucially, **gating must be conservative in one direction**: a sample that fails to escalate is
a potential false negative, so gates should err toward escalation, and every gate decision must
be recorded so it can be audited and tuned. → [Ch 23](../sudarshan/23-detection-pipeline.md)

---

## 3. Tier 0 — structural

Everything from [Ch 08 §10](../apk/08-apk-file-format.md#10-detection-logic-for-sudarshan) and
[Ch 07 §11](../security/07-apk-signing.md#11-detection-logic-for-sudarshan), run on 100% of
input:

- ZIP: prepended data (Janus check), duplicate entries, LFH↔CD mismatch, entries after EOCD,
  traversal in names, compression of `classes.dex` / `resources.arsc`, timestamp normalisation
- DEX: magic version, **recomputed Adler-32 and SHA-1**, header↔`map_list` consistency,
  string-pool overlaps
- Signing: which schemes verified, signer fingerprints, v3 rotation lineage, signing-block IDs
- ELF: per-library entropy, `.init_array` / `JNI_OnLoad` presence, packer fingerprint

These findings are **deterministic and explainable** — the highest-precision output the
platform produces, and the easiest to defend in an audit.

```python
import zipfile, hashlib, zlib, struct

def tier0(path):
    out = {}
    with open(path, 'rb') as f:
        head = f.read(8)
    # Janus: DEX magic on a file that is also a valid ZIP
    out['dex_magic_at_offset_0'] = head[:4] == b'dex\n'

    with open(path, 'rb') as f:
        blob = f.read()
    out['first_lfh_offset'] = blob.find(b'PK\x03\x04')
    out['prepended_bytes'] = max(out['first_lfh_offset'], 0)
    out['has_signing_block'] = b'APK Sig Block 42' in blob

    with zipfile.ZipFile(path) as z:
        names = [i.filename for i in z.infolist()]
        out['duplicate_entries'] = [n for n in set(names) if names.count(n) > 1]
        out['traversal_entries'] = [n for n in names if '..' in n]
        for i in z.infolist():
            if i.filename == 'resources.arsc':
                out['arsc_compressed'] = i.compress_type != zipfile.ZIP_STORED
        # DEX integrity — hand-edit detection
        out['dex'] = []
        for n in [x for x in names if x.startswith('classes') and x.endswith('.dex')]:
            d = z.read(n)
            out['dex'].append({
                'name': n,
                'version': d[4:7].decode(errors='replace'),
                'adler32_ok': zlib.adler32(d[12:]) & 0xffffffff == struct.unpack('<I', d[8:12])[0],
                'sha1_ok': hashlib.sha1(d[32:]).digest() == d[12:32],
            })
    return out
```

---

## 4. Tier 1 — manifest and capability extraction

### The capability vector

This is the single most important data structure in SUDARSHAN's static analysis. Everything
downstream — scoring, correlation, reporting — consumes it.

```python
from androguard.core.bytecodes.apk import APK

A11Y_ACTION = 'android.accessibilityservice.AccessibilityService'
NOTIF_SVC   = 'android.service.notification.NotificationListenerService'

def capability_vector(path):
    a = APK(path)
    perms = set(a.get_permissions())
    services = a.get_services()

    v = {
        'package': a.get_package(),
        'version_code': a.get_androidversion_code(),
        'target_sdk': a.get_effective_target_sdk_version(),
        'min_sdk': a.get_min_sdk_version(),

        # --- the cluster --------------------------------------------------
        'declares_a11y_service': any(
            A11Y_ACTION in str(a.get_intent_filters('service', s)) for s in services),
        'declares_notification_listener': any(
            NOTIF_SVC in str(a.get_intent_filters('service', s)) for s in services),
        'has_overlay': 'android.permission.SYSTEM_ALERT_WINDOW' in perms,
        'has_request_install': 'android.permission.REQUEST_INSTALL_PACKAGES' in perms,
        'has_query_all_packages': 'android.permission.QUERY_ALL_PACKAGES' in perms,
        'has_sms': bool(perms & {'android.permission.RECEIVE_SMS',
                                 'android.permission.READ_SMS'}),
        'has_manage_external_storage':
            'android.permission.MANAGE_EXTERNAL_STORAGE' in perms,
        'declares_device_admin': 'android.permission.BIND_DEVICE_ADMIN' in str(a.get_xml_obj()),
        'fgs_types': extract_fgs_types(a),          # → mediaProjection is the tell
        'boot_receiver': 'android.intent.action.BOOT_COMPLETED' in str(a.get_xml_obj()),

        # --- hygiene / posture ---------------------------------------------
        'debuggable': a.get_element('application', 'debuggable') == 'true',
        'allow_backup': a.get_element('application', 'allowBackup') != 'false',
        'cleartext_permitted':
            a.get_element('application', 'usesCleartextTraffic') == 'true',
        'exported_unprotected': find_exported_unprotected(a),
        'shared_user_id': a.get_element('manifest', 'sharedUserId'),
    }
    return v
```

### The accessibility config — parse it, always

From [Ch 02 §4](../apk/02-apk-architecture.md#4-androidmanifestxml--the-apps-declaration-of-intent):
when an a11y service exists, its `@xml/...` config is where the real capability lives.

```python
def a11y_config(apk: APK):
    """Extract the accessibility-service capability flags."""
    cfg = {}
    for f in apk.get_files():
        if f.startswith('res/xml/') and f.endswith('.xml'):
            xml = apk.get_android_resources().get_string(...)  # or parse AXML directly
            # look for the accessibility-service root element
            cfg['can_retrieve_window_content'] = 'canRetrieveWindowContent="true"' in xml
            cfg['can_perform_gestures']        = 'canPerformGestures="true"' in xml
            cfg['event_types_all']             = 'typeAllMask' in xml
            cfg['package_scope_empty']         = 'packageNames=""' in xml or 'packageNames' not in xml
            cfg['notification_timeout']        = extract_timeout(xml)
    return cfg
```

| Flag | Meaning | Weight |
|---|---|---|
| `canRetrieveWindowContent` | **Read** any app's screen | High |
| `canPerformGestures` | **Write** input to any app | High |
| `typeAllMask` | Every event on the device | Medium |
| empty `packageNames` | Unscoped — targets everything | Medium |
| `notificationTimeout` ≤ 100 | Real-time capture intent | Low |

> **⚙️ Engineering Note:** `canRetrieveWindowContent` + `canPerformGestures` + unscoped
> `packageNames` is functionally *"read and control every app on this device."* A legitimate
> password manager typically scopes `packageNames` or at minimum doesn't need
> `canPerformGestures`. **Parsing this config is the highest-value 50 milliseconds in the whole
> pipeline** — it converts a generic permission into a specific, explainable capability claim.

---

## 5. Tier 2 — resource and asset mining

### What to extract, and why a bank cares

| Extraction | Business value |
|---|---|
| **Locale set** (`res/values-*/`) | **Victim geography.** Antidot (Cyble, May 16 2024) carried German, French, Spanish, Russian, Portuguese, Romanian, English — the resource set *was* the target list. |
| **Referenced package names** | **Overlay target list.** Is the client bank on it? |
| **URLs in resources** | C2 and phishing infrastructure |
| **Overlay HTML in `assets/`** | Direct evidence of phishing intent; often bank-branded |
| **VIDE UI structural profile** (`res/layout` + `assets/*.html` + optional dynamic WebView/uiautomator) | **Disjoint-package impersonation** — deterministic **VIDE-F001** vs lab baselines; CH06 signer check separate. See [VIDE architecture](../../docs/architecture/VIDE.md). **Static path: verified in CI.** **Dynamic WebView path: code + bundle verified; live device requires frida-server (see `scripts/verify_vide_webview_device.md`).** Lab baselines only — not production bank authority. |
| **High-entropy blobs in `assets/`** | Encrypted stage-2 payload |
| **Certificate/key material** | Correlation pivots → [Ch 05 §10](../security/05-android-cryptography.md#10-detection-logic-for-sudarshan) |

```bash
# locale set — the targeting map
$ aapt2 dump configurations app.apk | tr ' ' '\n' | grep -E '^[a-z]{2}(-r[A-Z]{2})?$' | sort -u

# referenced package names — the overlay target list
$ apktool d -s app.apk -o w/ >/dev/null
$ grep -rEoh '\bcom\.[a-z0-9_]+(\.[a-z0-9_]+)+' w/res/ w/assets/ 2>/dev/null \
    | sort | uniq -c | sort -rn | head -40

# infrastructure strings
$ grep -rEoh 'https?://[^"<[:space:]]+' w/res/ w/assets/ | sort -u

# entropy scan of assets — encrypted payload candidates
$ python3 - <<'PY'
import math, os, collections
for root, _, files in os.walk('w/assets'):
    for fn in files:
        p = os.path.join(root, fn)
        b = open(p,'rb').read()
        if not b: continue
        c = collections.Counter(b)
        H = -sum((n/len(b))*math.log2(n/len(b)) for n in c.values())
        if H > 7.5:
            print(f"{H:.2f}  {len(b):>9}  {p}")
PY
```

> **🏛️ Enterprise Insight:** The single most valuable output of Tier 2 for a bank client is
> the **overlay target list**. It converts "this is malware" into *"this campaign specifically
> hunts for `com.yourbank.app`, alongside 47 other Indian financial apps."* That is the finding
> a CISO escalates, and it costs under a second to produce.
> → [Ch 29](../sudarshan/29-investigation-reports.md)

---

## 6. Tier 3 — code analysis

### API cross-reference extraction

The core technique: find calls to security-relevant APIs, then walk the call graph backwards to
learn **the trigger**.

```python
from androguard.misc import AnalyzeAPK

SENSITIVE = {
    'sms_send':       ('Landroid/telephony/SmsManager;', 'sendTextMessage'),
    'sms_read':       ('Landroid/telephony/SmsMessage;', 'createFromPdu'),
    'pkg_enum':       ('Landroid/content/pm/PackageManager;', 'getInstalledPackages'),
    'overlay_add':    ('Landroid/view/WindowManager;', 'addView'),
    'a11y_gesture':   ('Landroid/accessibilityservice/AccessibilityService;', 'dispatchGesture'),
    'a11y_global':    ('Landroid/accessibilityservice/AccessibilityService;', 'performGlobalAction'),
    'screen_capture': ('Landroid/media/projection/MediaProjection;', 'createVirtualDisplay'),
    'device_wipe':    ('Landroid/app/admin/DevicePolicyManager;', 'wipeData'),
    'dcl_file':       ('Ldalvik/system/DexClassLoader;', '<init>'),
    'dcl_memory':     ('Ldalvik/system/InMemoryDexClassLoader;', '<init>'),
    'reflect_invoke': ('Ljava/lang/reflect/Method;', 'invoke'),
    'crypto':         ('Ljavax/crypto/Cipher;', 'doFinal'),
}

def api_xrefs(path):
    a, d, dx = AnalyzeAPK(path)
    found, total_edges, unresolved = {}, 0, 0
    for label, (cls, meth) in SENSITIVE.items():
        callers = []
        for m in dx.find_methods(classname=cls, methodname=meth):
            for _, caller, _ in m.get_xref_from():
                callers.append(f"{caller.class_name}->{caller.name}")
        if callers:
            found[label] = sorted(set(callers))
    # analysis-quality metric → Ch 10 §13
    for m in dx.get_methods():
        total_edges += len(list(m.get_xref_to()))
    return {'apis': found, 'call_graph_edges': total_edges}
```

### Patterns worth encoding as rules

| Pattern | Meaning |
|---|---|
| `Cipher.doFinal` → `InMemoryDexClassLoader.<init>` | **Encrypted payload loaded in memory.** Very high signal. |
| `Cipher.doFinal` → `Class.forName` | Encrypted reflection target |
| `SMS_RECEIVED` receiver → `HttpURLConnection` | **OTP exfiltration** |
| `getInstalledPackages` → list comparison → `WindowManager.addView` | **Overlay targeting loop** ([Ch 10 §5](../reverse-engineering/10-reverse-engineering.md#5-reading-smali)) |
| `onAccessibilityEvent` → `performGlobalAction` | Automated UI control |
| `ServiceManager.getService` via reflection | Hidden-API bypass |
| `Runtime.exec` with `su`/`pm install` | Shell escalation attempt |

> **⚙️ Engineering Note:** These *chains* are what distinguish real detection from permission
> counting. "App has SMS permission" is noise. "A `BroadcastReceiver` registered for
> `SMS_RECEIVED` reads message bodies and passes them to an HTTP POST" is a finding with
> evidence. Encode chains, not endpoints.

### Where code analysis breaks

- **Reflection** severs edges → [Ch 03 §7](../android/03-android-runtime.md#7-reflection)
- **Native code** is invisible to Java-level xrefs
- **Packing** means there is no real code to analyse until you unpack
  ([Ch 10 §9](../reverse-engineering/10-reverse-engineering.md#9-unpacking-strategy))
- **Dynamic loading** means the interesting code isn't present

All four must be reported as **analysis-quality metadata** that caps confidence.

---

## 7. Taint analysis

### WHAT

Track whether data from a **source** (sensitive input) reaches a **sink** (an output that
leaves the app).

```
   SOURCES                                    SINKS
   ───────                                    ─────
   getDeviceId()          ┐              ┌──► HttpURLConnection.write()
   SmsMessage.getBody()   │              │    Socket.getOutputStream()
   getAccounts()          ├──► taint ────┤    SmsManager.sendTextMessage()
   getLastKnownLocation() │    propagates│    FileOutputStream.write()
   AccessibilityNodeInfo  │              │    Log.d()
     .getText()           ┘              └──► WebView.loadUrl()
```

A path from source to sink is a **data-flow finding**: "SMS body reaches an HTTP POST."

### Tools

| Tool | Notes |
|---|---|
| **FlowDroid** | The reference academic static taint engine for Android; context/flow/object/field-sensitive |
| **Amandroid / Argus-SAF** | Inter-component data flow |
| **MobSF** | Ships lighter pattern-based flow checks, not full taint |
| **QARK** | Legacy; largely superseded |

### The honest assessment

> **🔬 Research Gap / practical warning:** Full static taint analysis on real-world Android
> apps is **slow** (minutes to hours per app), **memory-hungry**, and **fragile** — it degrades
> badly on obfuscated code, reflection, native calls, and inter-component communication via
> Binder. FlowDroid is excellent research work and is genuinely useful for *auditing a known,
> unobfuscated app* (e.g. vetting a bank's own build). It is **not** a practical component of a
> high-throughput malware pipeline in 2026.
>
> SUDARSHAN's position: use lightweight **pattern-based flow rules** (source API and sink API
> both present in the same method or adjacent in the call graph) at Tier 3, and reserve real
> taint analysis for the app-vetting use case where the app is cooperative and time is
> available. Claiming full taint analysis at scale is an overclaim judges and engineers will
> catch.

---

## 8. MobSF

### WHAT

**Mobile Security Framework (MobSF)** is the de-facto open-source mobile app security tool —
a Django application (GPL-3.0, v4.4.x) offering static and dynamic analysis for Android and
iOS through a web UI and REST API.

**Supported inputs:** APK, XAPK, AAB, AAR, JAR, SO (Android) and IPA, APPX/dylib/a (iOS/Windows).

### Architecture

```
┌───────────────────────────────────────────────────────────┐
│  Web UI (Django)          REST API                        │
├───────────────────────────────────────────────────────────┤
│  Static Analyzer                                          │
│   ├── APK/manifest parsing (androguard-derived)           │
│   ├── permission + component analysis                     │
│   ├── code pattern rules (regex/semantic)                 │
│   ├── secret/hardcoded-string detection                   │
│   ├── certificate analysis                                │
│   ├── native library + tracker detection                  │
│   └── malware/domain lookup, VirusTotal integration       │
├───────────────────────────────────────────────────────────┤
│  Dynamic Analyzer (Android VM / emulator + Frida)         │
├───────────────────────────────────────────────────────────┤
│  Report generator (HTML / PDF / JSON)                     │
└───────────────────────────────────────────────────────────┘
   Each scan isolated in an MD5-named directory
```

### The REST API

```bash
# 1. upload → returns a hash
$ curl -F 'file=@sample.apk' \
       -H "Authorization: $MOBSF_API_KEY" \
       http://localhost:8000/api/v1/upload
# {"file_name":"sample.apk","hash":"<md5>","scan_type":"apk"}

# 2. scan
$ curl -X POST --url http://localhost:8000/api/v1/scan \
       --data "hash=<md5>" -H "Authorization: $MOBSF_API_KEY"

# 3. JSON report
$ curl -X POST --url http://localhost:8000/api/v1/report_json \
       --data "hash=<md5>" -H "Authorization: $MOBSF_API_KEY" > report.json

# API-only deployment
$ docker run -e MOBSF_API_ONLY=1 -p 8000:8000 opensecurity/mobile-security-framework-mobsf
```

### The scoring formula — and why you must not trust it blindly

MobSF produces a **security score (0–100)** and an **A–F grade**, computed approximately as:

```
Score ≈ 100 − ( (High + 0.5·Medium − 0.2·Secure) / count )
```

> **🚨 Misconception:** "MobSF gave it a low score, so it's malware." **MobSF measures app
> security hygiene, not maliciousness.** The two are different axes and frequently
> anti-correlated:
>
> - A **legitimate bank app** with certificate pinning, obfuscation, root detection, and
>   sensitive permissions can score poorly — the formula penalises high-severity findings and
>   the app legitimately needs risky capabilities.
> - A **dropper** with three permissions and no crypto misuse can score **well** — it has
>   nothing insecure in it, because the malicious payload isn't there yet
>   ([Ch 09 §7](../apk/09-package-manager.md#7-droppers-the-technique-in-full)).
>
> Use MobSF's *findings* as features. **Do not use its score as a maliciousness verdict.**

### Where MobSF fits in SUDARSHAN

| Use it for | Don't use it for |
|---|---|
| Rapid Tier 1–3 feature extraction | The final verdict |
| A baseline to benchmark your own extractors against | Campaign correlation |
| App-vetting reports (bank's own and vendor apps, mapped to MASVS) | Dropper detection |
| Its dynamic analyser as one detonation option | Scoring |

**Version note:** MobSF **v4.4.6 (March 2026)** patched a SQL-injection vulnerability in its
SQLite viewer. Analysis tools are software too — keep them patched and, more importantly,
**run them in an isolated sandbox**, because you are feeding them hostile input by design.

> **⚙️ Engineering Note:** That last point generalises. Your analysis stack — MobSF, apktool,
> jadx, unzip — parses attacker-controlled files. Parser vulnerabilities in analysis tooling
> are a real and recurring attack surface. Never run intake parsing on the orchestrator host.
> → [Ch 24](../sudarshan/24-threat-intake.md)

---

## 9. YARA

### WHAT

YARA is a pattern-matching engine for classifying files by strings and byte patterns. **YARA-X**
is the modern Rust rewrite, now the recommended engine — faster, safer, with a compatible rule
language.

### An Android-oriented rule

```yara
import "hash"

rule Android_A11y_Overlay_Banking_Capability
{
    meta:
        description   = "Android app with accessibility + overlay + package enumeration"
        author        = "SUDARSHAN"
        date          = "2026-08-05"
        severity      = "medium"
        confidence    = "low"      // capability, NOT family attribution
        mitre         = "T1453,T1417.001"
        reference     = "docs/malware/13-android-malware.md"

    strings:
        $a11y_action = "android.accessibilityservice.AccessibilityService" ascii
        $a11y_content= "canRetrieveWindowContent" ascii
        $a11y_gesture= "canPerformGestures" ascii
        $overlay     = "SYSTEM_ALERT_WINDOW" ascii
        $overlay_type= "TYPE_APPLICATION_OVERLAY" ascii
        $enum        = "getInstalledPackages" ascii
        $query_all   = "QUERY_ALL_PACKAGES" ascii

    condition:
        uint32(0) == 0x04034b50            // ZIP local file header
        and $a11y_action
        and 1 of ($a11y_content, $a11y_gesture)
        and 1 of ($overlay*)
        and 1 of ($enum, $query_all)
}

rule Android_Janus_Format
{
    meta:
        description = "File is simultaneously a valid DEX and ZIP (CVE-2017-13156 shape)"
        severity    = "critical"
        confidence  = "high"
        reference   = "docs/security/07-apk-signing.md#9-the-three-classic-attacks"
    condition:
        uint32(0) == 0x0A786564            // "dex\n"
        and for any i in (0..filesize) : ( false )   // placeholder; see note
}
```

> **⚙️ Engineering Note:** The Janus case is better handled by the deterministic byte check in
> [Ch 08 §10](../apk/08-apk-file-format.md#10-detection-logic-for-sudarshan) than by YARA —
> YARA is poor at expressing "is also a valid ZIP." **Use the right tool per signal:** YARA for
> string and byte patterns, purpose-built parsers for structural logic. Cramming structural
> checks into YARA produces slow, fragile rules.

### Rules over DEX and native libraries

Because APKs are ZIPs, string matching against the outer file only catches **stored** entries.
For reliable matching:

```
   app.apk
      │  unzip
      ▼
   classes*.dex  ──► YARA rules for DEX strings, opcode patterns
   lib/*.so      ──► YARA rules for native strings, packer signatures
   assets/*      ──► YARA rules for embedded payloads
```

**Scan the extracted members, not just the container.** This is a very common beginner error
that produces silently-empty rule sets.

```bash
$ yr scan rules.yar sample.apk                    # YARA-X CLI
$ mkdir x && unzip -q sample.apk -d x
$ yr scan --recursive rules.yar x/                # ← the one that actually works
```

### Rule design discipline

| Do | Don't |
|---|---|
| Encode `severity` **and** `confidence` separately in `meta` | Treat every hit as a verdict |
| Write capability rules (broad) and family rules (narrow) separately | Mix the two in one rule |
| Anchor family rules on **distinctive** strings (custom protocol tokens, unique class names) | Anchor on common framework strings |
| Version rules and track FP rate per rule | Ship rules without measuring |
| Reference the doc chapter in `meta` | Leave rules unexplained |

> **⚙️ Engineering Note:** Track **false-positive rate per rule** in production and retire
> rules that exceed a threshold. A rule library nobody prunes becomes a rule library nobody
> trusts, and then a rule library nobody reads. Rules are code — they need ownership, tests,
> and deprecation.

---

## 10. Similarity hashing

For clustering and campaign correlation ([Ch 28](../sudarshan/28-campaign-correlation.md)),
cryptographic hashes are useless — one byte changes everything. **Fuzzy hashes** survive small
changes.

| Hash | Property | Use |
|---|---|---|
| **SSDEEP** | Context-triggered piecewise hashing | Legacy compatibility; widely present in TI feeds |
| **TLSH** | Locality-sensitive; distance score | **Preferred** — better behaviour on larger files, numeric distance |
| **Import/API hash** | Digest of the sorted sensitive-API set | DEX analogue of PE imphash |
| **Manifest hash** | Digest of normalised permission + component set | Clusters same-builder apps |
| **Resource hash** | Digest of the overlay target list / asset names | Clusters campaigns sharing target sets |

```python
import tlsh

def similarity_features(path, dex_bytes, capability_vector):
    return {
        'tlsh_file': tlsh.hash(open(path,'rb').read()),
        'tlsh_dex':  tlsh.hash(dex_bytes),            # more stable than whole-APK
        'api_hash':  sha256(','.join(sorted(capability_vector['apis'])).encode()).hexdigest(),
        'manifest_hash': sha256(normalise_manifest(capability_vector).encode()).hexdigest(),
    }

# distance: 0 = identical; <50 typically "same family lineage"; >150 unrelated
tlsh.diff(h1, h2)
```

> **⚙️ Engineering Note:** Hash the **DEX**, not just the whole APK. Whole-APK TLSH is
> dominated by resources and assets, which vary per campaign (different overlays, different
> icons) even when the code is identical. **DEX-level TLSH tracks the code lineage**, which is
> what you actually want for family clustering.

---

## 11. What static analysis cannot do

An honest boundary list. Publishing this internally prevents overclaiming externally.

| Cannot do | Why | Mitigation |
|---|---|---|
| See a payload that isn't there | Droppers fetch later | Dynamic + TI + installer attribution → [Ch 09](../apk/09-package-manager.md) |
| Resolve reflection targets | Computed at runtime | Hook `Method.invoke` → [Ch 12](../dynamic-analysis/12-dynamic-analysis.md) |
| Read packed code | Encrypted until runtime | Class-loader dump → [Ch 10 §9](../reverse-engineering/10-reverse-engineering.md#9-unpacking-strategy) |
| Analyse native logic at scale | Requires native RE | Ghidra + `jnitrace`, human tier |
| Determine C2 liveness | No network | Dynamic + TI enrichment |
| Distinguish hardening from hiding | Identical techniques | Signer + capability + behaviour |
| Prove intent | Code shows capability, not purpose | Behavioural corroboration |

> **🚨 Misconception:** "Static analysis is enough." It is necessary, fast, and reproducible —
> and it is structurally blind to staged and packed malware, which is the dominant modern
> pattern. The converse misconception ("dynamic is enough") fails for the opposite reason:
> evasion, geofencing, and C2-gating. **Neither alone is sufficient; the fusion is the
> product.** → [Ch 32](../appendix/32-common-misconceptions.md)

---

## 12. Detection logic for SUDARSHAN

### The static analysis record

```yaml
static_analysis:
  tier0_structural:      { ... }   # Ch 08 §10
  tier1_capability:      { ... }   # §4
  tier1_a11y_config:     { ... }   # §4
  tier2_resources:
    locales: []                    # victim geography
    referenced_packages: []        # ★ overlay target list
    urls: []
    high_entropy_assets: []
    overlay_html_present: bool
  tier3_code:
    api_xrefs: { ... }             # §6
    api_chains_matched: []         # ★ the chains, not the endpoints
    yara_hits: [{rule, severity, confidence}]
    similarity: { tlsh_dex, api_hash, manifest_hash }

  analysis_quality:                # ★ MANDATORY → Ch 10 §13
    packed: bool
    unpacked: bool | null
    decompilation_ok: bool
    call_graph_coverage: float
    unresolved_reflection_edges: int
    native_code_ratio: float
    confidence_ceiling: float
```

### The escalation gate

```yaml
escalate_to_dynamic_when:
  any_of:
    # the ODF capability cluster
    - all_of:
        - capability.declares_a11y_service
        - any_of: [a11y.can_retrieve_window_content, a11y.can_perform_gestures]
        - at_least_2_of:
            - capability.has_overlay
            - capability.has_request_install
            - capability.has_sms
            - capability.declares_notification_listener
            - "mediaProjection" in capability.fgs_types
    # staging machinery
    - code.api_chains_matched contains "crypto_to_classloader"
    - capability.has_request_install and resources.high_entropy_assets
    # analysis blocked → must observe at runtime
    - analysis_quality.packed and not analysis_quality.unpacked
    # intel
    - similarity.tlsh_dex within 50 of a known-malicious sample
    - signer in threat_intel.malicious_signers
    # structural
    - tier0.dex_magic_at_offset_0            # Janus
    - tier0.duplicate_entries
```

> **⚙️ Engineering Note — the fourth condition is the one people forget.** *"Packed and could
> not be unpacked"* must escalate to dynamic analysis. Otherwise the pipeline's response to
> "I can't read this" is silence, and the samples that most resist analysis are exactly the
> ones that most deserve it. Make inability-to-analyse a first-class escalation trigger.

---

## 13. Limitations, edge cases, false positives

### False positives by signal

| Signal | Innocent population |
|---|---|
| Accessibility declared | Password managers, screen readers, automation, remote support |
| Overlay permission | Chat bubbles, floating players, screen dimmers |
| `QUERY_ALL_PACKAGES` | Launchers, AV, backup, parental controls |
| `REQUEST_INSTALL_PACKAGES` | App stores, updaters, MDM |
| High-entropy assets | ML models, DRM, compressed game data |
| Many locales | Genuinely international apps |
| Packer present | Banks, games, DRM |
| Low MobSF score | Hardened banking apps |
| Crypto misuse findings | Legacy code in otherwise benign apps |

### False negatives

- Droppers (payload absent).
- Native-implemented behaviour.
- Successfully packed, un-unpacked samples — **caught only if you escalate on analysis failure**.
- Novel techniques with no rule coverage.

### Edge cases

| Case | Handling |
|---|---|
| React Native / Flutter / Cordova | Logic outside DEX → [Ch 10 §14](../reverse-engineering/10-reverse-engineering.md#14-limitations-edge-cases-false-positives) |
| Split APKs / XAPK | Explode and analyse the full set |
| Very large APKs | Stream; enforce timeouts |
| Apps with no DEX | Legal; not a finding |
| Manifest-merged SDK permissions | A permission may come from a third-party SDK, not app intent |

> **⚙️ Engineering Note — the SDK attribution problem.** Manifest merging means an app's
> permission list includes everything its libraries request. An ad SDK requesting
> `QUERY_ALL_PACKAGES` makes the *app* look like it enumerates packages. Where possible,
> attribute capabilities to the declaring component and note SDK provenance — otherwise you
> will generate false positives against apps whose developers never asked for the permission.
> This is a genuine, under-addressed accuracy problem in mobile static analysis.

### Performance budget

| Tier | Target p95 | Coverage |
|---|---|---|
| 0 | 50 ms | 100% |
| 1 | 200 ms | 100% |
| 2 | 1 s | 100% |
| 3 | 120 s | ~20% |

Tier 3 timeouts are normal on large or hostile samples. **A timeout is an analysis-quality
event, not a clean result** — record it and cap confidence.

---

## 14. Engineering tips

1. **Tier everything.** Never run Tier 3 on 100% of input.
2. **Parse the accessibility config**, not just the permission.
3. **Extract the overlay target list.** Highest business value per millisecond.
4. **Encode API *chains*, not endpoints.**
5. **Scan extracted DEX/`.so` with YARA**, not just the APK container.
6. **TLSH the DEX**, not the whole APK.
7. **Use MobSF findings as features; ignore its score as a verdict.**
8. **Escalate on analysis failure**, not just on positive findings.
9. **Record analysis quality on every result and enforce a confidence ceiling.**
10. **Run all parsing in a sandbox** — your tools parse hostile input.
11. **Track per-rule false-positive rates** and prune.
12. **Attribute permissions to SDKs** where you can.

---

## 15. Judge Insights

**What judges ask:** *"What exactly does your static analysis do that MobSF doesn't already
do for free?"*

**Perfect answer:** MobSF is an excellent app-security scanner and we use it as a baseline —
but it answers a different question. MobSF scores **security hygiene**; we assess
**maliciousness**, and those are different axes that are often anti-correlated. A hardened
bank app with pinning, obfuscation, and root detection scores badly in MobSF; a dropper with
three permissions and no crypto misuse scores well, because its payload isn't there yet.
Concretely we add: parsing the accessibility service *config* rather than just the permission,
so we can say "this can read every app's screen and inject taps"; extracting the overlay target
list from resources, so we can tell a bank whether it's specifically targeted; API *chains*
rather than API presence, so "encrypted blob decrypted then handed to an in-memory class
loader" is one finding instead of three unrelated ones; DEX-level fuzzy hashing for family
clustering; and a mandatory analysis-quality record that caps our confidence when we couldn't
actually read the sample.

**Common mistakes:**
- Presenting a security score as a malware verdict.
- Claiming full static taint analysis at scale. FlowDroid is real research, but it's slow,
  memory-hungry, and fragile on obfuscated code — say what you actually run.
- Not acknowledging that static analysis is blind to droppers.

**Follow-ups to expect:**
- *"What's your false positive rate?"* → The honest framing: single signals have high FP rates
  by design, which is why nothing is scored in isolation. The cluster rule plus the signer
  registry is where precision comes from. Then quote your measured numbers on a labelled
  corpus — and if you don't have a labelled corpus yet, say that.
- *"How do you handle packed samples?"* → Escalate on *inability to analyse*, dump at runtime,
  recurse. Never silently return "clean."
- *"Isn't this just permission counting?"* → No — and here's the accessibility config parse and
  the crypto-to-classloader chain as concrete counter-examples.

**Fact that impresses:** MobSF's score formula is roughly
`100 − ((High + 0.5·Medium − 0.2·Secure)/count)` — which means it **penalises apps for having
high-severity findings regardless of context**. A bank's genuinely hardened app can grade worse
than a clean-looking dropper. Knowing the formula and its consequence shows you've read the
tool rather than just run it.

---

## 16. Interview Insights

**Q: "How would you build an Android malware static analysis pipeline?"**
Tiered by cost: structural (~10 ms, 100%), manifest/capability (~50 ms, 100%), resources
(~500 ms, 100%), code analysis (~seconds, ~20%), dynamic (~minutes, ~5%), human RE (<1%). Each
tier gates the next. Emphasise that gates must err toward escalation and be auditable.

**Q: "What's the difference between static analysis and reverse engineering?"**
Scale and purpose. Static analysis is automated fact extraction across thousands of samples,
producing feature vectors. RE is a human understanding specific logic deeply, producing IOCs
and rules. RE feeds patterns back into static analysis — that's the loop that makes a team
compound.

**Q: "Write a YARA rule for Android banking malware."**
Then explain what you did: match on the ZIP magic, require the accessibility service action
plus a capability flag, plus an overlay indicator, plus package enumeration — and set
`confidence` low in `meta` because it's a **capability** rule, not a family rule. Also mention
that you must scan the **extracted** DEX, not just the container, because APK entries are
compressed.

**Q: "Why can't static analysis alone detect banking trojans?"**
Droppers — the payload isn't in the file at analysis time. Anatsa's Play droppers were
genuinely clean at review. Also packing, native code, reflection, and C2-gated behaviour.

**Q: "What's taint analysis and would you use it?"**
Tracking data from sensitive sources to exfiltration sinks; FlowDroid is the reference
implementation. Honest answer: excellent for auditing a cooperative, unobfuscated app; too
slow and fragile for a high-throughput malware pipeline. Use pattern-based flow rules at scale.

**Q: "How do you cluster samples into families?"**
Signer certificate fingerprint first ([Ch 06](../security/06-certificates.md)), then
**DEX-level** TLSH (not whole-APK, which is dominated by resources), API-set hashing, shared
C2 infrastructure, and resource artifacts like the overlay target list.

**Beginner mistakes:**
- Counting permissions and calling it detection.
- Running YARA against the APK container only.
- Treating a security score as a malware verdict.
- Returning "clean" for samples that couldn't be analysed.
- Ignoring that permissions may come from bundled SDKs.

---

## 17. Cross-references

**Upstream:**
- [← Ch 04 Android Security Model](../security/04-android-security-model.md) — capability weights
- [← Ch 08 APK File Format](../apk/08-apk-file-format.md) — Tier 0 structural checks
- [← Ch 10 Reverse Engineering](../reverse-engineering/10-reverse-engineering.md) — the manual craft this automates

**Downstream:**
- [→ Ch 12 Dynamic Analysis](../dynamic-analysis/12-dynamic-analysis.md) — where escalation goes
- [→ Ch 16 Threat Intelligence](../threat-intelligence/16-threat-intelligence.md) — MITRE mapping, IOC context
- [→ Ch 23 Detection Pipeline](../sudarshan/23-detection-pipeline.md) — the tiering formalised
- [→ Ch 26 IOC Extraction](../sudarshan/26-ioc-extraction.md) — Tier 2/3 outputs as indicators
- [→ Ch 27 Risk Scoring](../sudarshan/27-risk-scoring.md) — consuming the capability vector
- [→ Ch 28 Campaign Correlation](../sudarshan/28-campaign-correlation.md) — similarity hashing

**Related chain:** Manifest → capability vector → escalation gate → dynamic analysis →
IOC extraction → risk score → report.

---

## 18. References

1. MobSF — *Mobile Security Framework* documentation. https://mobsf.github.io/docs/
2. MobSF — REST API reference. https://mobsf.github.io/docs/#/rest_api
3. MobSF project repository (v4.4.x; v4.4.6 SQLite-viewer SQLi fix, March 2026). https://github.com/MobSF/Mobile-Security-Framework-MobSF
4. YARA-X documentation. https://virustotal.github.io/yara-x/
5. YARA documentation (legacy engine). https://yara.readthedocs.io/
6. Androguard documentation. https://androguard.readthedocs.io/
7. FlowDroid — static taint analysis for Android. https://github.com/secure-software-engineering/FlowDroid
8. TLSH — Trend Micro Locality Sensitive Hash. https://github.com/trendmicro/tlsh
9. ssdeep — context-triggered piecewise hashing. https://ssdeep-project.github.io/ssdeep/
10. OWASP MASVS v2.1.0 and MASTG — static analysis test cases. https://mas.owasp.org/
11. NIST SP 800-163 Rev. 1 — *Vetting the Security of Mobile Applications*.
12. Cyble Research and Intelligence Labs — *Antidot* (May 16, 2024) — multi-locale overlay targeting.
13. ThreatFabric — Anatsa Google Play dropper campaigns (July 2025).
14. MITRE ATT&CK for Mobile. https://attack.mitre.org/matrices/mobile/

### Further reading
- Androguard `Analysis` API — cross-reference and call-graph construction
- VirusTotal Retrohunt and LiveHunt documentation (YARA at scale)
- OWASP MASTG — MASVS-CODE and MASVS-RESILIENCE test cases

---

*Previous: [← Ch 10 Reverse Engineering](../reverse-engineering/10-reverse-engineering.md) · Next: [Ch 12 Dynamic Analysis →](../dynamic-analysis/12-dynamic-analysis.md)*
