# 10 - Reverse Engineering

> **Chapter ID:** `CH10` · **Block:** B (Analysis Craft) · **Status:** Stable
> **Tags:** `#reverse-engineering` `#apktool` `#jadx` `#smali` `#obfuscation` `#packers` `#ghidra` `#unpacking`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 02](../apk/02-apk-architecture.md), [Ch 03](../android/03-android-runtime.md), [Ch 08](../apk/08-apk-file-format.md)

---

## Table of Contents

1. [What reverse engineering is for](#1-what-reverse-engineering-is-for)
2. [The toolchain](#2-the-toolchain)
3. [apktool - resources and smali](#3-apktool--resources-and-smali)
4. [jadx - the daily driver](#4-jadx--the-daily-driver)
5. [Reading smali](#5-reading-smali)
6. [Androguard - scriptable analysis](#6-androguard--scriptable-analysis)
7. [Obfuscation](#7-obfuscation)
8. [Packers](#8-packers)
9. [Unpacking strategy](#9-unpacking-strategy)
10. [Native reverse engineering](#10-native-reverse-engineering)
11. [Anti-analysis and how it fails](#11-anti-analysis-and-how-it-fails)
12. [The RE workflow, end to end](#12-the-re-workflow-end-to-end)
13. [Detection logic for SUDARSHAN](#13-detection-logic-for-sudarshan)
14. [Limitations, edge cases, false positives](#14-limitations-edge-cases-false-positives)
15. [Engineering tips](#15-engineering-tips)
16. [Judge Insights](#16-judge-insights)
17. [Interview Insights](#17-interview-insights)
18. [Cross-references](#18-cross-references)
19. [References](#19-references)

---

## 1. What reverse engineering is for

Reverse engineering answers one question that nothing else can: **what does this code
actually do?**

Static capability extraction ([Ch 11](../static-analysis/11-static-analysis.md)) tells you an
app *can* read SMS. Dynamic analysis ([Ch 12](../dynamic-analysis/12-dynamic-analysis.md))
tells you it *did* read SMS on one particular run. Reverse engineering tells you **under what
conditions it reads SMS, what it does with the contents, where it sends them, and what the
decryption key is** - the logic, not just the surface or a single trace.

### When to reach for it

| Situation | RE needed? |
|---|---|
| Triage: is this worth investigating? | ❌ No - manifest and capability profile suffice |
| Bulk pipeline classification | ❌ No - too slow, doesn't scale |
| "What is this sample's C2 protocol?" | ✅ Yes |
| "What triggers the payload?" | ✅ Yes |
| "Write a YARA rule for this family" | ✅ Yes |
| "The sandbox showed nothing - why?" | ✅ Yes |
| "Is this a variant of Anatsa or something new?" | ✅ Yes |

> **⚙️ Engineering Note - the economics.** Manifest parsing costs ~50 ms. Full decompilation
> costs seconds to minutes. Human reverse engineering costs **hours to days**. SUDARSHAN's
> job is to make sure the expensive human tier only ever sees samples that deserve it. That
> economic gradient is the entire architecture of [Ch 23](../sudarshan/23-detection-pipeline.md).
> RE is the apex of the pyramid, not the base.

### The RE mindset

Three habits that separate productive analysts from people who stare at decompiled code:

1. **Start from a question, not from `MainActivity`.** "Where does the C2 URL come from?" is
   a plan. "Let me read this app" is not.
2. **Work backwards from the interesting API.** Find `sendTextMessage`, `getInstalledPackages`,
   `InMemoryDexClassLoader` - then walk up the call graph to the trigger.
3. **When static gets hard, go dynamic.** Obfuscation is designed to waste your time. The
   runtime has to produce plaintext eventually ([Ch 03](../android/03-android-runtime.md)).
   Switching layers is a skill, not a defeat.

---

## 2. The toolchain

| Tool | Input → Output | Use it for |
|---|---|---|
| **jadx / jadx-gui** | DEX → Java | **Primary decompiler.** Reading logic. |
| **apktool** | APK → smali + decoded resources | Resources, manifest, and **repackaging** |
| **Androguard** | APK → Python objects | **Automation**, call graphs, scripting |
| **baksmali / smali** | DEX ↔ smali | Precise disassembly and reassembly |
| **dex2jar** | DEX → JAR | Feeding Java-ecosystem tools (JD-GUI, Procyon) |
| **aapt2** | APK → manifest/resource dumps | Fast metadata, closest to Android's own parser |
| **apkanalyzer** | APK → size/DEX stats | Method counts, DEX composition |
| **Ghidra** | ELF → decompiled C | **Native library RE** (free, scriptable) |
| **radare2 / rizin / Cutter** | ELF → disassembly | Native RE, strong CLI/scripting |
| **IDA Pro** | ELF → decompiled C | Commercial native RE |
| **Bytecode Viewer** | APK → several decompilers at once | Cross-checking when one decompiler fails |
| **frida / objection** | Runtime | When static stalls → [Ch 12](../dynamic-analysis/12-dynamic-analysis.md) |

### Installation

```bash
# jadx
$ wget https://github.com/skylot/jadx/releases/latest/download/jadx-1.5.0.zip
$ unzip jadx-1.5.0.zip -d ~/tools/jadx && export PATH=$PATH:~/tools/jadx/bin

# apktool
$ wget https://github.com/iBotPeaches/Apktool/releases/latest/download/apktool_2.9.3.jar

# Androguard
$ pip install androguard

# Android build-tools (aapt2, apksigner, zipalign, dexdump)
$ sdkmanager "build-tools;34.0.0"
```

> **⚙️ Engineering Note:** Pin tool versions in your analysis environment and record them in
> the artifact metadata. Decompiler output changes between versions - a rule or a finding that
> depended on jadx 1.4 output may not reproduce on 1.5. Reproducibility matters when a bank's
> report has to survive an audit six months later.

---

## 3. apktool - resources and smali

### WHAT it does

Decodes an APK into a rebuildable project tree: binary AXML → readable XML,
`resources.arsc` → `res/values/*.xml`, and DEX → smali.

```bash
# Full decode
$ apktool d suspicious.apk -o work/

# ★ Resources + manifest ONLY - skip smali. 10-50x faster.
$ apktool d -s suspicious.apk -o work/

# Rebuild (lab only - output is unsigned, v2 invalidated → Ch 07)
$ apktool b work/ -o rebuilt.apk
```

Output tree:

```
work/
├── AndroidManifest.xml       ← now readable text
├── apktool.yml               ← metadata: version codes, compression, sdk levels
├── original/META-INF/        ← original v1 signature material
├── res/                      ← decoded resources
│   ├── values/strings.xml    ← ★ resource strings, often where C2 URLs hide
│   └── xml/                  ← ★ accessibility_service_config, network_security_config
├── assets/                   ← raw, untouched
├── lib/                      ← native .so, untouched
└── smali/, smali_classes2/   ← one dir per classesN.dex
```

### Why `-s` matters so much

From [Ch 02 §9](../apk/02-apk-architecture.md#9-first-contact-triage-workflow): you want the
capability profile *before* you commit to expensive work. `-s` gives you the manifest,
accessibility config, network security config, locale set, and all resource strings in a
couple of seconds.

```bash
# The 10-second capability read
$ apktool d -s app.apk -o work/ >/dev/null 2>&1
$ grep -E 'uses-permission|accessibilityservice|foregroundServiceType' work/AndroidManifest.xml
$ cat work/res/xml/*accessib* 2>/dev/null
$ grep -rEoh 'https?://[^"<]+' work/res/ | sort -u | head -20
```

> **⚙️ Engineering Note:** When `apktool` fails but the app installs and runs, that is
> **evidence**, not an obstacle ([Ch 08 §9](../apk/08-apk-file-format.md#9-format-level-anti-analysis)).
> Log the failure mode, fall back to `aapt2 dump` or Androguard, and score the divergence.
> Deliberately malformed AXML and `resources.arsc` are documented anti-analysis techniques - > Android's parser is tolerant, `apktool` is not.

---

## 4. jadx - the daily driver

jadx decompiles DEX straight to Java. It is the tool you will spend the most hours in.

```bash
# CLI decompile
$ jadx -d out/ suspicious.apk

# Keep going despite errors (essential on obfuscated samples)
$ jadx -d out/ --no-res --show-bad-code suspicious.apk

# GUI - where the real work happens
$ jadx-gui suspicious.apk
```

### The GUI features that matter

| Feature | Shortcut | Why |
|---|---|---|
| **Text search** | `Ctrl+Shift+F` | Find API calls, strings, URLs across the whole app |
| **Find usage** | `X` on a symbol | Walk the call graph backwards - your primary navigation |
| **Go to declaration** | `Ctrl+Click` | Follow forwards |
| **Deobfuscation** | Preferences → Deobfuscation | Stable synthetic names for mangled classes |
| **Show smali** | Right-click → Show bytecode | When Java output is wrong or missing |
| **Rename** | `N` | Annotate as you understand - build your own map |
| **Save project** | - | **Persist your renames.** Losing an afternoon of naming hurts. |

### The search terms that find banking malware fast

```
# capability APIs
AccessibilityService · onAccessibilityEvent · performGlobalAction · dispatchGesture
TYPE_APPLICATION_OVERLAY · WindowManager.addView
SmsManager · getMessageBody · SmsMessage.createFromPdu
NotificationListenerService · onNotificationPosted
MediaProjection · createVirtualDisplay
DevicePolicyManager · lockNow · wipeData
getInstalledPackages · getInstalledApplications · queryIntentActivities

# staging / evasion  → Ch 03
DexClassLoader · InMemoryDexClassLoader · PathClassLoader · DexFile
Class.forName · getDeclaredMethod · setAccessible · Method.invoke
System.loadLibrary · registerNatives

# crypto / C2  → Ch 05
Cipher.getInstance · SecretKeySpec · IvParameterSpec · Base64
HttpURLConnection · OkHttpClient · Socket · WebSocket · MqttClient
api.telegram.org · firebaseio.com
```

> **⚙️ Engineering Note:** jadx sometimes emits wrong Java for heavily obfuscated code - > silently. If control flow looks impossible (unreachable code, mismatched types, missing
> method bodies), **switch to the smali view.** Smali is a faithful rendering of the bytecode;
> Java is an interpretation. When they disagree, smali is right.

---

## 5. Reading smali

You do not need to write smali fluently. You do need to read it, because it is ground truth.

### Registers and types

Dalvik is **register-based**. Registers are `v0, v1, …` (locals) and `p0, p1, …` (parameters).
For an instance method, **`p0` is `this`**.

Type descriptors:

| Descriptor | Java |
|---|---|
| `V` | void |
| `Z` `B` `S` `C` `I` `J` `F` `D` | boolean, byte, short, char, int, long, float, double |
| `Ljava/lang/String;` | Object type - `L` + path + `;` |
| `[I` | `int[]` |
| `[Ljava/lang/String;` | `String[]` |

Method signature: `methodName(ParamTypes)ReturnType`
→ `sendTextMessage(Ljava/lang/String;Ljava/lang/String;)V`

### An annotated example

```smali
.method public onAccessibilityEvent(Landroid/view/accessibility/AccessibilityEvent;)V
    .locals 3                          # uses v0, v1, v2
    # p0 = this, p1 = the AccessibilityEvent

    invoke-virtual {p1}, Landroid/view/accessibility/AccessibilityEvent;->getPackageName()Ljava/lang/CharSequence;
    move-result-object v0              # v0 = foreground app package name

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;
    move-result-object v0

    iget-object v1, p0, Lcom/x/A11y;->targets:Ljava/util/List;   # target bank list
    invoke-interface {v1, v0}, Ljava/util/List;->contains(Ljava/lang/Object;)Z
    move-result v2

    if-eqz v2, :not_target             # if not in target list, skip
    invoke-direct {p0, v0}, Lcom/x/A11y;->showOverlay(Ljava/lang/String;)V   # ☠️

    :not_target
    return-void
.end method
```

Read that and you have the core of an overlay trojan: **get foreground package → check
against a target list → if match, show a fake window.** That is the banking-malware loop in
eight instructions.

### Instructions worth recognising

| Instruction | Meaning |
|---|---|
| `invoke-virtual` | Normal instance method call |
| `invoke-direct` | Private / constructor |
| `invoke-static` | Static method |
| `invoke-interface` | Interface method |
| `move-result{,-object,-wide}` | **Capture the return value** - always follows an invoke |
| `iget/iput{,-object}` | Instance field read/write |
| `sget/sput{,-object}` | Static field read/write |
| `const-string` | **String literal** - where unencrypted secrets live |
| `new-instance` / `new-array` | Allocation |
| `if-eqz` / `if-nez` | Branch on zero / non-zero |
| `check-cast` | Cast |

> **⚙️ Engineering Note:** `const-string` is your friend. `grep -rn "const-string" smali/ |
> grep -Ei 'http|token|key'` finds unencrypted URLs and secrets in seconds. When it returns
> nothing on a sample that clearly talks to a C2, you have just learned the strings are
> encrypted - which is itself a finding, and tells you to go dynamic
> ([Ch 05 §9](../security/05-android-cryptography.md#9-how-malware-uses-cryptography)).

### baksmali / smali directly

```bash
$ baksmali d classes.dex -o smali_out/
$ smali a smali_out/ -o patched.dex
```

Useful when you need exact control (patching a single instruction) or when `apktool` chokes
on resources but the DEX is fine.

---

## 6. Androguard - scriptable analysis

`jadx` is for humans. **Androguard is for pipelines.** SUDARSHAN's static stage is built on
this shape of code.

```python
from androguard.misc import AnalyzeAPK

a, d, dx = AnalyzeAPK("suspicious.apk")
# a  = APK object (manifest, certs, resources)
# d  = list of DalvikVMFormat (one per classesN.dex)
# dx = Analysis object (cross-references, call graph)

# --- identity & capability -------------------------------------------------
print(a.get_package(), a.get_androidversion_code())
print("targetSdk:", a.get_effective_target_sdk_version())
for c in a.get_certificates():
    print("signer:", c.sha256_fingerprint)          # → Ch 06, the identity key
print("perms:", a.get_permissions())
print("activities:", a.get_activities())
print("services:", a.get_services())
print("receivers:", a.get_receivers())

# --- who calls the dangerous APIs? -----------------------------------------
TARGETS = [
    ("Landroid/telephony/SmsManager;", "sendTextMessage"),
    ("Ldalvik/system/DexClassLoader;", "<init>"),
    ("Ldalvik/system/InMemoryDexClassLoader;", "<init>"),
    ("Ljava/lang/reflect/Method;", "invoke"),
    ("Landroid/app/admin/DevicePolicyManager;", "lockNow"),
]
for cls, meth in TARGETS:
    for m in dx.find_methods(classname=cls, methodname=meth):
        for _, caller, _ in m.get_xref_from():
            print(f"{cls}->{meth}  <=  {caller.class_name}->{caller.name}")

# --- strings that look like infrastructure ---------------------------------
import re
URL = re.compile(r"https?://[^\s\"'<>]+")
for s in d[0].get_strings():
    if URL.search(s):
        print("url:", s)
```

### Why cross-references are the point

`dx.get_xref_from()` gives you the **call graph**, which turns "this app contains
`sendTextMessage`" into "this app calls `sendTextMessage` from a `BroadcastReceiver`
triggered by `SMS_RECEIVED`." The first is noise; the second is a finding.

> **⚙️ Engineering Note - the reflection caveat.** Androguard's call graph is built from
> *direct* invocations. Reflection ([Ch 03 §7](../android/03-android-runtime.md#7-reflection))
> creates edges it cannot see. **A clean call graph on a sample that heavily uses
> `Method.invoke` is a false negative, not a clean bill of health.** Always report call-graph
> coverage alongside call-graph findings.

---

## 7. Obfuscation

### The critical framing

> **🚨 Misconception:** "Obfuscated = malicious." **Practically every app on Google Play is
> obfuscated.** R8 is enabled by default in release builds. Every major bank's app uses
> ProGuard/R8 at minimum and frequently a commercial protector. Flagging obfuscation as
> malicious means flagging the entire Play Store - and, embarrassingly, flagging your own
> client's hardened banking app as the most suspicious thing on the device
> ([Ch 05 §11](../security/05-android-cryptography.md#11-limitations-edge-cases-false-positives)).

What *is* meaningful is **obfuscation that exceeds commercial norms**, and specific
techniques that have no legitimate purpose.

### The techniques

| Technique | Tool | Legit? | Analyst impact |
|---|---|---|---|
| **Name mangling** (`a.b.c`) | R8, ProGuard | ✅ Universal | Annoying, not blocking |
| **Dead code removal / shrinking** | R8 | ✅ Universal | Smaller attack surface to read |
| **String encryption** | DexGuard, custom | ⚠️ Common in fintech | **Blocks grep.** Go dynamic. |
| **Control-flow flattening** | DexGuard, commercial | ⚠️ Used by banks | Decompiler output becomes a state machine |
| **Reflection indirection** | Any | ⚠️ Both | **Breaks call graphs** |
| **Class encryption / packing** | Commercial packers | ⚠️ Both | Static analysis sees a stub |
| **Native migration** | Manual | ⚠️ Both | jadx shows empty methods |
| **Junk code insertion** | Commercial | ⚠️ Both | Signal-to-noise collapse |
| **API hiding via `ServiceManager`** | Manual | ❌ **Rarely legitimate** | Hidden-API bypass → [Ch 03 §8](../android/03-android-runtime.md#8-non-sdk-hidden-api-restrictions) |
| **Anti-debug / anti-Frida in native** | RASP vendors + malware | ⚠️ Both | Blocks dynamic analysis |

### Distinguishing hardening from hiding

You cannot do it from obfuscation alone. You do it from **context**:

```
  Is it obfuscated?  ──► says almost nothing
          │
          ▼
  What is the SIGNER?          → known bank / known-good publisher? → hardening
          │                      unknown, fresh, or debug cert?     → suspect
          ▼
  What are the CAPABILITIES?   → a11y + overlay + SMS + install?    → malicious cluster
          │                      network + camera for a bank app?   → normal
          ▼
  What does it DO at runtime?  → C2 beacon + overlay injection?     → verdict
```

That ordering - signer, then capability, then behaviour - is the discriminator. Obfuscation is
never the first question.

### Working through name mangling

```bash
# jadx deobfuscation produces stable synthetic names
$ jadx --deobf --deobf-min 3 --deobf-max 64 -d out/ app.apk
```

Practical technique: **rename as you go** in jadx-gui (`N`), starting from the entry points
you care about. Obfuscation removes *names*, not *structure* - the call graph, string
constants, API calls, and control flow all survive. You are rebuilding a map, not decrypting
a cipher.

---

## 8. Packers

### WHAT a packer does

Encrypts or hides the real DEX, ships a small loader stub, and reconstructs the real code at
runtime - usually in native code, often inside `JNI_OnLoad`
([Ch 03 §9](../android/03-android-runtime.md#9-jni-and-native-code)).

```
  Shipped APK                          At runtime
  ───────────                          ──────────
  classes.dex  = tiny stub             native loader decrypts
  assets/xyz.dat = encrypted real DEX  →  real DEX in memory
  lib/libpacker.so = the unpacker      →  handed to a ClassLoader
                                       →  real classes now resolvable
```

### Fingerprints

| Packer | Vendor | Telltale files |
|---|---|---|
| **Jiagu** | 360 | `libjiagu.so`, `libjiagu_art.so`, `libjiagu_x86.so` |
| **SecNeo / Bangcle** | SecNeo | `libDexHelper.so`, `libsecexe.so`, `assets/classes0.jar` |
| **Tencent Legu** | Tencent | `libshella-*.so`, `libtup.so`, `libtprt.so` |
| **Virbox** | SenseShield | Virbox runtime artifacts - documented by Cleafy in **Klopatra** (Aug 2025) |
| **Alibaba/Ali** | Alibaba | `libmobisec.so` |
| **Baidu** | Baidu | `libbaiduprotect.so` |
| **ApkProtect** | - | `libAPKProtect.so` |

```bash
# One-line packer check
$ unzip -l app.apk | grep -Ei 'libjiagu|libDexHelper|libshell|libsecexe|libmobisec|libbaiduprotect|virbox'

# The structural tell: tiny DEX, huge native
$ unzip -l app.apk | awk '/classes.*\.dex/ {d+=$1} /\.so$/ {s+=$1} END {print "dex:",d," so:",s," ratio:",s/d}'
```

> **⚙️ Engineering Note:** A **thin `classes.dex` plus a large native library** is the
> packer signature even when the library name is unknown. Ratio > ~5:1 native-to-DEX with a
> DEX under a few hundred KB in an app that clearly does a lot is a strong structural
> indicator. Record it as `packer_suspected: true` with the ratio as evidence.

### Why malware packs, and why banks pack

Both use the same products. **Klopatra** (Cleafy, August 2025) used the commercial **Virbox**
protector *and* shifted logic from Java to native - a leading-edge example of a banking trojan
adopting enterprise-grade protection. **GodFather** variants likewise migrated to native code
(Cyble).

Meanwhile legitimate banks buy DexGuard, Promon, Appdome, Guardsquare, Build38, and Verimatrix
for exactly the same reasons. **The tool does not distinguish intent.** Signer and behaviour do.

---

## 9. Unpacking strategy

### The governing principle

> **The runtime must eventually see plaintext DEX in order to execute it.** No packer can
> avoid this. Therefore the reliable unpacking method is not static decryption - it is
> **catching the moment of materialisation**.

This is the same principle as [Ch 03 §6](../android/03-android-runtime.md#6-dynamic-code-loading--the-technique-that-breaks-static-analysis),
applied to packers instead of droppers.

### The ladder - try in this order

```
 1. Is it actually packed?         unzip -l | packer fingerprint; dex/so ratio
        │ yes
        ▼
 2. Class-loader hook (Frida)      dump every DEX handed to any ClassLoader   ★ BEST
        │ fails (native loading, anti-Frida)
        ▼
 3. Memory scan for DEX magic      scan process maps for "dex\n0XX\0", carve
        │ fails
        ▼
 4. .vdex extraction               pull /data/app/.../oat/*/base.vdex → Ch 03 §4
        │ fails
        ▼
 5. Native RE of the unpacker      Ghidra on JNI_OnLoad + .init_array
        │ fails
        ▼
 6. Emulated/instrumented ART      heavy tooling; rarely necessary
```

### Step 2 in practice

```javascript
// Frida - universal DEX dumper. Covers packers AND droppers.
Java.perform(function () {
  function dump(bytes, tag) {
    var path = '/data/local/tmp/dump_' + tag + '_' + Date.now() + '.dex';
    var f = new File(path, 'wb'); f.write(bytes); f.flush(); f.close();
    console.log('[+] dumped ' + path + ' (' + bytes.length + ' bytes)');
  }

  var IMDCL = Java.use('dalvik.system.InMemoryDexClassLoader');
  // BOTH overloads - single buffer and array. Missing one loses half the samples.
  IMDCL.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader')
    .implementation = function (buf, p) {
      console.log('[!] InMemoryDexClassLoader size=' + buf.remaining());
      return this.$init(buf, p);
    };
  IMDCL.$init.overload('[Ljava.nio.ByteBuffer;', 'java.lang.ClassLoader')
    .implementation = function (bufs, p) {
      console.log('[!] InMemoryDexClassLoader array n=' + bufs.length);
      return this.$init(bufs, p);
    };

  var DCL = Java.use('dalvik.system.DexClassLoader');
  DCL.$init.overload('java.lang.String','java.lang.String','java.lang.String','java.lang.ClassLoader')
    .implementation = function (p1,p2,p3,p4) {
      console.log('[!] DexClassLoader path=' + p1);
      return this.$init(p1,p2,p3,p4);
    };
});
```

### Step 3 - memory carving

```javascript
// Scan for DEX magic in RW memory and carve
Process.enumerateRanges('r--').forEach(function (r) {
  Memory.scan(r.base, r.size, '64 65 78 0a 30 33', {   // "dex\n03"
    onMatch: function (addr) {
      var size = addr.add(32).readU32();               // file_size at 0x20 → Ch 08
      if (size > 0x70 && size < 64*1024*1024) {
        var f = new File('/data/local/tmp/carved_' + addr + '.dex', 'wb');
        f.write(Memory.readByteArray(addr, size)); f.close();
        console.log('[+] carved DEX at ' + addr + ' size=' + size);
      }
    },
    onComplete: function () {}
  });
});
```

> **⚙️ Engineering Note:** Carved DEX often has a **wrong Adler-32 and SHA-1** (the header
> fields from [Ch 08 §6](../apk/08-apk-file-format.md#6-dex-format)) because it was
> reconstructed in memory. Tools may reject it. Fix the checksums, or use a tolerant parser.
> Do not conclude the dump failed just because `dexdump` complains.

### After unpacking: recurse

Every dumped DEX is a **new artifact** that must go back through the full static pipeline,
linked to its parent ([Ch 03 §11](../android/03-android-runtime.md#11-detection-logic-for-sudarshan)).
This is where the real capability profile appears.

---

## 10. Native reverse engineering

### The starting points

For a shared object, there is no `main`. Start here, **in this order**:

```
 1. .init_array   ← constructors. Run BEFORE JNI_OnLoad. Anti-analysis hides here.
 2. JNI_OnLoad    ← first JNI entry. Packers unpack here. RegisterNatives called here.
 3. Java_* exports ← statically-registered native methods
 4. Dynamically registered natives ← recover via RegisterNatives hook / jnitrace
```

```bash
$ readelf -h libnative.so                     # arch, type
$ readelf -d libnative.so | head -20          # NEEDED libs, SONAME
$ readelf -S libnative.so                     # sections + sizes (entropy candidates)
$ nm -D libnative.so | grep -E 'JNI_OnLoad|Java_'
$ objdump -s -j .init_array libnative.so      # constructor pointers
$ strings -n 8 libnative.so | grep -Ei 'http|/api/|frida|ptrace|/proc/self'
```

### Ghidra workflow

1. Import the `.so`, choose the correct ARM/AArch64 language.
2. Auto-analyse.
3. Navigate to `JNI_OnLoad` via the Symbol Tree.
4. Apply the **JNI type library** so `JNIEnv*` calls become readable
   (`env->FindClass(...)` instead of `(*(code **)(*param_1 + 24))(...)`). This single step
   transforms readability.
5. Look for `RegisterNatives` - its arguments are an array of
   `{name, signature, fnPtr}`, which hands you the Java↔native mapping.

> **⚙️ Engineering Note:** Without the JNI type library applied, Ghidra's decompilation of
> JNI code is nearly unreadable offset arithmetic. With it, it reads like C. If you take one
> practical tip from this section, take that one - it is the difference between an hour and a
> day.

### Recovering `RegisterNatives` dynamically

Static recovery is fiddly. Use **`jnitrace`**:

```bash
$ pip install jnitrace
$ jnitrace -m libnative.so -l libnative.so com.suspect.app
```

It traces every JNI API call, including `RegisterNatives`, giving you the mapping and the
argument values without reversing the registration code.

---

## 11. Anti-analysis and how it fails

| Technique | Implementation | Countermeasure |
|---|---|---|
| **Root detection** | `su` binary paths, Magisk packages, `ro.debuggable` | Hook the check; Magisk DenyList |
| **Emulator detection** | `ro.product.model`, `Build.FINGERPRINT`, sensor absence, `/dev/qemu_pipe` | **Use real devices** |
| **Debugger detection** | `android:debuggable`, `Debug.isDebuggerConnected()`, `TracerPid` in `/proc/self/status` | Hook; patch `TracerPid` |
| **Frida detection** | Port 27042 scan, `frida-server` in process list, `/proc/self/maps` string scan, named pipes | Rename `frida-server`, non-default port, `frida-gadget` |
| **`ptrace` self-attach** | Process ptraces itself so a debugger can't | Hook `ptrace` |
| **Integrity self-check** | Verifies its own signature / DEX CRC | Hook the check ([Ch 07](../security/07-apk-signing.md)) |
| **Time checks** | Detects slow execution under instrumentation | Hook time APIs |
| **Geofencing** | Skips execution outside target countries; **ERMAC excludes CIS nations** | Spoof locale/SIM/IP |
| **C2 gating** | No payload unless C2 responds | **Flag as inconclusive** - never "clean" |

### The two structural weaknesses of all anti-analysis

1. **Every check is code you can find and neutralise.** It runs in a process you control on a
   device you own. It can be hooked, patched, or removed.
2. **Detection logic is itself a fingerprint.** An app that checks for `frida-server`, scans
   `/proc/self/maps`, and enumerates Magisk packages has told you a great deal about its
   intent - and that *combination* is far rarer in benign apps than any single check.

> **🚨 Misconception:** "Anti-analysis present → malware." Every serious banking app ships
> RASP with exactly these checks. Root detection, emulator detection, and anti-Frida are
> *industry-standard hardening*. The signal is the combination with a malicious capability
> cluster and an unknown signer - never the anti-analysis alone.
> → [Ch 32](../appendix/32-common-misconceptions.md)

---

## 12. The RE workflow, end to end

```
        ┌────────────────────────────────────────────┐
        │  Sample arrives (escalated from triage)    │
        └────────────────────┬───────────────────────┘
                             ▼
        ┌────────────────────────────────────────────┐
        │ 1. IDENTITY                                │
        │    sha256 · apksigner --print-certs        │  → Ch 06/07
        │    check TI DB for known signer/family     │
        └────────────────────┬───────────────────────┘
                             ▼
        ┌────────────────────────────────────────────┐
        │ 2. FAST SURFACE  (apktool -s, ~5s)         │
        │    manifest · a11y config · locales        │  → Ch 02
        │    resource strings · assets · lib listing │
        └────────────────────┬───────────────────────┘
                             ▼
                  ┌──────────────────────┐
                  │ Packed? (fingerprint,│
                  │  dex/so ratio)       │
                  └───┬──────────────┬───┘
                    yes             no
                     │               │
                     ▼               │
        ┌────────────────────────┐   │
        │ 3. UNPACK  (§9 ladder) │   │
        │   dump → recurse       │   │
        └────────────┬───────────┘   │
                     └───────┬───────┘
                             ▼
        ┌────────────────────────────────────────────┐
        │ 4. DECOMPILE  (jadx-gui)                   │
        │    entry points: a11y service, receivers,  │
        │    Application.onCreate, exported comps    │
        └────────────────────┬───────────────────────┘
                             ▼
        ┌────────────────────────────────────────────┐
        │ 5. TRACE THE QUESTIONS                     │
        │    • where is the C2 URL built?            │
        │    • what triggers the payload?            │
        │    • what is the target list?              │
        │    • how are strings decrypted?            │
        └────────────────────┬───────────────────────┘
                             ▼
                  ┌──────────────────────┐
                  │ Strings encrypted /  │
                  │ logic native?        │
                  └───┬──────────────┬───┘
                    yes             no
                     │               │
                     ▼               │
        ┌────────────────────────┐   │
        │ 6a. NATIVE RE (Ghidra) │   │
        │ 6b. GO DYNAMIC → Ch 12 │   │
        │     Cipher hooks,      │   │
        │     heap dump          │   │
        └────────────┬───────────┘   │
                     └───────┬───────┘
                             ▼
        ┌────────────────────────────────────────────┐
        │ 7. OUTPUTS                                 │
        │    IOCs (C2, keys, targets)   → Ch 26      │
        │    YARA rule                  → Ch 11      │
        │    MITRE technique mapping    → Ch 16      │
        │    family attribution         → Ch 28      │
        │    written findings           → Ch 29      │
        └────────────────────────────────────────────┘
```

> **⚙️ Engineering Note - always produce artifacts.** An RE session that ends with
> understanding but no YARA rule, no IOCs, and no MITRE mapping has produced knowledge that
> dies with the analyst. **Every RE session must emit machine-consumable output** that feeds
> the platform. That requirement is what makes a team's analysis capability compound over
> time instead of resetting with each sample.

---

## 13. Detection logic for SUDARSHAN

### Signals this chapter contributes

| Signal | Extraction | Weight | Notes |
|---|---|---|---|
| **Packer fingerprint** | Library filename match | Medium | Legit and malicious both use these |
| **Native/DEX size ratio** | ZIP entry sizes | Medium | Structural packer indicator |
| **`apktool` failure + fallback success** | Parser divergence | Medium | Deliberate malformation → [Ch 08](../apk/08-apk-file-format.md) |
| **String-encryption density** | Ratio of `const-string` to code size | Low-Medium | Very low literal density in a large app is odd |
| **Reflection density** | `Method.invoke` xrefs / method count | Low-Medium | Contextual |
| **Reflection into `ServiceManager`** | Androguard xref | **High** | Hidden-API bypass intent |
| **Anti-Frida / anti-debug strings** | `strings` on `.so` + smali | Low alone | **High** combined with malicious cluster |
| **Empty Java methods + large `.so`** | Method body analysis | Medium | Logic pushed native |
| **Call-graph coverage** | Resolved vs unresolved edges | - | **Report as analysis-quality metadata** |

### The analysis-quality contract

```yaml
# Every static result MUST carry this. Non-negotiable.
analysis_quality:
  decompilation_successful: bool
  decompiler_errors: int
  packed: bool
  unpacked_successfully: bool | null
  dumped_child_artifacts: [sha256, ...]
  call_graph_coverage: float        # 0.0-1.0, resolved edges
  reflection_edges_unresolved: int
  native_code_ratio: float
  confidence_ceiling: float         # ← caps the risk score
```

> **⚙️ Engineering Note - the confidence ceiling.** If a sample is packed and unpacking
> failed, **the static analysis cannot produce a high-confidence clean verdict, ever.** The
> pipeline must enforce this structurally: `confidence ≤ ceiling` where the ceiling is set by
> analysis quality. A platform that reports "low risk" on a sample it could not actually read
> is worse than one that reports "unable to assess" - because a bank will act on the first.
> → [Ch 27](../sudarshan/27-risk-scoring.md)

### What to automate vs. what to leave to humans

| Automate | Leave to humans |
|---|---|
| Packer fingerprinting | Understanding novel C2 protocols |
| Class-loader dumping + recursion | Attributing a new family |
| API xref extraction | Reconstructing custom crypto |
| String/URL/IOC extraction | Judging intent in ambiguous cases |
| YARA candidate generation | Validating and tuning YARA rules |
| MITRE mapping from known API patterns | Mapping novel techniques |

---

## 14. Limitations, edge cases, false positives

### Limitations

- **RE does not scale.** Hours per sample. It is the apex tier, not the pipeline.
- **Decompilers lie.** jadx can emit plausible-but-wrong Java on obfuscated input.
- **Call graphs miss reflection and native calls.**
- **Unpacking can fail**, and the honest response is a capped confidence, not a guess.

### False positives

| Trigger | Innocent cause |
|---|---|
| Heavy obfuscation | R8 default; every commercial app |
| Commercial packer | Banks, games, DRM - same products |
| Anti-debug / anti-Frida / root detection | **Standard banking-app RASP** |
| Native-heavy code | Games, ML, codecs, DRM |
| Reflection | Gson, Retrofit, Dagger, Room, AndroidX compat |
| String encryption | Fintech apps protecting API keys |

### False negatives

- Payload not present in the sample (dropper → [Ch 09](../apk/09-package-manager.md)).
- Logic entirely native and heavily obfuscated.
- Behaviour gated on C2, geography, or time.
- Successfully packed and un-unpackable within the time budget.

### Edge cases

| Case | Handling |
|---|---|
| Multidex | Decompile all `classes*.dex`; jadx handles this, home-grown scripts often don't |
| Split APKs | Merge or analyse together - a split may hold the interesting code |
| Kotlin | `kotlin/` metadata, `Intrinsics` null-checks everywhere; coroutines produce state machines that look obfuscated but aren't |
| React Native | Logic is in `assets/index.android.bundle` (JS), **not** in DEX - a very common miss |
| Flutter | Logic in `libapp.so` as compiled Dart; needs specialised tooling (`reFlutter`) |
| Cordova/WebView apps | Logic in `assets/www/` HTML/JS |

> **⚙️ Engineering Note:** The cross-platform frameworks are a **recurring blind spot**. An
> analyst who decompiles the DEX of a React Native app finds only framework glue and concludes
> "nothing here." The actual application logic is a JavaScript bundle in `assets/`. Always
> check for `index.android.bundle`, `libapp.so` (Flutter), and `assets/www/` before concluding
> a sample is empty.

---

## 15. Engineering tips

1. **`apktool d -s` first.** Capability profile in seconds before committing to decompilation.
2. **Start from a question**, not from `MainActivity`.
3. **Use "Find usage" (`X`) constantly** - backwards navigation beats forwards reading.
4. **Rename as you understand, and save the jadx project.**
5. **When Java looks impossible, read the smali.** Smali is ground truth.
6. **`grep const-string` for unencrypted secrets.** Empty result = strings are encrypted = go
   dynamic.
7. **Check for React Native / Flutter / Cordova** before declaring a DEX empty.
8. **Apply Ghidra's JNI type library.** Single biggest native-RE quality-of-life win.
9. **Use `jnitrace`** rather than reversing `RegisterNatives` by hand.
10. **Every dumped DEX gets recursed** through the full pipeline.
11. **Always emit YARA + IOCs + MITRE mapping.** Knowledge that isn't encoded is knowledge lost.
12. **Record analysis quality and cap confidence accordingly.**

---

## 16. Judge Insights

**What judges ask:** *"If the malware is packed and obfuscated, how do you analyse it at all?"*

**Perfect answer:** Packing has one unavoidable weakness: the runtime has to see plaintext
bytecode in order to execute it. So we don't try to decrypt the packer statically - we hook
the class loaders and dump the DEX at the moment ART materialises it, then feed that dumped
payload back through the full static pipeline as a linked child artifact. If the packer loads
natively and never touches a Java class loader, we scan process memory for DEX magic and carve
it out. If both fail, we reverse the unpacker in Ghidra starting at `JNI_OnLoad`. And
critically - if none of that works, we don't guess. The sample carries an analysis-quality
record with a **confidence ceiling**, so the platform structurally cannot report "low risk" on
something it couldn't read. For a bank, "unable to assess, escalate" is a far safer output than
a confident wrong answer.

**Common mistakes:**
- "We use AI to deobfuscate." Judges will ask how. The class-loader-dump answer is concrete
  and demonstrably works.
- Treating obfuscation as a malicious indicator. Every Play Store app is obfuscated; so is
  every bank's app.
- Claiming 100% unpacking success. Nobody has that.

**Follow-ups to expect:**
- *"What if it detects Frida?"* → Rename the server, non-default port, or use frida-gadget.
  And the detection logic itself is a fingerprint - an app checking for Frida, scanning
  `/proc/self/maps`, and enumerating Magisk packages has told us a lot about its intent.
- *"Isn't the bank's own app also packed and obfuscated?"* → Yes, and that's exactly why we
  never score obfuscation as malicious. We discriminate on signer identity first, capability
  cluster second, runtime behaviour third.
- *"How long does this take?"* → Automated stages are seconds to minutes; human RE is hours.
  Which is why the pipeline's job is to make sure only samples that deserve a human get one.

**Fact that impresses:** Klopatra - documented by Cleafy in August 2025 - uses **Virbox**, a
commercial software protector, and migrated its logic from Java to native code. That's a
banking trojan adopting the same enterprise-grade protection that banks buy to defend their
own apps. The tooling is symmetrical; only intent differs, which is precisely why detection
has to rest on signer and behaviour rather than on protection technology.

---

## 17. Interview Insights

**Q: "Walk me through reverse engineering an Android app."**
Identity first (hash, signer cert), then fast surface via `apktool -s` (manifest, a11y config,
resources), check for packing, unpack if needed, then jadx for logic, tracing from entry points
backwards using find-usage. Emphasise **starting from a question**, and switching to dynamic
when strings are encrypted.

**Q: "What's smali?"**
Human-readable assembly for Dalvik bytecode. Register-based (`v` locals, `p` params, `p0` is
`this`), with type descriptors like `Ljava/lang/String;`. You read it when the decompiler's
Java output is wrong or absent - smali is faithful to the bytecode, Java is an interpretation.

**Q: "How do you handle an obfuscated app?"**
First: obfuscation is normal - R8 is on by default and every bank app is obfuscated, so it's
not a signal by itself. Structure survives obfuscation even when names don't: call graphs,
string constants, API calls, control flow. Use jadx `--deobf`, rename as you go, and navigate
by API usage rather than by class names.

**Q: "How would you unpack a packed APK?"**
The principle: the runtime must see plaintext DEX to run it. Hook class loaders with Frida and
dump; failing that, memory-scan for DEX magic and carve; failing that, extract from `.vdex`;
failing that, reverse the native unpacker starting at `JNI_OnLoad` - and check `.init_array`
first, because constructors run before it.

**Q: "You decompile an app and the methods are empty. What's happening?"**
Either native implementation (check `lib/`, look for `System.loadLibrary` and `JNI_OnLoad`), or
a packer stub, or it's a cross-platform app - React Native logic lives in
`assets/index.android.bundle`, Flutter in `libapp.so`. Mentioning the cross-platform case
unprompted is a strong signal of practical experience.

**Q: "Difference between apktool and jadx?"**
apktool decodes resources and produces smali, and can **rebuild** - it's for resources and
repackaging. jadx decompiles DEX to Java and cannot rebuild - it's for reading logic. You use
both, for different jobs.

**Beginner mistakes:**
- Treating obfuscation or anti-debug as proof of malice.
- Reading decompiled Java top to bottom instead of navigating by API usage.
- Trusting jadx output when it looks impossible.
- Not recursing on dumped payloads.
- Missing React Native / Flutter bundles.
- Analysing only `classes.dex`.

---

## 18. Cross-references

**Upstream:**
- [← Ch 02 APK Architecture](../apk/02-apk-architecture.md) - what you're pulling apart
- [← Ch 03 Android Runtime](../android/03-android-runtime.md) - class loaders, reflection, JNI
- [← Ch 08 APK File Format](../apk/08-apk-file-format.md) - DEX/ELF structure, format anomalies

**Downstream:**
- [→ Ch 11 Static Analysis](../static-analysis/11-static-analysis.md) - automating what's manual here
- [→ Ch 12 Dynamic Analysis](../dynamic-analysis/12-dynamic-analysis.md) - where RE hands off when static stalls
- [→ Ch 13 Android Malware](../malware/13-android-malware.md) - the techniques you'll find
- [→ Ch 26 IOC Extraction](../sudarshan/26-ioc-extraction.md) - RE outputs as indicators
- [→ Ch 27 Risk Scoring](../sudarshan/27-risk-scoring.md) - the confidence ceiling
- [→ Ch 28 Campaign Correlation](../sudarshan/28-campaign-correlation.md) - code similarity

**Related chain:** Packer → class-loader hook → DEX dump → recursive static analysis →
capability profile → YARA rule → family attribution.

---

## 19. References

1. `jadx` - Dex to Java decompiler. https://github.com/skylot/jadx
2. `Apktool` - reverse engineering tool for Android apps. https://apktool.org/
3. Androguard documentation. https://androguard.readthedocs.io/
4. `smali`/`baksmali` - assembler/disassembler for DEX. https://github.com/google/smali
5. AOSP - *Dalvik bytecode reference*. https://source.android.com/docs/core/runtime/dalvik-bytecode
6. AOSP - *Dalvik Executable format*. https://source.android.com/docs/core/runtime/dex-format
7. NSA - Ghidra software reverse engineering framework. https://ghidra-sre.org/
8. `jnitrace` - JNI API tracing for Android. https://github.com/chame1eon/jnitrace
9. Frida documentation - JavaScript API. https://frida.re/docs/javascript-api/
10. Guardsquare - ProGuard and DexGuard documentation (obfuscation and RASP techniques).
11. Cleafy Labs - *Klopatra* (August 2025) - Virbox protector, Java→native migration.
12. Cyble Research and Intelligence Labs - GodFather variant analysis - native-code migration.
13. ThreatFabric - ERMAC analyses - CIS-nation exclusion / geofencing behaviour.
14. OWASP MASTG - reverse engineering and tampering test cases (MASVS-RESILIENCE). https://mas.owasp.org/MASTG/
15. `reFlutter` - Flutter application reverse engineering framework.

### Further reading
- *Android Internals: A Confectioner's Cookbook*, Jonathan Levin
- *The Ghidra Book*, Chris Eagle & Kara Nance
- Google Cloud / Mandiant - *Delving into Dalvik* (DEX string-index manipulation)

---

*Previous: [← Ch 09 Package Manager](../apk/09-package-manager.md) · Next: [Ch 11 Static Analysis →](../static-analysis/11-static-analysis.md)*
