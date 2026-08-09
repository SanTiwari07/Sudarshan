# 33 - Cheat Sheets

> **Chapter ID:** `CH33` · **Block:** F (Reference) · **Status:** Stable
> **Tags:** `#cheatsheet` `#commands` `#reference` `#quickref` `#workflows`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0

> **Purpose.** Everything operationally useful from Blocks A–E, compressed. Print §2, §3, and §12.

---

## Table of Contents

1. [10-minute triage](#1-10-minute-triage)
2. [adb command reference](#2-adb-command-reference)
3. [Device triage - the high-value trio](#3-device-triage--the-high-value-trio)
4. [Analysis toolchain](#4-analysis-toolchain)
5. [Frida hook library](#5-frida-hook-library)
6. [Android version gates](#6-android-version-gates)
7. [APK signing schemes](#7-apk-signing-schemes)
8. [The capability cluster](#8-the-capability-cluster)
9. [MITRE ATT&CK Mobile quick map](#9-mitre-attck-mobile-quick-map)
10. [Malware family quick reference](#10-malware-family-quick-reference)
11. [Pivot and IOC durability](#11-pivot-and-ioc-durability)
12. [Incident response runbook](#12-incident-response-runbook)
13. [Install failure codes](#13-install-failure-codes)
14. [Key file paths](#14-key-file-paths)
15. [Numbers worth memorising](#15-numbers-worth-memorising)

---

## 1. 10-minute triage

```
 1. HASH            sha256sum app.apk
 2. SIGNER      ★   apksigner verify --verbose --print-certs app.apk
                    → in canonical registry for its package name?  → Ch 06
 3. MANIFEST        apktool d -s app.apk -o w/   (-s = skip smali, 10-50× faster)
                    aapt2 dump badging app.apk
 4. A11Y CONFIG ★   cat w/res/xml/*accessib*
                    canRetrieveWindowContent? canPerformGestures? packageNames empty?
 5. CLUSTER         grep -E 'uses-permission|foregroundServiceType' w/AndroidManifest.xml
 6. TARGETS     ★   grep -rEoh '\bcom\.[a-z0-9_]+(\.[a-z0-9_]+)+' w/res/ | sort -u
                    → is a client bank package in the list?
 7. ASSETS/LIB      unzip -l app.apk | grep -E 'assets/|\.so$'
 8. STRINGS         grep -rEoh 'https?://[^"<[:space:]]+' w/res/ w/assets/ | sort -u
 9. TI              signer + hash lookup
10. DECIDE          deep static (Ch 11) / detonate (Ch 12) / close
```

---

## 2. adb command reference

### Packages
```bash
adb shell pm list packages -f -i -3          # ★ path + INSTALLER, third-party only
adb shell pm path com.suspect                # ★ ALL splits - pull every one
adb shell dumpsys package com.suspect        # perms, signer, install times
adb shell pm uninstall --user 0 com.suspect
adb shell pm install --bypass-low-target-sdk-block old.apk   # A14+ legacy
```

### The security-state trio
```bash
adb shell settings get secure enabled_accessibility_services   # ★★★
adb shell settings get secure enabled_notification_listeners   # ★★
adb shell cmd appops get com.suspect SYSTEM_ALERT_WINDOW       # ★
```

### System state
```bash
adb shell dumpsys accessibility
adb shell dumpsys device_policy              # device admins
adb shell dumpsys window | grep -i overlay
adb shell dumpsys usagestats                 # ★ which apps ran, when
adb shell dumpsys notification
adb shell cmd appops get --all
adb shell dumpsys activity activities | grep mResumedActivity
```

### Processes & logs
```bash
adb shell ps -A | grep com.suspect           # ★ catch :subprocesses
adb logcat -d -b all > logcat.txt
adb logcat | grep -i "avc: denied"           # SELinux denials
adb logcat | grep "Accessing hidden"         # ★ non-SDK bypass attempts
```

### Acquisition
```bash
adb bugreport bugreport_$(date -u +%Y%m%dT%H%M%SZ).zip
adb shell am dumpheap com.suspect /data/local/tmp/h.hprof && adb pull /data/local/tmp/h.hprof
hprof-conv h.hprof h-std.hprof
adb shell pm path com.suspect | sed 's/package://' | while read p; do adb pull "$p"; done
```

### Dexopt
```bash
adb shell cmd package compile -m speed -f com.suspect
adb shell cmd package compile --reset com.suspect        # if Frida hooks won't fire
```

---

## 3. Device triage - the high-value trio

> **The three commands that answer most Android banking-fraud triage questions.**

```bash
# 1. Which accessibility services are enabled?   ← THE signal
adb shell settings get secure enabled_accessibility_services

# 2. Which apps read notifications?              ← OTP theft path
adb shell settings get secure enabled_notification_listeners

# 3. Who installed what?                         ← dropper attribution
adb shell pm list packages -f -i -3
```

**The join that is the detection:**

```
   non-store installer  +  accessibility enabled  =  the current playbook
```

---

## 4. Analysis toolchain

| Task | Command |
|---|---|
| Resources + manifest only (fast) | `apktool d -s app.apk -o w/` |
| Full decode incl. smali | `apktool d app.apk -o w/` |
| Rebuild (lab) | `apktool b w/ -o out.apk` |
| Decompile to Java | `jadx -d out/ app.apk` · `jadx-gui app.apk` |
| Keep going on errors | `jadx --show-bad-code --deobf -d out/ app.apk` |
| Manifest tree | `aapt2 dump xmltree app.apk --file AndroidManifest.xml` |
| Badging summary | `aapt2 dump badging app.apk` |
| Resource strings | `aapt2 dump strings app.apk` |
| **Locale set (targeting)** | `aapt2 dump configurations app.apk` |
| Verify signature | `apksigner verify --verbose --print-certs app.apk` |
| Align (before signing!) | `zipalign -p -f 4 in.apk out.apk` |
| Sign | `apksigner sign --ks lab.keystore --out signed.apk aligned.apk` |
| Find signing block | `grep -abo "APK Sig Block 42" app.apk` |
| **Janus check** | `xxd -l 8 app.apk` → `dex.035.` = ☠️ |
| DEX header | `unzip -p app.apk classes.dex \| xxd -l 112` |
| Packer check | `unzip -l app.apk \| grep -Ei 'libjiagu\|libDexHelper\|libshell\|libsecexe\|virbox'` |
| Native symbols | `nm -D lib.so \| grep -E 'JNI_OnLoad\|Java_'` |
| YARA (extract first!) | `mkdir x && unzip -q app.apk -d x && yr scan -r rules.yar x/` |

### jadx-gui shortcuts
`Ctrl+Shift+F` search · `X` find usage · `N` rename · `Ctrl+Click` go to declaration ·
right-click → Show bytecode

### Search terms that find banking malware
```
AccessibilityService · onAccessibilityEvent · performGlobalAction · dispatchGesture
TYPE_APPLICATION_OVERLAY · WindowManager.addView · MediaProjection
SmsManager · createFromPdu · NotificationListenerService · onNotificationPosted
DevicePolicyManager · lockNow · wipeData · getInstalledPackages
DexClassLoader · InMemoryDexClassLoader · Class.forName · Method.invoke
Cipher.getInstance · SecretKeySpec · api.telegram.org · firebaseio.com
```

---

## 5. Frida hook library

```bash
frida-ps -U
frida -U -f com.suspect -l hooks.js --pause    # ★ SPAWN, never attach
objection -g com.suspect explore
jnitrace -m libnative.so com.suspect
```

### The five essential hooks

```javascript
Java.perform(function () {

  // 1 ★ CLASS LOADERS - dumps packers AND droppers. Hook BOTH overloads.
  const IM = Java.use('dalvik.system.InMemoryDexClassLoader');
  IM.$init.overload('java.nio.ByteBuffer','java.lang.ClassLoader')
    .implementation = function(b,p){ console.log('[DEX] '+b.remaining()); return this.$init(b,p); };
  IM.$init.overload('[Ljava.nio.ByteBuffer;','java.lang.ClassLoader')
    .implementation = function(bs,p){ console.log('[DEX] array '+bs.length); return this.$init(bs,p); };
  const DCL = Java.use('dalvik.system.DexClassLoader');
  DCL.$init.overload('java.lang.String','java.lang.String','java.lang.String','java.lang.ClassLoader')
    .implementation = function(a,b,c,d){ console.log('[DEX] '+a); return this.$init(a,b,c,d); };

  // 2 CRYPTO - recovers C2 URLs and keys
  const C = Java.use('javax.crypto.Cipher');
  C.doFinal.overload('[B').implementation = function(i){
    const o = this.doFinal(i);
    console.log('[crypto] '+this.getAlgorithm());
    try { console.log('  '+Java.use('java.lang.String').$new(o)); } catch(e){}
    return o; };
  const K = Java.use('javax.crypto.spec.SecretKeySpec');
  K.$init.overload('[B','java.lang.String').implementation = function(k,a){
    console.log('[key] '+a); return this.$init(k,a); };

  // 3 REFLECTION - rebuilds the real call graph
  const M = Java.use('java.lang.reflect.Method');
  M.invoke.overload('java.lang.Object','[Ljava.lang.Object;').implementation = function(o,a){
    console.log('[refl] '+this.getDeclaringClass().getName()+'.'+this.getName());
    return this.invoke(o,a); };

  // 4 NETWORK - endpoints regardless of TLS
  const U = Java.use('java.net.URL');
  U.$init.overload('java.lang.String').implementation = function(s){
    console.log('[net] '+s); return this.$init(s); };

  // 5 ★ OVERLAY - type 2038 over another app = the attack, observed
  const W = Java.use('android.view.WindowManagerImpl');
  W.addView.implementation = function(v,p){
    console.log('[OVERLAY] type='+p.type.value); return this.addView(v,p); };
});
```

**Hook not firing? Check in this order:** inlining → wrong overload → different process →
different class loader → Frida detected.

---

## 6. Android version gates

| Android | API | Security change |
|---|---|---|
| 6.0 | 23 | Runtime permissions |
| 7.0 | 24 | v2 signing; **user CAs untrusted by default** |
| 8.0 | 26 | Background limits; `InMemoryDexClassLoader`; per-app unknown sources |
| 9 | 28 | v3 signing (rotation); non-SDK restrictions; StrongBox |
| 10 | 29 | Scoped storage; `sharedUserId` deprecated |
| 11 | 30 | v4 signing; **v1-only install blocked**; uncompressed `resources.arsc` |
| 12 | 31 | Explicit `android:exported`; ART Mainline; overlay-obscured touches blocked |
| 13 | 33 | **Restricted Settings**; `POST_NOTIFICATIONS` |
| 14 | 34 | **Min targetSdk API 23** (`INSTALL_FAILED_DEPRECATED_SDK_VERSION`); FGS types mandatory; world-writable DCL blocked |
| 15 | 35 | **Min targetSdk API 24**; a11y/notif-listener denied unless installed via **session API** |
| 16 | 36 | targetSdk floor **not** raised beyond 24 |

---

## 7. APK signing schemes

| Scheme | Android | Covers | Stored | Block ID |
|---|---|---|---|---|
| v1 (JAR) | all | ZIP **entries** | `META-INF/` | - |
| **v2** | 7.0 (24) | **whole file** | Signing Block | `0x7109871a` |
| **v3** | 9 (28) | whole file + **rotation lineage** | Signing Block | `0xf05368c0` |
| v3.1 | 13 era | SDK-targeted rotation | Signing Block | `0x1b93ad61` |
| v4 | 11 (30) | Merkle tree | **`.apk.idsig`** | - |

**Rules:** v1-only rejected from API 30 · v4 requires v2/v3 alongside · higher scheme wins, v1 not
checked if v2+ verifies · **align before signing**.

**The three classic attacks:**

| Attack | Trick | Fixed by |
|---|---|---|
| **Master Key** (2013) | Duplicate ZIP filenames - verifier and installer read different files | v2 |
| **Fake ID** (2014) | Certificate chain claim not cryptographically validated | Chain validation fix |
| **Janus** (CVE-2017-13156) | File is a valid ZIP *and* a valid DEX - prepend DEX, v1 signature still valid. Android 5.0–8.0, **v1-only**, patched Dec 2017 | **v2 (whole-file digest)** |

---

## 8. The capability cluster

```
  CORE (need ≥1)
   └─ Accessibility service WITH canRetrieveWindowContent OR canPerformGestures

  SUPPORTING (need ≥2)
   ├─ SYSTEM_ALERT_WINDOW            (overlay phishing)
   ├─ REQUEST_INSTALL_PACKAGES       (dropper)
   ├─ RECEIVE_SMS / READ_SMS         (OTP)
   ├─ NotificationListenerService    (OTP without SMS perm)  ★ weight = SMS
   ├─ foregroundServiceType=mediaProjection  (VNC/screen capture)
   ├─ BIND_DEVICE_ADMIN              (anti-uninstall/wipe)
   └─ QUERY_ALL_PACKAGES             (target discovery)

  ★ No cluster → severity capped at MEDIUM, however scary a single signal looks.
```

### a11y config decoder
```xml
canRetrieveWindowContent="true"   → READ every app's screen
canPerformGestures="true"         → WRITE input to every app
accessibilityEventTypes="typeAllMask" → every event
packageNames=""                   → unscoped: targets everything
```
**READ + WRITE over all UI = remote control inside the user's own session.**

---

## 9. MITRE ATT&CK Mobile quick map

| Technique | ID |
|---|---|
| **Abuse Accessibility Features** | **T1453** |
| Input Capture: Keylogging | T1417.001 |
| Input Capture: GUI Input Capture | T1417.002 |
| Input Injection | T1516 |
| Screen Capture | T1513 |
| Access Notifications | T1517 |
| Protected User Data: SMS | T1636.004 |
| Adversary-in-the-Middle | T1638 |
| Device Administrator Permissions | T1626.001 |
| **Prevent Application Removal** | **T1629.001** |
| Event Triggered Execution | T1624 |
| Download New Code at Runtime | T1407 |
| Obfuscated Files or Information | T1406 |
| Software Discovery | T1418 |
| User Evasion | T1618 |
| Foreground Persistence | T1541 |

*Pin your ATT&CK version - IDs get revised.*

---

## 10. Malware family quick reference

### Lineage
```
 Exobot(2016) → Octo/Coper(2021) → Octo2(Sep 2024, DGA)   [Octo source leaked 2024]
 Cerberus(2019) ──leak Aug 2020──┬→ Alien(2020) → Xenomorph(2022)
                                  ├→ ERMAC(2021) → Hook(2023)   [ERMAC 3.0 leaked Aug 2025]
                                  └→ Phoenix
 LokiBot → MysteryBot → Parasite → Xerxes → BlackRock(2020)
 SpyNote/CypherRat ──public GitHub Oct 2022──→ forks, CraxsRat
 TgToxic(2023) → ToxicPanda(Oct 2024)
 B4A + MQTT shared by: BRATA · Copybara · DroidBot
 NO LINEAGE: BingoMod(2024) · Crocodilus(2025) · Klopatra(2025)
```

### Fingerprints
| Family | Artifact | Vendor / date |
|---|---|---|
| Anatsa | 831 institutions; direct payload install (not DEX loading) | Zscaler, Aug 2025 |
| Chameleon | `is_chameleon` prefs; Discord CDN; **biometric→PIN downgrade** | Cyble / ThreatFabric Dec 2023 |
| ToxicPanda | `dksu[.]top`, `mixcom[.]one`; **AES-ECB** | Cleafy, Oct 2024 |
| Klopatra | `adsservices.uk`, `adsservice2.org`; **Virbox**; Java→native | Cleafy, Aug 2025 |
| Antidot | `46[.]228.205.159:5055`; socket.io | Cyble, May 2024 |
| ERMAC | `141.164.62[.]236`; AES-CBC; excludes CIS | Hunt.io, Aug 2025 |
| Crocodilus | cmd `TRU9MMRHBCRO` (fake "Bank Support" contact); seed-phrase parser | ThreatFabric, Mar 2025 |
| SpyNote | decoy pkg `yps.eton.application` | ThreatFabric, Jan 2023 |
| Octo2 | DGA-generated C2; Zombinder first stage | ThreatFabric, Sep 2024 |
| BingoMod | 40 socket commands; €15,000 transfers; **wipes device** | Cleafy, Jul 2024 |
| Vultur | first VNC-instead-of-overlay banker | ThreatFabric 2021 / NCC Mar 2024 |

**⚠ "Medusa" collision:** Android banker (Cleafy) ≠ ransomware gang ≠ Mirai-based DDoS botnet.
Always qualify.

---

## 11. Pivot and IOC durability

```
 DURABLE ◄──────────────────────────────────────────────► VOLATILE

 signer   v3 lineage   hardcoded  DEX TLSH  protocol  TLS   domain  IP   hash
 cert                  key                            cert
   │          │           │          │         │       │      │      │     │
 never     never       365d       180d      180d    180d    90d   14d   30d
   │          │           │          │         │       │      │      │     │
 BLOCK     BLOCK       BLOCK      review    review  review review  ✗    dedup
```

**Rule: match pivot precision to action cost.** Signer match → automated session hold.
TLSH match → review only. IP match → nothing on its own (shared hosting).

**Also track:** `sinkholed` (inverts meaning), `shared_hosting` (suppresses IP enforcement).

---

## 12. Incident response runbook

```
╔════════════════════════════════════════════════════════════════════╗
║ 0. DO NOT power off.  DO NOT uninstall yet.                        ║
║    Power off → AFU→BFU, CE data inaccessible.                      ║
║    Uninstall → BRATA/BingoMod may WIPE.                            ║
╠════════════════════════════════════════════════════════════════════╣
║ 1. ISOLATE     airplane mode / Faraday bag                         ║
╠════════════════════════════════════════════════════════════════════╣
║ 2. CONTAIN (parallel, account-side, minutes - medium confidence OK)║
║    session hold · block pending txns · freeze beneficiary          ║
║    ★ SWEEP customer base by SIGNER                                 ║
╠════════════════════════════════════════════════════════════════════╣
║ 3. ACQUIRE     the trio + dumpsys + appops + bugreport + APKs      ║
║                hash everything                                     ║
╠════════════════════════════════════════════════════════════════════╣
║ 4. ANALYSE     submit to SUDARSHAN                                 ║
╠════════════════════════════════════════════════════════════════════╣
║ 5. REMEDIATE   ★ SAFE MODE (kills 3rd-party apps + their a11y)     ║
║                → revoke device admin → uninstall → verify          ║
╠════════════════════════════════════════════════════════════════════╣
║ 6. ERADICATE   credential reset - ONLY AFTER the device is clean   ║
║                (else the attacker reads the new credentials)       ║
╠════════════════════════════════════════════════════════════════════╣
║ 7. RECOVER     graduated limits · 30-90d monitoring · fund recovery║
╠════════════════════════════════════════════════════════════════════╣
║ 8. POST        new rule · retro-hunt · CERT-In 6h clock assessment ║
╚════════════════════════════════════════════════════════════════════╝
```

### What fails / holds under ODF
| ❌ Fails | ✅ Holds |
|---|---|
| Device fingerprinting | Per-transaction biometric (Keystore + `setUserAuthenticationRequired`) |
| Geolocation / IP | `FLAG_SECURE` on sensitive screens |
| Play Integrity / attestation | Overlay + a11y detection from within the bank app |
| SMS OTP · authenticator app · push approval | Treating biometric→PIN downgrade as a risk signal |
| Certificate pinning | |

---

## 13. Install failure codes

| Code | Meaning |
|---|---|
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | **Signer mismatch** - repackaged clone |
| `INSTALL_FAILED_DEPRECATED_SDK_VERSION` | targetSdk below floor (A14: <23, A15: <24) |
| `INSTALL_PARSE_FAILED_NO_CERTIFICATES` | Unsigned / broken signature |
| `INSTALL_PARSE_FAILED_RESOURCES_ARSC_COMPRESSED` | Pre-A11 build on A11+ |
| `INSTALL_FAILED_VERSION_DOWNGRADE` | Lower versionCode |
| `INSTALL_FAILED_INVALID_APK` | Structural failure |
| `INSTALL_FAILED_TEST_ONLY` | `testOnly=true` → use `pm install -t` |

---

## 14. Key file paths

### On device
```
/data/system/packages.xml        ★ installer · install times · SIGNER CERT · granted perms
/data/system/packages-backup.xml   prior state
/data/system/packages.list         UID ↔ package
/data/system/appops.xml            special permission grants
/data/system/device_policies.xml   device admins
/data/system/users/0/settings_secure.xml  ★ enabled_accessibility_services
/data/system/usagestats/           ★ which apps ran, when
/data/data/<pkg>/                  app sandbox (databases/ shared_prefs/ files/)
/data/app/<pkg>-<rand>/base.apk    installed APK (+ splits)
/data/app/<pkg>-<rand>/oat/<isa>/  .odex .vdex .art   (vdex → recoverable DEX)
/data/misc/profiles/cur/0/<pkg>/primary.prof   methods actually executed
```

**★ SQLite: always pull `-wal` and `-shm` siblings, or you lose recent transactions.**

### Inside an APK
```
AndroidManifest.xml        binary AXML
classes*.dex               ★ GLOB - never just classes.dex
resources.arsc             uncompressed + aligned (required A11+)
res/xml/*accessib*         ★ the capability config
res/xml/network_security_config.xml
assets/                    ★ raw passthrough - payload hiding place
lib/<abi>/*.so             native; packer fingerprints
META-INF/*.{RSA,DSA,EC}    v1 signature (not always CERT.RSA)
[APK Signing Block]        ★ not a ZIP entry; magic "APK Sig Block 42"
```

---

## 15. Numbers worth memorising

| Figure | Source | Date |
|---|---|---|
| 34 families · **1,243 institutions** · 90 countries | Zimperium | Mar 19, 2026 |
| Android fraud transactions **+67% YoY** | Zimperium | Mar 19, 2026 |
| ~50% of families have extortion capability; **85% ATO** | Zimperium | Mar 19, 2026 |
| Anatsa: **831 financial institutions** | Zscaler ThreatLabz | Aug 2025 |
| Anatsa dropper reached **#4 Play Top Free Tools** | ThreatFabric | Jun 29, 2025 |
| Play Protect: **~200B apps scanned daily** | Google | 2024 review |
| **13M+ malicious apps found OUTSIDE Play** | Google | 2024 review |
| 2.36M policy-violating apps blocked; 158k dev accounts banned | Google | 2024 review |
| AI assisted **92%** of harmful-app human reviews | Google | 2024 review |
| India UPI fraud: **13.42 lakh cases / ₹1,087 crore**, **+85% YoY** | Lok Sabha | Nov 25, 2024 |
| India: **₹1,750+ crore** lost in 4 months | I4C | 2024 |
| Install-blocking pilots: 10M devices / 36M+ risky installs | Google | 2024 review |
| SafetyNet Attestation shut down | Google | **Jan 31, 2025** |
| ERMAC v2 rental | ESET | ~$5,000/month (May 2022) |
| BingoMod live-operator transfers | Cleafy | up to €15,000 |

### Pipeline reference numbers
```
 T0 ~10ms (100%) · T1 ~50ms (100%) · T2 ~500ms (100%)
 T3 ~10-120s (~20%) · T4 5-15min (~5%) · T5 hours (<1%)

 devices = (samples/day × 0.05 × 15min) / (1440 × 0.6)
 e.g. 10,000/day → ~9 devices + 2 reserved for the urgent lane
```

---

*Previous: [← Ch 32 Common Misconceptions](32-common-misconceptions.md) · Next: [Ch 34 Judge Preparation →](34-judge-preparation.md)*
