# 08 — APK File Format

> **Chapter ID:** `CH08` · **Block:** A (Foundations) · **Status:** Stable
> **Tags:** `#file-format` `#zip` `#axml` `#resources-arsc` `#dex` `#parser-differential` `#bytes`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0
> **Prerequisites:** [Ch 02](02-apk-architecture.md), [Ch 07](../security/07-apk-signing.md)

---

## Table of Contents

1. [Why go to the byte level](#1-why-go-to-the-byte-level)
2. [ZIP internals](#2-zip-internals)
3. [ZIP anomalies and parser differentials](#3-zip-anomalies-and-parser-differentials)
4. [Binary XML (AXML)](#4-binary-xml-axml)
5. [resources.arsc](#5-resourcesarsc)
6. [DEX format](#6-dex-format)
7. [The DEX name-resolution chain](#7-the-dex-name-resolution-chain)
8. [ELF and native libraries](#8-elf-and-native-libraries)
9. [Format-level anti-analysis](#9-format-level-anti-analysis)
10. [Detection logic for SUDARSHAN](#10-detection-logic-for-sudarshan)
11. [Limitations, edge cases, false positives](#11-limitations-edge-cases-false-positives)
12. [Engineering tips](#12-engineering-tips)
13. [Judge Insights](#13-judge-insights)
14. [Interview Insights](#14-interview-insights)
15. [Cross-references](#15-cross-references)
16. [References](#16-references)

---

## 1. Why go to the byte level

[Chapter 02](02-apk-architecture.md) told you what an APK *contains*. This chapter tells you
what it *is*, byte for byte. You need that for four reasons:

1. **Attacks live in format ambiguity.** Janus, Master Key, and every packer evasion trick in
   [Ch 07 §9](../security/07-apk-signing.md#9-the-three-classic-attacks) exploit two parsers
   disagreeing about the same bytes. You cannot detect that by reading decompiled Java.
2. **Tools lie by omission.** When `apktool` fails and the app still installs, the answer is
   in the bytes. Your tooling normalises; the adversary exploits what it normalised away.
3. **Detection at this layer is cheap and deterministic.** No ML, no heuristics — read eight
   bytes, get an answer. These are the highest-precision rules SUDARSHAN will ever ship.
4. **You will write parsers.** SUDARSHAN's intake stage is, fundamentally, a set of format
   parsers. Building them on wrong assumptions is how you get a platform that misses the
   samples that matter most.

> **⚙️ Engineering Note — the governing principle of this chapter:**
> **Record anomalies; do not normalise them away.** Every mature analysis pipeline eventually
> learns this the hard way. A tolerant parser that "helpfully" fixes a duplicate ZIP entry has
> just destroyed the single most important fact about the sample.

---

## 2. ZIP internals

### The layout

A ZIP is read **from the end**. This is the fact that makes Janus possible.

```
offset 0
┌────────────────────────────────────────────────────────────┐
│  Local File Header  (PK\x03\x04)                           │ ← entry 1
│    version, flags, compression method, CRC-32,             │
│    compressed size, uncompressed size,                     │
│    filename length, extra field length                     │
│    filename, extra field                                   │
│  ── file data (deflated or stored) ──                      │
├────────────────────────────────────────────────────────────┤
│  Local File Header  (PK\x03\x04)                           │ ← entry 2
│  ── file data ──                                           │
├────────────────────────────────────────────────────────────┤
│                          ...                               │
├────────────────────────────────────────────────────────────┤
│  ★ APK SIGNING BLOCK (v2/v3/v3.1)  → Ch 07 §4              │
│    ends with magic "APK Sig Block 42"                      │
├────────────────────────────────────────────────────────────┤
│  Central Directory  (PK\x01\x02) — one record per entry    │
│    filename, compression, CRC-32, sizes,                   │
│    ★ OFFSET OF LOCAL HEADER  ← the authoritative pointer   │
│    external attrs, comment                                 │
├────────────────────────────────────────────────────────────┤
│  End of Central Directory  (PK\x05\x06)                    │
│    number of entries, size of CD, ★ OFFSET OF CD,          │
│    comment length, comment                                 │
└────────────────────────────────────────────────────────────┘ ← parsing STARTS here
```

### The parse order

```
  1. Scan BACKWARD from EOF for the EOCD magic PK\x05\x06
  2. Read "offset of central directory" from the EOCD
  3. Walk the central directory records
  4. For each record, jump to its "offset of local header"
  5. Read the local header, then the file data
```

**Everything before the first local file header is never read.** That is not a bug — it is
how self-extracting archives work (an executable stub followed by a ZIP). It is also exactly
what Janus abuses.

### The fields that matter for security

| Field | Where | Why you care |
|---|---|---|
| **Compression method** | LFH + CD | `0` = stored (uncompressed), `8` = deflate. `classes.dex` and `resources.arsc` must be **stored** |
| **CRC-32** | LFH + CD | Appears twice; **mismatch between the two is an anomaly** |
| **Compressed / uncompressed size** | LFH + CD | Also duplicated; also a mismatch opportunity |
| **Offset of local header** | CD only | The authoritative pointer. Two CD records can point to the same or overlapping data |
| **Filename** | LFH + CD | Duplicated; **mismatch is the Master Key class of bug** |
| **General purpose bit flag** | LFH | Bit 3 = "sizes in data descriptor after data" — a parser-divergence surface |
| **Extra field** | LFH + CD | Alignment padding lives here; also a hiding place for data |
| **Archive comment** | EOCD | Arbitrary trailing bytes, unprotected by v1 |

> **⚙️ Engineering Note:** Nearly every ZIP field exists **twice** — once in the local file
> header and once in the central directory. The specification does not require them to agree,
> and different parsers trust different copies. **That redundancy is the root cause of an
> entire vulnerability class.** When you write a parser, read both and diff them.

### Inspecting raw ZIP structure

```bash
# Human-readable structure incl. compression method and alignment
$ zipdetails -v app.apk | head -60          # perl-zip-utils
$ unzip -lv app.apk                          # Method column: Stored vs Defl:N

# Is classes.dex stored (required) or deflated (anomalous)?
$ unzip -lv app.apk | grep -E 'classes.*\.dex|resources\.arsc'
  2841520  Stored  2841520   0% 1981-01-01 01:01 3f2a1b8c  classes.dex
   445120  Stored   445120   0% 1981-01-01 01:01 7c91e0d4  resources.arsc

# Where does the first local file header actually start?
$ grep -abo -m1 $'PK\x03\x04' app.apk | head -1
0:PK...                    # ← should be 0. Non-zero = prepended data. JANUS.

# Locate the signing block
$ grep -abo "APK Sig Block 42" app.apk

# First 8 bytes — DEX magic check
$ xxd -l 8 app.apk
00000000: 504b 0304 1400 0800                      PK......      # normal ZIP
# vs
00000000: 6465 780a 3033 3500                      dex.035.      # ☠️ JANUS
```

---

## 3. ZIP anomalies and parser differentials

This is the section that turns [Ch 07 §9](../security/07-apk-signing.md#9-the-three-classic-attacks)
into detection rules.

### The catalogue

| Anomaly | Bytes to check | What it means |
|---|---|---|
| **Prepended data** | Offset of first `PK\x03\x04` > 0 | Janus-class. If those bytes are DEX magic, it *is* Janus. |
| **Duplicate filenames** | Two CD records, same name | Master-Key-class parser differential |
| **LFH ↔ CD mismatch** | Compare filename, CRC, sizes | Deliberate divergence; which one does your tool trust? |
| **Overlapping entries** | Two CD offsets → overlapping ranges | Malformed by design |
| **Appended data after EOCD** | Bytes beyond EOCD + comment length | Hidden payload; unprotected by v1 |
| **Oversized extra field** | Extra field length ≫ alignment need | Data smuggling |
| **Compressed `classes.dex`** | Method = 8 | Cannot be `mmap`'d — either very old or deliberately odd |
| **Compressed `resources.arsc`** | Method = 8 | **Install fails on Android 11+** (`INSTALL_PARSE_FAILED_RESOURCES_ARSC_COMPRESSED`). Dating signal. |
| **Directory traversal in names** | `../` in a filename | Zip-Slip; affects careless extractors — **including yours** |
| **Non-normalised timestamps** | Varied DOS timestamps | Hand-repackaged (build tools normalise to 1981-01-01) |
| **ZIP64 records** | ZIP64 EOCD locator present | Legal for >4 GB; ensure your parser handles it |

### Zip-Slip — the one that attacks *you*

```
  Entry name: ../../../../home/analyst/.ssh/authorized_keys
```

A naive extractor that does `open(dest_dir + entry_name, "w")` writes outside `dest_dir`.
This is not a theoretical concern for a malware analysis platform: **you extract untrusted
archives for a living.**

```python
# SAFE extraction — canonicalise and verify containment
import os, zipfile

def safe_extract(apk_path, dest):
    dest = os.path.realpath(dest)
    with zipfile.ZipFile(apk_path) as z:
        for info in z.infolist():
            target = os.path.realpath(os.path.join(dest, info.filename))
            if not target.startswith(dest + os.sep):
                raise ValueError(f"Zip-Slip attempt: {info.filename!r}")
            # also: enforce a size cap to resist zip bombs
            if info.file_size > 500 * 1024 * 1024:
                raise ValueError(f"Oversized entry: {info.filename!r}")
            z.extract(info, dest)
```

> **⚙️ Engineering Note:** Also cap **total** decompressed size and entry count, not just
> per-entry size — a zip bomb is many small entries or one entry with an enormous expansion
> ratio. And run extraction inside the sandbox, never on the orchestrator host.
> → [Ch 24](../sudarshan/24-threat-intake.md)

### The detection principle, restated

```
        Tolerant parser                  Strict parser + anomaly log
        ───────────────                  ───────────────────────────
   duplicate entry → picks one       duplicate entry → RECORD IT, then decide
   prepended bytes → skips them      prepended bytes → RECORD IT (Janus check)
   CRC mismatch    → ignores         CRC mismatch    → RECORD IT
        │                                     │
        ▼                                     ▼
   "looks like a normal APK"          "this sample is structurally anomalous"
        │                                     │
        ▼                                     ▼
      MISSED                            HIGH-CONFIDENCE FINDING
```

---

## 4. Binary XML (AXML)

### WHAT

`AndroidManifest.xml` and everything under `res/` that is XML are stored in **AXML** — a
compiled binary form, not text. `cat` gives you garbage. This surprises every beginner once.

### The structure

AXML is a sequence of **chunks**, each with an 8-byte header:

```
┌──────────────────────────────────────────────┐
│ Chunk header:                                │
│   type   (uint16)                            │
│   headerSize (uint16)                        │
│   size   (uint32)   ← total chunk size       │
└──────────────────────────────────────────────┘

  0x0003  RES_XML_TYPE                 ← the file wrapper
    0x0001  RES_STRING_POOL_TYPE       ← ALL strings live here
    0x0180  RES_XML_RESOURCE_MAP_TYPE  ← attr name → resource ID
    0x0100  RES_XML_START_NAMESPACE_TYPE
    0x0102  RES_XML_START_ELEMENT_TYPE ← <manifest>, <activity>, ...
    0x0103  RES_XML_END_ELEMENT_TYPE
    0x0101  RES_XML_END_NAMESPACE_TYPE
```

Elements and attributes reference strings **by index** into the string pool. Attribute values
are typed (`TYPE_STRING`, `TYPE_INT_BOOLEAN`, `TYPE_REFERENCE`, `TYPE_INT_DEC`...).

### The string pool

```
┌────────────────────────────────────────┐
│ stringCount, styleCount                │
│ flags  ← bit 0x100 = UTF-8, else UTF-16│
│ stringsStart, stylesStart              │
│ string offsets[]  (uint32 each)        │
│ string data (length-prefixed)          │
└────────────────────────────────────────┘
```

> **⚙️ Engineering Note — the UTF-8 flag trap:** AXML string pools may be UTF-8 or UTF-16
> depending on a single flag bit. Some obfuscators set the flag inconsistently or emit
> lengths that disagree with the data. Android's parser is tolerant; third-party parsers
> often are not — which is precisely why some samples defeat `apktool` while installing
> perfectly. **If `apktool` fails on the manifest, fall back to a tolerant parser
> (Androguard's AXML parser, or `aapt2 dump xmltree`) and record the failure as a signal.**

### Reading AXML

```bash
# aapt2 — closest to what Android itself does
$ aapt2 dump xmltree app.apk --file AndroidManifest.xml | head -40
$ aapt2 dump badging app.apk           # summarised: package, sdk, perms, launchable activity

# apktool — decodes to readable XML on disk
$ apktool d -s app.apk -o work/ && head -40 work/AndroidManifest.xml

# Androguard — scriptable, most tolerant
$ python3 -c "
from androguard.core.bytecodes.apk import APK
a = APK('app.apk')
print(a.get_android_manifest_axml().get_xml().decode()[:2000])
"
```

### Manifest-level anti-analysis

Known tricks that exploit tolerant-vs-strict parsing:

- **Oversized/invalid string-pool lengths** — crashes strict parsers, tolerated by Android.
- **Extra chunks** of unknown type — Android skips by `size`, some parsers choke.
- **Duplicate attributes** on one element — Android takes one; tools may take the other.
- **Namespace confusion** — attributes in unexpected namespaces.
- **`headerSize`/`size` inconsistency** — deliberate chunk-walking desync.

> **🚨 Misconception:** "`apktool` failed, so the APK is corrupt." Frequently the opposite:
> the APK is fine *for Android* and deliberately hostile to tools. Treat tool failure as
> **evidence**, log which tool failed and how, and route to a fallback parser.

---

## 5. resources.arsc

### WHAT

A compiled resource **table** mapping numeric IDs to values, organised by package, type, and
configuration.

```
Resource ID:  0x7F 0A 0012
              │  │  └──── entry index (0x0012)
              │  └─────── type ID (0x0A = e.g. "string")
              └────────── package ID (0x7F = app; 0x01 = android framework)
```

### Structure

```
RES_TABLE_TYPE (0x0002)
  ├── global string pool          ← all resource STRING VALUES live here ★
  └── RES_TABLE_PACKAGE_TYPE (0x0200)
        ├── type string pool      ("string", "drawable", "layout", ...)
        ├── key string pool       (resource NAMES: "app_name", ...)
        ├── RES_TABLE_TYPE_SPEC_TYPE (0x0202)   ← config-change flags per entry
        └── RES_TABLE_TYPE_TYPE (0x0201)        ← ONE per configuration
              config: locale=tr, density=xxhdpi, ...
              entries[]: offset → ResTable_entry → Res_value
```

### Why analysts care

1. **Strings hide here.** C2 URLs, overlay HTML, target bank names, and phishing copy are
   routinely resource strings, not DEX strings. **Grepping only the DEX misses them.**
2. **The configuration list is a targeting map.** `values-tr/`, `values-es/`, `values-it/`
   tells you the victim geography. Cyble's *Antidot* analysis (May 16, 2024) documented
   overlay support across German, French, Spanish, Russian, Portuguese, Romanian, and
   English — the resource set *was* the target list.
3. **Package ID `0x7F` is the app's own.** Non-standard package IDs (used by some resource
   obfuscators and by dynamic-loading frameworks) are unusual and worth recording.
4. **Must be uncompressed and 4-byte aligned since Android 11** — otherwise
   `INSTALL_PARSE_FAILED_RESOURCES_ARSC_COMPRESSED`.

```bash
$ aapt2 dump resources app.apk | head -60
$ aapt2 dump strings app.apk | grep -Ei 'http|\.php|api|token' | head
$ aapt2 dump configurations app.apk        # ← the targeting map
```

> **🏛️ Enterprise Insight:** Extracting the locale set and any referenced package names from
> `resources.arsc` answers the question a bank actually asks — *"is this aimed at us?"* — in
> under a second, with no decompilation. Make it a first-class field in the intake record.
> → [Ch 24](../sudarshan/24-threat-intake.md), [Ch 29](../sudarshan/29-investigation-reports.md)

---

## 6. DEX format

### The header

`classes.dex` opens with a **0x70-byte (112) `header_item`**:

```
offset  size  field
──────  ────  ─────────────────────────────────────────────────────
0x00     8    magic          "dex\n035\0" | "dex\n037\0" |
                             "dex\n038\0" | "dex\n039\0"
0x08     4    checksum       ★ Adler-32 of everything after this field
0x0C    20    signature      ★ SHA-1 of everything after this field
0x20     4    file_size
0x24     4    header_size    = 0x70
0x28     4    endian_tag     0x12345678 (little-endian)
0x2C     4    link_size
0x30     4    link_off
0x34     4    map_off        → map_list: index of ALL sections
0x38     4    string_ids_size
0x3C     4    string_ids_off
0x40     4    type_ids_size
0x44     4    type_ids_off
0x48     4    proto_ids_size
0x4C     4    proto_ids_off
0x50     4    field_ids_size
0x54     4    field_ids_off
0x58     4    method_ids_size
0x5C     4    method_ids_off
0x60     4    class_defs_size
0x64     4    class_defs_off
0x68     4    data_size
0x6C     4    data_off
```

### The sections

```
┌──────────────────┐
│ header_item      │  0x70 bytes
├──────────────────┤
│ string_ids[]     │  offsets → string_data_item (MUTF-8, ULEB128 length prefix)
├──────────────────┤
│ type_ids[]       │  index into string_ids  ("Lcom/bank/Login;")
├──────────────────┤
│ proto_ids[]      │  method prototypes: shorty, return type, params
├──────────────────┤
│ field_ids[]      │  class + type + name
├──────────────────┤
│ method_ids[]     │  class + proto + name
├──────────────────┤
│ class_defs[]     │  class_idx, access_flags, superclass, interfaces,
│                  │  source_file, annotations, class_data, static_values
├──────────────────┤
│ call_site_ids[]  │  (invoke-custom / lambdas, DEX 038+)
│ method_handles[] │
├──────────────────┤
│ data[]           │  code_item (the actual bytecode), debug info,
│                  │  type lists, encoded arrays, string data
├──────────────────┤
│ map_list         │  authoritative index of every section
├──────────────────┤
│ hiddenapi_class_data  ← Android 10+, boot classpath DEX only
└──────────────────┘
```

### DEX version ↔ Android version

| Magic | DEX version | Introduced | Adds |
|---|---|---|---|
| `dex\n035\0` | 035 | Original | — |
| `dex\n037\0` | 037 | Android 7.0 (API 24) | `invoke-polymorphic`, method handles |
| `dex\n038\0` | 038 | Android 8.0 (API 26) | `invoke-custom`, call sites |
| `dex\n039\0` | 039 | Android 9 (API 28) | `const-method-handle`, hidden-API metadata support |

> **⚙️ Engineering Note:** DEX magic is a **cheap dating signal**. A `dex\n039\0` file cannot
> have been produced by a 2016 toolchain. Combined with the signature-scheme profile from
> [Ch 07 §11](../security/07-apk-signing.md#11-detection-logic-for-sudarshan) and ZIP
> timestamp normalisation, you get a decent build-era fingerprint for free — useful for
> spotting samples that *claim* to be old, and for clustering builds within a campaign.

### The checksum and signature fields

- `checksum` is **Adler-32** over everything after it.
- `signature` is **SHA-1** over everything after it.

Neither is a security control — an attacker who modifies the DEX simply recomputes both.
They exist for **integrity against corruption**, not tampering. But they are useful to you:

> **⚙️ Engineering Note:** **A DEX whose stored Adler-32 or SHA-1 does not match its content
> was hand-edited by a tool that didn't fix them up.** Legitimate toolchains (`d8`, `dx`)
> always compute them correctly. A mismatch is a strong, cheap, deterministic signal of
> manual patching. Compute both at intake. Android's loader tolerates some mismatches, so
> you cannot rely on the platform to surface this for you.

```bash
# quick DEX header read
$ unzip -p app.apk classes.dex | xxd -l 112 | head -8

# structural dump
$ dexdump -f classes.dex | head -30          # Android SDK build-tools
$ python3 -c "
from androguard.core.bytecodes.dvm import DalvikVMFormat
d = DalvikVMFormat(open('classes.dex','rb').read())
print('strings:', len(d.get_strings()), 'classes:', len(d.get_classes()))
"
```

### The 64K limit and multidex

`method_ids`, `field_ids`, and `type_ids` are indexed by **16-bit** values → maximum 65,536
method *references* per DEX file. Large apps exceed this, hence **multidex**:
`classes.dex`, `classes2.dex`, `classes3.dex`, …

> **⚙️ Engineering Note:** Any tool or script that analyses only `classes.dex` is **wrong**.
> This is a genuinely common bug in home-grown pipelines and in some published research.
> Enumerate `classes*.dex` with a glob, always.

---

## 7. The DEX name-resolution chain

To get a class name from a `class_def_item`, you follow four hops. Understanding this chain
is what lets you read obfuscated DEX and spot manipulation.

```
class_def_item
     │ .class_idx  (uint32)
     ▼
type_ids[class_idx]
     │ .descriptor_idx  (uint32)
     ▼
string_ids[descriptor_idx]
     │ .string_data_off  (uint32)
     ▼
string_data_item
     │  ULEB128 length, then MUTF-8 bytes
     ▼
  "Lcom/bank/LoginActivity;"
```

Method resolution is the same shape, one level deeper:

```
method_id_item
  ├── class_idx  → type_ids → string_ids → "Lcom/bank/Api;"
  ├── proto_idx  → proto_ids → shorty + return type + parameter type list
  └── name_idx   → string_ids → "sendCredentials"
```

### Why this chain is an obfuscation target

Google Cloud / Mandiant's **"Delving into Dalvik"** research documents how obfuscators
manipulate `string_id_item` indices and string-data layout so that tools resolving names
naively get wrong or unusable results while ART resolves correctly. Variants seen in the wild:

| Manipulation | Effect |
|---|---|
| **Unused/duplicate string entries** | Inflates the pool, confuses index-based tooling |
| **Overlapping `string_data_item`s** | One byte range serves two entries; tolerant readers diverge |
| **Non-standard ULEB128 encoding** | Redundant continuation bytes; strict parsers reject, ART accepts |
| **Invalid MUTF-8 sequences** | Renders as garbage in tools; ART tolerates |
| **Section offsets disagreeing with `map_list`** | Header says one thing, map says another — which does your parser trust? |
| **Unusual class names** | Unicode, extremely long, or reserved-looking names that break UI display |

> **⚙️ Engineering Note:** Parse `map_list` (`map_off`) **and** the header offsets, then
> **diff them**. They should agree. Disagreement is a deliberate anti-analysis signal and
> costs you one extra read to detect. This is the DEX-level equivalent of diffing local file
> headers against the central directory in §2 — the same defensive pattern, one layer down.

### MUTF-8, briefly

DEX strings use **Modified UTF-8**: the null character is encoded as two bytes (`0xC0 0x80`)
rather than one, and supplementary characters are encoded as surrogate pairs (CESU-8 style)
rather than 4-byte UTF-8. Standard UTF-8 decoders mishandle both. Use a MUTF-8-aware decoder,
or accept corruption on a subset of strings.

---

## 8. ELF and native libraries

Native libraries under `lib/<abi>/` are standard **ELF** shared objects. What matters:

| ELF feature | Analyst relevance |
|---|---|
| `.init_array` | **Constructors run before `JNI_OnLoad`** — anti-analysis often hides here |
| `JNI_OnLoad` | First JNI entry point; **packers unpack here** |
| `.dynsym` / `.dynamic` | Exported symbols; `Java_*` mangled names |
| Section entropy | High entropy = packed/encrypted payload |
| Missing/stripped sections | Deliberate; complicates static analysis |
| Alignment (16 KB pages) | Newer devices require 16 KB page alignment for native libs |

```bash
$ file work/lib/arm64-v8a/libnative.so
$ readelf -h work/lib/arm64-v8a/libnative.so
$ readelf -d work/lib/arm64-v8a/libnative.so | head
$ nm -D work/lib/arm64-v8a/libnative.so | grep -E 'JNI_OnLoad|Java_'
$ readelf -S work/lib/arm64-v8a/libnative.so   # section headers + sizes
$ strings -n 8 work/lib/arm64-v8a/libnative.so | grep -Ei 'http|/api/|token'
```

**Packer fingerprints by filename** (from [Ch 02 §6](02-apk-architecture.md#6-native-libraries)):
`libjiagu.so` (360 Jiagu), `libDexHelper.so` (SecNeo/Bangcle), `libshella*.so`, `libtprt.so`
(Tencent), and Virbox artifacts — the protector documented by Cleafy in **Klopatra**
(August 2025). Full treatment in [Ch 10](../reverse-engineering/10-reverse-engineering.md).

---

## 9. Format-level anti-analysis

A consolidated table. Each row is a rule you can implement.

| Technique | Layer | Android | Your tools | Detection |
|---|---|---|---|---|
| Prepended DEX (Janus) | ZIP | Loads DEX | See ZIP | First 8 bytes = DEX magic **and** valid ZIP |
| Duplicate ZIP entries | ZIP | Picks one | May pick other | Compare CD record names |
| LFH ↔ CD mismatch | ZIP | Trusts CD | Varies | Diff both copies |
| Data after EOCD | ZIP | Ignored | Ignored | Compare file size vs EOCD end + comment |
| Malformed AXML chunks | AXML | Tolerant | `apktool` fails | Log parser failure; fall back to Androguard |
| AXML UTF-8 flag abuse | AXML | Tolerant | Garbled | Parse both encodings, compare |
| `resources.arsc` malformation | ARSC | Tolerant | `apktool` fails | Log failure; use `aapt2` |
| DEX header ↔ `map_list` mismatch | DEX | Uses map | Varies | Diff them |
| Bad Adler-32 / SHA-1 in DEX | DEX | Tolerant | Ignored | **Recompute both** |
| Overlapping `string_data_item` | DEX | Correct | Wrong names | Range-overlap check across the pool |
| Non-standard ULEB128 | DEX | Accepts | Strict parsers reject | Tolerant decode + flag |
| Encrypted DEX in `assets/` | Container | Loaded at runtime | Invisible | Entropy scan + class-loader hook ([Ch 03](../android/03-android-runtime.md)) |
| Native packer | ELF | Runs | `jadx` empty | Library name + entropy + thin DEX |

> **🔬 Research Gap:** There is no canonical, maintained corpus of Android format-confusion
> test cases equivalent to what exists for PE/PDF. Building one — a set of APKs exercising
> each row above, with known-correct expected parses — would be a genuinely valuable
> contribution and would let SUDARSHAN regression-test its parsers.
> → [Ch 31](../appendix/31-future-research.md)

---

## 10. Detection logic for SUDARSHAN

### Intake-stage structural checks (all deterministic, all sub-second)

```yaml
structural_analysis:
  zip:
    first_lfh_offset: int            # != 0  → prepended data
    prepended_bytes_magic: bytes     # DEX magic → JANUS
    duplicate_entry_names: []
    lfh_cd_mismatches: []            # {entry, field, lfh_value, cd_value}
    bytes_after_eocd: int
    entries_with_traversal: []       # "../" → Zip-Slip
    classes_dex_compression: enum    # stored | deflate
    resources_arsc_compression: enum # deflate → pre-Android-11 build
    timestamps_normalised: bool      # all 1981-01-01 → build-tool output
    zip64: bool
    signing_block_ids: []            # → Ch 07

  axml:
    parse_ok: bool
    parser_used: enum                # aapt2 | androguard | apktool
    fallback_required: bool          # ← SIGNAL
    anomalies: []                    # chunk size mismatch, dup attrs, bad flags

  arsc:
    parse_ok: bool
    package_ids: []                  # non-0x7F → unusual
    locales: []                      # ← TARGETING MAP
    referenced_package_names: []     # ← OVERLAY TARGET LIST

  dex:
    files: [classes.dex, classes2.dex, ...]   # GLOB, never just the first
    per_file:
      magic_version: enum            # 035 | 037 | 038 | 039
      adler32_valid: bool            # ← hand-edit signal
      sha1_valid: bool               # ← hand-edit signal
      header_vs_maplist_consistent: bool
      string_pool_overlaps: int
      uleb128_nonstandard: int
      counts: {strings, types, methods, fields, classes}

  elf:
    per_library:
      abi, size, entropy
      has_init_array: bool
      has_jni_onload: bool
      exported_java_symbols: int     # 0 + JNI_OnLoad present → RegisterNatives
      packer_fingerprint: string|null
```

### Rules

| Rule | Logic | Severity | Confidence |
|---|---|---|---|
| **Janus format** | DEX magic at offset 0 **and** valid ZIP | Critical | **High** — deterministic |
| **Duplicate ZIP entries** | any | High | High |
| **Zip-Slip entry name** | `../` in any name | High | High |
| **DEX checksum/SHA-1 mismatch** | recomputed ≠ stored | High | High |
| **Header ↔ `map_list` mismatch** | any | Medium-High | High |
| **String-pool overlap** | overlapping `string_data_item` ranges | Medium-High | Medium |
| **LFH ↔ CD mismatch** | any field | Medium-High | Medium |
| **AXML/ARSC parser fallback required** | `apktool` failed, fallback succeeded | Medium | Medium |
| **Compressed `resources.arsc`** | method = deflate | Low | High (dating, not malice) |
| **Non-normalised timestamps** | varied DOS times | Low | Low |
| **Data after EOCD** | > 0 bytes | Medium | Medium |

> **⚙️ Engineering Note — why these rules are disproportionately valuable:** every rule above
> is **deterministic, cheap, and explainable**. In a bank's regulated environment,
> "`classes.dex` declares SHA-1 `abc…` but its content hashes to `def…`, therefore it was
> modified after compilation" is an argument that survives audit. A model confidence score is
> not. Ship these first, and lead demos with them. → [Ch 27](../sudarshan/27-risk-scoring.md)

### Parser architecture

```
             ┌──────────────────────────────┐
   APK ────► │ STRICT parser (spec-exact)   │
             └──────────────┬───────────────┘
                            │
                 ┌──────────┴──────────┐
              success                fail
                 │                     │
                 ▼                     ▼
        record clean parse    ┌────────────────────────┐
                              │ TOLERANT parser        │
                              │ (Androguard / aapt2)   │
                              └───────────┬────────────┘
                                          │
                              ┌───────────┴───────────┐
                           success                  fail
                              │                       │
                              ▼                       ▼
                    ★ RECORD: strict failed,   quarantine +
                      tolerant succeeded        manual review
                      → ANOMALY SIGNAL
```

**The divergence between strict and tolerant is itself the detection.** Run both. Never run
only the tolerant one.

---

## 11. Limitations, edge cases, false positives

### False positives

| Trigger | Innocent cause |
|---|---|
| Non-normalised timestamps | Some CI pipelines, some third-party stores re-zip legitimately |
| Compressed `resources.arsc` | Genuinely old app (pre-Android-11 build) |
| ZIP64 | Very large legitimate apps (games) |
| High-entropy native sections | Compressed game assets, ML models, DRM |
| `apktool` failure | `apktool` has plenty of ordinary bugs; failure ≠ malice on its own |
| Data after EOCD | Some signing/distribution tooling appends benign metadata |
| Unusual DEX string counts | Kotlin + heavy R8 output looks odd but is normal |

> **🚨 Misconception:** "Malformed = malicious." Plenty of legitimate apps are built by
> unusual toolchains, repacked by regional stores, or simply old. The **combination** of
> structural anomaly plus capability cluster ([Ch 04 §11](../security/04-android-security-model.md#11-detection-logic-for-sudarshan))
> is what carries weight. A structural anomaly alone is a *review* flag.

### False negatives

- Well-formed malware. **Most banking trojans are structurally perfect** — they don't need
  format tricks because they rely on user consent. Structural analysis is a high-precision,
  **low-recall** layer. Do not oversell it.
- Payload arrives post-install ([Ch 03 §6](../android/03-android-runtime.md#6-dynamic-code-loading--the-technique-that-breaks-static-analysis)).
- Encrypted assets that look like ordinary compressed data.

### Edge cases

| Case | Handling |
|---|---|
| Split APKs | Parse **every** split |
| XAPK/APKS/APKM | Explode container first |
| APK with no `classes.dex` | Legal (resource-only or pure-native splits) |
| Very large APKs | Enforce timeouts and size caps; stream rather than load fully |
| ZIP bombs | Cap total decompressed size and entry count |
| `.idsig` present | v4 → [Ch 07 §7](../security/07-apk-signing.md#7-v4--incremental--streaming-install) |

### Performance

| Operation | Typical cost |
|---|---|
| ZIP structure scan | ~10 ms |
| Manifest AXML parse | ~50 ms |
| `resources.arsc` parse | ~100–500 ms |
| DEX header + counts | ~50 ms per DEX |
| DEX checksum recompute | ~100–500 ms per DEX (I/O bound) |
| Full decompile (`jadx`) | **seconds to minutes** |

**Everything in this chapter is in the cheap tier.** Run it on 100% of samples; use it to gate
the expensive tier. → [Ch 23](../sudarshan/23-detection-pipeline.md)

---

## 12. Engineering tips

1. **Glob `classes*.dex`.** Never assume one DEX.
2. **Run strict and tolerant parsers; the diff is the signal.**
3. **Recompute DEX Adler-32 and SHA-1.** Cheap, deterministic hand-edit detection.
4. **Diff LFH against CD, and DEX header against `map_list`.** Same defensive pattern, two layers.
5. **Check the first 8 bytes for DEX magic** at intake — the Janus check.
6. **Canonicalise paths before extraction** and cap sizes/counts. You extract hostile archives.
7. **Extract locales and referenced package names from `resources.arsc`** — highest business
   value per millisecond in the whole pipeline.
8. **Use a MUTF-8-aware decoder** for DEX strings.
9. **Log which parser succeeded** in the artifact record, for reproducibility.
10. **Never claim structural cleanliness means benign.** Low recall by design.

---

## 13. Judge Insights

**What judges ask:** *"You've shown static and dynamic analysis. What can you detect that a
normal antivirus can't?"*

**Perfect answer:** Structural anomalies at the byte level, deterministically. We parse the
APK with both a strict spec-exact parser and a tolerant one, and the *divergence between them*
is the detection — because that divergence is exactly what format-confusion attacks depend on.
Concretely: we recompute the Adler-32 and SHA-1 stored in the DEX header, so we can prove a
DEX was hand-edited after compilation; we diff ZIP local file headers against the central
directory, which catches the Master Key class of bug; we check whether the first eight bytes
are DEX magic on a file that also parses as a ZIP, which is the Janus signature. None of that
needs a model or a signature database, and every finding is a byte offset an auditor can
verify. In a regulated bank environment, that explainability is worth more than a confidence
score.

**Common mistakes:**
- Overselling it. Structural analysis is **high precision, low recall**. Most banking trojans
  are structurally perfect because they rely on user consent, not format tricks. Say so —
  judges respect calibrated claims and punish overreach.
- Not knowing why the checks work (i.e. not being able to explain Janus).

**Follow-ups to expect:**
- *"How often does that actually fire?"* → Rarely, and that's the point — it's a precision
  layer, not a recall layer. The capability-cluster and behavioural layers carry recall.
- *"Couldn't the attacker just fix the checksums?"* → Yes, trivially. Which is why it's one
  cheap layer among many, and why we never present it as the primary control.
- *"What's the performance cost?"* → Sub-second per sample. It runs on 100% of intake and
  gates the expensive stages.

**Fact that impresses:** The DEX header stores an Adler-32 checksum and a SHA-1 signature over
its own contents. Neither is a security control — an attacker recomputes them — but legitimate
toolchains always get them right, so **a mismatch is deterministic evidence of manual
patching by a tool that didn't fix them up.** It costs one pass over the file.

---

## 14. Interview Insights

**Q: "Why is `AndroidManifest.xml` unreadable when you extract an APK?"**
It's compiled binary XML (AXML) — a chunked format with a string pool, where elements and
attributes reference strings by index. Use `aapt2 dump xmltree`, `apktool`, or Androguard.

**Q: "Where does ZIP parsing start?"**
At the **end** — scan backward for the EOCD, read the central directory offset, then walk the
records. That's why bytes before the first local file header are ignored, and that's the
precondition for Janus.

**Q: "What's in a DEX header?"**
Magic (`dex\n0XX\0`), Adler-32 checksum, SHA-1 signature, `file_size`, `header_size` (0x70),
endian tag, then size/offset pairs for `string_ids`, `type_ids`, `proto_ids`, `field_ids`,
`method_ids`, `class_defs`, `data`, plus `map_off`.

**Q: "What's the 64K limit?"**
Method, field, and type references are indexed by 16-bit values → 65,536 references per DEX.
Exceeding it requires multidex (`classes2.dex`, …). Follow-up: *"So what does that mean for
your analysis?"* → **Always glob `classes*.dex`.**

**Q: "How do you get a class name out of a DEX?"**
`class_def_item.class_idx` → `type_ids` → `descriptor_idx` → `string_ids` → `string_data_item`
(ULEB128 length + MUTF-8). Knowing the full chain distinguishes people who've written a
parser from people who've read a blog post.

**Q: "What's MUTF-8?"**
Modified UTF-8: null encoded as `0xC0 0x80`, supplementary characters as surrogate pairs
rather than 4-byte sequences. Standard UTF-8 decoders corrupt both cases.

**Q: "How would you detect a repackaged APK?"**
Signer fingerprint mismatch against a known-good registry ([Ch 06](../security/06-certificates.md))
is primary. Supporting signals: non-normalised ZIP timestamps, DEX checksum mismatch, ZIP
structural anomalies, and `apktool`-rebuild artifacts.

**Beginner mistakes:**
- Analysing only `classes.dex`.
- `cat`-ing the manifest and assuming corruption.
- Using a standard UTF-8 decoder on DEX strings.
- Trusting a single tolerant parser.
- Extracting untrusted ZIPs without path canonicalisation.

---

## 15. Cross-references

**Upstream:**
- [← Ch 02 APK Architecture](02-apk-architecture.md) — the conceptual layout
- [← Ch 07 APK Signing](../security/07-apk-signing.md) — the signing block; Janus/Master Key/Fake ID

**Downstream:**
- [→ Ch 09 Package Manager](09-package-manager.md) — how Android parses these bytes at install
- [→ Ch 10 Reverse Engineering](../reverse-engineering/10-reverse-engineering.md) — smali, packers, native RE
- [→ Ch 11 Static Analysis](../static-analysis/11-static-analysis.md) — automating §10
- [→ Ch 24 Threat Intake](../sudarshan/24-threat-intake.md) — safe extraction, artifact records
- [→ Ch 31 Future Research](../appendix/31-future-research.md) — the missing format-confusion corpus

**Related chain:** ZIP structure → parser differential → Janus/Master Key → v2 signing →
structural detection.

---

## 16. References

1. AOSP — *Dalvik Executable format*. https://source.android.com/docs/core/runtime/dex-format
2. AOSP — *Dalvik bytecode reference*. https://source.android.com/docs/core/runtime/dalvik-bytecode
3. AOSP — *Application Signing* (APK Signing Block layout). https://source.android.com/docs/security/features/apksigning
4. PKWARE — *.ZIP File Format Specification* (APPNOTE.TXT).
5. Google Cloud / Mandiant — *Delving into Dalvik: A Look Inside the DEX File Format* — string-index manipulation by obfuscators.
6. AOSP — `frameworks/base/tools/aapt2/` — resource compiler and `ResTable` format source.
7. AOSP — `libziparchive` — Android's ZIP reader implementation.
8. Androguard documentation — AXML, ARSC, and DVM parsers. https://androguard.readthedocs.io/
9. Android Developers — `aapt2` reference. https://developer.android.com/tools/aapt2
10. Android Developers — *Behavior changes: Android 11* (uncompressed `resources.arsc`). https://developer.android.com/about/versions/11/behavior-changes-all
11. Android Security Bulletin — December 2017 (CVE-2017-13156, Janus). https://source.android.com/docs/security/bulletin/2017-12-01
12. Snyk — *Zip Slip* vulnerability research (archive path traversal).
13. Cyble Research and Intelligence Labs — *Antidot* (May 16, 2024) — multi-locale overlay resources.
14. Cleafy Labs — *Klopatra* (August 2025) — Virbox native protection.

### Further reading
- ELF specification (System V ABI) and ARM64 supplement
- `dexdump` / `dexlib2` (smali project) source — practical DEX parsing references
- OWASP MASTG — reverse engineering and tampering test cases

---

*Previous: [← Ch 07 APK Signing](../security/07-apk-signing.md) · Next: [Ch 09 Package Manager →](09-package-manager.md)*
