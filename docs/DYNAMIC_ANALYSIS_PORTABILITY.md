# Dynamic Analysis: Why It Broke Per-Machine, and What Is Automatic Now

Dynamic analysis used to work on one laptop and fail on the next, and each
developer re-fixed it by hand. This documents what was machine-specific, what is
now resolved automatically, and the one command to run when something is off.

## The root cause

`tools/` is in `.gitignore` — the frida-server binary is ~106 MB, above GitHub's
100 MB file limit, so it can never be committed. A fresh clone therefore had
**no frida-server**, and every new machine hit the same wall:

```
Frida startup failed
Expected binary: frida-server-17.16.4-android-x86_64
Binary found: no
```

The fix was always the same manual ritual — find the right release, match the
version to the pinned client, match the ABI to the emulator, decompress, drop it
in `tools/`. Nothing in the repo did it for you.

## What is automatic now

**frida-server is fetched on demand.** `ensure_frida_server()` in
`shared/sudarshan_core/sandbox/frida_assets.py` resolves the device ABI, picks
the pinned version, and downloads the matching build from the official GitHub
release if it is not already cached. It is idempotent — a cached binary
short-circuits immediately — and it runs from both the sandbox provider and
`scripts/setup_dynamic_analysis.py`, so no one has to remember it.

Version and architecture are never guessed:

- Version comes from `FRIDA_VERSION` (default pinned in `frida_assets.py`) and
  **must** match the `frida` Python package in `backend/requirements.txt`.
- Architecture comes from the device's own `ro.product.cpu.abi`. An x86_64
  binary is never pushed to an arm64 device.

**Device selection is automatic.** `adb devices -l` is enumerated at runtime; set
`ANDROID_DEVICE_SERIAL` (or `DEVICE_SERIAL`) only when more than one sandbox is online.
The engine no longer falls back to a hardcoded `192.168.56.101` Genymotion IP.

**Reliable Docker Connectivity.** Inside Docker environments, connecting Frida via the proxy USB
ADB interface can be unstable (resulting in `TransportError` or timeouts). The `frida_sandbox.py`
engine now mitigates this by automatically mapping an `adb forward tcp:27042` tunnel to the emulator
and prioritizing a remote TCP connection (`host.docker.internal:27042`) over local USB enumeration.

**Nothing is hardcoded to one host.** There are no absolute user paths, serials,
or emulator names in the engine — the `emulator-5554` strings in the codebase are
docstrings. Furthermore, the `ADB_HOST` fallback in `bootstrap_sandbox.py` and
`setup_dynamic_analysis.py` no longer forces `host.docker.internal`, which previously
broke the analysis on standard local/non-Docker desktop runs.

**Concurrent Device Execution.** The engine is now completely capable of parallel
dynamic analysis. `_DEVICE_LOCK` was removed from the global `main.py` entrypoint.
Now `frida_sandbox.py` tracks an asynchronous lock mapped by the actual device serial,
so multiple submissions to the API can be run simultaneously as long as there is an
available free device (or using multi-device logic).

## Environment knobs

| Variable | Default | Purpose |
|---|---|---|
| `SUDARSHAN_FRIDA_AUTO_DOWNLOAD` | `1` | Set `0` on air-gapped hosts to restore locate-only behaviour |
| `FRIDA_SERVER_DIR` | `<repo>/tools` | Where binaries are cached and searched |
| `FRIDA_VERSION` | pinned | Must match the `frida` package version |
| `DEVICE_SERIAL` | auto | Only needed with multiple devices attached |
| `FRIDA_ANALYSIS_DURATION` | `90` | Capture window in seconds |
| `SUDARSHAN_ACTION_EVIDENCE_FRAMES` | `1` | One screenshot per explorer action; `0` reverts to conditional capture |

## When something is wrong

Run this first — it detects the device, enables root, sets SELinux permissive,
downloads and pushes frida-server, and verifies that Frida can attach:

```bash
python scripts/setup_dynamic_analysis.py
```

If it reports a device but Frida cannot attach, the usual causes are a
version mismatch between the pushed server and the `frida` client package, or a
frida-server left running from a previous session.

## What is still environment-dependent

- **A rooted Android emulator must be running.** The engine does not create one.
- **Emulator image.** Verified on API 37 x86_64 including the 16 KB-page image.
  Java hooking works there with frida 17.16.4; see the notes in
  `frida_hooks/banking_trojan.bundle.js` for the API 34+ deoptimisation path.
