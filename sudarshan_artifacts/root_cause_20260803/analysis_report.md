# Dynamic-analysis root-cause report

Target: `test apk/Vulnerable/InsecureBankv2.apk` (`com.android.insecurebankv2`)

| Stage | PASS | FAIL | Root Cause / evidence |
|---|---:|---:|---|
| Host Python / ADB / Frida | PASS |  | Python 3.13.6; ADB 37.0.0; Frida Python 17.16.4; `emulator-5554` connected. |
| Emulator readiness | PASS |  | boot completed; Android 17/API 37; x86_64; root; SELinux Permissive; 16 KiB pages; 8.1 GiB storage free. |
| APK structure | PASS |  | Package `com.android.insecurebankv2`; launcher `.LoginActivity`; no native libraries or split APKs. |
| Install / launch / UI | PASS |  | Install succeeded; `am start -W` complete in 7.666 s; PID 15036 stayed present for 5 s; focused window and UI dump were confirmed; no ANR/crash. |
| Frida transport | PASS |  | `frida-server` 17.16.4 listened on 127.0.0.1:27042; direct attach to PID 15036, script load, and canary all passed. |
| Java-hook initialization |  | FAIL | Production run received the canary then `Java.perform()` failed: `Unable to find fields in java/lang/Thread; please file a bug`. `java_hooks_installed=0`, `java_bridge_failed=true`, `dynamic_status=INSTRUMENTATION_FAILED`. |
| Individual Java hooks | NOT RUN |  | Prohibited after the Java bridge failed; none can be installed. |
| Runtime event / evidence / correlator / risk / AI / dashboard | NOT RUN |  | Prohibited after the upstream instrumentation failure. The returned BFCI 0.0 is not valid behavioral telemetry. |

## Exact failure

The exact failing call is `Java.perform(...)` at `shared/sudarshan_core/engines/frida_hooks/banking_trojan.js:405`. It calls the bundled `frida-java-bridge` 7.0.13 (locked in `shared/sudarshan_core/engines/frida_hooks/package-lock.json:442-444`). That bridge fails while reflecting `java/lang/Thread` on this Android 17 / API 37 / 16 KiB-page emulator. The application did not throw an exception and did not crash.

`shared/sudarshan_core/engines/frida_sandbox.py:1547-1555` records that failure, and `:2933-2945` correctly marks the session `INSTRUMENTATION_FAILED` rather than treating zero events as benign behavior.

## Why the previous fixes did not fix this run

The prior bundle fix solved a different failure: making `frida-java-bridge` available to Frida 17 and producing a real bundled script. This run proves that transport and bundle loading now work (`canary_received=true`, native hooks installed). The still-pinned bridge fails only when Java instrumentation initializes against the current emulator ART runtime; replacing launch logic, PID polling, or server forwarding cannot alter that failure.

There is also a separately confirmed controller defect: `FridaSession.run()` has two consecutive attach/load blocks. It loads a script at `shared/sudarshan_core/engines/frida_sandbox.py:2249-2251`, resets `self._session` at `:2277`, then attaches and loads the same script again at `:2360-2362`. The production log contains exactly two attaches, two groups of the same eight native hooks, and two identical Java initialization failures. This duplicate injection is a confirmed source of non-determinism and can aggravate crashes, but it is not the first failure: the first script already fails in `Java.perform` before the duplicate path runs.

## Required corrective action

Upgrade the *entire aligned Frida toolchain* (Frida Python bindings, on-device server, `frida-java-bridge`, and compiled hook bundle) to a release verified to support this Android 17/API 37 ART runtime, or run the dynamic-analysis AVD on an Android API level supported by the pinned 17.16.4/7.0.13 toolchain. Rebuild `banking_trojan.bundle.js`, deploy the matching server, then gate every analysis on a Java self-test that executes `Java.perform` and installs at least one Java hook. Do not permit BFCI/risk/report stages unless that gate passes.

After the compatibility gate passes, remove the second attach/load block; retain one session and one script per target PID. Verify one attach and one occurrence of each native hook before re-enabling end-to-end analysis.

Supporting artifacts: `launch.log`, `frida.log`, `hook.log`, `pipeline.log`, `risk.log`, and `crash.log` in this directory. `crash.log` is the complete post-launch logcat capture; it contains no target crash or `FATAL EXCEPTION`.
