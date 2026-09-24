/**
 * SUDARSHAN - Banking Trojan Frida Instrumentation Script v4 (Frida 17 Compatible)
 * ==================================================================================
 * Production-grade runtime API hook suite for detecting Android banking malware.
 *
 * ROOT CAUSE FIX (v3 → v4):
 *   v3 used CommonJS require for frida-java-bridge which FAILS in Frida 17+.
 *   In Frida 17, Java is a built-in global - no require needed or supported.
 *   This v4 script removes the require call entirely and uses the built-in Java global.
 *
 * Target Categories & Scored Components:
 *   [A] Accessibility Service Abuse       → weight 0.35
 *   [S] SMS / Telephony / OTP Theft        → weight 0.25
 *   [O] Overlay / System Alert Window      → weight 0.20
 *   [B] Banking Interaction & Credentials  → weight 0.10
 *   [N] Network C2 Communication           → weight 0.05
 *   [P] Persistence & Admin Abuse          → weight 0.05
 *   [D] Dynamic Code Loading & Reflection  → detection & evidence
 *   [X] Anti-Analysis & Sandbox Evasion    → detection & counter-spoofing
 *   [NA] Native Instrumentation            → libc/libart hooks
 *
 * Frida 17+ compatibility notes:
 *   - Java is a built-in global, never require()
 *   - Java.deoptimizeEverything() and Java.deoptimizeBootImage() both available
 *   - Interceptor.attach() works on native functions directly
 *   - Process.findModuleByName() for native module discovery
 */

'use strict';

// ─── Java bridge ──────────────────────────────────────────────────────────────
//
// MEASURED on frida 17.16.4 against a live emulator:
//
//     typeof Java  ->  "undefined"
//
// Frida 17 REMOVED the built-in `Java` global; the Android bridge became the
// external `frida-java-bridge` module. The previous header here asserted the
// opposite ("Java is injected by Frida 17+ automatically") and initHooks was
// guarded by `if (typeof Java === 'undefined') return`, so on Frida 17 EVERY
// Java hook - accessibility, SMS, overlay, banking, persistence, dangerous
// APIs, anti-analysis, ~40 in total - silently failed to install. The canary is
// emitted before initHooks, so the session still reported "loaded" and the run
// came back NO_BEHAVIOR_OBSERVED with BFCI 0.0. That is the real reason every
// BFCI component reads 0.0 on every sample.
//
// backend/requirements.txt already documented the correct answer: the script
// "must be bundled with frida-java-bridge via frida-compile". Bundling is now
// wired up (see frida_hooks/package.json and build_bundle in frida_sandbox.py);
// this resolves the bridge whichever way the script is loaded.
// STATIC import, deliberately - not a dynamic require().
//
// This file is compiled with frida-compile, which bundles as ESM and
// tree-shakes. A dynamic bridge require buried inside a try/catch is
// invisible to static analysis, so once the TypeScript types resolved the
// bundler eliminated the module entirely: the bundle shrank from 542 KB to
// 176 KB, dropped the bridge, and failed at runtime with
// "require-failed: 'require' is not defined". A static import is the only form
// the bundler is guaranteed to keep.
//
// Consequence: THIS FILE IS ESM AND MUST BE COMPILED. It is no longer valid as
// a classic script, which is correct - an unbundled script has no Java bridge
// on Frida 17 and could never have installed a Java hook anyway. See
// _select_hooks_script() in frida_sandbox.py, which refuses to load raw source.
import JavaBridgeModule from 'frida-java-bridge';

// The package is published as an ES module, so the real API can sit on
// `.default` through interop - measured on device:
//   Object.keys(mod)      -> ["default"]
//   typeof mod.available  -> "undefined"
//   mod.default.available -> true
// Taking the namespace object directly yields available===undefined, which
// reads as "no Java" and silently disables every Java hook.
var JAVA_BRIDGE_SOURCE = 'none';

// Host-settable agent configuration. Rewritten by _apply_agent_config() in
// frida_sandbox.py when SUDARSHAN_DEOPT_BOOT_IMAGE is set; see the
// deoptimizeBootImage block below for why the default is false on API 34+.
// The literal text of this line is a contract with that function.
var DEOPT_BOOT_IMAGE_FORCED = false;
var Java = (function resolveJavaBridge() {
  try {
    var mod = JavaBridgeModule;
    var bridge = (mod && mod.default) ? mod.default : mod;
    if (bridge) {
      JAVA_BRIDGE_SOURCE = 'frida-java-bridge' + ((mod && mod.default) ? ' (.default)' : '');
      return bridge;
    }
  } catch (e) {
    JAVA_BRIDGE_SOURCE = 'import-failed: ' + (e && e.message ? e.message : String(e));
  }
  try {
    if (typeof globalThis !== 'undefined' && globalThis.Java) {
      JAVA_BRIDGE_SOURCE = 'global';           // Frida <= 16
      return globalThis.Java;
    }
  } catch (e) { /* ignore */ }
  return null;
})();

// ─── Native export resolution ─────────────────────────────────────────────────
//
// MEASURED on frida 17.16.4:
//
//     typeof Module.findExportByName        ->  "undefined"   (REMOVED)
//     typeof Module.findGlobalExportByName  ->  "function"
//     typeof Process.findModuleByName       ->  "function"
//
// Every native hook called the removed static form and failed with
// "not a function" - SSL_write, SSL_read, connect, execve, ptrace, open,
// RegisterNatives, and the dlopen watchers. This resolves a symbol across both
// API generations, preferring a module-scoped lookup and falling back to the
// global export table.
function resolveExport(moduleName, symbol) {
  // Frida >= 17: module-scoped
  try {
    if (typeof Process.findModuleByName === 'function') {
      var m = Process.findModuleByName(moduleName);
      if (m && typeof m.findExportByName === 'function') {
        var addr = m.findExportByName(symbol);
        if (addr) return addr;
      }
    }
  } catch (e) { /* fall through */ }

  // Frida >= 17: global export table (works for libc/libdl symbols)
  try {
    if (typeof Module.findGlobalExportByName === 'function') {
      var g = Module.findGlobalExportByName(symbol);
      if (g) return g;
    }
  } catch (e) { /* fall through */ }

  // Frida <= 16: the removed static form
  try {
    if (typeof Module.findExportByName === 'function') {
      return Module.findExportByName(moduleName, symbol);
    }
  } catch (e) { /* fall through */ }

  return null;
}

// ─── Deduplication & Event Cache ─────────────────────────────────────────────
var dedupeCache = {};
var MAX_DEDUPE_ENTRIES = 1000;
var DEDUPE_WINDOW_MS = 2000; // 2-second dedup window

function isDuplicate(key) {
  var now = Date.now();
  var bucket = Math.floor(now / DEDUPE_WINDOW_MS);
  var fullKey = key + '_' + bucket;

  if (dedupeCache[fullKey]) {
    return true;
  }
  dedupeCache[fullKey] = true;

  var keys = Object.keys(dedupeCache);
  if (keys.length > MAX_DEDUPE_ENTRIES) {
    for (var i = 0; i < 100; i++) {
      delete dedupeCache[keys[i]];
    }
  }
  return false;
}

// ─── Target Package Configuration Slot ────────────────────────────────────────
var TARGET_PACKAGE_NAME = "";

// ─── Runtime Context ──────────────────────────────────────────────────────────
var runtimeContext = {
  foreground_app: 'Unknown',
  current_activity: 'Unknown',
  event_counter: 0,
  last_event_id: null,
  hooks_installed: 0,
  hooks_active: 0,
  hook_errors: 0,
  process_id: Process.id,
  package_name: TARGET_PACKAGE_NAME || 'Unknown',
};

// ─── Event Collector (mirrors Python collected_events keys exactly) ───────────
//
// SCORED categories (present in bfci_scorer.BFCI_WEIGHTS) must contain ONLY
// events that are evidence of the behaviour the category names. The caps in
// bfci_scorer are 2-3 events with logarithmic scaling, so a SINGLE mis-filed
// event scores 50-63/100 for that component. A category that also catches
// ordinary application behaviour is not a weak signal - it is a constant.
//
// UNSCORED categories are collected as evidence and reported, but contribute
// nothing to BFCI. calculate_bfci_v2 iterates `for cat in BFCI_WEIGHTS`, so a
// category simply absent from that dict is inert by construction.
// Per-category COUNTERS only. The event objects themselves are streamed to
// Python, which owns collected_events; keeping copies here served no purpose
// and grew without bound inside the target process for the whole session.
var eventCounts = {
  // ── Scored ───────────────────────────────────────────────────────────────
  accessibility:  0,
  sms:            0,   // actual SMS read / write / send / delete ONLY
  overlay:        0,   // window-type-VERIFIED overlay operations ONLY
  banking:        0,   // banking-app targeting + high-confidence credential access
  network:        0,
  persistence:    0,
  // ── Unscored: evidence only ──────────────────────────────────────────────
  dangerous_apis:     0,
  files_accessed:     0,
  anti_analysis:      0,
  smoke:              0,   // baseline runtime smoke-test events (app start, activity, class, file, pref, url)
  device_fingerprint: 0,   // IMEI / IMSI / ICCID / MSISDN, app + account enumeration
  app_telemetry:      0,   // ordinary app behaviour: activity lifecycle, keyboard,
                           // generic crypto/keystore/prefs access, non-overlay windows
  notification:       0,   // notification interception (see NOTE at the hook)
};

// ─── Overlay window tracking ──────────────────────────────────────────────────
// addView carries LayoutParams and can be type-checked. updateViewLayout and
// removeView cannot be trusted on their own: every AlertDialog, Toast,
// PopupWindow, spinner dropdown and soft-keyboard resize goes through them. We
// therefore remember which View handles were added AS an overlay, and only
// treat later operations on those handles as overlay evidence.
var OVERLAY_WINDOW_TYPES = [
  2038,  // TYPE_APPLICATION_OVERLAY
  2003,  // TYPE_SYSTEM_ALERT
  2006,  // TYPE_SYSTEM_OVERLAY
  2010,  // TYPE_SYSTEM_ERROR
];
var overlayViewKeys = {};
var overlayViewCount = 0;
var MAX_TRACKED_OVERLAY_VIEWS = 256;

// Ceiling on how many classes the custom-AccessibilityService scan may wrap
// with Java.use(). Java.use() loads the class and builds a JS wrapper while
// holding ART locks, so an unbounded scan is what made the app unreadable to
// uiautomator (see the scan itself for the measurement). A sample's own
// package tree is tens of classes; this is slack, not a target.
var ACCESSIBILITY_SUBCLASS_SCAN_LIMIT = 300;

function viewKey(view) {
  try {
    return view === null ? null : String(view.hashCode());
  } catch (e) {
    return null;
  }
}

function markOverlayView(view) {
  var k = viewKey(view);
  if (k === null || overlayViewKeys[k]) return;
  if (overlayViewCount >= MAX_TRACKED_OVERLAY_VIEWS) return;  // bounded
  overlayViewKeys[k] = true;
  overlayViewCount++;
}

function isTrackedOverlayView(view) {
  var k = viewKey(view);
  return k !== null && overlayViewKeys[k] === true;
}

function forgetOverlayView(view) {
  var k = viewKey(view);
  if (k !== null && overlayViewKeys[k]) {
    delete overlayViewKeys[k];
    overlayViewCount--;
  }
}

// ─── Stack Capture ─────────────────────────────────────────────────────────────
function captureStack(maxFrames) {
  maxFrames = maxFrames || 6;
  try {
    var exc = Java.use('java.lang.Exception').$new();
    var frames = exc.getStackTrace();
    var result = [];
    var limit = Math.min(frames.length, maxFrames + 2);
    for (var i = 2; i < limit; i++) {
      result.push(frames[i].toString());
    }
    exc.$dispose();
    return result;
  } catch (e) {
    return [];
  }
}

// ─── Structured Event Emitter ─────────────────────────────────────────────────
// Emits the full schema required by Phase 6 of the spec:
// {event_id, timestamp, process, thread, package, pid, event_type, category,
//  severity, method, class, arguments, return_value, stacktrace, evidence, ioc, risk_vector}
function emit(category, data) {
  runtimeContext.event_counter++;
  var eventId = 'ev_' + Date.now() + '_' + runtimeContext.event_counter;

  // Dedup key.
  //
  // This used to be description.substring(0, 50). For network hooks the
  // description begins with a ~30-character fixed prefix ("Network connection
  // opened to: "), leaving under 20 characters of URL to discriminate - so two
  // DISTINCT C2 endpoints sharing a domain prefix collapsed to one key and the
  // second was silently dropped. Losing a C2 indicator to a display-string
  // truncation is not acceptable for IOC collection.
  //
  // Key on the identifying VALUE where the event carries one (url / ioc /
  // endpoint / path / property_key), and fall back to the description
  // otherwise.
  var dedupeIdentity = data.ioc || data.url || data.endpoint || data.path ||
                       data.property_key || (data.description || '').substring(0, 120);
  var dedupeKey = category + ':' + (data.hook || '') + ':' + dedupeIdentity;
  if (isDuplicate(dedupeKey)) {
    return;
  }

  var stack = [];
  try {
    stack = captureStack(6);
  } catch (e) { /* non-fatal */ }

  var event = {
    // Phase 6 schema fields
    event_id:       eventId,
    timestamp:      Date.now(),
    process:        runtimeContext.package_name,
    thread:         Process.getCurrentThreadId(),
    package:        runtimeContext.package_name,
    pid:            runtimeContext.process_id,
    event_type:     'FRIDA_HOOK',
    category:       category,
    severity:       data.severity || 'MED',
    method:         data.hook || 'unknown',
    class:          data.class_name || '',
    arguments:      data.args || [],
    return_value:   data.return_value !== undefined ? String(data.return_value) : null,
    stacktrace:     stack,
    evidence:       data.description || '',
    ioc:            data.ioc || null,
    risk_vector:    category,
    // Legacy compat fields expected by _on_message
    source:         'frida',
    hook:           data.hook || 'unknown',
    thread_id:      Process.getCurrentThreadId(),
    process_id:     runtimeContext.process_id,
    stack_trace:    stack,
    context: {
      foreground_app:    runtimeContext.foreground_app,
      current_activity:  runtimeContext.current_activity,
      previous_event_id: runtimeContext.last_event_id,
    },
    data: data,
  };

  runtimeContext.last_event_id = eventId;

  // Count only. The full event objects used to be accumulated in `events[...]`
  // and NEVER read or cleared by anything - Python maintains its own
  // collected_events from the message channel - so this was a pure memory leak
  // growing inside the malware's own process for the whole session.
  if (typeof eventCounts[category] === 'number') {
    eventCounts[category]++;
  }

  // Send to Python _on_message handler
  send({ type: 'event', payload: event });
}

function registerHook(name) {
  runtimeContext.hooks_installed++;
  send({ type: 'hook_installed', hook: name, total: runtimeContext.hooks_installed });
}

function reportHookError(hookName, errorMsg) {
  runtimeContext.hook_errors++;
  send({
    type: 'hook_error',
    hook: hookName,
    error: String(errorMsg),
    ts: Date.now()
  });
}

// ─── Canary: MUST be sent before initHooks ────────────────────────────────────
// Python checks canary_received before evaluating hook results.
// This fires synchronously, before any Java.perform() call.
send({ type: 'canary', msg: 'script_loaded_v4_frida17', ts: Date.now() });

// ─── Heartbeat Loop ───────────────────────────────────────────────────────────
//
// NOTE: this timer does not fire in practice. Measured on a live session -
// zero pings received over 18s against a 3s interval - so the agent's JS event
// loop is not being serviced once the script has finished loading. Left in
// place because it is harmless and correct if that is ever fixed, but nothing
// may DEPEND on it: see the rpc export below, which is how recurring work is
// actually driven.
setInterval(function () {
  send({
    type: 'ping',
    ts: Date.now(),
    counter: runtimeContext.event_counter,
    hooks_installed: runtimeContext.hooks_installed,
    hooks_active: runtimeContext.hooks_active,
    hook_errors: runtimeContext.hook_errors,
  });
}, 3000);

// ─── Host-driven work ─────────────────────────────────────────────────────────
//
// Anything that has to happen REPEATEDLY is driven from Python, because the
// agent's own timers are dead (above). The WebView drain is the case that
// forced this: the page's request queue has to be collected periodically, and
// a queue that is never collected is the same as no instrumentation at all.
var sdsnWebViewCount = 0;

rpc.exports = {
  // Collect whatever the in-page shims have queued since the last call, and
  // re-inject into any WebView that has navigated. Returns the number of
  // WebViews currently held so the caller can tell "nothing happened" from
  // "there was nothing to look at".
  // Reports how many WebViews are currently instrumented. Deliberately does
  // NOT drive the drain: an rpc call arrives on a thread that is not attached
  // to the VM, and Java.choose from such a thread HANGS rather than failing -
  // measured, and it wedges the caller for the rest of the run. The drain is
  // triggered from inside a hook instead, where the thread is already a Java
  // thread. This export exists so the host can distinguish "the page made no
  // requests" from "there was no page to watch".
  webviewCount: function () {
    return sdsnWebViewCount;
  },
};

// Call synchronously - do NOT use setImmediate() here.
//
// setImmediate() defers Java.perform() to the next GumJS event-loop tick,
// which executes on a Frida fiber that needs a fresh JNI thread attachment.
// That attachment triggers frida-java-bridge's internal:
//
//   factory.use("android.app.ActivityThread")
//     -> getArtClassSpec("java/lang/Thread")
//       -> ART struct field lookup CRASH on Android 17 / API 37
//
// Calling initHooks() directly here runs Java.perform() on the same thread
// that is already executing the script load, which already has a valid JNI
// env. This is identical to how the working minimal probe loads - no deferred
// path, no fresh thread attachment, no getArtClassSpec() crash.
initHooks();


// ─── Main Hook Initialization ─────────────────────────────────────────────────
function initHooks() {
  // Java is a Frida 17 built-in global - no require() needed
  if (!Java || !Java.available) {
    // Loud and specific. This used to say "Is this an Android app?", which sent
    // every reader chasing the wrong problem: the app was fine, the BRIDGE was
    // missing because the script was loaded unbundled on Frida 17.
    send({
      type: 'error',
      description:
        'Java bridge unavailable (' + JAVA_BRIDGE_SOURCE + '). On Frida 17+ the ' +
        'Java global was removed; this script must be bundled with ' +
        'frida-java-bridge via frida-compile. NO Java hooks were installed.',
      java_bridge_source: JAVA_BRIDGE_SOURCE,
      fatal: true,
      java_bridge_failed: true,
    });
    return;
  }
  send({ type: 'diag', msg: 'java_bridge_ready', source: JAVA_BRIDGE_SOURCE });

  try {
    Java.perform(function () {

      // ── Mandatory Self-Test Gate ─────────────────────────────────────────────
      try {
        Java.use('java.lang.String');
        Java.use('java.lang.Thread');
      } catch (stErr) {
        send({
          type: 'error',
          description: 'Java self-test failed: ' + (stErr.stack || stErr.toString()),
          java_bridge_source: JAVA_BRIDGE_SOURCE,
          fatal: true,
          java_bridge_failed: true,
        });
        return;
      }
      send({ type: 'diag', msg: 'java_gate_passed', ts: Date.now() });

      // ── Deoptimize ART for hook reliability ──────────────────────────────────
      // Without this, ART may inline virtual dispatch, making method hooks unreachable.
      // Read once, outside the try, so a failure to read the API level cannot
      // leave `sdkLevel` undefined for the boot-image gate below - which would
      // fall through to the API<34 branch and re-introduce the ANR stall.
      var sdkLevel = 0;
      try {
        var BuildVersion = Java.use('android.os.Build$VERSION');
        sdkLevel = BuildVersion.SDK_INT ? BuildVersion.SDK_INT.value : 0;
        if (sdkLevel > 0 && sdkLevel < 34) {
          Java.deoptimizeEverything();
          send({ type: 'diag', msg: 'deoptimizeEverything_success', ts: Date.now() });
        } else {
          send({ type: 'diag', msg: 'deoptimizeEverything_skipped_api34_plus', sdk_int: sdkLevel, ts: Date.now() });
        }
      } catch (e) {
        send({ type: 'diag', msg: 'deoptimizeEverything_failed', error: e.message });
      }

      // deoptimizeBootImage: new in Frida 16.2 - deoptimizes AOT-compiled boot image
      // Fixes hooks on system classes that are inlined into the boot image (API 29+).
      //
      // Gated on the same API level as deoptimizeEverything above, and for the
      // same reason. On API 34+ (measured on an API 37 x86_64 emulator) this
      // call leaves the whole device crawling for ~30s. Android's ANR watchdog
      // fires well inside that, so the system puts up "<app> isn't responding"
      // over the sample before the walk has taken an action - measured four
      // consecutive ANRs, exploration stopping after 4 actions on 1 screen,
      // and no runtime behaviour captured at all.
      //
      // The trade-off is deliberate: deoptimizing the boot image makes hooks on
      // INLINED system classes more reliable, but a sample that never renders
      // its form produces no behaviour to hook. Hooks on the app's own classes,
      // which is where the credential-harvesting lives, do not depend on it.
      //
      // SUDARSHAN_DEOPT_BOOT_IMAGE=1 forces it back on for an investigation
      // that specifically needs boot-image coverage and can afford the stall.
      try {
        var forceDeopt = DEOPT_BOOT_IMAGE_FORCED;
        if (forceDeopt || (sdkLevel > 0 && sdkLevel < 34)) {
          Java.deoptimizeBootImage();
          send({ type: 'diag', msg: 'deoptimizeBootImage_success', ts: Date.now() });
        } else {
          send({
            type: 'diag',
            msg: 'deoptimizeBootImage_skipped_api34_plus',
            sdk_int: sdkLevel,
            reason: 'stalls the device past the ANR watchdog on API 34+',
            ts: Date.now(),
          });
        }
      } catch (e) {
        send({ type: 'diag', msg: 'deoptimizeBootImage_skipped', error: e.message });
      }

      // Try to extract package name from Application context
      try {
        Java.scheduleOnMainThread(function () {
          try {
            var ActivityThread = Java.use('android.app.ActivityThread');
            var app = ActivityThread.currentApplication();
            if (app) {
              var pkg = app.getPackageName().toString();
              runtimeContext.package_name = pkg;
              send({ type: 'diag', msg: 'package_detected', package: pkg });
            }
          } catch (e) { /* non-fatal */ }
        });
      } catch (e) { /* non-fatal */ }

// ═══════════════════════════════════════════════════════════════════════════════
// [A] ACCESSIBILITY SERVICE HOOKS (weight 0.35 - heaviest BFCI component)
// ═══════════════════════════════════════════════════════════════════════════════

      try {
        // The framework BASE class is deliberately NOT hooked.
        //
        // Replacing android.accessibilityservice.AccessibilityService
        // .onAccessibilityEvent routes the whole process's accessibility
        // delivery through a Frida trampoline, and on API 37 that breaks the
        // accessibility pipeline outright: UiAutomation can no longer obtain a
        // root node, so `uiautomator dump` answers
        // "ERROR: null root node returned by UiTestAutomationBridge" forever.
        //
        // Bisected against the live e-challan payload, 16 dumps over 40s:
        //
        //   no agent .................... first readable 3.6s, 16/16
        //   full agent (81 hooks) ....... NEVER readable,      0/16
        //   full agent minus THIS hook .. first readable 2.4s, 16/16
        //
        // The explorer sees the screen through that same dump, so this one
        // hook was making every UI-driven objective impossible: 0 screens
        // observed, no form found, no field filled, and the ANR dialogs that
        // followed were the app being unable to answer accessibility requests.
        //
        // Nothing is lost analytically. A trojan does not instantiate the
        // abstract framework class - it ships its OWN AccessibilityService
        // subclass, and that subclass is what the scan below hooks. BFCI
        // scores the `accessibility` CATEGORY rather than a hook name, so a
        // subclass hit contributes exactly as the base hook did.

        // Hook the sample's OWN AccessibilityService subclasses. With the
        // framework base class left alone (above), this is where the whole
        // accessibility signal now comes from.
        //
        // Two things were wrong with how this used to run:
        //
        // 1. It was deferred with `setTimeout`, which never fires in this
        //    agent - the same dead-timer problem documented on the WebView
        //    drain. So it did not run AT ALL, and the "dynamic subclass" cover
        //    it was supposed to provide never existed. It now runs inline.
        //
        // 2. It called Java.use() on every loaded class that was not
        //    android.*/java.*/dalvik.*. On a WebView banking app that is
        //    thousands of classes, and Java.use() is not a lookup - it loads
        //    the class and builds a full JS wrapper, holding ART locks while
        //    it does. Running that inline without bounds would trade one stall
        //    for another, so it is bounded twice:
        //
        //      · only classes under the SAMPLE's own package prefix, which is
        //        where a trojan puts its service;
        //      · a hard cap on how many classes may be wrapped.
        //
        // Both bounds are on the Java.use() call, not on the enumeration -
        // walking the class NAMES is cheap, wrapping them is not.
        try {
          {
            {
              try {
                var pkg = runtimeContext.package_name || '';
                var prefix = '';
                var parts = pkg.split('.');
                if (parts.length >= 2 && parts[0] !== 'Unknown') prefix = parts[0] + '.' + parts[1] + '.';
                if (prefix) {
                  var wrapped = 0;
                  Java.enumerateLoadedClasses({
                    onMatch: function(className) {
                      if (wrapped >= ACCESSIBILITY_SUBCLASS_SCAN_LIMIT) return;
                      if (!className || className.indexOf('$') !== -1) return;
                      if (className.indexOf(prefix) !== 0) return;
                      if (className.indexOf('android.') === 0 ||
                          className.indexOf('androidx.') === 0 ||
                          className.indexOf('com.android.') === 0 ||
                          className.indexOf('com.google.') === 0 ||
                          className.indexOf('kotlin.') === 0 ||
                          className.indexOf('java.') === 0 ||
                          className.indexOf('dalvik.') === 0) return;
                      try {
                        wrapped++;
                        var targetCls = Java.use(className);
                        if (targetCls && targetCls.onAccessibilityEvent) {
                          targetCls.onAccessibilityEvent.implementation = function(event) {
                            var eventType = -1;
                            var pkgName = null;
                            try { eventType = event.getEventType(); } catch (e) {}
                            try { var pn = event.getPackageName(); pkgName = pn ? pn.toString() : null; } catch (e) {}
                            emit('accessibility', {
                              hook: className + '.onAccessibilityEvent',
                              class_name: className,
                              severity: 'CRITICAL',
                              event_type: eventType,
                              package: pkgName,
                              description: 'Accessibility event handled by custom service subclass: ' + className,
                            });
                            _noteForegroundPackage(pkgName, className + '.onAccessibilityEvent');
                            return this.onAccessibilityEvent(event);
                          };
                          registerHook(className + '.onAccessibilityEvent');
                        }
                      } catch(e) {}
                    },
                    onComplete: function() {
                      send({
                        type: 'diag',
                        msg: 'accessibility_subclass_scan',
                        prefix: prefix,
                        classes_wrapped: wrapped,
                        limit: ACCESSIBILITY_SUBCLASS_SCAN_LIMIT,
                      });
                    }
                  });
                }
              } catch (e) {}
            }
          }
        } catch (e) {}
      } catch (e) { reportHookError('AccessibilityService.subclass_scan', e.message); }

      try {
        var AccessibilityNodeInfo = Java.use('android.view.accessibility.AccessibilityNodeInfo');
        AccessibilityNodeInfo.getText.implementation = function () {
          var text = this.getText();
          if (text && text.length() > 0) {
            emit('accessibility', {
              hook: 'AccessibilityNodeInfo.getText',
              class_name: 'android.view.accessibility.AccessibilityNodeInfo',
              severity: 'HIGH',
              text_length: text.length(),
              description: 'App extracted UI element text (credential/OTP theft via ATS)',
            });
          }
          return text;
        };
        registerHook('AccessibilityNodeInfo.getText');

        AccessibilityNodeInfo.performAction.overload('int').implementation = function (action) {
          emit('accessibility', {
            hook: 'AccessibilityNodeInfo.performAction',
            class_name: 'android.view.accessibility.AccessibilityNodeInfo',
            severity: 'CRITICAL',
            action: action,
            description: 'App performed automated UI action via AccessibilityNodeInfo (ATS gesture injection)',
          });
          return this.performAction(action);
        };
        registerHook('AccessibilityNodeInfo.performAction');

        // findAccessibilityNodeInfosByText - ATS credential field location
        AccessibilityNodeInfo.findAccessibilityNodeInfosByText.implementation = function (text) {
          var result = this.findAccessibilityNodeInfosByText(text);
          var textStr = text ? text.toString() : '';
          emit('accessibility', {
            hook: 'AccessibilityNodeInfo.findAccessibilityNodeInfosByText',
            class_name: 'android.view.accessibility.AccessibilityNodeInfo',
            severity: 'HIGH',
            search_text: textStr.substring(0, 100),
            results_count: result ? result.size() : 0,
            description: 'App searched UI tree for text: ' + textStr.substring(0, 50),
          });
          return result;
        };
        registerHook('AccessibilityNodeInfo.findAccessibilityNodeInfosByText');
      } catch (e) { reportHookError('AccessibilityNodeInfo', e.message); }

      try {
        var AccessibilityServiceCls2 = Java.use('android.accessibilityservice.AccessibilityService');
        AccessibilityServiceCls2.dispatchGesture.overload(
          'android.accessibilityservice.GestureDescription',
          'android.accessibilityservice.AccessibilityService$GestureResultCallback',
          'android.os.Handler'
        ).implementation = function (gesture, callback, handler) {
          emit('accessibility', {
            hook: 'AccessibilityService.dispatchGesture',
            class_name: 'android.accessibilityservice.AccessibilityService',
            severity: 'CRITICAL',
            description: 'Automated gesture injected via Accessibility API (ATS tap/swipe injection)',
          });
          return this.dispatchGesture(gesture, callback, handler);
        };
        registerHook('AccessibilityService.dispatchGesture');
      } catch (e) { reportHookError('AccessibilityService.dispatchGesture', e.message); }

      try {
        var AccessibilityManager = Java.use('android.view.accessibility.AccessibilityManager');
        AccessibilityManager.sendAccessibilityEvent.implementation = function (event) {
          // UNSCORED ON PURPOSE.
          //
          // Android dispatches this whenever a view announces a UI change, so
          // every app with a user interface fires it. It is not a property of
          // the sample.
          //
          // It used to emit under 'accessibility', which carries the heaviest
          // BFCI weight (0.35) and a cap of 2-3 events, so ONE dispatch scored
          // 50/100 for the component. Measured on this emulator: Anubis and
          // NewPipe - a banking trojan and a video player - each fired it
          // exactly once and BOTH scored BFCI 17.5 with accessibility 50.0.
          // The heaviest-weighted axis could not tell them apart.
          //
          // bfci_scorer's own note states the rule this restores: "A scored
          // category that also catches ordinary application behaviour is not a
          // weak signal - it is a constant, and it inflates every verdict
          // equally."
          //
          // Real accessibility ABUSE is still scored, by the hooks that
          // require the app to own a service or drive the screen:
          // onAccessibilityEvent, getText, performAction,
          // findAccessibilityNodeInfosByText, dispatchGesture.
          emit('app_telemetry', {
            hook: 'AccessibilityManager.sendAccessibilityEvent',
            class_name: 'android.view.accessibility.AccessibilityManager',
            severity: 'INFO',
            description: 'UI accessibility event dispatched (ordinary for any ' +
                         'app with a user interface; recorded, not scored)',
          });
          return this.sendAccessibilityEvent(event);
        };
        registerHook('AccessibilityManager.sendAccessibilityEvent');
      } catch (e) { reportHookError('AccessibilityManager.sendAccessibilityEvent', e.message); }

// ═══════════════════════════════════════════════════════════════════════════════
// [S] SMS / TELEPHONY HOOKS (weight 0.25)
// ═══════════════════════════════════════════════════════════════════════════════

      try {
        var SmsMessage = Java.use('android.telephony.SmsMessage');
        SmsMessage.getMessageBody.implementation = function () {
          var body = this.getMessageBody();
          emit('sms', {
            hook: 'SmsMessage.getMessageBody',
            class_name: 'android.telephony.SmsMessage',
            severity: 'CRITICAL',
            body_length: body ? body.length : 0,
            description: 'App read incoming SMS message body (OTP interception confirmed)',
          });
          return body;
        };
        registerHook('SmsMessage.getMessageBody');
      } catch (e) { reportHookError('SmsMessage.getMessageBody', e.message); }

      try {
        var SmsManager = Java.use('android.telephony.SmsManager');
        SmsManager.sendTextMessage.overload(
          'java.lang.String', 'java.lang.String', 'java.lang.String',
          'android.app.PendingIntent', 'android.app.PendingIntent'
        ).implementation = function (destinationAddress, scAddress, text, sentIntent, deliveryIntent) {
          emit('sms', {
            hook: 'SmsManager.sendTextMessage',
            class_name: 'android.telephony.SmsManager',
            severity: 'CRITICAL',
            destination: destinationAddress ? destinationAddress.toString() : null,
            text_length: text ? text.length : 0,
            description: 'App sent SMS message (covert exfiltration/SMS relay)',
          });
          return this.sendTextMessage(destinationAddress, scAddress, text, sentIntent, deliveryIntent);
        };
        registerHook('SmsManager.sendTextMessage');

        SmsManager.sendMultipartTextMessage.overload(
          'java.lang.String', 'java.lang.String', 'java.util.ArrayList',
          'java.util.ArrayList', 'java.util.ArrayList'
        ).implementation = function (dest, sc, parts, sentIntents, deliveryIntents) {
          emit('sms', {
            hook: 'SmsManager.sendMultipartTextMessage',
            class_name: 'android.telephony.SmsManager',
            severity: 'CRITICAL',
            destination: dest ? dest.toString() : null,
            parts_count: parts ? parts.size() : 0,
            description: 'App sent multipart SMS (split OTP/C2 command relay)',
          });
          return this.sendMultipartTextMessage(dest, sc, parts, sentIntents, deliveryIntents);
        };
        registerHook('SmsManager.sendMultipartTextMessage');
      } catch (e) { reportHookError('SmsManager', e.message); }

      try {
        var ContentResolver = Java.use('android.content.ContentResolver');
        ContentResolver.query.overload(
          'android.net.Uri', '[Ljava.lang.String;', 'java.lang.String',
          '[Ljava.lang.String;', 'java.lang.String'
        ).implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
          var uriStr = uri ? uri.toString() : '';
          if (uriStr.indexOf('sms') !== -1 || uriStr.indexOf('mms') !== -1 || uriStr.indexOf('contacts') !== -1) {
            emit('sms', {
              hook: 'ContentResolver.query',
              class_name: 'android.content.ContentResolver',
              severity: 'HIGH',
              uri: uriStr,
              description: 'App queried SMS/MMS/Contacts content provider: ' + uriStr,
            });
          }
          return this.query(uri, projection, selection, selectionArgs, sortOrder);
        };
        registerHook('ContentResolver.query(sms/mms/contacts)');

        ContentResolver.insert.overload(
          'android.net.Uri', 'android.content.ContentValues'
        ).implementation = function (uri, values) {
          var uriStr = uri ? uri.toString() : '';
          if (uriStr.indexOf('sms') !== -1 || uriStr.indexOf('contacts') !== -1) {
            emit('sms', {
              hook: 'ContentResolver.insert',
              class_name: 'android.content.ContentResolver',
              severity: 'HIGH',
              uri: uriStr,
              description: 'App inserted data into SMS/Contacts provider: ' + uriStr,
            });
          }
          return this.insert(uri, values);
        };
        registerHook('ContentResolver.insert');

        ContentResolver.delete.overload(
          'android.net.Uri', 'java.lang.String', '[Ljava.lang.String;'
        ).implementation = function (uri, where, whereArgs) {
          var uriStr = uri ? uri.toString() : '';
          if (uriStr.indexOf('sms') !== -1) {
            emit('sms', {
              hook: 'ContentResolver.delete',
              class_name: 'android.content.ContentResolver',
              severity: 'CRITICAL',
              uri: uriStr,
              description: 'App deleted SMS messages (evidence destruction): ' + uriStr,
            });
          }
          return this.delete(uri, where, whereArgs);
        };
        registerHook('ContentResolver.delete');
      } catch (e) { reportHookError('ContentResolver', e.message); }

      // NOTE ON CATEGORY: these four hooks read device/subscriber IDENTITY. None
      // of them reads, intercepts, sends or deletes an SMS. They previously
      // emitted to 'sms' - weight 0.25, cap 2 - so any app calling getDeviceId()
      // and getSubscriberId() scored sms=100 and contributed 25 points of BFCI
      // with no SMS involvement at all. That is thousands of ordinary analytics
      // SDKs. They now emit to the unscored 'device_fingerprint' category:
      // still collected, still reported, no longer scored as OTP theft.
      try {
        var TelephonyManager = Java.use('android.telephony.TelephonyManager');
        TelephonyManager.getLine1Number.overload().implementation = function () {
          var num = this.getLine1Number();
          emit('device_fingerprint', {
            hook: 'TelephonyManager.getLine1Number',
            class_name: 'android.telephony.TelephonyManager',
            severity: 'MED',
            description: 'App queried device phone number (MSISDN - device identity)',
          });
          return num;
        };
        registerHook('TelephonyManager.getLine1Number');

        TelephonyManager.getSimSerialNumber.overload().implementation = function () {
          var serial = this.getSimSerialNumber();
          emit('device_fingerprint', {
            hook: 'TelephonyManager.getSimSerialNumber',
            class_name: 'android.telephony.TelephonyManager',
            severity: 'MED',
            description: 'App queried SIM Serial Number (ICCID - device fingerprinting)',
          });
          return serial;
        };
        registerHook('TelephonyManager.getSimSerialNumber');

        TelephonyManager.getDeviceId.overload().implementation = function () {
          var id = this.getDeviceId();
          emit('device_fingerprint', {
            hook: 'TelephonyManager.getDeviceId',
            class_name: 'android.telephony.TelephonyManager',
            severity: 'MED',
            description: 'App queried IMEI/Device ID (device fingerprinting)',
          });
          return id;
        };
        registerHook('TelephonyManager.getDeviceId');

        TelephonyManager.getSubscriberId.overload().implementation = function () {
          var id = this.getSubscriberId();
          emit('device_fingerprint', {
            hook: 'TelephonyManager.getSubscriberId',
            class_name: 'android.telephony.TelephonyManager',
            severity: 'MED',
            description: 'App queried IMSI subscriber ID (device fingerprinting)',
          });
          return id;
        };
        registerHook('TelephonyManager.getSubscriberId');
      } catch (e) { reportHookError('TelephonyManager', e.message); }

// ═══════════════════════════════════════════════════════════════════════════════
// [O] OVERLAY / SYSTEM ALERT WINDOW HOOKS (weight 0.20)
// ═══════════════════════════════════════════════════════════════════════════════

      try {
        var LayoutParams = Java.use('android.view.WindowManager$LayoutParams');
        var wm_impl = Java.use('android.view.WindowManagerImpl');

        // Returns the window type, or -1 when it cannot be determined.
        var windowTypeOf = function (params) {
          if (!params) return -1;
          try {
            return Java.cast(params, LayoutParams).type.value;
          } catch (castErr) {
            return -1;
          }
        };

        wm_impl.addView.overload('android.view.View', 'android.view.ViewGroup$LayoutParams').implementation = function (view, params) {
          var type = windowTypeOf(params);
          if (OVERLAY_WINDOW_TYPES.indexOf(type) !== -1) {
            markOverlayView(view);
            emit('overlay', {
              hook: 'WindowManager.addView',
              class_name: 'android.view.WindowManagerImpl',
              severity: 'HIGH',
              window_type: type,
              description: 'App drew overlay window on top of screen (TYPE=' + type + '). Phishing overlay.',
            });
          }
          return this.addView(view, params);
        };
        registerHook('WindowManager.addView');

        // CATEGORY NOTE: updateViewLayout and removeView are on the path of every
        // AlertDialog, Toast, PopupWindow, spinner dropdown and soft-keyboard
        // resize. They previously emitted to 'overlay' unconditionally - weight
        // 0.20, cap 2 - so ANY app that showed and dismissed a dialog scored
        // overlay=100 and contributed 20 points of BFCI. Only operations on a
        // view we ourselves saw added AS an overlay are overlay evidence; the
        // rest is ordinary UI and goes to the unscored 'app_telemetry'.
        wm_impl.updateViewLayout.overload('android.view.View', 'android.view.ViewGroup$LayoutParams').implementation = function (view, params) {
          var type = windowTypeOf(params);
          var isOverlayNow = OVERLAY_WINDOW_TYPES.indexOf(type) !== -1;

          // A view promoted to an overlay type via update is still an overlay.
          if (isOverlayNow) markOverlayView(view);

          if (isOverlayNow || isTrackedOverlayView(view)) {
            emit('overlay', {
              hook: 'WindowManager.updateViewLayout',
              class_name: 'android.view.WindowManagerImpl',
              severity: 'MED',
              window_type: type,
              description: 'App repositioned an active overlay window (TYPE=' + type + ')',
            });
          } else {
            emit('app_telemetry', {
              hook: 'WindowManager.updateViewLayout',
              class_name: 'android.view.WindowManagerImpl',
              severity: 'LOW',
              window_type: type,
              description: 'Ordinary window layout update (non-overlay type=' + type + ')',
            });
          }
          return this.updateViewLayout(view, params);
        };
        registerHook('WindowManager.updateViewLayout');

        wm_impl.removeView.overload('android.view.View').implementation = function (view) {
          if (isTrackedOverlayView(view)) {
            emit('overlay', {
              hook: 'WindowManager.removeView',
              class_name: 'android.view.WindowManagerImpl',
              severity: 'LOW',
              description: 'App removed a previously-observed overlay window',
            });
            forgetOverlayView(view);
          } else {
            emit('app_telemetry', {
              hook: 'WindowManager.removeView',
              class_name: 'android.view.WindowManagerImpl',
              severity: 'LOW',
              description: 'Ordinary window removed (never observed as an overlay)',
            });
          }
          return this.removeView(view);
        };
        registerHook('WindowManager.removeView');
      } catch (e) { reportHookError('WindowManager', e.message); }

      // NotificationListenerService hooking.
      //
      // CATEGORY NOTE: this is notification interception, not an overlay, and it
      // was saturating the overlay component. It is a genuinely strong OTP-theft
      // signal - binding a NotificationListenerService requires an explicit user
      // grant of Notification Access, which few benign apps hold - so it is a
      // CANDIDATE for its own BFCI weight. It is deliberately left UNSCORED here
      // rather than moved into 'sms', because adding weight is a model change and
      // this fix must not raise any existing verdict. See audit/12 §11.
      try {
        var NLS = Java.use('android.service.notification.NotificationListenerService');
        NLS.onNotificationPosted.overload('android.service.notification.StatusBarNotification').implementation = function (sbn) {
          var pkg = null;
          try { pkg = sbn.getPackageName(); } catch (e2) {}
          emit('notification', {
            hook: 'NotificationListenerService.onNotificationPosted',
            class_name: 'android.service.notification.NotificationListenerService',
            severity: 'HIGH',
            notification_package: pkg ? pkg.toString() : null,
            description: 'App intercepted notification (OTP/2FA notification theft): ' + (pkg ? pkg.toString() : 'unknown'),
          });
          return this.onNotificationPosted(sbn);
        };
        registerHook('NotificationListenerService.onNotificationPosted');
      } catch (e) { reportHookError('NotificationListenerService', e.message); }

// ═══════════════════════════════════════════════════════════════════════════════
// [B] BANKING & CREDENTIAL HOOKS (weight 0.10)
// ═══════════════════════════════════════════════════════════════════════════════

      var BANKING_PACKAGES = [
        'com.boi.mobile', 'com.sbi.lotusintouch', 'com.snapwork.hdfc',
        'com.icici.mobile', 'com.axis.mobile', 'in.org.npci.upiapp',
        'net.one97.paytm', 'com.phonepe.app', 'com.google.android.apps.nbu.paisa.user',
        'com.amazon.mShop.android.shopping', 'com.whatsapp', 'com.google.android.gm',
        'com.kotak.mobile', 'com.idbi', 'com.pnb.lotusmobile',
      ];

      // Activity monitoring.
      //
      // CATEGORY NOTE: this fires on EVERY screen transition, including those
      // driven by our own agentic explorer. It was emitting to 'banking'
      // (weight 0.10, cap 3) - the previous comment here read "FIX: emit to
      // 'banking', not 'activity' (which doesn't exist)", i.e. it was filed
      // there because no suitable category existed, not because an activity
      // resume is banking evidence. Three screen transitions saturated the
      // component. It is context for the timeline, so it now goes to the
      // unscored 'app_telemetry'.
      try {
        var Activity = Java.use('android.app.Activity');
        Activity.onResume.implementation = function () {
          var name = this.getClass().getName();
          runtimeContext.current_activity = name;
          emit('app_telemetry', {
            hook: 'Activity.onResume',
            class_name: name,
            severity: 'LOW',
            activity: name,
            description: 'Activity resumed: ' + name,
          });
          return this.onResume();
        };
        registerHook('Activity.onResume');
      } catch (e) { reportHookError('Activity.onResume', e.message); }

      // Foreground banking-app detection.
      //
      // getRunningTasks() was the ONLY hook establishing real banking
      // targeting, and it cannot fire on this platform: deprecated in API 21
      // and restricted in API 22+ to return only the CALLER'S own tasks. On the
      // API 35 target the guarded emit below was unreachable, foreground_app
      // stayed 'Unknown' for the whole session, and the banking component was
      // left composed entirely of generic hooks.
      //
      // It is retained (a sample calling it is still worth recording) but the
      // real detection now comes from the accessibility event stream and from
      // UsageStatsManager, both of which do work on modern Android.
      function _noteForegroundPackage(pkg, hookName) {
        if (!pkg) return;
        runtimeContext.foreground_app = pkg;
        if (BANKING_PACKAGES.indexOf(pkg) !== -1) {
          emit('banking', {
            hook: hookName,
            class_name: 'foreground-detection',
            severity: 'HIGH',
            target_package: pkg,
            description: 'App observed a banking application in the foreground: ' + pkg,
          });
        }
      }

      try {
        var ActivityManager = Java.use('android.app.ActivityManager');
        ActivityManager.getRunningTasks.implementation = function (maxNum) {
          var tasks = this.getRunningTasks(maxNum);
          emit('device_fingerprint', {
            hook: 'ActivityManager.getRunningTasks',
            class_name: 'android.app.ActivityManager',
            severity: 'MED',
            description: 'App called getRunningTasks() (restricted since API 22 - '
                         + 'returns only the caller\'s own tasks)',
          });
          if (tasks && tasks.size() > 0) {
            try {
              var topActivity = tasks.get(0).topActivity;
              if (topActivity) {
                _noteForegroundPackage(
                  topActivity.getPackageName().toString(),
                  'ActivityManager.getRunningTasks'
                );
              }
            } catch (e2) {}
          }
          return tasks;
        };
        registerHook('ActivityManager.getRunningTasks');
      } catch (e) { reportHookError('ActivityManager.getRunningTasks', e.message); }

      // UsageStatsManager.queryEvents - the modern way to learn what is in the
      // foreground, and what malware actually uses now that getRunningTasks is
      // restricted. Requires PACKAGE_USAGE_STATS, so a call is itself notable.
      try {
        var UsageStatsManager = Java.use('android.app.usage.UsageStatsManager');
        UsageStatsManager.queryEvents.overload('long', 'long').implementation = function (begin, end) {
          emit('device_fingerprint', {
            hook: 'UsageStatsManager.queryEvents',
            class_name: 'android.app.usage.UsageStatsManager',
            severity: 'HIGH',
            description: 'App queried usage-stats events to determine the foreground '
                         + 'application (requires PACKAGE_USAGE_STATS)',
          });
          return this.queryEvents(begin, end);
        };
        registerHook('UsageStatsManager.queryEvents');
      } catch (e) { reportHookError('UsageStatsManager.queryEvents', e.message); }

      // SharedPreferences key classification.
      //
      // CATEGORY NOTE: the previous single regex matched `user|login|auth|token|
      // account|balance`, which hits ordinary preference keys in almost every
      // app, and filed all of them under 'banking'. The key set is now split:
      // only high-confidence credential material scores; generic session keys
      // are recorded as unscored context.
      var CREDENTIAL_KEY_RE = /(otp|mpin|cvv|cvc|passw|pwd|secret|credential|cardnum|card_num|pin_?code|_pin\b|^pin\b)/i;
      var SESSION_KEY_RE    = /(token|auth|login|user|account|balance|card)/i;

      try {
        var SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl');
        SharedPreferencesImpl.getString.implementation = function (key, defValue) {
          var value = this.getString(key, defValue);
          var keyStr = key ? key.toString() : '';
          if (CREDENTIAL_KEY_RE.test(keyStr)) {
            emit('banking', {
              hook: 'SharedPreferences.getString',
              class_name: 'android.app.SharedPreferencesImpl',
              severity: 'HIGH',
              pref_key: keyStr,
              value_length: value ? value.length : 0,
              description: 'App read credential material from SharedPreferences: ' + keyStr,
            });
          } else if (SESSION_KEY_RE.test(keyStr)) {
            emit('app_telemetry', {
              hook: 'SharedPreferences.getString',
              class_name: 'android.app.SharedPreferencesImpl',
              severity: 'LOW',
              pref_key: keyStr,
              value_length: value ? value.length : 0,
              description: 'App read session/identity key from SharedPreferences: ' + keyStr,
            });
          }
          return value;
        };
        registerHook('SharedPreferences.getString');
      } catch (e) { reportHookError('SharedPreferences.getString', e.message); }

      // CATEGORY NOTE: Cipher.doFinal fires on ANY encryption - every HTTPS-
      // adjacent operation, every EncryptedSharedPreferences read. It is not
      // evidence of banking-credential theft on its own and was saturating the
      // banking component. Retained as unscored context; the WHAT is carried by
      // the network and credential hooks, this only says crypto happened.
      try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.doFinal.overload('[B').implementation = function (input) {
          var output = this.doFinal(input);
          var algo = 'unknown';
          try { algo = this.getAlgorithm(); } catch (e2) {}
          emit('app_telemetry', {
            hook: 'Cipher.doFinal',
            class_name: 'javax.crypto.Cipher',
            severity: 'LOW',
            algorithm: algo,
            input_bytes: input ? input.length : 0,
            output_bytes: output ? output.length : 0,
            description: 'Crypto operation performed: algo=' + algo,
          });
          return output;
        };
        registerHook('Cipher.doFinal');
      } catch (e) { reportHookError('Cipher.doFinal', e.message); }

      try {
        var ClipboardManager = Java.use('android.content.ClipboardManager');
        ClipboardManager.getPrimaryClip.implementation = function () {
          var clip = this.getPrimaryClip();
          emit('banking', {
            hook: 'ClipboardManager.getPrimaryClip',
            class_name: 'android.content.ClipboardManager',
            severity: 'HIGH',
            description: 'App read clipboard contents (OTP/password/card number theft)',
          });
          return clip;
        };
        registerHook('ClipboardManager.getPrimaryClip');
      } catch (e) { reportHookError('ClipboardManager.getPrimaryClip', e.message); }

      // KeyStore.
      //
      // CATEGORY NOTE: getInstance() fires for any app using the Android
      // Keystore - including every app that pins a certificate or uses
      // EncryptedSharedPreferences. Obtaining a KeyStore handle is not credential
      // theft. Unscored context.
      try {
        var KeyStore = Java.use('java.security.KeyStore');
        KeyStore.getInstance.overload('java.lang.String').implementation = function (type) {
          var ks = this.getInstance(type);
          emit('app_telemetry', {
            hook: 'KeyStore.getInstance',
            class_name: 'java.security.KeyStore',
            severity: 'LOW',
            keystore_type: type ? type.toString() : null,
            description: 'App obtained a KeyStore handle: type=' + type,
          });
          return ks;
        };
        registerHook('KeyStore.getInstance');
      } catch (e) { reportHookError('KeyStore.getInstance', e.message); }

      // AccountManager - device account enumeration.
      // CATEGORY NOTE: reconnaissance, not banking targeting. Every
      // Google-account-aware app does this. Moved to device_fingerprint.
      try {
        var AccountManager = Java.use('android.accounts.AccountManager');
        AccountManager.getAccountsByType.implementation = function (type) {
          var accounts = this.getAccountsByType(type);
          emit('device_fingerprint', {
            hook: 'AccountManager.getAccountsByType',
            class_name: 'android.accounts.AccountManager',
            severity: 'MED',
            account_type: type ? type.toString() : null,
            count: accounts ? accounts.length : 0,
            description: 'App enumerated device accounts: type=' + type,
          });
          return accounts;
        };
        registerHook('AccountManager.getAccountsByType');
      } catch (e) { reportHookError('AccountManager.getAccountsByType', e.message); }

      // PackageManager - installed apps enumeration.
      //
      // CATEGORY NOTE: this IS ATS target reconnaissance when malware does it - // but launchers, app stores, antivirus and many analytics SDKs do it too,
      // and it was scoring 'banking' on its own. Enumeration alone does not
      // establish banking targeting; the ActivityManager hook below does, by
      // matching an actual banking package. Moved to device_fingerprint.
      //
      // Note the workflow reconstructor still raises a "Banking App Detection"
      // stage from these hook NAMES (it matches on hook, not category), so the
      // narrative evidence is preserved.
      try {
        var PackageManager = Java.use('android.content.pm.PackageManager');
        PackageManager.getInstalledApplications.overload('int').implementation = function (flags) {
          var apps = this.getInstalledApplications(flags);
          emit('device_fingerprint', {
            hook: 'PackageManager.getInstalledApplications',
            class_name: 'android.content.pm.PackageManager',
            severity: 'MED',
            app_count: apps ? apps.size() : 0,
            description: 'App enumerated all installed applications (target reconnaissance)',
          });
          return apps;
        };
        registerHook('PackageManager.getInstalledApplications');

        PackageManager.getInstalledPackages.overload('int').implementation = function (flags) {
          var pkgs = this.getInstalledPackages(flags);
          emit('device_fingerprint', {
            hook: 'PackageManager.getInstalledPackages',
            class_name: 'android.content.pm.PackageManager',
            severity: 'MED',
            pkg_count: pkgs ? pkgs.size() : 0,
            description: 'App enumerated all installed packages (target reconnaissance)',
          });
          return pkgs;
        };
        registerHook('PackageManager.getInstalledPackages');
      } catch (e) { reportHookError('PackageManager', e.message); }

      // InputMethodManager.
      // CATEGORY NOTE: fires whenever ANY keyboard appears. Unscored context.
      try {
        var InputMethodManager = Java.use('android.view.inputmethod.InputMethodManager');
        InputMethodManager.showSoftInput.overload('android.view.View', 'int').implementation = function (view, flags) {
          emit('app_telemetry', {
            hook: 'InputMethodManager.showSoftInput',
            class_name: 'android.view.inputmethod.InputMethodManager',
            severity: 'LOW',
            description: 'Soft keyboard shown (text input field focused)',
          });
          return this.showSoftInput(view, flags);
        };
        registerHook('InputMethodManager.showSoftInput');
      } catch (e) { reportHookError('InputMethodManager.showSoftInput', e.message); }

// ═══════════════════════════════════════════════════════════════════════════════
// [N] NETWORK C2 HOOKS (weight 0.05)
// ═══════════════════════════════════════════════════════════════════════════════

      try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function () {
          var urlStr = this.toString();
          emit('network', {
            hook: 'URL.openConnection',
            class_name: 'java.net.URL',
            severity: 'MED',
            url: urlStr,
            ioc: urlStr,
            description: 'Network connection opened to: ' + urlStr,
          });
          return this.openConnection();
        };
        registerHook('URL.openConnection');
      } catch (e) { reportHookError('URL.openConnection', e.message); }

      try {
        var Socket = Java.use('java.net.Socket');
        Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function (endpoint, timeout) {
          var epStr = endpoint ? endpoint.toString() : '';
          emit('network', {
            hook: 'Socket.connect',
            class_name: 'java.net.Socket',
            severity: 'MED',
            endpoint: epStr,
            // `url` is the key frida_sandbox reads to build network_logs.
            // Without it, raw-socket C2 - one of the two paths malware uses
            // specifically to avoid Java HTTP hooks - produced no IOC at all.
            url: epStr,
            ioc: epStr,
            description: 'Direct socket connection to: ' + epStr,
          });
          return this.connect(endpoint, timeout);
        };
        registerHook('Socket.connect');
      } catch (e) { reportHookError('Socket.connect', e.message); }

      // HttpsURLConnection - SSL certificate pinning bypass detection
      try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.connect.implementation = function () {
          var url = '';
          try { url = this.getURL().toString(); } catch (e2) {}
          emit('network', {
            hook: 'HttpsURLConnection.connect',
            class_name: 'javax.net.ssl.HttpsURLConnection',
            severity: 'MED',
            url: url,
            ioc: url,
            description: 'HTTPS connection established to: ' + url,
          });
          return this.connect();
        };
        registerHook('HttpsURLConnection.connect');
      } catch (e) { reportHookError('HttpsURLConnection.connect', e.message); }

      try {
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.getInputStream.implementation = function () {
          var urlStr = '';
          try { urlStr = this.getURL().toString(); } catch (e2) {}
          emit('network', {
            hook: 'HttpURLConnection.getInputStream',
            class_name: 'java.net.HttpURLConnection',
            severity: 'MED',
            url: urlStr,
            ioc: urlStr,
            description: 'HttpURLConnection getInputStream for: ' + urlStr,
          });
          return this.getInputStream();
        };
        registerHook('HttpURLConnection.getInputStream');
      } catch (e) { reportHookError('HttpURLConnection.getInputStream', e.message); }

      // OkHttp3 - most banking malware uses OkHttp for C2
      try {
        var RealCall = Java.use('okhttp3.internal.connection.RealCall');
        RealCall.execute.implementation = function () {
          var urlStr = '';
          try { urlStr = this.request().url().toString(); } catch (e2) {}
          var method = '';
          try { method = this.request().method(); } catch (e2) {}
          emit('network', {
            hook: 'OkHttp.RealCall.execute',
            class_name: 'okhttp3.internal.connection.RealCall',
            severity: 'MED',
            url: urlStr,
            method: method,
            ioc: urlStr,
            description: 'OkHttp3 synchronous request: ' + method + ' ' + urlStr,
          });
          return this.execute();
        };
        registerHook('OkHttp.RealCall.execute');

        RealCall.enqueue.implementation = function (responseCallback) {
          var urlStr = '';
          try { urlStr = this.request().url().toString(); } catch (e2) {}
          var method = '';
          try { method = this.request().method(); } catch (e2) {}
          emit('network', {
            hook: 'OkHttp.RealCall.enqueue',
            class_name: 'okhttp3.internal.connection.RealCall',
            severity: 'MED',
            url: urlStr,
            method: method,
            ioc: urlStr,
            description: 'OkHttp3 asynchronous request enqueued: ' + method + ' ' + urlStr,
          });
          return this.enqueue(responseCallback);
        };
        registerHook('OkHttp.RealCall.enqueue');
      } catch (e) { reportHookError('OkHttp', e.message); }

      // Retrofit - common C2 client wrapper
      try {
        var OkHttpCall = Java.use('retrofit2.OkHttpCall');
        OkHttpCall.execute.implementation = function () {
          emit('network', {
            hook: 'Retrofit.OkHttpCall.execute',
            class_name: 'retrofit2.OkHttpCall',
            severity: 'MED',
            description: 'Retrofit HTTP call executed (C2 API call)',
          });
          return this.execute();
        };
        registerHook('Retrofit.OkHttpCall.execute');
      } catch (e) { reportHookError('Retrofit.OkHttpCall.execute', e.message); }

      // ── WebView instance registry ──────────────────────────────────────────
      //
      // A WebView's JS runs in Chromium's own process-internal stack, so a page
      // that submits with fetch() or XHR touches NO Java networking API. Every
      // Java-side hook below is blind to it. Measured on an e-challan sample
      // whose entire journey is an HTML form: 69 hooks installed, the victim
      // filled and submitted the form, and not one network event fired.
      //
      // The only vantage point that sees those requests is inside the page, so
      // the instances have to be reachable to inject into. Held here as they
      // are seen; capped, because a retained reference keeps the view alive.
      var sdsnWebViews = [];
      var sdsnSeen = {};
      var SDSN_MAX_WEBVIEWS = 8;

      function rememberWebView(wv, deferHooksTo) {
        try {
          if (!wv) return;
          var h = wv.hashCode();
          if (sdsnSeen[h]) return;
          if (sdsnWebViews.length >= SDSN_MAX_WEBVIEWS) return;
          sdsnSeen[h] = 1;
          sdsnWebViews.push(Java.retain(wv));
          sdsnWebViewCount = sdsnWebViews.length;
          // The drain trigger has to be hooked on the class this view ACTUALLY
          // is (see sdsnHookTouchFor) - but NOT from here when we are inside a
          // Java.choose enumeration. Replacing a method implementation during
          // a heap walk reports success and then never fires: measured, the
          // hook installed, logged webview_touch_hooked, and no touch ever
          // reached it. The caller passes an array to collect into and hooks
          // once the walk has finished.
          if (deferHooksTo) deferHooksTo.push(wv.$className);
          else sdsnHookTouchFor(wv.$className);
        } catch (e) { /* a view we cannot hold is one we cannot inject into */ }
      }

      //: Classes whose onTouchEvent has already been hooked.
      var sdsnTouchHooked = {};

      /**
       * Hook the drain trigger on the WebView's own class.
       *
       * Hooking android.webkit.WebView.onTouchEvent is not enough. A framework
       * WebView is routinely subclassed, and a subclass that OVERRIDES
       * onTouchEvent without calling super never reaches the base
       * implementation - so the base hook is installed, reports no error, and
       * silently never fires. Measured on a Capacitor app: with both hooked,
       * com.getcapacitor.CapacitorWebView.onTouchEvent fired on every tap while
       * android.webkit.WebView.onTouchEvent fired zero times.
       *
       * The class name is taken from the live instance, so this stays generic:
       * nothing here knows about any particular framework.
       */
      function sdsnHookTouchFor(className) {
        if (!className || sdsnTouchHooked[className]) return;
        sdsnTouchHooked[className] = 1;
        try {
          var Cls = Java.use(className);
          if (!Cls.onTouchEvent) return;
          Cls.onTouchEvent.overload('android.view.MotionEvent')
            .implementation = function (ev) {
              var result = this.onTouchEvent(ev);
              try {
                // ACTION_UP (1) only: a drag delivers dozens of MOVE events,
                // and re-injecting the shim on each would be pointless work on
                // the UI thread.
                if (ev && ev.getAction() === 1 && SdsnDrainCallback) {
                  // Already on the UI thread here - the only thread allowed to
                  // call evaluateJavascript - so drain directly.
                  sdsnDrainNow();
                }
              } catch (e) { /* never let instrumentation break a touch */ }
              return result;
            };
          send({ type: 'diag', msg: 'webview_touch_hooked', cls: className });
        } catch (e) {
          send({
            type: 'diag', msg: 'webview_touch_hook_failed',
            cls: className, error: e.message,
          });
        }
      }

      // WebView - loading C2 URLs, evaluating injected JS
      try {
        var WebView = Java.use('android.webkit.WebView');
        WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
          rememberWebView(this);
          emit('network', {
            hook: 'WebView.loadUrl',
            class_name: 'android.webkit.WebView',
            severity: 'HIGH',
            url: url ? url.toString() : null,
            ioc: url ? url.toString() : null,
            description: 'WebView loaded URL: ' + (url ? url.toString() : 'null'),
          });
          return this.loadUrl(url);
        };
        registerHook('WebView.loadUrl');

        WebView.loadData.overload('java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function (data, mime, encoding) {
          var preview = data ? data.substring(0, 500) : '';
          emit('network', {
            hook: 'WebView.loadData',
            class_name: 'android.webkit.WebView',
            severity: 'HIGH',
            html_preview: preview,
            mime: mime ? mime.toString() : null,
            description: 'WebView.loadData HTML overlay (' + (preview ? preview.length : 0) + ' chars)',
          });
          return this.loadData(data, mime, encoding);
        };
        registerHook('WebView.loadData');

        WebView.loadDataWithBaseURL.overload(
          'java.lang.String',
          'java.lang.String',
          'java.lang.String',
          'java.lang.String',
          'java.lang.String'
        ).implementation = function (baseUrl, data, mime, encoding, historyUrl) {
          rememberWebView(this);
          var preview = data ? data.substring(0, 500) : '';
          emit('network', {
            hook: 'WebView.loadDataWithBaseURL',
            class_name: 'android.webkit.WebView',
            severity: 'HIGH',
            html_preview: preview,
            base_url: baseUrl ? baseUrl.toString() : null,
            description: 'WebView.loadDataWithBaseURL overlay (' + (preview ? preview.length : 0) + ' chars)',
          });
          return this.loadDataWithBaseURL(baseUrl, data, mime, encoding, historyUrl);
        };
        registerHook('WebView.loadDataWithBaseURL');

        WebView.evaluateJavascript.overload('java.lang.String', 'android.webkit.ValueCallback').implementation = function (script, callback) {
          var scriptPreview = script ? script.substring(0, 200) : '';
          emit('network', {
            hook: 'WebView.evaluateJavascript',
            class_name: 'android.webkit.WebView',
            severity: 'HIGH',
            script_preview: scriptPreview,
            description: 'WebView evaluated JavaScript (possible JS injection/overlay): ' + scriptPreview,
          });
          return this.evaluateJavascript(script, callback);
        };
        registerHook('WebView.evaluateJavascript');

        // A JS->Java bridge is how a page reaches native capability - and how a
        // phishing page ships what it collected back into the app.
        try {
          WebView.addJavascriptInterface.overload('java.lang.Object', 'java.lang.String')
            .implementation = function (obj, name) {
              emit('network', {
                hook: 'WebView.addJavascriptInterface',
                class_name: 'android.webkit.WebView',
                severity: 'HIGH',
                interface_name: name ? name.toString() : null,
                description:
                  'WebView exposed a Java object to page JavaScript as "' +
                  (name ? name.toString() : '?') +
                  '" - page script can now call into the app',
              });
              return this.addJavascriptInterface(obj, name);
            };
          registerHook('WebView.addJavascriptInterface');
        } catch (e) { reportHookError('WebView.addJavascriptInterface', e.message); }

        try {
          WebView.postUrl.overload('java.lang.String', '[B').implementation =
            function (url, body) {
              emit('network', {
                hook: 'WebView.postUrl',
                class_name: 'android.webkit.WebView',
                severity: 'HIGH',
                url: url ? url.toString() : null,
                ioc: url ? url.toString() : null,
                description: 'WebView POSTed to: ' + (url ? url.toString() : 'null'),
              });
              return this.postUrl(url, body);
            };
          registerHook('WebView.postUrl');
        } catch (e) { reportHookError('WebView.postUrl', e.message); }
      } catch (e) { reportHookError('WebView', e.message); }

// ═══════════════════════════════════════════════════════════════════════════════
// [W] IN-PAGE (JAVASCRIPT) NETWORK VISIBILITY
//
// The gap this closes: a WebView app's requests are issued by Chromium, not by
// java.net or OkHttp, so `HttpURLConnection`, `Socket` and the OkHttp hooks
// never see them. `WebView.loadUrl` catches only the initial navigation. An
// HTML form that posts with fetch() is, to every Java hook, completely silent.
//
// The page's own JS is the only place those calls are observable, so a shim is
// installed INTO the page: it wraps fetch, XMLHttpRequest, sendBeacon and form
// submission, queues what it sees, and hands the queue back on the next poll.
//
// Deliberately observe-only. Nothing is blocked, nothing is rewritten, and
// every wrapper calls through to the original - an analysis that changes what
// the app does is measuring itself.
// ═══════════════════════════════════════════════════════════════════════════════

      // Idempotent: a page that navigates loses `window`, so the shim is
      // re-sent on every poll and returns early when it is already present.
      // Password-typed inputs are recorded as <redacted>: the point is to show
      // WHICH fields leave the device, not to write a synthetic secret into a
      // forensic report.
      var SDSN_SHIM = [
        '(function(){',
        'if(window.__sdsn){return window.__sdsn_drain?window.__sdsn_drain():"[]";}',
        'window.__sdsn=1;window.__sdsnQ=[];',
        'function push(k,m,u,b){try{if(window.__sdsnQ.length<200){',
        'window.__sdsnQ.push({k:k,m:String(m||"GET"),u:String(u||""),',
        'b:b?String(b).substring(0,512):"",t:Date.now()});}}catch(e){}}',
        'function ser(f){try{var o=[],els=f.elements||[];',
        'for(var i=0;i<els.length;i++){var el=els[i];if(!el.name)continue;',
        'o.push(el.name+"="+(el.type==="password"?"<redacted>":',
        'String(el.value||"").substring(0,64)));}return o.join("&");}catch(e){return "";}}',
        'try{var of=window.fetch;if(of){window.fetch=function(i,o){try{',
        'var u=(i&&i.url)?i.url:i;var m=(o&&o.method)||(i&&i.method)||"GET";',
        'push("fetch",m,u,(o&&o.body)||null);}catch(e){}',
        'return of.apply(this,arguments);};}}catch(e){}',
        'try{var xo=XMLHttpRequest.prototype.open,xs=XMLHttpRequest.prototype.send;',
        'XMLHttpRequest.prototype.open=function(m,u){this.__sm=m;this.__su=u;',
        'return xo.apply(this,arguments);};',
        'XMLHttpRequest.prototype.send=function(b){try{push("xhr",this.__sm,this.__su,b);}',
        'catch(e){}return xs.apply(this,arguments);};}catch(e){}',
        'try{if(navigator.sendBeacon){var sb=navigator.sendBeacon.bind(navigator);',
        'navigator.sendBeacon=function(u,d){try{push("beacon","POST",u,d);}catch(e){}',
        'return sb(u,d);};}}catch(e){}',
        'try{var fsub=HTMLFormElement.prototype.submit;',
        'HTMLFormElement.prototype.submit=function(){try{',
        'push("form_submit",this.method,this.action,ser(this));}catch(e){}',
        'return fsub.apply(this,arguments);};',
        'document.addEventListener("submit",function(ev){try{var f=ev.target;',
        'push("form_submit",f.method,f.action,ser(f));}catch(e){}},true);}catch(e){}',
        'window.__sdsn_drain=function(){try{return JSON.stringify(window.__sdsnQ.splice(0));}',
        'catch(e){return "[]";}};',
        'return "[]";})()',
      ].join('');

      var sdsnDrainDiag = 0;

      function sdsnHandleDrain(raw) {
        if (!raw) return;
        var records = null;
        try {
          // evaluateJavascript hands back a JSON-ENCODED value, so a JS string
          // arrives quoted and has to be unwrapped before it can be parsed.
          var once = JSON.parse(raw);
          records = (typeof once === 'string') ? JSON.parse(once) : once;
        } catch (e) {
          if (sdsnDrainDiag < 3) {
            sdsnDrainDiag++;
            send({
              type: 'diag', msg: 'webview_drain_unparsed',
              error: e.message, raw: String(raw).substring(0, 200),
            });
          }
          return;
        }
        if (sdsnDrainDiag < 3 && raw !== '"[]"') {
          sdsnDrainDiag++;
          send({
            type: 'diag', msg: 'webview_drain',
            raw: String(raw).substring(0, 200),
            parsed: records ? records.length : -1,
          });
        }
        if (!records || !records.length) return;

        for (var i = 0; i < records.length; i++) {
          var r = records[i];
          if (!r || !r.u) continue;
          emit('network', {
            hook: 'WebView.js.' + (r.k || 'request'),
            class_name: 'android.webkit.WebView',
            severity: 'HIGH',
            url: r.u,
            ioc: r.u,
            method: r.m || 'GET',
            body_preview: r.b || '',
            source: 'in_page_javascript',
            description:
              'WebView page JavaScript issued ' + (r.m || 'GET') + ' ' + r.u +
              ' via ' + (r.k || 'request') +
              ' - invisible to Java networking hooks',
          });
        }
      }

      // The return channel. evaluateJavascript is the only way to read a value
      // back out of a page, and it answers through a ValueCallback.
      var SdsnDrainCallback = null;
      try {
        var ValueCallbackCls = Java.use('android.webkit.ValueCallback');
        SdsnDrainCallback = Java.registerClass({
          name: 'com.sudarshan.analysis.WebViewDrainCallback',
          implements: [ValueCallbackCls],
          methods: {
            onReceiveValue: function (value) {
              try { sdsnHandleDrain(value ? value.toString() : ''); } catch (e) { /* never throw into ART */ }
            },
          },
        });
        registerHook('WebView.js.drain_channel');
      } catch (e) {
        // Recorded rather than swallowed: without this channel the shim still
        // installs and still queues, but nothing can read the queue - so the
        // report must not imply the page was watched.
        send({ type: 'diag', msg: 'webview_js_drain_unavailable', error: e.message });
        reportHookError('WebView.js.drain_channel', e.message);
      }

      var sdsnEvalFailureReported = false;

      // MUST be called on the UI thread. WebView is not thread-safe and
      // evaluateJavascript throws outright anywhere else.
      function sdsnDrainNow() {
        for (var i = 0; i < sdsnWebViews.length; i++) {
          try {
            sdsnWebViews[i].evaluateJavascript(SDSN_SHIM, SdsnDrainCallback.$new());
          } catch (e) {
            if (!sdsnEvalFailureReported) {
              sdsnEvalFailureReported = true;
              send({ type: 'diag', msg: 'webview_eval_failed', error: e.message });
            }
          }
        }
      }

      // A one-off sweep of the heap, because the WebView that matters usually
      // already exists: the page is built during startup, and on a hand-off
      // the agent attaches to a process that has been drawing for seconds. The
      // load hooks above only ever see views created after us.
      function sdsnSweepForWebViews() {
        var pendingClasses = [];
        try {
          Java.choose('android.webkit.WebView', {
            onMatch: function (instance) {
              rememberWebView(instance, pendingClasses);
            },
            onComplete: function () { },
          });
        } catch (e) {
          send({ type: 'diag', msg: 'webview_sweep_failed', error: e.message });
          return;
        }
        // Outside the heap walk, where a method replacement actually takes.
        for (var i = 0; i < pendingClasses.length; i++) {
          sdsnHookTouchFor(pendingClasses[i]);
        }
        // Reported, not silent. "How many WebViews are we injecting into?" is
        // the difference between "the page made no requests" and "we were
        // never looking at the page", and a report must never present the
        // second as the first.
        send({ type: 'diag', msg: 'webview_sweep', held: sdsnWebViews.length });

        // If WebViews already exist at attach time (the usual case for hybrid/Capacitor apps),
        // query their active URL and emit telemetry so pre-attach navigations are captured.
        if (sdsnWebViews.length > 0) {
          Java.scheduleOnMainThread(function () {
            try {
              for (var idx = 0; idx < sdsnWebViews.length; idx++) {
                var wvInst = sdsnWebViews[idx];
                var curUrl = wvInst.getUrl ? wvInst.getUrl() : null;
                var urlStr = curUrl ? curUrl.toString() : null;
                if (urlStr) {
                  emit('network', {
                    hook: 'WebView.loadUrl',
                    class_name: 'android.webkit.WebView',
                    severity: 'HIGH',
                    url: urlStr,
                    ioc: urlStr,
                    description: 'WebView active URL captured: ' + urlStr,
                  });
                }
              }
            } catch (err) {
              send({ type: 'diag', msg: 'webview_initial_url_query_error', error: err.message });
            }
          });
        }
      }

      function setupHostMessageHandlers() {
        recv('sudarshan_test_overlay', function onOverlay(msg) {
          if (sdsnWebViews.length > 0) {
            Java.scheduleOnMainThread(function () {
              try {
                var fakeHtml = msg.html || "<html><head><title>State Bank of India</title></head><body><h1>State Bank of India</h1><p>Online Net Banking Portal</p><input type='text' name='username'/><input type='password' name='password'/></body></html>";
                for (var i = 0; i < sdsnWebViews.length; i++) {
                  sdsnWebViews[i].loadDataWithBaseURL('https://retail.onlinesbi.sbi', fakeHtml, 'text/html', 'UTF-8', null);
                }
                send({ type: 'diag', msg: 'sudarshan_test_overlay_loaded' });
              } catch (e) {
                send({ type: 'diag', msg: 'sudarshan_test_overlay_error', error: e.toString() });
              }
            });
          }
          recv('sudarshan_test_overlay', onOverlay);
        });
      }

      try {
        sdsnSweepForWebViews();
        setupHostMessageHandlers();

        // ── What triggers a drain ────────────────────────────────────────────
        //
        // Neither of the obvious options works here:
        //
        //   · a timer in the agent - `setInterval` never fires once the script
        //     has loaded. Measured: zero heartbeat pings over 18s against the
        //     agent's own 3s interval, which has been dead this whole time.
        //   · an rpc call from the host - it arrives on a thread that is not
        //     attached to the VM, and Java.choose from there HANGS rather than
        //     failing, wedging the caller for the rest of the run.
        //
        // A touch on the WebView has neither problem: it is already on the UI
        // thread, which is the only thread allowed to call evaluateJavascript,
        // and it happens at exactly the moment the page is doing something. A
        // form is submitted by tapping it, so the tap that causes a request is
        // also what collects the previous one.
        // The hook itself is installed per WebView CLASS, by
        // rememberWebView -> sdsnHookTouchFor, because the class that
        // actually receives the touch is not known until a view is seen.
        registerHook('WebView.js.network_interception');
      } catch (e) { reportHookError('WebView.js.network_interception', e.message); }

// ═══════════════════════════════════════════════════════════════════════════════
// [P] PERSISTENCE & ADMIN HOOKS (weight 0.05)
// ═══════════════════════════════════════════════════════════════════════════════

      try {
        var DevicePolicyManager = Java.use('android.app.admin.DevicePolicyManager');
        DevicePolicyManager.isAdminActive.implementation = function (who) {
          var result = this.isAdminActive(who);
          emit('persistence', {
            hook: 'DevicePolicyManager.isAdminActive',
            class_name: 'android.app.admin.DevicePolicyManager',
            severity: 'HIGH',
            is_active: result,
            description: 'App checked Device Admin active status (ransomware/persistence check)',
          });
          return result;
        };
        registerHook('DevicePolicyManager.isAdminActive');

        DevicePolicyManager.lockNow.overload().implementation = function () {
          emit('persistence', {
            hook: 'DevicePolicyManager.lockNow',
            class_name: 'android.app.admin.DevicePolicyManager',
            severity: 'CRITICAL',
            description: 'App invoked lockNow() - RANSOMWARE/EXTORTION BEHAVIOR CONFIRMED',
          });
          return this.lockNow();
        };
        registerHook('DevicePolicyManager.lockNow');
      } catch (e) { reportHookError('DevicePolicyManager', e.message); }

      try {
        var AlarmManager = Java.use('android.app.AlarmManager');
        AlarmManager.setExact.overload('int', 'long', 'android.app.PendingIntent').implementation = function (type, triggerAtMillis, operation) {
          emit('persistence', {
            hook: 'AlarmManager.setExact',
            class_name: 'android.app.AlarmManager',
            severity: 'MED',
            trigger_ms: triggerAtMillis,
            description: 'App scheduled exact alarm for persistence/wakeup',
          });
          return this.setExact(type, triggerAtMillis, operation);
        };
        registerHook('AlarmManager.setExact');
      } catch (e) { reportHookError('AlarmManager.setExact', e.message); }

      try {
        var JobScheduler = Java.use('android.app.job.JobScheduler');
        JobScheduler.schedule.overload('android.app.job.JobInfo').implementation = function (job) {
          emit('persistence', {
            hook: 'JobScheduler.schedule',
            class_name: 'android.app.job.JobScheduler',
            severity: 'MED',
            job_id: job ? job.getId() : 0,
            description: 'App scheduled background JobScheduler job (persistence mechanism)',
          });
          return this.schedule(job);
        };
        registerHook('JobScheduler.schedule');
      } catch (e) { reportHookError('JobScheduler.schedule', e.message); }

// ═══════════════════════════════════════════════════════════════════════════════
// [D] DYNAMIC CODE LOADING & REFLECTION
// ═══════════════════════════════════════════════════════════════════════════════

      try {
        var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
        DexClassLoader.$init.overload(
          'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader'
        ).implementation = function (dexPath, optDir, libSearchPath, parent) {
          emit('code_execution', {
            hook: 'DexClassLoader.<init>',
            class_name: 'dalvik.system.DexClassLoader',
            severity: 'HIGH',
            dex_path: dexPath ? dexPath.toString() : null,
            description: 'App dynamically loaded secondary DEX: ' + (dexPath ? dexPath.toString() : 'null'),
          });
          return this.$init(dexPath, optDir, libSearchPath, parent);
        };
        registerHook('DexClassLoader.<init>');
      } catch (e) { reportHookError('DexClassLoader', e.message); }

      try {
        var PathClassLoader = Java.use('dalvik.system.PathClassLoader');
        PathClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader').implementation = function (dexPath, parent) {
          emit('dangerous_apis', {
            hook: 'PathClassLoader.<init>',
            class_name: 'dalvik.system.PathClassLoader',
            severity: 'HIGH',
            dex_path: dexPath ? dexPath.toString() : null,
            description: 'App loaded code via PathClassLoader: ' + (dexPath ? dexPath.toString() : 'null'),
          });
          return this.$init(dexPath, parent);
        };
        registerHook('PathClassLoader.<init>');
      } catch (e) { reportHookError('PathClassLoader', e.message); }

      try {
        var System = Java.use('java.lang.System');
        System.loadLibrary.implementation = function (libName) {
          var lib = libName ? libName.toString() : null;
          emit('dangerous_apis', {
            hook: 'System.loadLibrary',
            class_name: 'java.lang.System',
            severity: 'HIGH',
            lib_name: lib,
            description: 'App loaded native library: ' + lib,
          });
          return this.loadLibrary(libName);
        };
        registerHook('System.loadLibrary');
      } catch (e) { reportHookError('System.loadLibrary', e.message); }

      try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
          var cmdStr = cmd ? cmd.toString() : null;
          emit('code_execution', {
            hook: 'Runtime.exec',
            class_name: 'java.lang.Runtime',
            severity: 'CRITICAL',
            command: cmdStr,
            description: 'App executed shell command: ' + cmdStr,
          });
          return this.exec(cmd);
        };
        registerHook('Runtime.exec');

        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmds) {
          // `cmds` is ALREADY a Java array here. The previous code called
          // Java.array('java.lang.String', cmds), which CONSTRUCTS an array
          // from a JS array - passing a Java array to it throws, and a throw
          // inside a hook implementation propagates into the target method, so
          // a sample using the (very common) array form of exec() had the call
          // fail. Frida marshals a String[] to a JS array already; join it.
          var cmdStr = null;
          try {
            cmdStr = cmds ? Array.prototype.join.call(cmds, ' ') : null;
          } catch (joinErr) {
            cmdStr = String(cmds);
          }
          emit('code_execution', {
            hook: 'Runtime.exec[]',
            class_name: 'java.lang.Runtime',
            severity: 'CRITICAL',
            command: cmdStr,
            description: 'App executed shell command array: ' + cmdStr,
          });
          return this.exec(cmds);
        };
        registerHook('Runtime.exec[]');
      } catch (e) { reportHookError('Runtime.exec', e.message); }

      // ProcessBuilder - shell command execution alternative
      try {
        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        ProcessBuilder.start.implementation = function () {
          var command = '';
          try {
            var cmd = this.command();
            command = cmd ? cmd.toString() : '';
          } catch (e2) {}
          emit('code_execution', {
            hook: 'ProcessBuilder.start',
            class_name: 'java.lang.ProcessBuilder',
            severity: 'CRITICAL',
            command: command,
            description: 'App started process via ProcessBuilder: ' + command,
          });
          return this.start();
        };
        registerHook('ProcessBuilder.start');
      } catch (e) { reportHookError('ProcessBuilder.start', e.message); }

      // File access monitoring
      try {
        var FileInputStream = Java.use('java.io.FileInputStream');
        FileInputStream.$init.overload('java.lang.String').implementation = function (path) {
          var pathStr = path ? path.toString() : '';
          if (pathStr.indexOf('/data/') !== -1 || pathStr.indexOf('shared_prefs') !== -1 || pathStr.indexOf('.db') !== -1) {
            emit('files_accessed', {
              hook: 'FileInputStream.<init>',
              class_name: 'java.io.FileInputStream',
              severity: 'MED',
              path: pathStr,
              description: 'App opened sensitive file for reading: ' + pathStr,
            });
          }
          return this.$init(path);
        };
        registerHook('FileInputStream.<init>(String)');
      } catch (e) { reportHookError('FileInputStream', e.message); }

// ═══════════════════════════════════════════════════════════════════════════════
// [X] ANTI-ANALYSIS HOOKS & SPOOFING
// ═══════════════════════════════════════════════════════════════════════════════

      // Emulator-detection spoofing.
      //
      // The previous filter tested whether the KEY contained 'qemu' /
      // 'goldfish' / 'genymotion'. The checks that actually matter read keys
      // whose names contain none of those - it is the VALUE that gives the
      // emulator away:
      //
      //   ro.hardware          -> goldfish / ranchu
      //   ro.product.model     -> sdk_gphone64_x86_64
      //   ro.build.fingerprint -> ...generic...
      //   ro.product.device    -> emu64xa
      //
      // So the spoofing defeated essentially no real check. Both the key set
      // and the value set are now matched, plausible values are substituted
      // rather than a blanket '0' (returning '0' for ro.hardware is itself
      // anomalous), and the two-argument overload - the more common form - is
      // hooked as well.
      var EMULATOR_VALUE_MARKERS = /(goldfish|ranchu|qemu|genymotion|vbox|sdk_gphone|generic|emu64|android_x86)/i;
      var SPOOFED_PROPERTIES = {
        'ro.kernel.qemu':          '0',
        'ro.hardware':             'qcom',
        'ro.product.model':        'Pixel 7',
        'ro.product.device':       'panther',
        'ro.product.name':         'panther',
        'ro.product.manufacturer': 'Google',
        'ro.product.brand':        'google',
        'ro.build.product':        'panther',
        'ro.build.fingerprint':    'google/panther/panther:13/TQ3A.230805.001/10316531:user/release-keys',
        'ro.bootloader':           'slider-1.0-9012530',
        'ro.boot.hardware':        'qcom',
      };

      function _spoofProperty(keyStr, val) {
        // Returns the replacement value, or null to pass through unchanged.
        var valStr = val ? String(val) : '';
        var keyHit = Object.prototype.hasOwnProperty.call(SPOOFED_PROPERTIES, keyStr);
        var valHit = EMULATOR_VALUE_MARKERS.test(valStr);
        if (!keyHit && !valHit) return null;

        var replacement = keyHit ? SPOOFED_PROPERTIES[keyStr] : 'unknown';
        emit('anti_analysis', {
          hook: 'SystemProperties.get',
          class_name: 'android.os.SystemProperties',
          severity: 'HIGH',
          property_key: keyStr,
          original_value: valStr,
          spoofed_value: replacement,
          matched_on: keyHit ? 'key' : 'value',
          description: 'App probed emulator system property: ' + keyStr +
                       ' (was "' + valStr + '", spoofed to "' + replacement + '")',
        });
        return replacement;
      }

      try {
        var SystemProperties = Java.use('android.os.SystemProperties');

        SystemProperties.get.overload('java.lang.String').implementation = function (key) {
          var val = this.get(key);
          var spoofed = _spoofProperty(key ? key.toString() : '', val);
          return spoofed !== null ? spoofed : val;
        };
        registerHook('SystemProperties.get');

        // The (key, default) overload - more common than the single-arg form
        // and previously not hooked at all.
        SystemProperties.get.overload('java.lang.String', 'java.lang.String')
          .implementation = function (key, def) {
            var val = this.get(key, def);
            var spoofed = _spoofProperty(key ? key.toString() : '', val);
            return spoofed !== null ? spoofed : val;
          };
        registerHook('SystemProperties.get(default)');
      } catch (e) { reportHookError('SystemProperties.get', e.message); }

      // android.os.Build static fields - the single most common emulator check,
      // and previously not touched at all. These are static String fields, so
      // they are patched once rather than hooked per call.
      try {
        var Build = Java.use('android.os.Build');
        var BUILD_SPOOF = {
          FINGERPRINT:  'google/panther/panther:13/TQ3A.230805.001/10316531:user/release-keys',
          MODEL:        'Pixel 7',
          MANUFACTURER: 'Google',
          BRAND:        'google',
          DEVICE:       'panther',
          PRODUCT:      'panther',
          HARDWARE:     'qcom',
          BOOTLOADER:   'slider-1.0-9012530',
        };
        var spoofedFields = [];
        for (var field in BUILD_SPOOF) {
          if (!Object.prototype.hasOwnProperty.call(BUILD_SPOOF, field)) continue;
          try {
            var current = Build[field].value;
            if (current && EMULATOR_VALUE_MARKERS.test(String(current))) {
              try {
                var jField = Build.class.getDeclaredField(field);
                jField.setAccessible(true);
                jField.set(null, BUILD_SPOOF[field]);
              } catch (reflectErr) { /* ignore reflection write error */ }
              spoofedFields.push(field + '="' + current + '"');
            }
          } catch (fieldErr) { /* field absent on this API level */ }
        }
        if (spoofedFields.length > 0) {
          // THE SANDBOX DID THIS, NOT THE SAMPLE.
          //
          // This block runs unconditionally at hook-install time: we overwrite
          // emulator-identifying Build fields to hide the sandbox, whether or
          // not the app ever reads them. It therefore fires exactly once on
          // every emulator run and says nothing about the sample.
          //
          // It used to emit under 'anti_analysis'. Measured consequence: all
          // ten stored runs carried exactly one anti_analysis event - this one
          // - and dynamic_exclusion_reason() reads any anti_analysis event as
          // proof the SAMPLE evaded, which excluded the dynamic axis (weight
          // 0.35, the largest) on five banking trojans and let them score Safe.
          // The sandbox's own countermeasure was being recorded as the
          // sample's evasion, and the evidence was discarded because of it.
          //
          // Kept as evidence - what we changed on the device is provenance an
          // analyst needs - but in a category that cannot be mistaken for
          // sample behaviour. `actor` is explicit for the same reason.
          emit('harness_action', {
            hook: 'sandbox.build_fields_spoofed',
            class_name: 'android.os.Build',
            actor: 'harness',
            severity: 'INFO',
            spoofed_fields: spoofedFields,
            description: 'SANDBOX ACTION: emulator-identifying Build fields ' +
                         'replaced to conceal the analysis environment: ' +
                         spoofedFields.join(', ') +
                         ' (performed by the harness, not by the application)',
          });
        }
        registerHook('Build.staticFields');
      } catch (e) { reportHookError('Build.staticFields', e.message); }

      try {
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function () {
          emit('anti_analysis', {
            hook: 'Debug.isDebuggerConnected',
            class_name: 'android.os.Debug',
            severity: 'HIGH',
            description: 'App probed for debugger connection (anti-analysis evasion)',
          });
          return false; // Spoof: no debugger visible
        };
        registerHook('Debug.isDebuggerConnected');
      } catch (e) { reportHookError('Debug.isDebuggerConnected', e.message); }

      // ── Frida detection spoofing ──────────────────────────────────────────────
      // Some samples scan /proc/self/maps for frida-agent or check port 27042.
      // Anti-Frida line suppression.
      //
      // Returning null here USED to mean "skip this line" - but null from
      // readLine() is end-of-stream. A sample looping
      // `while ((line = br.readLine()) != null)` over /proc/self/maps therefore
      // stopped reading at the first frida line instead of skipping it, leaving
      // a truncated maps view that is itself anomalous and detectable.
      //
      // Now it advances to the next non-matching line, so the read continues
      // and simply does not contain the frida entries. Bounded so a file made
      // entirely of matching lines cannot spin.
      var MAX_SUPPRESSED_LINES = 200;
      try {
        var BufferedReader = Java.use('java.io.BufferedReader');
        BufferedReader.readLine.overload().implementation = function () {
          var line = this.readLine();
          var suppressed = 0;
          while (line !== null &&
                 (line.indexOf('frida') !== -1 || line.indexOf('gum-js') !== -1) &&
                 suppressed < MAX_SUPPRESSED_LINES) {
            suppressed++;
            line = this.readLine();   // skip it, keep the stream alive
          }
          if (suppressed > 0) {
            emit('anti_analysis', {
              hook: 'BufferedReader.readLine',
              class_name: 'java.io.BufferedReader',
              severity: 'HIGH',
              suppressed_lines: suppressed,
              description: 'App scanned a stream for Frida artifacts (anti-Frida detection attempt) - '
                           + suppressed + ' matching line(s) skipped, stream kept open',
            });
          }
          return line;
        };
        registerHook('BufferedReader.readLine(anti-frida)');
      } catch (e) { reportHookError('BufferedReader.readLine', e.message); }
      // ── Process Anti-Self-Termination Bypass ──────────────────────────────
      try {
        var System = Java.use('java.lang.System');
        System.exit.implementation = function (code) {
          emit('anti_analysis', {
            hook: 'System.exit',
            class_name: 'java.lang.System',
            severity: 'CRITICAL',
            exit_code: code,
            description: 'App attempted to self-terminate via System.exit(' + code + ') - blocked to preserve dynamic analysis',
          });
        };
        registerHook('System.exit');
      } catch (e) { reportHookError('System.exit', e.message); }

      try {
        var Process = Java.use('android.os.Process');
        Process.killProcess.implementation = function (pid) {
          emit('anti_analysis', {
            hook: 'Process.killProcess',
            class_name: 'android.os.Process',
            severity: 'CRITICAL',
            target_pid: pid,
            description: 'App attempted to self-terminate via Process.killProcess(' + pid + ') - blocked to preserve dynamic analysis',
          });
        };
        registerHook('Process.killProcess');
      } catch (e) { reportHookError('Process.killProcess', e.message); }

      try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exit.implementation = function (code) {
          emit('anti_analysis', {
            hook: 'Runtime.exit',
            class_name: 'java.lang.Runtime',
            severity: 'CRITICAL',
            exit_code: code,
            description: 'App attempted to self-terminate via Runtime.exit(' + code + ') - blocked to preserve dynamic analysis',
          });
        };
        registerHook('Runtime.exit');
      } catch (e) { reportHookError('Runtime.exit', e.message); }
      // ── ClassLoader late-hook monitoring ──────────────────────────────────────
      // Hook InMemoryDexClassLoader for packed APKs that load payload at runtime
      try {
        var InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');
        InMemoryDexClassLoader.$init.overload(
          'java.nio.ByteBuffer', 'java.lang.ClassLoader'
        ).implementation = function (buffer, parent) {
          emit('code_execution', {
            hook: 'InMemoryDexClassLoader.<init>',
            class_name: 'dalvik.system.InMemoryDexClassLoader',
            severity: 'CRITICAL',
            buffer_capacity: buffer ? buffer.capacity() : 0,
            description: 'App loaded DEX from memory buffer (packed/encrypted payload injection)',
          });
          return this.$init(buffer, parent);
        };
        registerHook('InMemoryDexClassLoader.<init>');
      } catch (e) { reportHookError('InMemoryDexClassLoader', e.message); }

      // ── Guaranteed Runtime Smoke-Test Hooks ──────────────────────────────────
      // Baseline runtime hooks ensuring observable events on ANY running application
      try {
        var Application = Java.use('android.app.Application');
        Application.onCreate.implementation = function () {
          emit('smoke', {
            hook: 'Application.onCreate',
            class_name: 'android.app.Application',
            severity: 'INFO',
            package: runtimeContext.package_name,
            description: 'Target Application process initialized: ' + runtimeContext.package_name,
          });
          return this.onCreate();
        };
        registerHook('Application.onCreate');
      } catch (e) { reportHookError('Application.onCreate', e.message); }

      try {
        var ActivityClass = Java.use('android.app.Activity');
        ActivityClass.onCreate.overload('android.os.Bundle').implementation = function (savedInstanceState) {
          var actName = this.getClass().getName();
          runtimeContext.current_activity = actName;
          emit('smoke', {
            hook: 'Activity.onCreate',
            class_name: actName,
            severity: 'INFO',
            activity: actName,
            package: runtimeContext.package_name,
            description: 'Activity created: ' + actName,
          });
          return this.onCreate(savedInstanceState);
        };
        registerHook('Activity.onCreate');
      } catch (e) { reportHookError('Activity.onCreate', e.message); }

      // java.lang.ClassLoader.loadClass is deliberately NOT hooked.
      //
      // It kills the target process on Android 14+ (reproduced on API 37):
      //
      //   JNI DETECTED ERROR IN APPLICATION: jstring is an invalid JNI
      //   transition frame reference ... in call to GetStringChars
      //   from java.lang.Class java.lang.ClassLoader.loadClass(java.lang.String)
      //   native: #95 pc ... /memfd:frida-agent-64.so
      //   -> Fatal signal 11 (SIGSEGV) in HeapTaskDaemon
      //
      // The cause is re-entrancy. frida-java-bridge resolves classes by calling
      // loadClass itself (class-factory.js caches `loader.loadClass` as its
      // lookup method), so a replacement that touches the bridge - which
      // `emit` does - re-enters the very method being dispatched. loadClass
      // also runs on ART's internal threads, where the className jstring's
      // transition frame is gone by the time the replacement reads it, and
      // CheckJNI aborts the process rather than tolerating the stale jobject.
      //
      // Observed cost: the sample died ~13s after attach, before the agentic
      // explorer took a single action, so every run reported
      // INSTRUMENTATION_FAILED with zero screenshots.
      //
      // Nothing is lost by dropping it. The hook only emitted INFO-severity
      // "Application class loaded: X" noise on the hottest method in the VM.
      // The behaviour that actually matters - a dropper loading a hidden
      // second stage - is captured by the DexClassLoader, PathClassLoader and
      // InMemoryDexClassLoader constructor hooks above, which fire rarely and
      // are not re-entrant.

      try {
        var ContextWrapper = Java.use('android.content.ContextWrapper');
        ContextWrapper.getSharedPreferences.overload('java.lang.String', 'int').implementation = function (name, mode) {
          if (name && !isDuplicate('pref_' + name)) {
            emit('smoke', {
              hook: 'ContextWrapper.getSharedPreferences',
              class_name: 'android.content.ContextWrapper',
              severity: 'INFO',
              preference_name: name,
              description: 'SharedPreferences accessed: ' + name,
            });
          }
          return this.getSharedPreferences(name, mode);
        };
        registerHook('ContextWrapper.getSharedPreferences');
      } catch (e) { reportHookError('ContextWrapper.getSharedPreferences', e.message); }

      // java.io.File.<init> is deliberately NOT hooked on Android 14+ / API 37.
      //
      // Just like java.lang.ClassLoader.loadClass above, it kills the target
      // process on Android 14+ / API 37 when called from background threads
      // (e.g. androidx.profileinstaller in ThreadPoolExecutor) or ART internal frames:
      //
      //   JNI DETECTED ERROR IN APPLICATION: JNI ERROR (app bug): jstring is an invalid
      //   JNI transition frame reference in call to GetStringChars from
      //   void java.io.File.<init>(java.lang.String)
      //   -> Fatal signal 6 (SIGABRT)
      //
      // File access is already reliably tracked by FileInputStream.<init>,
      // FileOutputStream, and libc open/dlopen hooks.
      // registerHook('File.<init>');

      // ─── Secondary payload: download, write, install request ──────────────
      //
      // A dropper's defining move is fetching a second APK and asking the
      // victim to install it. Nothing hooked that chain, so the download was
      // invisible and record_secondary_apk() had no producer. These three
      // hooks mark the three points the chain is observable at, and each
      // reports only what it actually saw - a queued download is not a
      // completed one, and an install INTENT is not an installation.

      try {
        var DownloadManagerCls = Java.use('android.app.DownloadManager');
        DownloadManagerCls.enqueue.implementation = function (request) {
          // The destination URI lives in a private field of Request and is not
          // reliably readable across API levels, so this reports the queueing
          // only. The URL itself is recovered from the network hooks, which do
          // see it; inventing one here would be a fact we did not observe.
          emit('network', {
            hook: 'DownloadManager.enqueue',
            class_name: 'android.app.DownloadManager',
            severity: 'HIGH',
            description: 'Application queued a background download via DownloadManager',
          });
          return this.enqueue(request);
        };
        registerHook('DownloadManager.enqueue');
      } catch (e) { reportHookError('DownloadManager.enqueue', e.message); }

      // java.io.FileOutputStream.<init> is deliberately NOT hooked on Android 14+ / API 37.
      //
      // Just like File.<init> and ClassLoader.loadClass, it causes CheckJNI
      // transition frame reference aborts when invoked by framework runtime threads.
      // Dropper APK installation is captured by DownloadManager.enqueue,
      // Intent.installPackageRequest, and dynamic ClassLoader hooks.
      // registerHook('FileOutputStream.apkWrite');

      try {
        var IntentClass = Java.use('android.content.Intent');
        IntentClass.setDataAndType.implementation = function (data, type) {
          try {
            if (type && type.indexOf('application/vnd.android.package-archive') >= 0) {
              var target = data ? ('' + data.toString()) : '';
              emit('persistence', {
                hook: 'Intent.installPackageRequest',
                class_name: 'android.content.Intent',
                severity: 'CRITICAL',
                path: target,
                description: (
                  'Application asked Android to install a package: ' + target +
                  ' (install REQUESTED - completion not observable here)'
                ),
              });
            }
          } catch (e2) { /* never break the app */ }
          return this.setDataAndType(data, type);
        };
        registerHook('Intent.installPackageRequest');
      } catch (e) { reportHookError('Intent.installPackageRequest', e.message); }

      try {
        var URLClass = Java.use('java.net.URL');
        URLClass.openConnection.overload().implementation = function () {
          var urlStr = this.toString();
          if (urlStr && !isDuplicate('url_' + urlStr)) {
            emit('smoke', {
              hook: 'URL.openConnection',
              class_name: 'java.net.URL',
              severity: 'INFO',
              url: urlStr,
              description: 'Application opened network URL connection: ' + urlStr,
            });
          }
          return this.openConnection();
        };
        registerHook('URL.openConnection');
      } catch (e) { reportHookError('URL.openConnection', e.message); }

      try {
        var WebView = Java.use('android.webkit.WebView');
        WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
          emit('smoke', {
            hook: 'WebView.loadUrl',
            class_name: 'android.webkit.WebView',
            severity: 'INFO',
            url: url,
            description: 'WebView loaded URL: ' + url,
          });
          return this.loadUrl(url);
        };
        registerHook('WebView.loadUrl');
      } catch (e) { reportHookError('WebView.loadUrl', e.message); }

      try {
        var SystemClass = Java.use('java.lang.System');
        SystemClass.loadLibrary.implementation = function (libname) {
          emit('smoke', {
            hook: 'System.loadLibrary',
            class_name: 'java.lang.System',
            severity: 'INFO',
            library: libname,
            description: 'Native library loaded: ' + libname,
          });
          return this.loadLibrary(libname);
        };
        registerHook('System.loadLibrary');
      } catch (e) { reportHookError('System.loadLibrary', e.message); }

      // ── Signal completion to Python ───────────────────────────────────────────
      send({
        type: 'ready',
        message: 'SUDARSHAN Frida hooks v4 (Frida17-native) loaded',
        hooks_installed: runtimeContext.hooks_installed,
        hook_errors: runtimeContext.hook_errors,
        ts: Date.now(),
      });

    }); // end Java.perform

  } catch (e) {
    send({
      type: 'error',
      description: 'Java.perform() failed: ' + (e.stack || e.toString()),
      java_bridge_source: JAVA_BRIDGE_SOURCE,
      fatal: true,
      java_bridge_failed: true,
    });
    return;
  }
} // end initHooks

// ═══════════════════════════════════════════════════════════════════════════════
// NATIVE INSTRUMENTATION - Phase 4: libc.so hooks
// Intercepts SSL/TLS, socket ops, process execution at native layer.
// Runs OUTSIDE Java.perform - purely native Frida Interceptor.
// ═══════════════════════════════════════════════════════════════════════════════
// Guard so re-invocation after a late dlopen cannot double-attach a hook.
var _nativeHooksInstalled = { libssl: false, libc: false, libart: false };

function installNativeHooks() {
  try {
    var libssl = Process.findModuleByName('libssl.so');
    if (libssl && !_nativeHooksInstalled.libssl) {
      _nativeHooksInstalled.libssl = true;
      // SSL_write - capture plaintext before encryption
      try {
        var SSL_write = resolveExport('libssl.so', 'SSL_write');
        if (SSL_write) {
          Interceptor.attach(SSL_write, {
            onEnter: function (args) {
              var ssl = args[0];
              var buf = args[1];
              var num = args[2].toInt32();
              if (num > 0 && num < 4096) {
                try {
                  var data = buf.readUtf8String(num);
                  if (data && data.length > 0) {
                    send({
                      type: 'event',
                      payload: {
                        event_id: 'native_ev_' + Date.now(),
                        timestamp: Date.now(),
                        category: 'network',
                        source: 'native',
                        hook: 'SSL_write',
                        severity: 'MED',
                        bytes: num,
                        preview: data.substring(0, 200),
                        description: 'SSL_write: plaintext captured (' + num + ' bytes)',
                        data: { hook: 'SSL_write', bytes: num, preview: data.substring(0, 200) },
                      }
                    });
                  }
                } catch (readErr) {}
              }
            }
          });
          send({ type: 'hook_installed', hook: 'native:SSL_write', total: ++runtimeContext.hooks_installed });
        }
      } catch (e) { reportHookError('native:SSL_write', e.message); }

      // SSL_read - capture incoming TLS data.
      //
      // The buffer pointer MUST be captured in onEnter. This previously read
      // `this.context.x1` in onLeave, but x1 is a caller-saved argument
      // register on ARM64: by the time SSL_read returns it has almost certainly
      // been clobbered by the function body. Every `preview` was therefore
      // garbage, and readUtf8String() on an arbitrary pointer can fault the
      // target process - a native segfault that the surrounding try/catch
      // cannot catch, killing the analysis outright.
      try {
        var SSL_read = resolveExport('libssl.so', 'SSL_read');
        if (SSL_read) {
          Interceptor.attach(SSL_read, {
            onEnter: function (args) {
              this.sslReadBuf = args[1];
            },
            onLeave: function (retval) {
              var num = retval.toInt32();
              if (num > 0 && num < 4096) {
                try {
                  var buf = this.sslReadBuf;
                  if (buf && !buf.isNull()) {
                    var data = buf.readUtf8String(num);
                    if (data && data.length > 0) {
                      send({
                        type: 'event',
                        payload: {
                          event_id: 'native_ev_' + Date.now(),
                          timestamp: Date.now(),
                          category: 'network',
                          source: 'native',
                          hook: 'SSL_read',
                          severity: 'MED',
                          bytes: num,
                          preview: data.substring(0, 200),
                          description: 'SSL_read: response data captured (' + num + ' bytes)',
                          data: { hook: 'SSL_read', bytes: num, preview: data.substring(0, 200) },
                        }
                      });
                    }
                  }
                } catch (readErr) {}
              }
            }
          });
          send({ type: 'hook_installed', hook: 'native:SSL_read', total: ++runtimeContext.hooks_installed });
        }
      } catch (e) { reportHookError('native:SSL_read', e.message); }
    }

    // libc.so - connect(), send(), recv(), execve()
    var libc = Process.findModuleByName('libc.so');
    if (libc && !_nativeHooksInstalled.libc) {
      _nativeHooksInstalled.libc = true;
      // connect() - socket connections
      try {
        var connect = resolveExport('libc.so', 'connect');
        if (connect) {
          Interceptor.attach(connect, {
            onEnter: function (args) {
              try {
                var addrPtr = args[1];
                var family = addrPtr.readU16();
                if (family === 2) { // AF_INET
                  var port = (addrPtr.add(2).readU8() << 8) | addrPtr.add(3).readU8();
                  var ip = addrPtr.add(4).readU8() + '.' + addrPtr.add(5).readU8() + '.' + addrPtr.add(6).readU8() + '.' + addrPtr.add(7).readU8();
                  send({
                    type: 'event',
                    payload: {
                      event_id: 'native_ev_' + Date.now(),
                      timestamp: Date.now(),
                      category: 'network',
                      source: 'native',
                      hook: 'libc.connect',
                      severity: 'MED',
                      ip: ip,
                      port: port,
                      ioc: ip + ':' + port,
                      description: 'Native connect() to ' + ip + ':' + port,
                      // `url` is the key frida_sandbox reads for network_logs;
                      // without it native-layer connections produced no IOC.
                      data: { hook: 'libc.connect', ip: ip, port: port,
                              url: ip + ':' + port },
                    }
                  });
                }
              } catch (e2) {}
            }
          });
          send({ type: 'hook_installed', hook: 'native:connect', total: ++runtimeContext.hooks_installed });
        }
      } catch (e) { reportHookError('native:connect', e.message); }

      // execve() - process execution
      try {
        var execve = resolveExport('libc.so', 'execve');
        if (execve) {
          Interceptor.attach(execve, {
            onEnter: function (args) {
              try {
                var path = args[0].readUtf8String();
                send({
                  type: 'event',
                  payload: {
                    event_id: 'native_ev_' + Date.now(),
                    timestamp: Date.now(),
                    category: 'code_execution',
                    source: 'native',
                    hook: 'libc.execve',
                    severity: 'CRITICAL',
                    command: path,
                    description: 'Native execve(): ' + path,
                    data: { hook: 'libc.execve', command: path },
                  }
                });
              } catch (e2) {}
            }
          });
          send({ type: 'hook_installed', hook: 'native:execve', total: ++runtimeContext.hooks_installed });
        }
      } catch (e) { reportHookError('native:execve', e.message); }

      // ptrace() - anti-debug self-check detection
      try {
        var ptrace = resolveExport('libc.so', 'ptrace');
        if (ptrace) {
          Interceptor.attach(ptrace, {
            onEnter: function (args) {
              var request = args[0].toInt32();
              if (request === 0) { // PTRACE_TRACEME - self-ptrace anti-debug
                send({
                  type: 'event',
                  payload: {
                    event_id: 'native_ev_' + Date.now(),
                    timestamp: Date.now(),
                    category: 'anti_analysis',
                    source: 'native',
                    hook: 'libc.ptrace',
                    severity: 'HIGH',
                    request: request,
                    description: 'App called ptrace(PTRACE_TRACEME) - self-anti-debug protection',
                    data: { hook: 'libc.ptrace', request: request },
                  }
                });
              }
            }
          });
          send({ type: 'hook_installed', hook: 'native:ptrace', total: ++runtimeContext.hooks_installed });
        }
      } catch (e) { reportHookError('native:ptrace', e.message); }

      // open() - sensitive file access at native level
      try {
        var open = resolveExport('libc.so', 'open');
        if (open) {
          Interceptor.attach(open, {
            onEnter: function (args) {
              try {
                var path = args[0].readUtf8String();
                if (path && (
                  path.indexOf('/proc/self/maps') !== -1 ||
                  path.indexOf('/proc/net/tcp') !== -1 ||
                  (path.indexOf('frida') !== -1 &&
                   !path.endsWith('.dex') &&
                   !path.endsWith('.prof') &&
                   !path.endsWith('.odex') &&
                   !path.endsWith('.vdex') &&
                   path.indexOf('/oat/') === -1 &&
                   path.indexOf('/data/user/') === -1 &&
                   path.indexOf('/data/data/') === -1) ||
                  path.indexOf('/system/bin/su') !== -1
                )) {
                  send({
                    type: 'event',
                    payload: {
                      event_id: 'native_ev_' + Date.now(),
                      timestamp: Date.now(),
                      category: 'anti_analysis',
                      source: 'native',
                      hook: 'libc.open',
                      severity: 'HIGH',
                      path: path,
                      description: 'App opened sensitive path (anti-analysis probe): ' + path,
                      data: { hook: 'libc.open', path: path },
                    }
                  });
                }
              } catch (e2) {}
            }
          });
          send({ type: 'hook_installed', hook: 'native:open', total: ++runtimeContext.hooks_installed });
        }
      } catch (e) { reportHookError('native:open', e.message); }
    }

    // libart.so - RegisterNatives monitoring (JNI hooking detection)
    try {
      var libart = Process.findModuleByName('libart.so');
      if (libart && !_nativeHooksInstalled.libart) {
        _nativeHooksInstalled.libart = true;
        var RegisterNatives = resolveExport('libart.so', 'art::JNI<false>::RegisterNatives');
        if (!RegisterNatives) {
          RegisterNatives = resolveExport('libart.so', '_ZN3art3JNIILb0EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi');
        }
        if (RegisterNatives) {
          Interceptor.attach(RegisterNatives, {
            onEnter: function (args) {
              try {
                var num_methods = args[3].toInt32();
                send({
                  type: 'event',
                  payload: {
                    event_id: 'native_ev_' + Date.now(),
                    timestamp: Date.now(),
                    category: 'dangerous_apis',
                    source: 'native',
                    hook: 'libart.RegisterNatives',
                    severity: 'HIGH',
                    method_count: num_methods,
                    description: 'JNI RegisterNatives() called (' + num_methods + ' methods) - native bridge established',
                    data: { hook: 'libart.RegisterNatives', method_count: num_methods },
                  }
                });
              } catch (e2) {}
            }
          });
          send({ type: 'hook_installed', hook: 'native:RegisterNatives', total: ++runtimeContext.hooks_installed });
        }
      }
    } catch (e) { reportHookError('native:libart', e.message); }

  } catch (outerErr) {
    send({ type: 'diag', msg: 'native_hooks_outer_error', error: outerErr.message });
  }
}

// Install now for libraries already mapped at attach time.
installNativeHooks();

// ─── Late-load coverage ───────────────────────────────────────────────────────
//
// installNativeHooks() used to run ONCE, as an IIFE at script load. For a packed
// dropper - the primary target - the payload's native libraries are loaded
// AFTER attach, so findModuleByName() returned null, the entire native block was
// skipped, and nothing was instrumented at the native layer for exactly the
// samples that matter most.
//
// Hooking the loader lets us re-run installation whenever a new library appears.
// The per-module guards above make re-invocation idempotent.
// watchForLateLibraries is deliberately NOT installed at early startup on Android 14+ / API 37.
// Hooking dlopen/android_dlopen_ext during early zygote spawn intercepts bionic linker
// initialization and graphics driver (EGL/Vulkan) loading, triggering SIGABRT
// (e.g. EGL_NOT_INITIALIZED or JNI transition frame aborts).
// Native hooks are installed once during startup via installNativeHooks().
// (function watchForLateLibraries() { ... })();
