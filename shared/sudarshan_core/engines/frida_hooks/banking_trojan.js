/**
 * SUDARSHAN — Banking Trojan Frida Instrumentation Script v4 (Frida 17 Compatible)
 * ==================================================================================
 * Production-grade runtime API hook suite for detecting Android banking malware.
 *
 * ROOT CAUSE FIX (v3 → v4):
 *   v3 used CommonJS require for frida-java-bridge which FAILS in Frida 17+.
 *   In Frida 17, Java is a built-in global — no require needed or supported.
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

// DO NOT add: var Java = require(...); Java is injected by Frida 17+ automatically.

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
  package_name: 'Unknown',
};

// ─── Event Collector (mirrors Python collected_events keys exactly) ───────────
var events = {
  accessibility:  [],
  sms:            [],
  overlay:        [],
  banking:        [],
  network:        [],
  persistence:    [],
  dangerous_apis: [],
  files_accessed: [],
  anti_analysis:  [],
};

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

  var dedupeKey = category + ':' + (data.hook || '') + ':' + (data.description || '').substring(0, 50);
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

  if (events[category]) {
    events[category].push(event);
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

// ─── Schedule hook initialization after current tick ─────────────────────────
setImmediate(initHooks);

// ─── Main Hook Initialization ─────────────────────────────────────────────────
function initHooks() {
  // Java is a Frida 17 built-in global — no require() needed
  if (typeof Java === 'undefined' || !Java.available) {
    send({ type: 'error', description: 'Java runtime not available in this process. Is this an Android app?' });
    return;
  }

  try {
    Java.perform(function () {

      // ── Deoptimize ART for hook reliability ──────────────────────────────────
      // Without this, ART may inline virtual dispatch, making method hooks unreachable.
      try {
        Java.deoptimizeEverything();
        send({ type: 'diag', msg: 'deoptimizeEverything_success', ts: Date.now() });
      } catch (e) {
        send({ type: 'diag', msg: 'deoptimizeEverything_failed', error: e.message });
      }

      // deoptimizeBootImage: new in Frida 16.2 — deoptimizes AOT-compiled boot image
      // Fixes hooks on system classes that are inlined into the boot image (API 29+).
      try {
        Java.deoptimizeBootImage();
        send({ type: 'diag', msg: 'deoptimizeBootImage_success', ts: Date.now() });
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
// [A] ACCESSIBILITY SERVICE HOOKS (weight 0.35 — heaviest BFCI component)
// ═══════════════════════════════════════════════════════════════════════════════

      try {
        var AccessibilityService = Java.use('android.accessibilityservice.AccessibilityService');
        AccessibilityService.onAccessibilityEvent.implementation = function (event) {
          var eventType = -1;
          var pkgName = null;
          try { eventType = event.getEventType(); } catch (e) {}
          try { var pn = event.getPackageName(); pkgName = pn ? pn.toString() : null; } catch (e) {}
          emit('accessibility', {
            hook: 'AccessibilityService.onAccessibilityEvent',
            class_name: 'android.accessibilityservice.AccessibilityService',
            severity: 'CRITICAL',
            event_type: eventType,
            package: pkgName,
            description: 'App is monitoring screen content via Accessibility API (ATS pattern)',
          });
          return this.onAccessibilityEvent(event);
        };
        registerHook('AccessibilityService.onAccessibilityEvent');

        // Dynamic subclass hook for malware custom AccessibilityService subclasses
        Java.enumerateLoadedClasses({
          onMatch: function(className) {
            if (className.indexOf('android.') === -1 && className.indexOf('java.') === -1 && className.indexOf('dalvik.') === -1) {
              try {
                var targetCls = Java.use(className);
                if (targetCls.onAccessibilityEvent) {
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
                    return this.onAccessibilityEvent(event);
                  };
                  registerHook(className + '.onAccessibilityEvent');
                }
              } catch(e) {}
            }
          },
          onComplete: function() {}
        });
      } catch (e) { reportHookError('AccessibilityService.onAccessibilityEvent', e.message); }

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

        // findAccessibilityNodeInfosByText — ATS credential field location
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
          emit('accessibility', {
            hook: 'AccessibilityManager.sendAccessibilityEvent',
            class_name: 'android.view.accessibility.AccessibilityManager',
            severity: 'HIGH',
            description: 'AccessibilityManager event dispatched (possible ATS relay)',
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

      try {
        var TelephonyManager = Java.use('android.telephony.TelephonyManager');
        TelephonyManager.getLine1Number.overload().implementation = function () {
          var num = this.getLine1Number();
          emit('sms', {
            hook: 'TelephonyManager.getLine1Number',
            class_name: 'android.telephony.TelephonyManager',
            severity: 'HIGH',
            description: 'App queried device phone number (MSISDN exfil)',
          });
          return num;
        };
        registerHook('TelephonyManager.getLine1Number');

        TelephonyManager.getSimSerialNumber.overload().implementation = function () {
          var serial = this.getSimSerialNumber();
          emit('sms', {
            hook: 'TelephonyManager.getSimSerialNumber',
            class_name: 'android.telephony.TelephonyManager',
            severity: 'HIGH',
            description: 'App queried SIM Serial Number (device fingerprinting)',
          });
          return serial;
        };
        registerHook('TelephonyManager.getSimSerialNumber');

        TelephonyManager.getDeviceId.overload().implementation = function () {
          var id = this.getDeviceId();
          emit('sms', {
            hook: 'TelephonyManager.getDeviceId',
            class_name: 'android.telephony.TelephonyManager',
            severity: 'HIGH',
            description: 'App queried IMEI/Device ID (device fingerprinting)',
          });
          return id;
        };
        registerHook('TelephonyManager.getDeviceId');

        TelephonyManager.getSubscriberId.overload().implementation = function () {
          var id = this.getSubscriberId();
          emit('sms', {
            hook: 'TelephonyManager.getSubscriberId',
            class_name: 'android.telephony.TelephonyManager',
            severity: 'HIGH',
            description: 'App queried IMSI subscriber ID (identity exfil)',
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

        wm_impl.addView.overload('android.view.View', 'android.view.ViewGroup$LayoutParams').implementation = function (view, params) {
          if (params) {
            try {
              var lp = Java.cast(params, LayoutParams);
              var type = lp.type.value;
              // TYPE_APPLICATION_OVERLAY=2038, TYPE_SYSTEM_ALERT=2003,
              // TYPE_SYSTEM_OVERLAY=2006, TYPE_SYSTEM_ERROR=2010
              if (type === 2038 || type === 2003 || type === 2006 || type === 2010) {
                emit('overlay', {
                  hook: 'WindowManager.addView',
                  class_name: 'android.view.WindowManagerImpl',
                  severity: 'HIGH',
                  window_type: type,
                  description: 'App drew overlay window on top of screen (TYPE=' + type + '). Phishing overlay.',
                });
              }
            } catch (castErr) {}
          }
          return this.addView(view, params);
        };
        registerHook('WindowManager.addView');

        wm_impl.updateViewLayout.overload('android.view.View', 'android.view.ViewGroup$LayoutParams').implementation = function (view, params) {
          emit('overlay', {
            hook: 'WindowManager.updateViewLayout',
            class_name: 'android.view.WindowManagerImpl',
            severity: 'MED',
            description: 'App updated overlay window layout (repositioning phishing screen)',
          });
          return this.updateViewLayout(view, params);
        };
        registerHook('WindowManager.updateViewLayout');

        wm_impl.removeView.overload('android.view.View').implementation = function (view) {
          emit('overlay', {
            hook: 'WindowManager.removeView',
            class_name: 'android.view.WindowManagerImpl',
            severity: 'LOW',
            description: 'App removed overlay window',
          });
          return this.removeView(view);
        };
        registerHook('WindowManager.removeView');
      } catch (e) { reportHookError('WindowManager', e.message); }

      // NotificationListenerService hooking
      try {
        var NLS = Java.use('android.service.notification.NotificationListenerService');
        NLS.onNotificationPosted.overload('android.service.notification.StatusBarNotification').implementation = function (sbn) {
          var pkg = null;
          try { pkg = sbn.getPackageName(); } catch (e2) {}
          emit('overlay', {
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

      // Activity monitoring — FIX: emit to 'banking', not 'activity' (which doesn't exist)
      try {
        var Activity = Java.use('android.app.Activity');
        Activity.onResume.implementation = function () {
          var name = this.getClass().getName();
          runtimeContext.current_activity = name;
          emit('banking', {
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

      try {
        var ActivityManager = Java.use('android.app.ActivityManager');
        ActivityManager.getRunningTasks.implementation = function (maxNum) {
          var tasks = this.getRunningTasks(maxNum);
          if (tasks && tasks.size() > 0) {
            try {
              var topTask = tasks.get(0);
              var topActivity = topTask.topActivity;
              if (topActivity) {
                var pkg = topActivity.getPackageName().toString();
                runtimeContext.foreground_app = pkg;
                if (BANKING_PACKAGES.indexOf(pkg) !== -1) {
                  emit('banking', {
                    hook: 'ActivityManager.getRunningTasks',
                    class_name: 'android.app.ActivityManager',
                    severity: 'HIGH',
                    target_package: pkg,
                    description: 'Malware monitoring foreground banking app: ' + pkg,
                  });
                }
              }
            } catch (e2) {}
          }
          return tasks;
        };
        registerHook('ActivityManager.getRunningTasks');
      } catch (e) { reportHookError('ActivityManager.getRunningTasks', e.message); }

      try {
        var SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl');
        SharedPreferencesImpl.getString.implementation = function (key, defValue) {
          var value = this.getString(key, defValue);
          var keyStr = key ? key.toString() : '';
          if (/(pass|pwd|pin|otp|token|secret|credential|auth|login|user|card|cvv|mpin|account|balance)/i.test(keyStr)) {
            emit('banking', {
              hook: 'SharedPreferences.getString',
              class_name: 'android.app.SharedPreferencesImpl',
              severity: 'HIGH',
              pref_key: keyStr,
              value_length: value ? value.length : 0,
              description: 'App read sensitive key from SharedPreferences: ' + keyStr,
            });
          }
          return value;
        };
        registerHook('SharedPreferences.getString');
      } catch (e) { reportHookError('SharedPreferences.getString', e.message); }

      try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.doFinal.overload('[B').implementation = function (input) {
          var output = this.doFinal(input);
          var algo = 'unknown';
          try { algo = this.getAlgorithm(); } catch (e2) {}
          emit('banking', {
            hook: 'Cipher.doFinal',
            class_name: 'javax.crypto.Cipher',
            severity: 'HIGH',
            algorithm: algo,
            input_bytes: input ? input.length : 0,
            output_bytes: output ? output.length : 0,
            description: 'Crypto operation (likely credential encryption before C2 exfil): algo=' + algo,
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

      // KeyStore — credential storage access
      try {
        var KeyStore = Java.use('java.security.KeyStore');
        KeyStore.getInstance.overload('java.lang.String').implementation = function (type) {
          var ks = this.getInstance(type);
          emit('banking', {
            hook: 'KeyStore.getInstance',
            class_name: 'java.security.KeyStore',
            severity: 'HIGH',
            keystore_type: type ? type.toString() : null,
            description: 'App accessed KeyStore (credential / certificate retrieval): type=' + type,
          });
          return ks;
        };
        registerHook('KeyStore.getInstance');
      } catch (e) { reportHookError('KeyStore.getInstance', e.message); }

      // AccountManager — account credential theft
      try {
        var AccountManager = Java.use('android.accounts.AccountManager');
        AccountManager.getAccountsByType.implementation = function (type) {
          var accounts = this.getAccountsByType(type);
          emit('banking', {
            hook: 'AccountManager.getAccountsByType',
            class_name: 'android.accounts.AccountManager',
            severity: 'HIGH',
            account_type: type ? type.toString() : null,
            count: accounts ? accounts.length : 0,
            description: 'App enumerated device accounts: type=' + type,
          });
          return accounts;
        };
        registerHook('AccountManager.getAccountsByType');
      } catch (e) { reportHookError('AccountManager.getAccountsByType', e.message); }

      // PackageManager — installed apps enumeration (ATS target reconnaissance)
      try {
        var PackageManager = Java.use('android.content.pm.PackageManager');
        PackageManager.getInstalledApplications.implementation = function (flags) {
          var apps = this.getInstalledApplications(flags);
          emit('banking', {
            hook: 'PackageManager.getInstalledApplications',
            class_name: 'android.content.pm.PackageManager',
            severity: 'HIGH',
            app_count: apps ? apps.size() : 0,
            description: 'App enumerated all installed applications (banking app target lookup)',
          });
          return apps;
        };
        registerHook('PackageManager.getInstalledApplications');

        PackageManager.getInstalledPackages.implementation = function (flags) {
          var pkgs = this.getInstalledPackages(flags);
          emit('banking', {
            hook: 'PackageManager.getInstalledPackages',
            class_name: 'android.content.pm.PackageManager',
            severity: 'HIGH',
            pkg_count: pkgs ? pkgs.size() : 0,
            description: 'App enumerated all installed packages (banking target reconnaissance)',
          });
          return pkgs;
        };
        registerHook('PackageManager.getInstalledPackages');
      } catch (e) { reportHookError('PackageManager', e.message); }

      // InputMethodManager — keyboard/IME monitoring
      try {
        var InputMethodManager = Java.use('android.view.inputmethod.InputMethodManager');
        InputMethodManager.showSoftInput.overload('android.view.View', 'int').implementation = function (view, flags) {
          emit('banking', {
            hook: 'InputMethodManager.showSoftInput',
            class_name: 'android.view.inputmethod.InputMethodManager',
            severity: 'MED',
            description: 'Keyboard shown (credential input field activated)',
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
            ioc: epStr,
            description: 'Direct socket connection to: ' + epStr,
          });
          return this.connect(endpoint, timeout);
        };
        registerHook('Socket.connect');
      } catch (e) { reportHookError('Socket.connect', e.message); }

      // HttpsURLConnection — SSL certificate pinning bypass detection
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

      // OkHttp3 — most banking malware uses OkHttp for C2
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

      // Retrofit — common C2 client wrapper
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

      // WebView — loading C2 URLs, evaluating injected JS
      try {
        var WebView = Java.use('android.webkit.WebView');
        WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
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
      } catch (e) { reportHookError('WebView', e.message); }

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
            description: 'App invoked lockNow() — RANSOMWARE/EXTORTION BEHAVIOR CONFIRMED',
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
        var JobScheduler = Java.use('android.app.JobScheduler');
        JobScheduler.schedule.implementation = function (job) {
          emit('persistence', {
            hook: 'JobScheduler.schedule',
            class_name: 'android.app.JobScheduler',
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
          emit('dangerous_apis', {
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
          emit('dangerous_apis', {
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
          var cmdStr = cmds ? Java.array('java.lang.String', cmds).join(' ') : null;
          emit('dangerous_apis', {
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

      // ProcessBuilder — shell command execution alternative
      try {
        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        ProcessBuilder.start.implementation = function () {
          var command = '';
          try {
            var cmd = this.command();
            command = cmd ? cmd.toString() : '';
          } catch (e2) {}
          emit('dangerous_apis', {
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

      try {
        var SystemProperties = Java.use('android.os.SystemProperties');
        SystemProperties.get.overload('java.lang.String').implementation = function (key) {
          var val = this.get(key);
          var keyStr = key ? key.toString() : '';
          if (keyStr === 'ro.kernel.qemu' || keyStr.indexOf('qemu') !== -1 || keyStr.indexOf('goldfish') !== -1 || keyStr.indexOf('genymotion') !== -1) {
            emit('anti_analysis', {
              hook: 'SystemProperties.get',
              class_name: 'android.os.SystemProperties',
              severity: 'HIGH',
              property_key: keyStr,
              original_value: val,
              spoofed_value: '0',
              description: 'App probed emulator system property: ' + keyStr + ' (spoofed to 0)',
            });
            return '0'; // Spoof: appear as real device
          }
          return val;
        };
        registerHook('SystemProperties.get');
      } catch (e) { reportHookError('SystemProperties.get', e.message); }

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
      try {
        var BufferedReader = Java.use('java.io.BufferedReader');
        BufferedReader.readLine.implementation = function () {
          var line = this.readLine();
          if (line && (line.indexOf('frida') !== -1 || line.indexOf('gum-js') !== -1)) {
            emit('anti_analysis', {
              hook: 'BufferedReader.readLine',
              class_name: 'java.io.BufferedReader',
              severity: 'HIGH',
              description: 'App scanning /proc/maps for Frida (anti-Frida detection attempt) — line suppressed',
            });
            return null; // Suppress frida-related /proc/maps lines
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
            description: 'App attempted to self-terminate via System.exit(' + code + ') — blocked to preserve dynamic analysis',
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
            description: 'App attempted to self-terminate via Process.killProcess(' + pid + ') — blocked to preserve dynamic analysis',
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
            description: 'App attempted to self-terminate via Runtime.exit(' + code + ') — blocked to preserve dynamic analysis',
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
          emit('dangerous_apis', {
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
      description: 'Java.perform() failed: ' + e.message,
      stack: e.stack || '',
    });
  }
} // end initHooks

// ═══════════════════════════════════════════════════════════════════════════════
// NATIVE INSTRUMENTATION — Phase 4: libc.so hooks
// Intercepts SSL/TLS, socket ops, process execution at native layer.
// Runs OUTSIDE Java.perform — purely native Frida Interceptor.
// ═══════════════════════════════════════════════════════════════════════════════
(function installNativeHooks() {
  try {
    var libssl = Process.findModuleByName('libssl.so');
    if (libssl) {
      // SSL_write — capture plaintext before encryption
      try {
        var SSL_write = Module.findExportByName('libssl.so', 'SSL_write');
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

      // SSL_read — capture incoming TLS data
      try {
        var SSL_read = Module.findExportByName('libssl.so', 'SSL_read');
        if (SSL_read) {
          Interceptor.attach(SSL_read, {
            onLeave: function (retval) {
              var num = retval.toInt32();
              if (num > 0 && num < 4096) {
                try {
                  var buf = this.context.x1 || this.context.r1; // ARM64 / ARM32
                  if (buf) {
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

    // libc.so — connect(), send(), recv(), execve()
    var libc = Process.findModuleByName('libc.so');
    if (libc) {
      // connect() — socket connections
      try {
        var connect = Module.findExportByName('libc.so', 'connect');
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
                      data: { hook: 'libc.connect', ip: ip, port: port },
                    }
                  });
                }
              } catch (e2) {}
            }
          });
          send({ type: 'hook_installed', hook: 'native:connect', total: ++runtimeContext.hooks_installed });
        }
      } catch (e) { reportHookError('native:connect', e.message); }

      // execve() — process execution
      try {
        var execve = Module.findExportByName('libc.so', 'execve');
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
                    category: 'dangerous_apis',
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

      // ptrace() — anti-debug self-check detection
      try {
        var ptrace = Module.findExportByName('libc.so', 'ptrace');
        if (ptrace) {
          Interceptor.attach(ptrace, {
            onEnter: function (args) {
              var request = args[0].toInt32();
              if (request === 0) { // PTRACE_TRACEME — self-ptrace anti-debug
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
                    description: 'App called ptrace(PTRACE_TRACEME) — self-anti-debug protection',
                    data: { hook: 'libc.ptrace', request: request },
                  }
                });
              }
            }
          });
          send({ type: 'hook_installed', hook: 'native:ptrace', total: ++runtimeContext.hooks_installed });
        }
      } catch (e) { reportHookError('native:ptrace', e.message); }

      // open() — sensitive file access at native level
      try {
        var open = Module.findExportByName('libc.so', 'open');
        if (open) {
          Interceptor.attach(open, {
            onEnter: function (args) {
              try {
                var path = args[0].readUtf8String();
                if (path && (
                  path.indexOf('/proc/self/maps') !== -1 ||
                  path.indexOf('/proc/net/tcp') !== -1 ||
                  path.indexOf('frida') !== -1 ||
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

    // libart.so — RegisterNatives monitoring (JNI hooking detection)
    try {
      var libart = Process.findModuleByName('libart.so');
      if (libart) {
        var RegisterNatives = Module.findExportByName('libart.so', 'art::JNI<false>::RegisterNatives');
        if (!RegisterNatives) {
          RegisterNatives = Module.findExportByName('libart.so', '_ZN3art3JNIILb0EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi');
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
                    description: 'JNI RegisterNatives() called (' + num_methods + ' methods) — native bridge established',
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
})();
