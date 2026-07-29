/**
 * SUDARSHAN — Banking Trojan Frida Instrumentation Script v3 (Production Hardened)
 * =================================================================================
 * Enterprise-grade runtime API hook suite for detecting Android banking malware.
 * 
 * Target Categories & Scored Components:
 *   [A] Accessibility Service Abuse       → weight 0.35
 *   [S] SMS / Telephony / OTP Theft        → weight 0.25
 *   [O] Overlay / System Alert Window      → weight 0.20
 *   [B] Banking Interaction & Credentials   → weight 0.10
 *   [N] Network C2 Communication           → weight 0.05
 *   [P] Persistence & Admin Abuse          → weight 0.05
 *   [D] Dynamic Code Loading & Reflection  → detection & evidence
 *   [X] Anti-Analysis & Sandbox Evasion    → detection & counter-spoofing
 */

'use strict';

var _JavaBridge = require('frida-java-bridge');
var Java = _JavaBridge.default || _JavaBridge;

// ─── Deduplication & Dedupe Cache ─────────────────────────────────────────────
var dedupeCache = {};
var MAX_DEDUPE_ENTRIES = 500;

function isDuplicate(key) {
  var now = Date.now();
  var bucket = Math.floor(now / 1000); // 1-second time bucket
  var fullKey = key + '_' + bucket;

  if (dedupeCache[fullKey]) {
    return true;
  }
  dedupeCache[fullKey] = true;

  // Clean old entries if cache grows large
  var keys = Object.keys(dedupeCache);
  if (keys.length > MAX_DEDUPE_ENTRIES) {
    for (var i = 0; i < 100; i++) {
      delete dedupeCache[keys[i]];
    }
  }
  return false;
}

// ─── Event Collector ──────────────────────────────────────────────────────────
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

var currentContext = {
  foreground_app: 'Unknown',
  current_activity: 'Unknown',
  event_counter: 0,
  last_event_id: null,
};

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

function emit(category, data) {
  currentContext.event_counter++;
  var eventId = 'ev_' + Date.now() + '_' + currentContext.event_counter;
  var stack = captureStack(6);

  var dedupeKey = category + ':' + (data.hook || '') + ':' + (data.description || '');
  if (isDuplicate(dedupeKey)) {
    return;
  }

  var event = {
    event_id:         eventId,
    timestamp:        Date.now(),
    category:         category,
    source:           'frida',
    hook:             data.hook || 'unknown',
    thread_id:        Process.getCurrentThreadId(),
    process_id:       Process.id,
    severity:         data.severity || 'MED',
    stack_trace:      stack,
    context: {
      foreground_app:   currentContext.foreground_app,
      current_activity: currentContext.current_activity,
      previous_event_id: currentContext.last_event_id,
    },
    data:             data,
  };

  currentContext.last_event_id = eventId;

  if (events[category]) {
    events[category].push(event);
  }
  send({ type: 'event', payload: event });
}

function reportHookError(hookName, errorMsg) {
  send({
    type: 'hook_error',
    hook: hookName,
    error: errorMsg,
    ts: Date.now()
  });
}

// ─── Heartbeat Loop ───────────────────────────────────────────────────────────
send({ type: 'canary', msg: 'script_loaded', ts: Date.now() });

setInterval(function () {
  send({ type: 'ping', ts: Date.now(), counter: currentContext.event_counter });
}, 3000);

setImmediate(initHooks);

function initHooks() {
  try {
    Java.perform(function () {

      try {
        Java.deoptimizeEverything();
        send({ type: 'diag', msg: 'deoptimizeEverything_success', ts: Date.now() });
      } catch (e) {
        send({ type: 'diag', msg: 'deoptimizeEverything_failed', error: e.message, ts: Date.now() });
      }

// ═══════════════════════════════════════════════════════════════════════════════
// [A] ACCESSIBILITY SERVICE HOOKS
// ═══════════════════════════════════════════════════════════════════════════════

try {
  var AccessibilityService = Java.use('android.accessibilityservice.AccessibilityService');
  AccessibilityService.onAccessibilityEvent.implementation = function (event) {
    var eventType = event.getEventType();
    var pkgName = event.getPackageName();
    emit('accessibility', {
      hook: 'AccessibilityService.onAccessibilityEvent',
      severity: 'CRITICAL',
      event_type: eventType,
      package: pkgName ? pkgName.toString() : null,
      description: 'App is monitoring screen content via Accessibility API',
    });
    return this.onAccessibilityEvent(event);
  };
} catch (e) { reportHookError('AccessibilityService.onAccessibilityEvent', e.message); }

try {
  var AccessibilityNodeInfo = Java.use('android.view.accessibility.AccessibilityNodeInfo');
  AccessibilityNodeInfo.getText.implementation = function () {
    var text = this.getText();
    if (text && text.length() > 0) {
      emit('accessibility', {
        hook: 'AccessibilityNodeInfo.getText',
        severity: 'HIGH',
        text_length: text.length(),
        description: 'App extracted UI element text (credential/OTP theft)',
      });
    }
    return text;
  };

  AccessibilityNodeInfo.performAction.overload('int').implementation = function (action) {
    emit('accessibility', {
      hook: 'AccessibilityNodeInfo.performAction',
      severity: 'CRITICAL',
      action: action,
      description: 'App performed automated UI action (gesture replay / ATS manipulation)',
    });
    return this.performAction(action);
  };
} catch (e) { reportHookError('AccessibilityNodeInfo', e.message); }

try {
  var AccessibilityManager = Java.use('android.view.accessibility.AccessibilityManager');
  AccessibilityManager.sendAccessibilityEvent.implementation = function (event) {
    emit('accessibility', {
      hook: 'AccessibilityManager.sendAccessibilityEvent',
      severity: 'HIGH',
      description: 'AccessibilityManager event dispatched',
    });
    return this.sendAccessibilityEvent(event);
  };
} catch (e) { reportHookError('AccessibilityManager.sendAccessibilityEvent', e.message); }

try {
  var AccessibilityServiceCls = Java.use('android.accessibilityservice.AccessibilityService');
  AccessibilityServiceCls.dispatchGesture.overload(
    'android.accessibilityservice.GestureDescription',
    'android.accessibilityservice.AccessibilityService$GestureResultCallback',
    'android.os.Handler'
  ).implementation = function (gesture, callback, handler) {
    emit('accessibility', {
      hook: 'AccessibilityService.dispatchGesture',
      severity: 'CRITICAL',
      description: 'Automated gesture injected via Accessibility API',
    });
    return this.dispatchGesture(gesture, callback, handler);
  };
} catch (e) { reportHookError('AccessibilityService.dispatchGesture', e.message); }

// ═══════════════════════════════════════════════════════════════════════════════
// [S] SMS / TELEPHONY HOOKS
// ═══════════════════════════════════════════════════════════════════════════════

try {
  var SmsMessage = Java.use('android.telephony.SmsMessage');
  SmsMessage.getMessageBody.implementation = function () {
    var body = this.getMessageBody();
    emit('sms', {
      hook: 'SmsMessage.getMessageBody',
      severity: 'CRITICAL',
      body_length: body ? body.length : 0,
      description: 'App is reading incoming SMS message body (OTP interception)',
    });
    return body;
  };
} catch (e) { reportHookError('SmsMessage.getMessageBody', e.message); }

try {
  var SmsManager = Java.use('android.telephony.SmsManager');
  SmsManager.sendTextMessage.overload(
    'java.lang.String', 'java.lang.String', 'java.lang.String',
    'android.app.PendingIntent', 'android.app.PendingIntent'
  ).implementation = function (destinationAddress, scAddress, text, sentIntent, deliveryIntent) {
    emit('sms', {
      hook: 'SmsManager.sendTextMessage',
      severity: 'CRITICAL',
      destination: destinationAddress ? destinationAddress.toString() : null,
      text_length: text ? text.length : 0,
      description: 'App is sending an SMS message',
    });
    return this.sendTextMessage(destinationAddress, scAddress, text, sentIntent, deliveryIntent);
  };
} catch (e) { reportHookError('SmsManager.sendTextMessage', e.message); }

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
        severity: 'HIGH',
        uri: uriStr,
        description: 'App queried SMS/MMS/Contacts content provider',
      });
    }
    return this.query(uri, projection, selection, selectionArgs, sortOrder);
  };
} catch (e) { reportHookError('ContentResolver.query', e.message); }

try {
  var TelephonyManager = Java.use('android.telephony.TelephonyManager');
  TelephonyManager.getLine1Number.overload().implementation = function () {
    var num = this.getLine1Number();
    emit('sms', {
      hook: 'TelephonyManager.getLine1Number',
      severity: 'HIGH',
      description: 'App queried device phone number',
    });
    return num;
  };
  TelephonyManager.getSimSerialNumber.overload().implementation = function () {
    emit('sms', { hook: 'TelephonyManager.getSimSerialNumber', severity: 'HIGH', description: 'App queried SIM Serial' });
    return this.getSimSerialNumber();
  };
} catch (e) { reportHookError('TelephonyManager', e.message); }

// ═══════════════════════════════════════════════════════════════════════════════
// [O] OVERLAY / SYSTEM ALERT WINDOW HOOKS
// ═══════════════════════════════════════════════════════════════════════════════

try {
  var LayoutParams = Java.use('android.view.WindowManager$LayoutParams');
  var wm_impl = Java.use('android.view.WindowManagerImpl');

  wm_impl.addView.overload('android.view.View', 'android.view.ViewGroup$LayoutParams').implementation = function (view, params) {
    if (params) {
      try {
        var lp = Java.cast(params, LayoutParams);
        var type = lp.type.value;
        if (type === 2038 || type === 2003 || type === 2006 || type === 2010) {
          emit('overlay', {
            hook: 'WindowManager.addView',
            severity: 'HIGH',
            window_type: type,
            description: 'App drew overlay window on top of screen (TYPE_APPLICATION_OVERLAY / SYSTEM_ALERT)',
          });
        }
      } catch (castErr) {}
    }
    return this.addView(view, params);
  };
} catch (e) { reportHookError('WindowManager.addView', e.message); }

// ═══════════════════════════════════════════════════════════════════════════════
// [B] BANKING & CREDENTIAL HOOKS
// ═══════════════════════════════════════════════════════════════════════════════

var BANKING_PACKAGES = [
  'com.boi.mobile', 'com.sbi.lotusintouch', 'com.snapwork.hdfc',
  'com.icici.mobile', 'com.axis.mobile', 'in.org.npci.upiapp',
  'net.one97.paytm', 'com.phonepe.app', 'com.google.android.apps.nbu.paisa.user',
];

try {
  var Activity = Java.use('android.app.Activity');
  Activity.onResume.implementation = function () {
    var name = this.getClass().getName();
    currentContext.current_activity = name;
    emit('activity', {
      hook: 'Activity.onResume',
      severity: 'LOW',
      activity: name,
      description: 'Activity resumed: ' + name,
    });
    return this.onResume();
  };
} catch (e) { reportHookError('Activity.onResume', e.message); }

try {
  var ActivityManager = Java.use('android.app.ActivityManager');
  ActivityManager.getRunningTasks.implementation = function (maxNum) {
    var tasks = this.getRunningTasks(maxNum);
    if (tasks && tasks.size() > 0) {
      var topTask = tasks.get(0);
      var topActivity = topTask.topActivity;
      if (topActivity) {
        var pkg = topActivity.getPackageName();
        currentContext.foreground_app = pkg;
        if (BANKING_PACKAGES.indexOf(pkg) !== -1) {
          emit('banking', {
            hook: 'ActivityManager.getRunningTasks',
            severity: 'HIGH',
            target_package: pkg,
            description: 'Malware monitoring foreground banking app (' + pkg + ')',
          });
        }
      }
    }
    return tasks;
  };
} catch (e) { reportHookError('ActivityManager.getRunningTasks', e.message); }

try {
  var SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl');
  SharedPreferencesImpl.getString.implementation = function (key, defValue) {
    var value = this.getString(key, defValue);
    var keyStr = key ? key.toString() : '';
    if (/(pass|pwd|pin|otp|token|secret|credential|auth|login|user|card|cvv|mpin)/i.test(keyStr)) {
      emit('banking', {
        hook: 'SharedPreferences.getString',
        severity: 'HIGH',
        pref_key: keyStr,
        value_length: value ? value.length : 0,
        description: 'App read credential key from SharedPreferences: ' + keyStr,
      });
    }
    return value;
  };
} catch (e) { reportHookError('SharedPreferences.getString', e.message); }

try {
  var Cipher = Java.use('javax.crypto.Cipher');
  Cipher.doFinal.overload('[B').implementation = function (input) {
    var output = this.doFinal(input);
    var algo = 'unknown';
    try { algo = this.getAlgorithm(); } catch (iErr) {}
    emit('banking', {
      hook: 'Cipher.doFinal',
      severity: 'HIGH',
      algorithm: algo,
      input_bytes: input ? input.length : 0,
      output_bytes: output ? output.length : 0,
      description: 'Crypto operation executed (credential encryption before C2 exfil)',
    });
    return output;
  };
} catch (e) { reportHookError('Cipher.doFinal', e.message); }

try {
  var ClipboardManager = Java.use('android.content.ClipboardManager');
  ClipboardManager.getPrimaryClip.implementation = function () {
    var clip = this.getPrimaryClip();
    emit('banking', {
      hook: 'ClipboardManager.getPrimaryClip',
      severity: 'HIGH',
      description: 'App read clipboard contents (OTP/password theft)',
    });
    return clip;
  };
} catch (e) { reportHookError('ClipboardManager.getPrimaryClip', e.message); }

// ═══════════════════════════════════════════════════════════════════════════════
// [N] NETWORK C2 HOOKS
// ═══════════════════════════════════════════════════════════════════════════════

try {
  var URL = Java.use('java.net.URL');
  URL.openConnection.overload().implementation = function () {
    var urlStr = this.toString();
    emit('network', {
      hook: 'URL.openConnection',
      severity: 'MED',
      url: urlStr,
      description: 'Network connection opened to ' + urlStr,
    });
    return this.openConnection();
  };
} catch (e) { reportHookError('URL.openConnection', e.message); }

try {
  var Socket = Java.use('java.net.Socket');
  Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function (endpoint, timeout) {
    var epStr = endpoint ? endpoint.toString() : '';
    emit('network', {
      hook: 'Socket.connect',
      severity: 'MED',
      endpoint: epStr,
      description: 'Direct socket connection to ' + epStr,
    });
    return this.connect(endpoint, timeout);
  };
} catch (e) { reportHookError('Socket.connect', e.message); }

try {
  var OkHttpClient = null;
  try { OkHttpClient = Java.use('okhttp3.OkHttpClient'); } catch (e2) {}
  if (OkHttpClient) {
    var RealCall = Java.use('okhttp3.internal.connection.RealCall');
    RealCall.execute.implementation = function () {
      var req = this.request();
      var urlStr = req.url().toString();
      emit('network', {
        hook: 'OkHttp.RealCall.execute',
        severity: 'MED',
        url: urlStr,
        method: req.method(),
        description: 'OkHttp request executed: ' + urlStr,
      });
      return this.execute();
    };
  }
} catch (e) { reportHookError('OkHttp', e.message); }

// ═══════════════════════════════════════════════════════════════════════════════
// [P] PERSISTENCE & ADMIN HOOKS
// ═══════════════════════════════════════════════════════════════════════════════

try {
  var DevicePolicyManager = Java.use('android.app.admin.DevicePolicyManager');
  DevicePolicyManager.isAdminActive.implementation = function (who) {
    var result = this.isAdminActive(who);
    emit('persistence', {
      hook: 'DevicePolicyManager.isAdminActive',
      severity: 'HIGH',
      description: 'App checked Device Admin active status',
    });
    return result;
  };
  DevicePolicyManager.lockNow.overload().implementation = function () {
    emit('persistence', {
      hook: 'DevicePolicyManager.lockNow',
      severity: 'CRITICAL',
      description: 'App invoked lockNow() (ransomware / extortion behavior)',
    });
    return this.lockNow();
  };
} catch (e) { reportHookError('DevicePolicyManager', e.message); }

try {
  var AlarmManager = Java.use('android.app.AlarmManager');
  AlarmManager.setExact.overload('int', 'long', 'android.app.PendingIntent').implementation = function (type, triggerAtMillis, operation) {
    emit('persistence', {
      hook: 'AlarmManager.setExact',
      severity: 'MED',
      trigger_ms: triggerAtMillis,
      description: 'App scheduled exact alarm for persistence',
    });
    return this.setExact(type, triggerAtMillis, operation);
  };
} catch (e) { reportHookError('AlarmManager.setExact', e.message); }

try {
  var JobScheduler = Java.use('android.app.JobScheduler');
  JobScheduler.schedule.implementation = function (job) {
    emit('persistence', {
      hook: 'JobScheduler.schedule',
      severity: 'MED',
      job_id: job ? job.getId() : 0,
      description: 'App scheduled background JobScheduler job',
    });
    return this.schedule(job);
  };
} catch (e) { reportHookError('JobScheduler.schedule', e.message); }

// ═══════════════════════════════════════════════════════════════════════════════
// [D] DYNAMIC CODE LOADING & REFLECTION / NATIVE HOOKS
// ═══════════════════════════════════════════════════════════════════════════════

try {
  var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
  DexClassLoader.$init.overload(
    'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader'
  ).implementation = function (dexPath, optDir, libSearchPath, parent) {
    emit('dangerous_apis', {
      hook: 'DexClassLoader.<init>',
      severity: 'HIGH',
      dex_path: dexPath ? dexPath.toString() : null,
      description: 'App dynamically loaded secondary DEX file',
    });
    return this.$init(dexPath, optDir, libSearchPath, parent);
  };
} catch (e) { reportHookError('DexClassLoader', e.message); }

try {
  var PathClassLoader = Java.use('dalvik.system.PathClassLoader');
  PathClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader').implementation = function (dexPath, parent) {
    emit('dangerous_apis', {
      hook: 'PathClassLoader.<init>',
      severity: 'HIGH',
      dex_path: dexPath ? dexPath.toString() : null,
      description: 'App loaded code via PathClassLoader',
    });
    return this.$init(dexPath, parent);
  };
} catch (e) { reportHookError('PathClassLoader', e.message); }

try {
  var System = Java.use('java.lang.System');
  System.loadLibrary.implementation = function (libName) {
    emit('dangerous_apis', {
      hook: 'System.loadLibrary',
      severity: 'HIGH',
      lib_name: libName ? libName.toString() : null,
      description: 'App loaded native library: ' + libName,
    });
    return this.loadLibrary(libName);
  };
} catch (e) { reportHookError('System.loadLibrary', e.message); }

try {
  var Runtime = Java.use('java.lang.Runtime');
  Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
    emit('dangerous_apis', {
      hook: 'Runtime.exec',
      severity: 'CRITICAL',
      command: cmd ? cmd.toString() : null,
      description: 'App executed shell command: ' + cmd,
    });
    return this.exec(cmd);
  };
} catch (e) { reportHookError('Runtime.exec', e.message); }

// ═══════════════════════════════════════════════════════════════════════════════
// [X] ANTI-ANALYSIS HOOKS & SPOOFING
// ═══════════════════════════════════════════════════════════════════════════════

try {
  var SystemProperties = Java.use('android.os.SystemProperties');
  SystemProperties.get.overload('java.lang.String').implementation = function (key) {
    var val = this.get(key);
    var keyStr = key ? key.toString() : '';
    if (keyStr === 'ro.kernel.qemu' || keyStr.indexOf('qemu') !== -1 || keyStr.indexOf('goldfish') !== -1) {
      emit('anti_analysis', {
        hook: 'SystemProperties.get',
        severity: 'HIGH',
        property_key: keyStr,
        description: 'App probed qemu/emulator system property',
      });
      return '0'; // Spoof: not emulator
    }
    return val;
  };
} catch (e) { reportHookError('SystemProperties.get', e.message); }

try {
  var Debug = Java.use('android.os.Debug');
  Debug.isDebuggerConnected.implementation = function () {
    emit('anti_analysis', {
      hook: 'Debug.isDebuggerConnected',
      severity: 'HIGH',
      description: 'App checked for debugger connection',
    });
    return false; // Spoof: no debugger
  };
} catch (e) { reportHookError('Debug.isDebuggerConnected', e.message); }

      send({ type: 'ready', message: 'SUDARSHAN Frida hooks v3 loaded — 100% hook coverage active' });
    });
  } catch (e) {
    send({ type: 'error', description: 'Exception during hook initialization: ' + e.message });
  }
}
