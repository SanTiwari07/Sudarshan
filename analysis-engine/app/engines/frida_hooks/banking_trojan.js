/**
 * SUDARSHAN — Banking Trojan Frida Instrumentation Script v2
 * ===========================================================
 * Hooks critical Android APIs used by banking malware.
 * Reports behavioral events to the Python controller via Frida's send() API.
 *
 * Detected behaviors:
 *   [A] Accessibility Service abuse       → weight 0.35
 *   [S] SMS interception / OTP theft      → weight 0.25
 *   [O] Overlay / System Alert Window     → weight 0.20
 *   [B] Banking app interaction           → weight 0.10
 *   [N] Network C2 communication         → weight 0.05
 *   [P] Persistence / Admin abuse         → weight 0.05
 *   [X] Anti-Analysis / Sandbox Evasion   → detection only (no BFCI weight)
 *
 * BFCI categories and Python _on_message contract are UNCHANGED.
 * Only the 'data' payload is enriched with:
 *   - severity: LOW / MED / HIGH / CRITICAL
 *   - thread_id: current thread identifier
 *   - stack_trace: up to 6 Java frames
 *   - args: sanitized argument list
 *   - return_value: (set post-call by some hooks)
 */

'use strict';

var _JavaBridge = require('frida-java-bridge');
var Java = _JavaBridge.default || _JavaBridge;


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
  anti_analysis:  [],   // NEW — sandbox evasion detection
};

/**
 * Capture Java stack trace (up to maxFrames).
 * Returns an array of strings. Silently returns [] on any error.
 */
function captureStack(maxFrames) {
  maxFrames = maxFrames || 6;
  try {
    var exc  = Java.use('java.lang.Exception').$new();
    var frames = exc.getStackTrace();
    var result = [];
    var limit  = Math.min(frames.length, maxFrames + 2); // skip emit() itself
    for (var i = 2; i < limit; i++) {
      result.push(frames[i].toString());
    }
    exc.$dispose();
    return result;
  } catch (e) {
    return [];
  }
}

/**
 * Core event emitter.
 * Enriches every event with thread_id, stack_trace, and severity
 * while keeping the original category/data structure intact for
 * backward compatibility with the Python BFCI pipeline.
 */
function emit(category, data) {
  var stack = captureStack(6);

  var event = {
    timestamp:   Date.now(),
    category:    category,
    data:        data,
    // ── NEW rich fields ──
    thread_id:   Process.getCurrentThreadId(),
    stack_trace: stack,
    severity:    data.severity || 'MED',
  };

  if (events[category]) {
    events[category].push(event);
  }
  send({ type: 'event', payload: event });
}

// ─── Hook Initialisation ──────────────────────────────────────────────────────

send({ type: 'canary', msg: 'script_loaded', ts: Date.now() });

setImmediate(initHooks);

function initHooks() {
  try {
    Java.perform(function () {

      // ── ART Deoptimization (MUST be first inside Java.perform) ──────────────
      // Frida hooks use Java.use() which patches ART's interpreter tables.
      // On API 37 (Android 15), ART aggressively JIT-compiles and inlines
      // lightweight methods, which bypasses interpreter tables entirely, causing
      // hooks to silently install but never fire.
      // Java.deoptimizeEverything() forces ART to deoptimize all compiled
      // methods, routing them back through the interpreter where hooks fire.
      // NOTE: process.env is Node.js API — NOT available in Frida's JS runtime.
      //       The previous conditional guard was always false. Call unconditionally.
      try {
        Java.deoptimizeEverything();
        send({type: 'diag', msg: 'deoptimizeEverything_success', ts: Date.now()});
      } catch (e) {
        send({type: 'diag', msg: 'deoptimizeEverything_failed', error: e.message, ts: Date.now()});
      }



// ═══════════════════════════════════════════════════════════════════════════════
// [A] ACCESSIBILITY SERVICE HOOKS
// ═══════════════════════════════════════════════════════════════════════════════

try {
  var AccessibilityService = Java.use('android.accessibilityservice.AccessibilityService');

  AccessibilityService.onAccessibilityEvent.implementation = function (event) {
    var eventType = event.getEventType();
    var pkgName   = event.getPackageName();
    emit('accessibility', {
      hook:        'AccessibilityService.onAccessibilityEvent',
      severity:    'CRITICAL',
      event_type:  eventType,
      package:     pkgName ? pkgName.toString() : null,
      args:        [String(eventType), pkgName ? pkgName.toString() : 'null'],
      description: 'App is monitoring screen content via Accessibility API',
    });
    return this.onAccessibilityEvent(event);
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'AccessibilityService.onAccessibilityEvent', error: e.message });
}

try {
  var AccessibilityNodeInfo = Java.use('android.view.accessibility.AccessibilityNodeInfo');

  AccessibilityNodeInfo.getText.implementation = function () {
    var text = this.getText();
    if (text) {
      emit('accessibility', {
        hook:        'AccessibilityNodeInfo.getText',
        severity:    'HIGH',
        text_length: text.length(),
        args:        [],
        return_value: '[' + text.length() + ' chars]',
        description: 'App is extracting text from UI elements (credential/OTP theft)',
      });
    }
    return text;
  };

  // Disambiguate: performAction has overloads (int) and (int, Bundle).
  AccessibilityNodeInfo.performAction.overload('int').implementation = function (action) {
    emit('accessibility', {
      hook:        'AccessibilityNodeInfo.performAction',
      severity:    'CRITICAL',
      action:      action,
      args:        [String(action)],
      description: 'App is performing automated UI action (gesture replay / ATS manipulation)',
    });
    return this.performAction(action);
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'AccessibilityNodeInfo', error: e.message });
}

// ═══════════════════════════════════════════════════════════════════════════════
// [S] SMS / OTP INTERCEPTION HOOKS
// ═══════════════════════════════════════════════════════════════════════════════

try {
  var SmsMessage = Java.use('android.telephony.SmsMessage');

  SmsMessage.getMessageBody.implementation = function () {
    var body = this.getMessageBody();
    emit('sms', {
      hook:         'SmsMessage.getMessageBody',
      severity:     'CRITICAL',
      body_length:  body ? body.length() : 0,
      args:         [],
      return_value: body ? '[' + body.length() + ' chars]' : 'null',
      description:  'App is reading incoming SMS message body (OTP interception)',
    });
    return body;
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'SmsMessage.getMessageBody', error: e.message });
}

try {
  var SmsManager = Java.use('android.telephony.SmsManager');

  // Disambiguate: sendTextMessage has several overloads; hook the classic 5-arg form.
  SmsManager.sendTextMessage.overload(
    'java.lang.String', 'java.lang.String', 'java.lang.String',
    'android.app.PendingIntent', 'android.app.PendingIntent'
  ).implementation = function (destinationAddress, scAddress, text, sentIntent, deliveryIntent) {
    emit('sms', {
      hook:        'SmsManager.sendTextMessage',
      severity:    'CRITICAL',
      destination: destinationAddress ? destinationAddress.toString() : null,
      text_length: text ? text.length() : 0,
      args:        [destinationAddress ? destinationAddress.toString() : 'null', '[text]'],
      description: 'App is sending an SMS (potential fraud forwarding or C2 exfil)',
    });
    return this.sendTextMessage(destinationAddress, scAddress, text, sentIntent, deliveryIntent);
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'SmsManager.sendTextMessage', error: e.message });
}

try {
  var ContentResolver = Java.use('android.content.ContentResolver');
  var Uri = Java.use('android.net.Uri');

  ContentResolver.query.overload(
    'android.net.Uri', '[Ljava.lang.String;', 'java.lang.String',
    '[Ljava.lang.String;', 'java.lang.String'
  ).implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
    var uriStr = uri ? uri.toString() : '';
    if (uriStr.indexOf('sms') !== -1 || uriStr.indexOf('mms') !== -1 || uriStr.indexOf('contacts') !== -1) {
      emit('sms', {
        hook:        'ContentResolver.query',
        severity:    'HIGH',
        uri:         uriStr,
        args:        [uriStr],
        description: 'App is querying SMS/MMS/Contacts content provider (data harvesting)',
      });
    }
    return this.query(uri, projection, selection, selectionArgs, sortOrder);
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'ContentResolver.query', error: e.message });
}

// ═══════════════════════════════════════════════════════════════════════════════
// [O] OVERLAY / SYSTEM ALERT WINDOW HOOKS
// ═══════════════════════════════════════════════════════════════════════════════

try {
  var LayoutParams = Java.use('android.view.WindowManager$LayoutParams');
  var wm_impl     = Java.use('android.view.WindowManagerImpl');

  wm_impl.addView.overload('android.view.View', 'android.view.ViewGroup$LayoutParams').implementation = function (view, params) {
    if (params) {
      try {
        var lp   = Java.cast(params, LayoutParams);
        var type = lp.type.value;
        // TYPE_APPLICATION_OVERLAY=2038, TYPE_SYSTEM_ALERT=2003, TYPE_SYSTEM_OVERLAY=2006
        if (type === 2038 || type === 2003 || type === 2006 || type === 2010) {
          emit('overlay', {
            hook:        'WindowManager.addView',
            severity:    'HIGH',
            window_type: type,
            args:        [String(type)],
            description: 'App is drawing an overlay window on top of other apps (phishing screen)',
          });
        }
      } catch (castErr) {}
    }
    return this.addView(view, params);
  };

} catch (e) {
  send({ type: 'hook_error', hook: 'WindowManager.addView', error: e.message });
}

// ═══════════════════════════════════════════════════════════════════════════════
// [B] BANKING APP INTERACTION HOOKS
// ═══════════════════════════════════════════════════════════════════════════════

// Preference keys worth reporting when read. Deliberately narrow: an app reads
// SharedPreferences constantly, and emitting every read would drown the
// evidence store and inflate the Frida event count meaninglessly.
var CREDENTIAL_KEY_PATTERN = /(pass|pwd|pin|otp|token|secret|credential|session|auth|login|user|account|card|cvv|mpin)/i;

var BANKING_PACKAGES = [
  'com.boi.mobile', 'com.sbi.lotusintouch', 'com.snapwork.hdfc',
  'com.icici.mobile', 'com.axis.mobile', 'in.org.npci.upiapp',
  'net.one97.paytm', 'com.phonepe.app', 'com.google.android.apps.nbu.paisa.user',
  'com.amazon.mShop.android.shopping', 'com.whatsapp',
];

try {
  var Activity = Java.use('android.app.Activity');
  Activity.onResume.implementation = function () {
    var name = this.getClass().getName();
    emit('banking', {
      hook:        'Activity.onResume',
      severity:    'LOW',
      activity:    name,
      args:        [name],
      description: 'App activity resumed: ' + name,
    });
    return this.onResume();
  };
  send({type: 'diag', msg: 'Activity.onResume hook installed'});
} catch (e) {
  send({ type: 'hook_error', hook: 'Activity.onResume', error: e.message });
}


try {
  var ActivityManager = Java.use('android.app.ActivityManager');
  ActivityManager.getRunningTasks.implementation = function (maxNum) {
    var tasks = this.getRunningTasks(maxNum);
    if (tasks && tasks.size() > 0) {
      var topTask     = tasks.get(0);
      var topActivity = topTask.topActivity;
      if (topActivity) {
        var pkg = topActivity.getPackageName();
        if (BANKING_PACKAGES.indexOf(pkg) !== -1) {
          emit('banking', {
            hook:           'ActivityManager.getRunningTasks',
            severity:       'HIGH',
            target_package: pkg,
            args:           [String(maxNum)],
            description:    'Malware is monitoring foreground banking app (pre-overlay positioning)',
          });
        }
      }
    }
    return tasks;
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'ActivityManager.getRunningTasks', error: e.message });
}


// ═══════════════════════════════════════════════════════════════════════════════
// [N] NETWORK C2 COMMUNICATION HOOKS
// ═══════════════════════════════════════════════════════════════════════════════

try {
  var URL = Java.use('java.net.URL');

  URL.openConnection.overload().implementation = function () {
    var urlStr = this.toString();
    emit('network', {
      hook:        'URL.openConnection',
      severity:    'MED',
      url:         urlStr,
      args:        [urlStr],
      description: 'App opened a network connection (potential C2 communication)',
    });
    return this.openConnection();
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'URL.openConnection', error: e.message });
}

try {
  var OkHttpClient = null;
  try { OkHttpClient = Java.use('okhttp3.OkHttpClient'); } catch (e2) {}

  if (OkHttpClient) {
    var RealCall = Java.use('okhttp3.internal.connection.RealCall');
    RealCall.execute.implementation = function () {
      var request = this.request();
      var urlStr  = request.url().toString();
      emit('network', {
        hook:        'OkHttp.RealCall.execute',
        severity:    'MED',
        url:         urlStr,
        method:      request.method(),
        args:        [urlStr, request.method()],
        description: 'OkHttp request executed (C2 data exfiltration)',
      });
      return this.execute();
    };
  }
} catch (e) {
  send({ type: 'hook_error', hook: 'OkHttp', error: e.message });
}

// ═══════════════════════════════════════════════════════════════════════════════
// [P] PERSISTENCE / ADMIN ABUSE HOOKS
// ═══════════════════════════════════════════════════════════════════════════════

try {
  var DevicePolicyManager = Java.use('android.app.admin.DevicePolicyManager');

  DevicePolicyManager.isAdminActive.implementation = function (who) {
    var result = this.isAdminActive(who);
    emit('persistence', {
      hook:         'DevicePolicyManager.isAdminActive',
      severity:     'HIGH',
      args:         [who ? who.toString() : 'null'],
      return_value: String(result),
      description:  'App is checking Device Admin status (persistence mechanism)',
    });
    return result;
  };

  // Disambiguate: lockNow has overloads () and (int).
  DevicePolicyManager.lockNow.overload().implementation = function () {
    emit('persistence', {
      hook:        'DevicePolicyManager.lockNow',
      severity:    'CRITICAL',
      args:        [],
      description: 'App is LOCKING THE DEVICE (ransomware or extortion behavior)',
    });
    return this.lockNow();
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'DevicePolicyManager', error: e.message });
}

// ═══════════════════════════════════════════════════════════════════════════════
// [D] DYNAMIC CODE LOADING HOOKS
// ═══════════════════════════════════════════════════════════════════════════════

try {
  var DexClassLoader = Java.use('dalvik.system.DexClassLoader');

  DexClassLoader.$init.overload(
    'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader'
  ).implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
    emit('dangerous_apis', {
      hook:        'DexClassLoader.<init>',
      severity:    'HIGH',
      dex_path:    dexPath ? dexPath.toString() : null,
      args:        [dexPath ? dexPath.toString() : 'null'],
      description: 'App is dynamically loading a DEX file (malicious payload dropper)',
    });
    return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'DexClassLoader', error: e.message });
}

// ═══════════════════════════════════════════════════════════════════════════════
// [F] FILE ACCESS HOOKS
// ═══════════════════════════════════════════════════════════════════════════════

try {
  var File = Java.use('java.io.File');

  File.$init.overload('java.lang.String').implementation = function (path) {
    var p = path ? path.toString() : '';
    if (p.indexOf('/data/data') !== -1 || p.indexOf('shared_prefs') !== -1 || p.indexOf('databases') !== -1) {
      emit('files_accessed', {
        hook:        'File.<init>',
        severity:    'LOW',
        path:        p,
        args:        [p],
        description: 'App is accessing sensitive app data directory',
      });
    }
    return this.$init(path);
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'File', error: e.message });
}

// ═══════════════════════════════════════════════════════════════════════════════
// [X] ANTI-ANALYSIS / SANDBOX EVASION DETECTION HOOKS
// ═══════════════════════════════════════════════════════════════════════════════
// These hooks detect when malware probes for emulator/debug/root conditions.
// They do NOT affect BFCI scoring (separate 'anti_analysis' category).
// Countermeasures (spoofing) are applied at hook level to improve detection.

try {
  var SystemProperties = Java.use('android.os.SystemProperties');

  SystemProperties.get.overload('java.lang.String').implementation = function (key) {
    var val = this.get(key);
    var keyStr = key ? key.toString() : '';
    if (keyStr === 'ro.kernel.qemu' || keyStr.indexOf('qemu') !== -1 ||
        keyStr === 'ro.product.model' || keyStr.indexOf('goldfish') !== -1) {
      // Spoof: return real-device value
      var spoofed = '';
      if (keyStr === 'ro.kernel.qemu') spoofed = '0';
      else if (keyStr === 'ro.product.model') spoofed = 'SM-G991B';
      emit('anti_analysis', {
        hook:          'SystemProperties.get',
        severity:      'HIGH',
        property_key:  keyStr,
        original_val:  val,
        spoofed_val:   spoofed || val,
        args:          [keyStr],
        description:   'App probed system property — possible emulator/root detection',
        technique:     'emulator_detection',
      });
      if (spoofed) return spoofed;
    }
    return val;
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'SystemProperties.get', error: e.message });
}

try {
  var Debug = Java.use('android.os.Debug');

  Debug.isDebuggerConnected.implementation = function () {
    emit('anti_analysis', {
      hook:        'Debug.isDebuggerConnected',
      severity:    'HIGH',
      args:        [],
      return_value: 'false (spoofed)',
      description: 'App checked for debugger connection — anti-debug technique',
      technique:   'anti_debug',
    });
    return false; // spoof: always report no debugger
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'Debug.isDebuggerConnected', error: e.message });
}

try {
  var System = Java.use('java.lang.System');
  System.exit.implementation = function (code) {
    emit('anti_analysis', {
      hook:        'System.exit',
      severity:    'HIGH',
      args:        [String(code)],
      description: 'App attempted to self-terminate via System.exit() — exit blocked by Sudarshan',
      technique:   'anti_analysis_exit',
    });
    // Exit blocked to allow dynamic analysis to continue
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'System.exit', error: e.message });
}

try {
  var Build = Java.use('android.os.Build');

  // Intercept field reads to detect model-based emulator detection
  var buildModelDesc = Object.getOwnPropertyDescriptor(Build, 'MODEL');
  if (buildModelDesc) {
    var _origModelGet = buildModelDesc.get;
    if (_origModelGet) {
      Object.defineProperty(Build, 'MODEL', {
        get: function() {
          var model = _origModelGet.call(this);
          if (model && (model.indexOf('sdk') !== -1 || model.indexOf('Emulator') !== -1 ||
              model.indexOf('Android SDK') !== -1)) {
            emit('anti_analysis', {
              hook:         'Build.MODEL.read',
              severity:     'MED',
              original_val: model,
              spoofed_val:  'SM-G991B',
              args:         [],
              description:  'App read Build.MODEL — emulator fingerprinting detected',
              technique:    'device_fingerprinting',
            });
            return 'SM-G991B';
          }
          return model;
        }
      });
    }
  }
} catch (e) {
  send({ type: 'hook_error', hook: 'Build.MODEL', error: e.message });
}

try {
  var PackageManager_cls = Java.use('android.app.ApplicationPackageManager');

  PackageManager_cls.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkgName, flags) {
    var name = pkgName ? pkgName.toString() : '';
    // Detect if app is scanning for frida, xposed, or security tools
    if (name.indexOf('frida') !== -1 || name.indexOf('xposed') !== -1 ||
        name.indexOf('rootbeer') !== -1 || name.indexOf('substrate') !== -1) {
      emit('anti_analysis', {
        hook:        'PackageManager.getPackageInfo',
        severity:    'HIGH',
        target_pkg:  name,
        args:        [name, String(flags)],
        description: 'App queried for security/analysis tool package — Frida/Xposed detection attempt',
        technique:   'tool_detection',
      });
      // Throw PackageManager.NameNotFoundException to hide the tool
      var NameNotFoundException = Java.use('android.content.pm.PackageManager$NameNotFoundException');
      throw NameNotFoundException.$new(name + ' not found (spoofed by Sudarshan)');
    }
    return this.getPackageInfo(pkgName, flags);
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'PackageManager.getPackageInfo', error: e.message });
}

// ═══════════════════════════════════════════════════════════════════════════════
// [K] KEYSTORE / CRYPTOGRAPHY HOOKS
// ═══════════════════════════════════════════════════════════════════════════════

try {
  var KeyStore = Java.use('java.security.KeyStore');

  KeyStore.getInstance.overload('java.lang.String').implementation = function (type) {
    var typeStr = type ? type.toString() : '';
    emit('dangerous_apis', {
      hook:        'KeyStore.getInstance',
      severity:    'MED',
      keystore_type: typeStr,
      args:        [typeStr],
      description: 'App accessed Android KeyStore (credential storage or key extraction)',
    });
    return this.getInstance(type);
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'KeyStore.getInstance', error: e.message });
}

// Credential storage read.
//
// Stage 5 ("Login Flow") in the goal graph declares this hook as its
// completion signal. It was never emitted, so stage 5 could never complete and
// — because it is not skippable and gates stages 6, 7, 8 and 10 — the entire
// downstream graph (SMS, banking, C2, dynamic loading) was unreachable.
//
// SECURITY: the KEY is reported, never the VALUE. Reading a stored credential
// is the signal; the credential itself must never leave the device.
try {
  var SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl');

  SharedPreferencesImpl.getString.implementation = function (key, defValue) {
    var value  = this.getString(key, defValue);
    var keyStr = key ? key.toString() : '';
    send({type: 'diag', msg: 'SharedPreferencesImpl.getString executed', key: keyStr});

    if (CREDENTIAL_KEY_PATTERN.test(keyStr)) {
      emit('banking', {
        hook:        'SharedPreferences.getString',
        severity:    'HIGH',
        pref_key:    keyStr,
        value_length: value ? value.length : 0,   // length only — never the value
        args:        [keyStr, '[redacted]'],
        description: 'App read a credential-like value from SharedPreferences',
      });
    }
    return value;
  };
  send({type: 'diag', msg: 'SharedPreferencesImpl.getString hook installed'});

} catch (e) {
  send({ type: 'hook_error', hook: 'SharedPreferences.getString', error: e.message });
}

// Cryptographic operation.
//
// Second completion signal for stage 5. Banking trojans encrypt harvested
// credentials before exfiltration, so doFinal on the login path is strong
// evidence of a credential-handling flow.
//
// SECURITY: only the algorithm and byte counts are reported — never plaintext
// or ciphertext.
try {
  var Cipher = Java.use('javax.crypto.Cipher');

  Cipher.doFinal.overload('[B').implementation = function (input) {
    var output = this.doFinal(input);
    var algo   = '';
    try { algo = this.getAlgorithm(); } catch (inner) { algo = 'unknown'; }

    emit('banking', {
      hook:        'Cipher.doFinal',
      severity:    'HIGH',
      algorithm:   algo ? algo.toString() : 'unknown',
      input_bytes:  input  ? input.length  : 0,
      output_bytes: output ? output.length : 0,
      args:        [algo ? algo.toString() : 'unknown', '[redacted]'],
      description: 'App performed a crypto operation (credential encryption before exfiltration)',
    });
    return output;
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'Cipher.doFinal', error: e.message });
}

      send({ type: 'ready', message: 'SUDARSHAN Frida hooks v2 loaded — rich evidence collection active' });
    }); // end Java.perform
  } catch (e) {
    send({ type: 'error', description: 'Exception during hook initialization: ' + e.message });
  }
} // end initHooks

