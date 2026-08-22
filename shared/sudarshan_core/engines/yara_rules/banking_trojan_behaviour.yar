/*
    SUDARSHAN - Android banking-trojan behaviour rules
    ==================================================

    These rules target YARAScanner.scan_strings(), which is fed strings
    recovered at RUNTIME by the Frida agent, not the APK on disk.

    That distinction is the whole design. Measured on the labelled corpus
    (8 banking trojans, 9 benign controls), the trojans are packed: payload API
    names are ABSENT from the APKs and PRESENT in the clean apps.

        AccessibilityNodeInfo   2/8 malware   8/9 benign
        frida                   0/8 malware   4/9 benign
        onAccessibilityEvent    1/8 malware   0/9 benign

    A static string rule over the APK would therefore flag the clean apps and
    miss the trojans. Once the dropper decrypts its second stage into memory the
    same strings become visible to Frida, and that is where these rules earn
    their keep. Low static recall on a packed sample is expected, not a bug.

    Concealment itself is deliberately NOT re-detected here. The static analyser
    already raises `has_concealed_payload` and the risk engine already floors a
    concealed sample away from "Safe". Nor is anti-analysis probing: the
    AntiAnalysisDetector already emits those events at runtime, and every
    formulation of a probing rule fired on UnCrackable L4 - a crackme whose
    whole purpose is root and instrumentation detection. Probing is not
    malicious on its own, so a rule that flags it buys noise, not signal.


    THE SELECTION RULE
    ------------------
    Every string below was measured across all 17 samples and appears in ZERO
    of the 9 benign controls. That is not a stylistic preference. The first
    draft of this file used the obvious API names - AccessibilityServiceInfo,
    dispatchGesture, TYPE_APPLICATION_OVERLAY, DexClassLoader - and produced 10
    false positives, because VLC, KeePassDX, NewPipe and Amaze bundle framework
    and plugin code that legitimately references all of them. Breadth was the
    problem, so breadth was removed.

    scripts/validate_yara_rules.py re-measures this and fails on any benign hit.
    Run it before adding a string.

    Every rule still requires MULTIPLE independent indicators: any single one
    can occur innocently, and it is the combination that is diagnostic.
    Severity lives in metadata so the scanner can surface it without parsing
    identifiers.
*/

rule android_accessibility_abuse_runtime
{
    meta:
        author      = "Sudarshan"
        description = "Accessibility service driven automation - the control channel banking trojans use to read screen content and act on the victim's behalf"
        severity    = "HIGH"
        threat      = "accessibility_abuse"
        surface     = "runtime_strings"
        corpus      = "1/8 malware, 0/9 benign (static pass; packed samples reveal these only at runtime)"

    strings:
        // Only the two measured clean. AccessibilityServiceInfo,
        // AccessibilityNodeInfo, ACTION_ACCESSIBILITY_FOCUS and
        // findAccessibilityNodeInfosByViewId were all dropped: androidx ships
        // them, so they appear in 8/9 benign samples.
        $impl = "onAccessibilityEvent"           ascii wide
        $bind = "BIND_ACCESSIBILITY_SERVICE"     ascii wide

        // Driving the UI rather than observing it. performGlobalAction is the
        // one action API absent from every benign control.
        $act  = "performGlobalAction"            ascii wide

    condition:
        // Implementing or binding the service AND driving the UI. A screen
        // reader satisfies the first half only.
        ($impl or $bind) and $act
}

rule android_sms_otp_interception
{
    meta:
        author      = "Sudarshan"
        description = "Programmatic interception of incoming SMS - the mechanism used to capture one-time passwords out of band"
        severity    = "CRITICAL"
        threat      = "otp_interception"
        surface     = "runtime_strings"
        corpus      = "1/8 malware, 0/9 benign"

    strings:
        $recv1 = "android.provider.Telephony.SMS_RECEIVED" ascii wide
        $recv2 = "createFromPdu"                 ascii wide
        $recv3 = "SmsMessage"                    ascii wide

        $read1 = "getMessageBody"                ascii wide
        $read2 = "getOriginatingAddress"         ascii wide
        $read3 = "getDisplayMessageBody"         ascii wide

        // Suppressing the notification so the victim never sees the code.
        // abortBroadcast on an SMS_RECEIVED receiver has no benign reading.
        $hide1 = "abortBroadcast"                ascii wide
        $hide2 = "setDefaultSmsPackage"          ascii wide

    condition:
        // Receiving AND reading the body. A messaging app that only declares
        // the receiver, or a formatter that only touches SmsMessage, fails one
        // half. Suppression is diagnostic on its own but only alongside receipt.
        (1 of ($recv*) and 1 of ($read*)) or
        (1 of ($recv*) and 1 of ($hide*))
}

rule android_overlay_credential_phishing
{
    meta:
        author      = "Sudarshan"
        description = "Overlay window driven by operator-supplied injection targets - the standard credential-phishing overlay"
        severity    = "CRITICAL"
        threat      = "overlay_phishing"
        surface     = "runtime_strings"
        corpus      = "0/8 malware, 0/9 benign (static pass); the injection vocabulary appears only after the payload decrypts"

    strings:
        $ov1 = "TYPE_APPLICATION_OVERLAY"        ascii wide
        $ov2 = "TYPE_SYSTEM_ALERT"               ascii wide
        $ov3 = "SYSTEM_ALERT_WINDOW"             ascii wide

        // Foreground-app polling alone was dropped as the second half:
        // getRunningAppProcesses is in 3/9 benign samples, and pairing it with
        // an overlay constant flagged NewPipe and VLC. The injection
        // vocabulary is what separates an attack from a floating widget - an
        // overlay is only phishing if something tells it which bank to imitate.
        $inj1 = "startInject"                    ascii wide
        $inj2 = "getInjectList"                  ascii wide
        $inj3 = "open_inject"                    ascii wide
        $inj4 = "inject_list"                    ascii wide
        $inj5 = "injects_list"                   ascii wide

    condition:
        1 of ($ov*) and 1 of ($inj*)
}

rule android_device_admin_persistence
{
    meta:
        author      = "Sudarshan"
        description = "Device-administrator privileges combined with uninstall resistance - keeps the payload on the device after the victim notices"
        severity    = "HIGH"
        threat      = "persistence"
        surface     = "runtime_strings"
        corpus      = "3/8 malware, 0/9 benign"

    strings:
        $adm1 = "DeviceAdminReceiver"            ascii wide
        $adm2 = "BIND_DEVICE_ADMIN"              ascii wide
        $adm3 = "ACTION_ADD_DEVICE_ADMIN"        ascii wide

        $abuse1 = "resetPassword"                ascii wide
        $abuse2 = "wipeData"                     ascii wide
        $abuse3 = "setKeyguardDisabledFeatures"  ascii wide

        $stay1 = "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" ascii wide
        $stay2 = "onDisableRequested"            ascii wide

    condition:
        // lockNow was dropped from the abuse group - VLC carries it.
        1 of ($adm*) and (1 of ($abuse*) or 1 of ($stay*))
}

rule android_in_memory_dex_payload
{
    meta:
        author      = "Sudarshan"
        description = "Second stage loaded straight from a decrypted buffer, never touching disk - the defining act of a dropper"
        severity    = "HIGH"
        threat      = "dynamic_code_loading"
        surface     = "runtime_strings"
        corpus      = "1/8 malware, 0/9 benign"

    strings:
        $mem = "InMemoryDexClassLoader"          ascii wide

    condition:
        // Narrowed to in-memory loading only, and renamed to say so.
        //
        // The previous version also matched DexClassLoader or PathClassLoader
        // alongside a Cipher constant. That pairing flagged Amaze File Manager,
        // VLC and InsecureBankv2: plugin architectures load DEX, and apps that
        // load DEX also tend to do crypto, so the conjunction carried no real
        // information. InMemoryDexClassLoader has no comparable legitimate use
        // - loading executable code from a buffer that never touches disk is
        // the behaviour, not an implementation detail of it.
        $mem
}

rule android_bot_command_channel
{
    meta:
        author      = "Sudarshan"
        description = "Command-and-control vocabulary recovered at runtime - the operator verbs a banking bot polls for"
        severity    = "CRITICAL"
        threat      = "c2_command_channel"
        surface     = "runtime_strings"
        corpus      = "0/8 malware, 0/9 benign (static pass) - a runtime-only rule by construction"

    strings:
        // Bot identity handed to the panel.
        $id1 = "bot_id"                          ascii wide
        $id2 = "botid"                           ascii wide
        $id3 = "device_admin_status"             ascii wide

        // Operator commands - the verbs, not class names, so they survive
        // rebuilds that rename everything else.
        $cmd1 = "startInject"                    ascii wide
        $cmd2 = "startKeylogger"                 ascii wide
        $cmd3 = "getInjectList"                  ascii wide
        $cmd4 = "grabbing_sms"                   ascii wide
        $cmd5 = "grabbing_google_auth"           ascii wide
        $cmd6 = "grab_cc"                        ascii wide
        $cmd7 = "open_inject"                    ascii wide
        $cmd8 = "kill_bot"                       ascii wide

        $panel1 = "/gate.php"                    ascii wide
        $panel2 = "/api/gate"                    ascii wide

    condition:
        // "sendSMS" was dropped from the command group - too close to ordinary
        // API naming to carry weight even in combination.
        2 of ($cmd*) or
        (1 of ($cmd*) and 1 of ($id*)) or
        (1 of ($panel*) and 1 of ($id*))
}
