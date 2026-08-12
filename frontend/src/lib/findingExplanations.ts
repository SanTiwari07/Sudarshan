import type { TechnicalFindingId } from './technicalFindings';

export type FindingExplanationContent = {
  title: string;
  whatItMeans: string;
  whyItMatters: string;
  whatItProvesStatic: string;
  whatItProvesDynamic: string;
  whatItProvesBoth: string;
  whatItDoesNotProveStatic: string;
  whatItDoesNotProveDynamic: string;
  riskImpactIntro: string;
  analystTakeaway: string;
  mitreHint?: string;
};

export const FINDING_EXPLANATIONS: Record<TechnicalFindingId, FindingExplanationContent> = {
  accessibility_abuse: {
    title: 'Accessibility Service Abuse',
    whatItMeans:
      'Android Accessibility Services let apps observe UI structure, read visible text, and perform automated gestures. Legitimate apps use this for assistive features; malware abuses it for screen scraping and tap injection.',
    whyItMatters:
      'Banking trojans routinely abuse Accessibility to read balances and OTP fields, auto-approve transfers, and interact with other apps without clear user intent - often combined with overlays or SMS theft.',
    whatItProvesStatic:
      'The APK declares accessibility binding and/or contains an AccessibilityService implementation - the capability exists before runtime.',
    whatItProvesDynamic:
      'Sandbox instrumentation observed accessibility-related API activity or events while the app executed.',
    whatItProvesBoth:
      'Static analysis confirms the accessibility capability; runtime analysis additionally observed accessibility-related behavior during execution.',
    whatItDoesNotProveStatic:
      'Manifest and code evidence alone do not prove credentials were stolen or that banking UI was accessed in production.',
    whatItDoesNotProveDynamic:
      'Observed events may include benign framework traffic; correlate with banking targeting and screenshots before escalation.',
    riskImpactIntro:
      'Credential-theft axis (CT) weights accessibility heavily because it enables direct UI control and harvesting when combined with banking or overlay signals.',
    analystTakeaway:
      'Review runtime accessibility events, sandbox screenshots, and whether protected banking packages appeared on screen during analysis.',
    mitreHint: 'T1417 - Input Capture',
  },
  overlay_capability: {
    title: 'Overlay Window Capability',
    whatItMeans:
      'SYSTEM_ALERT_WINDOW / TYPE_APPLICATION_OVERLAY allows drawing windows above other apps. Attackers use this to show fake login layers on top of legitimate banking apps.',
    whyItMatters:
      'Overlay phishing is a primary vector for credential theft on Android - users believe they are typing into their bank app while malware captures credentials.',
    whatItProvesStatic:
      'The application requests overlay or alert-window capability in the manifest or static configuration.',
    whatItProvesDynamic:
      'Runtime hooks observed window-manager or overlay APIs consistent with drawing above other applications.',
    whatItProvesBoth:
      'Overlay capability is declared statically and runtime instrumentation observed overlay-related activity.',
    whatItDoesNotProveStatic:
      'Having the permission does not prove a phishing overlay was shown to the user or that credentials were captured.',
    whatItDoesNotProveDynamic:
      'A single overlay API call may be benign; confirm context with screenshots and UI labels.',
    riskImpactIntro:
      'Contributes to the CT axis - overlays pair with accessibility and SMS interception in common fraud chains.',
    analystTakeaway:
      'Check sandbox screenshots for full-screen overlays and correlate with banking package launches.',
    mitreHint: 'T1411 - Input Prompt',
  },
  runtime_code_loading: {
    title: 'Runtime Code Loading',
    whatItMeans:
      'DexClassLoader, InMemoryDexClassLoader, and PathClassLoader load DEX bytecode after install. Malware uses this to unpack stage-2 payloads that never appear in the initial static scan.',
    whyItMatters:
      'Dynamic loading evades static scanners and lets attackers ship a small dropper that expands into full banking malware at runtime.',
    whatItProvesStatic:
      'Static analysis found APIs or code paths that can load secondary DEX or JAR payloads.',
    whatItProvesDynamic:
      'Runtime instrumentation observed class-loader activity consistent with loading non-packaged code.',
    whatItProvesBoth:
      'Loader APIs are present in static analysis and runtime observed dynamic loading behavior.',
    whatItDoesNotProveStatic:
      'Presence of loader APIs does not prove a malicious payload was downloaded or executed in the sandbox.',
    whatItDoesNotProveDynamic:
      'Loader activity may load legitimate plugins; inspect loaded artifacts and network staging if available.',
    riskImpactIntro:
      'Feeds the obfuscation / concealment axis (OB) - increases investigation difficulty and may indicate staged payloads.',
    analystTakeaway:
      'Inspect code findings for loader call sites, concealed assets, and any network retrieval during dynamic analysis.',
    mitreHint: 'T1407 - Downloaded Code',
  },
  obfuscation: {
    title: 'Obfuscation',
    whatItMeans:
      'Obfuscation renames classes, encrypts strings, and uses reflection to hide intent. High entropy and reflection make reverse engineering slower - common in fraud malware but also in some commercial apps.',
    whyItMatters:
      'Obfuscation is not malware by itself, but it delays analyst response and often co-occurs with credential theft capabilities.',
    whatItProvesStatic:
      'Static signals (entropy, reflection APIs, renamed resources) indicate the codebase is intentionally hard to inspect.',
    whatItProvesDynamic:
      'Runtime reflection or dynamic resolution was observed during sandbox execution.',
    whatItProvesBoth:
      'Static obfuscation indicators are present and runtime reflection or dynamic resolution was observed.',
    whatItDoesNotProveStatic:
      'Obfuscation alone does not prove fraud - it raises investigation priority when paired with dangerous permissions.',
    whatItDoesNotProveDynamic:
      'Reflection may serve legitimate SDK purposes; weigh alongside CT/BT findings.',
    riskImpactIntro:
      'Contributes to the OB axis at lower STEI weight - amplifies risk when combined with loader or concealed-payload signals.',
    analystTakeaway:
      'Document obfuscation score and reflection; prioritize decompilation review on critical classes.',
  },
  sms_otp_interception: {
    title: 'SMS & OTP Interception',
    whatItMeans:
      'READ_SMS / RECEIVE_SMS and SMS-related receivers let apps read inbound messages, including bank OTPs, before the user sees them.',
    whyItMatters:
      'OTP step-up is central to Indian mobile banking; SMS interception bypasses 2FA without phishing the password alone.',
    whatItProvesStatic:
      'SMS permissions or SMS-related components are declared in the manifest or static findings.',
    whatItProvesDynamic:
      'Runtime hooks observed SMS manager or message-processing APIs during sandbox execution.',
    whatItProvesBoth:
      'SMS capability is declared and runtime SMS-related activity was observed.',
    whatItDoesNotProveStatic:
      'Permissions alone do not prove OTP messages were read or exfiltrated.',
    whatItDoesNotProveDynamic:
      'Sandbox may not receive real carrier SMS; static capability still warrants blocking review.',
    riskImpactIntro:
      'Major contributor to CT axis - OTP interception is treated as critical in banking fraud models.',
    analystTakeaway:
      'Verify RECEIVE_SMS vs READ_SMS, exported receivers, and any C2 exfiltration of message content.',
    mitreHint: 'T1636.004 - SMS Messages',
  },
  banking_targeting: {
    title: 'Banking Targeting',
    whatItMeans:
      'The sample references package names, strings, or UI patterns associated with financial institutions - indicating intent to attack banking customers.',
    whyItMatters:
      'Targeting narrows victim scope and often triggers higher banking-impact scoring and customer advisory workflows.',
    whatItProvesStatic:
      'Hardcoded bank package names, strings, or VIDE baseline matches tie the app to financial brands.',
    whatItProvesDynamic:
      'Runtime observation referenced or launched banking-related packages during sandbox execution.',
    whatItProvesBoth:
      'Static targeting indicators and runtime banking-package interaction were observed.',
    whatItDoesNotProveStatic:
      'String matches alone do not prove active attacks against live customers.',
    whatItDoesNotProveDynamic:
      'Opening a bank app in sandbox does not prove overlay or credential theft occurred.',
    riskImpactIntro:
      'Drives the banking targeting axis (BT) and banking-impact component of FRS when present.',
    analystTakeaway:
      'List matched packages from intelligence report and correlate with overlay/accessibility findings.',
  },
  network_c2: {
    title: 'Network / C2 Indicators',
    whatItMeans:
      'Hardcoded URLs, IPs, or suspicious network sessions may indicate command-and-control or data exfiltration endpoints.',
    whyItMatters:
      'C2 enables remote control, payload updates, and stolen credential upload - beyond on-device capabilities.',
    whatItProvesStatic:
      'Network indicators are embedded in the APK resources or bytecode.',
    whatItProvesDynamic:
      'Sandbox network capture shows connections to suspicious hosts during execution.',
    whatItProvesBoth:
      'Hardcoded infrastructure indicators exist and runtime network activity to suspicious endpoints was captured.',
    whatItDoesNotProveStatic:
      'A hardcoded URL does not prove live communication or successful exfiltration.',
    whatItDoesNotProveDynamic:
      'Sandbox network may differ from production; validate IOCs against threat intel.',
    riskImpactIntro:
      'Feeds infrastructure risk (IR) and threat correlation components when IOC reputation is available.',
    analystTakeaway:
      'Pivot domains/IPs in threat intel view; preserve network logs for CERT reporting.',
    mitreHint: 'T1071 - Application Layer Protocol',
  },
  persistence: {
    title: 'Persistence Mechanisms',
    whatItMeans:
      'Boot receivers, device-admin APIs, and background services help malware survive reboots and resist removal.',
    whyItMatters:
      'Persistence keeps fraud capabilities available after device restart - increasing customer exposure duration.',
    whatItProvesStatic:
      'Manifest declares boot completion, device admin, or related persistence components.',
    whatItProvesDynamic:
      'Runtime observed registration or triggers consistent with persistence behavior.',
    whatItProvesBoth:
      'Persistence components are declared and runtime behavior consistent with persistence was observed.',
    whatItDoesNotProveStatic:
      'Declaration does not prove the app successfully registered as device admin on a user device.',
    whatItDoesNotProveDynamic:
      'Sandbox may not fully emulate post-reboot behavior.',
    riskImpactIntro:
      'Contributes to permission-risk (PR) axis and threat-scenario persistence ratings.',
    analystTakeaway:
      'Check device-admin receivers, boot receivers, and icon-hiding strings in manifest findings.',
    mitreHint: 'T1624 - Event Triggered Execution',
  },
  visual_impersonation: {
    title: 'Visual Impersonation (VIDE)',
    whatItMeans:
      'VIDE compares application UI fingerprints (strings, layout trees, colors) against laboratory banking baselines using deterministic rules - not generative AI verdicts.',
    whyItMatters:
      'Visual similarity to a protected bank brand increases fraud likelihood and may trigger critical escalation when combined with signer impersonation or theft capabilities.',
    whatItProvesStatic:
      'Deterministic VIDE rules matched the suspect UI profile to a protected institution baseline above configured thresholds.',
    whatItProvesDynamic:
      'WebView or dynamic UI capture contributed to the VIDE profile when integrated.',
    whatItProvesBoth:
      'Static and integrated UI sources contributed to a deterministic VIDE match.',
    whatItDoesNotProveStatic:
      'Visual similarity alone is not proof of credential theft - confirm with permissions and runtime behavior.',
    whatItDoesNotProveDynamic:
      'Similar layouts may occur in legitimate white-label apps; review rule ID and confidence.',
    riskImpactIntro:
      'Increases BT axis and may floor verdict severity when critical visual cluster rules fire.',
    analystTakeaway:
      'Open Technical View visual panel; review rule ID, confidence, and signer impersonation flags - do not treat as LLM narrative.',
    mitreHint: 'T1656 - Impersonation',
  },
};
