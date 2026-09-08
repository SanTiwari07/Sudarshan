import type { FraudCardData } from '../App';
import type { InvestigationEvidence } from '../types/investigation';
import { formatEvidenceSource, isCriticalSeverity } from './findingAnalystView';

export type FindingExplanation = {
  summary: string;
  whatWasFound: string;
  whyItMatters: string;
  severityExplanation: string;
  evidenceInterpretation: string;
  recommendedAction: string;
  artifactIntro: string;
  /** Null when the producing engine reported no confidence for the record. */
  confidenceTierLabel: string | null;
  confidenceTierExplanation: string | null;
};

function hay(evidence: InvestigationEvidence): string {
  return `${evidence.title} ${evidence.description || ''} ${evidence.hookNames?.join(' ') || ''} ${evidence.id}`.toLowerCase();
}

function isRuntime(evidence: InvestigationEvidence): boolean {
  return evidence.category === 'runtime';
}

function isThreat(evidence: InvestigationEvidence): boolean {
  return evidence.category === 'intel' || evidence.category === 'scenario' || evidence.sourceEngine.toLowerCase().includes('threat');
}

function artifactCount(evidence: InvestigationEvidence): number {
  return evidence.artifactRefs?.length ?? 0;
}

export function confidenceTierLabel(confidence: number): string {
  const pct = Math.max(0, Math.min(100, confidence));
  if (pct >= 90) return 'Very high confidence';
  if (pct >= 75) return 'High confidence';
  if (pct >= 50) return 'Moderate confidence';
  return 'Low confidence';
}

export function confidenceTierExplanation(confidence: number): string {
  const tier = confidenceTierLabel(confidence);
  if (tier === 'Very high confidence') {
    return 'The analyzer found strong, direct supporting evidence for this finding.';
  }
  if (tier === 'High confidence') {
    return 'The analyzer found direct supporting evidence for this finding.';
  }
  if (tier === 'Moderate confidence') {
    return 'Supporting evidence is present, but some details may be incomplete or indirect.';
  }
  return 'Evidence is limited; treat this finding as a weak signal until corroborated.';
}

function severityBand(evidence: InvestigationEvidence): string {
  const s = (evidence.severity || '').toLowerCase();
  if (s.includes('critical')) return 'critical';
  if (s.includes('high')) return 'high';
  if (s === 'good' || s.includes('positive')) return 'good';
  if (s.includes('warning') || s.includes('medium') || s.includes('moderate')) return 'warning';
  return 'info';
}

function severityExplanationFor(evidence: InvestigationEvidence): string {
  const band = severityBand(evidence);
  if (band === 'critical') {
    return 'CRITICAL means this finding represents a severe security concern that should be investigated immediately. It may indicate behaviour or capabilities that can directly harm banking customers or enable fraud when combined with other evidence.';
  }
  if (band === 'high') {
    return 'HIGH means this finding is a significant security concern. It does not always prove active fraud by itself, but it warrants prompt analyst review and correlation with runtime and threat-intelligence evidence.';
  }
  if (band === 'warning') {
    return 'WARNING means this finding highlights a meaningful security weakness or risky capability. Importance depends on whether attacker-controlled input or sensitive data can reach the affected code path.';
  }
  if (band === 'good') {
    return 'GOOD means this finding describes a protective or positive security control (for example hardening), not a threat signal.';
  }
  return 'INFO means this finding is a security observation. It does not by itself prove that the application is malicious. Its importance depends on what is actually involved and whether that information can be accessed by another party.';
}

function staticEvidenceBase(evidence: InvestigationEvidence): string {
  const n = artifactCount(evidence);
  if (n > 0) {
    return `Static analysis identified related patterns in ${n} decompiled source artifact${n === 1 ? '' : 's'}.`;
  }
  return 'Static analysis identified this pattern during code and manifest inspection without running the application.';
}

function runtimeEvidenceBase(evidence: InvestigationEvidence): string {
  const hooks = evidence.hookNames?.length ? evidence.hookNames.join(', ') : null;
  if (hooks) {
    return `Runtime instrumentation observed this behaviour in the sandbox (hooks: ${hooks}). This is observed execution behaviour, not only a static capability.`;
  }
  if (evidence.screenshotRef) {
    return 'Runtime sandbox execution produced observable behaviour for this finding, including visual evidence captured during analysis.';
  }
  return 'Runtime sandbox execution produced observable behaviour matching this finding.';
}

function evidenceInterpretation(evidence: InvestigationEvidence): string {
  const h = hay(evidence);
  const runtime = isRuntime(evidence);

  if (runtime) {
    if (h.includes('inconclusive') || h.includes('no ui')) {
      return 'Runtime analysis ran but did not produce conclusive behavioural proof for this item. This does not confirm malicious activity; it means the behaviour could not be reliably observed in the sandbox.';
    }
    return `${runtimeEvidenceBase(evidence)} This supports that the behaviour occurred under monitored execution, though it may still require analyst review to understand customer impact.`;
  }

  if (isThreat(evidence)) {
    return 'This finding reflects external threat correlation or scenario mapping. It supports association with known fraud patterns or infrastructure, but should be read alongside static and runtime evidence - not as standalone proof of on-device behaviour.';
  }

  if (h.includes('sql') && h.includes('raw')) {
    return `${staticEvidenceBase(evidence)} This confirms the presence of raw SQL query construction in code, but does not by itself prove that an attacker successfully injected SQL or accessed data without reviewing whether untrusted input reaches those queries.`;
  }

  if (h.includes('log') && !h.includes('catalog')) {
    return `${staticEvidenceBase(evidence)} This confirms logging-related code is present, but does not by itself prove that credentials, OTPs, or financial data were actually written to logs.`;
  }

  if (h.includes('md5') || h.includes('weak hash') || h.includes('insecure random')) {
    return `${staticEvidenceBase(evidence)} This confirms use of a weak cryptographic or randomness pattern in code. It indicates a potential weakness, not confirmed exploitation or data compromise.`;
  }

  if (h.includes('accessibility') || h.includes('a11y')) {
    return `${staticEvidenceBase(evidence)} This confirms accessibility-related APIs or permissions are present or referenced. Static evidence alone does not prove active screen reading or automated fraud - runtime correlation is needed to confirm abuse.`;
  }

  if (h.includes('sms') || h.includes('otp')) {
    const permOnly = h.includes('permission') || h.includes('receive') || h.includes('read sms');
    if (permOnly && !runtime) {
      return `${staticEvidenceBase(evidence)} This confirms SMS-related permission or API usage in the application package. It does not prove that SMS content was intercepted unless runtime or log evidence shows actual message access.`;
    }
    return `${staticEvidenceBase(evidence)} This supports SMS-related capability; analyst review should confirm whether message content (including OTPs) can be accessed.`;
  }

  if (h.includes('overlay') || h.includes('system alert')) {
    return `${staticEvidenceBase(evidence)} This confirms overlay or system-alert capability in the app. It does not prove a phishing overlay was shown to users without runtime or screenshot evidence.`;
  }

  if (h.includes('network') || h.includes('http') || h.includes('url') || h.includes('c2')) {
    return `${staticEvidenceBase(evidence)} This confirms network-related indicators in static analysis (for example hardcoded endpoints). It does not prove live communication with malicious infrastructure unless runtime network capture corroborates it.`;
  }

  if (h.includes('vide') || h.includes('impersonat') || h.includes('visual')) {
    return 'Visual similarity analysis compares UI elements against known banking interfaces. A match is evidence of possible impersonation design, not automatic proof that the app defrauded users.';
  }

  if (h.includes('virustotal') || h.includes('abuseipdb') || h.includes('otx') || h.includes('reputation')) {
    return 'Threat intelligence providers returned reputation or correlation signals for this case. This is third-party correlation evidence - it does not replace direct behavioural proof from static or runtime analysis.';
  }

  return `${staticEvidenceBase(evidence)} This supports the finding as coded or configured in the application, but may not prove real-world exploitation without further analyst review.`;
}

function whatWasFound(evidence: InvestigationEvidence): string {
  const h = hay(evidence);
  const runtime = isRuntime(evidence);

  if (runtime && evidence.hookNames?.length) {
    return `Sandbox instrumentation recorded activity linked to ${evidence.hookNames.join(', ')} while the application was running.`;
  }

  if (h.includes('log') && !h.includes('catalog')) {
    return 'This application contains code that writes information to application logs. Logging is not automatically malicious, but it becomes a security concern when sensitive data such as usernames, account identifiers, authentication tokens, OTPs, or transaction information is written to logs.';
  }

  if (h.includes('sql')) {
    return 'Static analysis found database access that may construct or execute SQL queries, including patterns where raw query strings are built in application code.';
  }

  if (h.includes('md5')) {
    return 'The application uses MD5 hashing in code. MD5 is considered weak for security-sensitive purposes because collision attacks are practical.';
  }

  if (h.includes('insecure random') || h.includes('weak random')) {
    return 'The application uses random number generation that may be predictable or unsuitable for security-sensitive operations such as tokens or session identifiers.';
  }

  if (h.includes('ssl') && h.includes('pin')) {
    return 'The application implements SSL certificate pinning, which restricts which server certificates the app will trust.';
  }

  if (h.includes('accessibility')) {
    return 'The application declares or references Android Accessibility services or APIs that can read on-screen content and perform automated interactions.';
  }

  if (h.includes('sms')) {
    return 'The application requests or uses SMS-related permissions or APIs that can access incoming text messages.';
  }

  if (h.includes('overlay') || h.includes('alert window')) {
    return 'The application can create overlay windows or system alert layers that may be drawn above other applications.';
  }

  if (isThreat(evidence)) {
    return 'Threat intelligence or fraud-scenario correlation produced a finding that links this application to known malware patterns, infrastructure, or documented banking fraud workflows.';
  }

  if (evidence.description?.trim() && evidence.description.trim() !== evidence.title.trim()) {
    return evidence.description.trim();
  }

  if (runtime) {
    return 'Runtime sandbox analysis observed behaviour associated with this finding while the application executed in an isolated environment.';
  }

  return `Static analysis flagged: ${evidence.title}. Review the referenced code or configuration to understand the exact implementation.`;
}

function whyItMatters(evidence: InvestigationEvidence, data: FraudCardData): string {
  const h = hay(evidence);

  if (h.includes('log') && !h.includes('catalog')) {
    return 'If sensitive information reaches logs, another process, debugging tool, compromised device, or attacker with sufficient access may be able to recover information that should have remained private.';
  }

  if (h.includes('sql')) {
    return 'If untrusted input reaches raw SQL queries without proper safeguards, an attacker may read, modify, or delete local application data - or in some designs, affect backend data depending on architecture.';
  }

  if (h.includes('md5') || h.includes('weak hash')) {
    return 'Weak hashing can allow attackers to forge or collide values used for integrity checks, weakening protections that depend on hash uniqueness.';
  }

  if (h.includes('insecure random')) {
    return 'Predictable randomness can weaken session tokens, cryptographic keys, or other values that should be unpredictable, making guessing or replay attacks easier.';
  }

  if (h.includes('accessibility')) {
    return 'Accessibility APIs can read screen content and automate taps. When abused, they may enable credential theft, OTP capture from on-screen messages, or unauthorized transaction approval.';
  }

  if (h.includes('sms') || h.includes('otp')) {
    return 'SMS access is commonly abused to intercept one-time passwords used for banking login and transaction step-up authentication.';
  }

  if (h.includes('overlay')) {
    return 'Overlay windows can mimic legitimate banking login screens to trick users into entering credentials on a fake interface controlled by malware.';
  }

  if (h.includes('network') || h.includes('c2')) {
    return 'Unexpected network endpoints may indicate command-and-control communication, data exfiltration, or reliance on attacker-controlled infrastructure.';
  }

  if (h.includes('bank') || data.targets_indian_banks) {
    return 'Findings that target banking applications or credentials increase direct fraud risk for customers using mobile banking services.';
  }

  if (isThreat(evidence)) {
    return 'Correlation with known fraud campaigns or malicious infrastructure raises the likelihood that this application is part of an organized fraud operation rather than a benign misconfiguration.';
  }

  if (isRuntime(evidence)) {
    return 'Observed runtime behaviour can confirm that a risky capability is not merely present in code but actually executed in a controlled environment.';
  }

  return 'This finding contributes to the overall fraud risk assessment and may compound with other signals when determining whether the application should be blocked or escalated.';
}

function recommendedAction(evidence: InvestigationEvidence): string {
  const h = hay(evidence);
  const band = severityBand(evidence);

  if (band === 'critical' || isCriticalSeverity(evidence.severity)) {
    return 'Treat this finding as requiring immediate investigation. Correlate with runtime captures, threat intelligence, and customer-impact indicators before clearing the case.';
  }

  if (h.includes('log') && !h.includes('catalog')) {
    return 'For an analyst: review the referenced logging statements and confirm whether credentials, OTPs, tokens, or financial information can reach application logs.';
  }

  if (h.includes('sql')) {
    return 'Review the vulnerable code path and determine whether attacker-controlled input can reach raw SQL execution. Prioritize queries that handle authentication or financial records.';
  }

  if (h.includes('accessibility')) {
    return 'Confirm whether Accessibility services are required for legitimate functionality. If not, treat as high-risk; correlate with runtime hooks and screenshots for evidence of screen scraping or automation.';
  }

  if (h.includes('sms') || h.includes('otp')) {
    return 'Verify whether the app reads SMS content at runtime, not only whether SMS permissions exist. Cross-check with OTP login flows targeted by this application.';
  }

  if (h.includes('overlay')) {
    return 'Review overlay usage and runtime screenshots to determine whether fake banking interfaces were displayed over other applications.';
  }

  if (isRuntime(evidence)) {
    return 'Review sandbox screenshots, network logs, and hook telemetry. Attempt to reproduce the observed behaviour on a clean device profile if customer impact is plausible.';
  }

  if (isThreat(evidence)) {
    return 'Validate threat provider results in the Threat Intelligence view and align scenario evidence with the score ledger before changing the case disposition.';
  }

  if (band === 'warning') {
    return 'Review the affected code path and determine whether attacker-controlled input or sensitive data can reach it. Document conclusions in analyst notes.';
  }

  return 'Record the finding in analyst notes, correlate with related evidence in this case, and monitor for additional signals before release to customers.';
}

function summaryLine(evidence: InvestigationEvidence): string {
  const h = hay(evidence);
  if (h.includes('log') && !h.includes('catalog')) return 'Sensitive data may be exposed via application logs';
  if (h.includes('sql')) return 'Raw SQL usage may allow injection if input is untrusted';
  if (h.includes('md5')) return 'Weak MD5 hashing weakens integrity protections';
  if (h.includes('accessibility')) return 'Accessibility APIs may enable screen control abuse';
  if (h.includes('sms') || h.includes('otp')) return 'SMS access may enable OTP interception';
  if (h.includes('overlay')) return 'Overlay capability may enable phishing overlays';
  if (h.includes('ssl') && h.includes('pin')) return 'Certificate pinning hardens TLS trust';
  if (isRuntime(evidence)) return 'Observed behaviour during sandbox execution';
  if (isThreat(evidence)) return 'Linked to known fraud or threat intelligence signals';
  if (h.includes('network') || h.includes('url')) return 'Network indicators may imply external communication';
  return 'Contributes to overall fraud risk assessment';
}

function artifactIntro(evidence: InvestigationEvidence): string {
  const n = artifactCount(evidence);
  const runtime = isRuntime(evidence);
  if (n === 0) {
    return runtime
      ? 'No file-level artifacts were linked to this runtime finding.'
      : 'No decompiled file paths were attached to this finding.';
  }
  if (runtime) {
    return `Runtime analysis linked ${n} artifact reference${n === 1 ? '' : 's'} to this behaviour.`;
  }
  return `Static analysis identified related code in ${n} decompiled source artifact${n === 1 ? '' : 's'}.`;
}

export function buildFindingExplanation(
  evidence: InvestigationEvidence,
  data?: FraudCardData,
): FindingExplanation {
  const caseData = data ?? ({ targets_indian_banks: false } as FraudCardData);
  const confidence = evidence.confidence;

  return {
    summary: summaryLine(evidence),
    whatWasFound: whatWasFound(evidence),
    whyItMatters: whyItMatters(evidence, caseData),
    severityExplanation: severityExplanationFor(evidence),
    evidenceInterpretation: evidenceInterpretation(evidence),
    recommendedAction: recommendedAction(evidence),
    artifactIntro: artifactIntro(evidence),
    confidenceTierLabel: confidence != null ? confidenceTierLabel(confidence) : null,
    confidenceTierExplanation:
      confidence != null ? confidenceTierExplanation(confidence) : null,
  };
}

export function findingHeadline(evidence: InvestigationEvidence): { title: string; subtitle: string | null } {
  const title = evidence.title.trim();
  const desc = evidence.description?.trim() || '';
  if (!desc || desc === title) return { title, subtitle: null };
  const norm = (s: string) => s.replace(/\s+/g, ' ').toLowerCase();
  if (norm(desc) === norm(title)) return { title, subtitle: null };
  if (norm(title).includes(norm(desc)) || norm(desc).includes(norm(title))) {
    return { title, subtitle: null };
  }
  return { title, subtitle: desc };
}

export function sourceDisplayLabel(evidence: InvestigationEvidence): string {
  const src = formatEvidenceSource(evidence);
  if (src === 'Runtime Analysis') return 'RUNTIME ANALYSIS';
  if (src === 'Threat Intelligence') return 'THREAT INTELLIGENCE';
  return 'STATIC ANALYSIS';
}
