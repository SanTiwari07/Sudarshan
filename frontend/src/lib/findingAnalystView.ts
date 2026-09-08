import type { FraudCardData } from '../App';
import type { InvestigationEvidence } from '../types/investigation';
import { riskRecommendedAction } from './analystCopy';

function hay(evidence: InvestigationEvidence): string {
  return `${evidence.title} ${evidence.description || ''} ${evidence.hookNames?.join(' ') || ''}`.toLowerCase();
}

export function isCriticalSeverity(severity?: string): boolean {
  if (!severity) return false;
  const s = severity.toUpperCase();
  return s === 'CRITICAL' || s.includes('CRITICAL');
}

export function formatEvidenceSource(evidence: InvestigationEvidence): string {
  if (evidence.category === 'runtime') return 'Runtime Analysis';
  const engine = evidence.sourceEngine || '';
  if (evidence.category === 'scenario' || engine.toLowerCase().includes('threat')) {
    return 'Threat Intelligence';
  }
  if (evidence.category === 'intel') return 'Threat Intelligence';
  return 'Static Analysis';
}

export function formatSeverityLabel(severity?: string): string {
  if (!severity) return 'Info';
  const s = severity.toUpperCase();
  if (s.includes('CRITICAL')) return 'Critical';
  if (s.includes('HIGH')) return 'High';
  if (s.includes('MEDIUM') || s.includes('MODERATE')) return 'Moderate';
  if (s.includes('LOW')) return 'Low';
  return severity;
}

export function whyThisMatters(evidence: InvestigationEvidence): string {
  const h = hay(evidence);
  if (h.includes('sms') || h.includes('otp')) return 'Can steal OTP';
  if (h.includes('accessibility') || h.includes('a11y')) return 'Can read and control banking screens';
  if (h.includes('overlay') || h.includes('alert window') || h.includes('system alert')) {
    return 'Can show fake login screens over banking apps';
  }
  if (h.includes('obfus') || h.includes('dex') || (h.includes('load') && h.includes('code'))) {
    return 'Can hide malicious code';
  }
  if (h.includes('network') || h.includes('c2') || h.includes('http') || h.includes('socket')) {
    return 'May communicate with attacker infrastructure';
  }
  if (h.includes('bank') || h.includes('upi') || h.includes('credential')) {
    return 'Targets banking apps or credentials';
  }
  if (h.includes('key') || h.includes('password') || h.includes('token')) {
    return 'May capture credentials';
  }
  if (h.includes('root') || h.includes('debug')) return 'May bypass device security controls';
  if (evidence.category === 'scenario') return 'Matches a known banking fraud scenario';
  return 'Adds verified risk to the fraud score';
}

export function evidencePlainText(evidence: InvestigationEvidence): string {
  const parts: string[] = [];
  if (evidence.description?.trim()) {
    parts.push(evidence.description.trim());
  }
  if (evidence.hookNames?.length) {
    parts.push(`Observed during runtime: ${evidence.hookNames.join(', ')}`);
  }
  if (evidence.artifactRefs?.length) {
    parts.push(`Linked artifacts: ${evidence.artifactRefs.slice(0, 5).join('; ')}`);
  }
  if (evidence.screenshotRef) {
    parts.push('Runtime screenshot captured for this behaviour.');
  }
  if (parts.length === 0) {
    return evidence.title;
  }
  return parts.join(' ');
}

export function technicalExplanation(evidence: InvestigationEvidence): string {
  const h = hay(evidence);
  if (h.includes('accessibility')) {
    return 'The app requests or uses Accessibility APIs that can read on-screen text and perform taps without user intent - a common technique in banking trojans.';
  }
  if (h.includes('sms')) {
    return 'SMS read or receive permissions allow the app to access message content, including one-time passwords sent by banks.';
  }
  if (h.includes('overlay') || h.includes('system alert')) {
    return 'Overlay or system alert window capability lets the app draw above other applications, which can mimic legitimate banking login screens.';
  }
  if (evidence.category === 'runtime') {
    return 'This behaviour was observed while the app ran in the Sudarshan sandbox, not only inferred from static code.';
  }
  if (evidence.category === 'scenario') {
    return 'Threat modelling mapped static and runtime signals to a documented fraud scenario used in risk scoring.';
  }
  if (evidence.description?.trim()) {
    return evidence.description.trim();
  }
  return 'Static inspection flagged this pattern in the application manifest, code, or configuration.';
}

export function fraudImpact(evidence: InvestigationEvidence, data: FraudCardData): string {
  const h = hay(evidence);
  if (h.includes('sms') || h.includes('otp')) {
    return 'Customers could lose account access if OTPs are intercepted during login or transaction approval.';
  }
  if (h.includes('accessibility')) {
    return 'Attackers may automate banking flows, harvest credentials from screen content, or approve transfers without clear user consent.';
  }
  if (h.includes('overlay')) {
    return 'Users may enter banking credentials into a fake screen controlled by the malware.';
  }
  if (h.includes('bank') || data.targets_indian_banks) {
    return 'Directly increases fraud risk for mobile banking customers and may violate app-store safety expectations.';
  }
  if (evidence.category === 'runtime') {
    return 'Confirms the capability is not theoretical - the app exhibited this behaviour under monitored execution.';
  }
  return 'Contributes to the overall fraud risk score and may compound with other findings on this case.';
}

export function affectedBankingBehaviour(evidence: InvestigationEvidence, data: FraudCardData): string {
  const h = hay(evidence);
  if (h.includes('sms') || h.includes('otp')) return 'SMS-based authentication and OTP step-up during login';
  if (h.includes('accessibility')) return 'On-screen banking sessions, balance views, and automated payment flows';
  if (h.includes('overlay')) return 'Login and credential entry while switching between apps';
  if (h.includes('upi') || h.includes('payment')) return 'UPI and payment authorization screens';
  if (data.targets_indian_banks) return 'Declared targeting of Indian banking applications';
  if (evidence.category === 'scenario') return 'End-to-end mobile banking fraud workflow';
  return 'General mobile banking trust and session integrity';
}

export function recommendedAnalystAction(evidence: InvestigationEvidence, data: FraudCardData): string {
  if (isCriticalSeverity(evidence.severity)) {
    return 'Escalate immediately: correlate with customer complaints, block distribution, and preserve runtime artifacts for CERT reporting.';
  }
  if (evidence.category === 'runtime') {
    return 'Review sandbox screenshot and network telemetry; confirm whether behaviour reproduces on a clean device profile.';
  }
  if (evidence.category === 'scenario') {
    return 'Cross-check scenario evidence against the score ledger and threat intel panel before clearing the case.';
  }
  if (data.final_risk_score >= 50) {
    return 'Treat as high-risk: document finding in case notes and align with fraud operations blocking policy.';
  }
  return 'Record in analyst notes and monitor for additional findings before customer release.';
}

export function overallAnalysisConfidence(
  records: InvestigationEvidence[],
  data: FraudCardData,
): number {
  const scored = records.filter((e) => typeof e.confidence === 'number');
  if (scored.length === 0) return 0;
  const avg = scored.reduce((s, e) => s + (e.confidence as number), 0) / scored.length;
  const scoreBoost = Math.min(15, data.final_risk_score * 0.1);
  return Math.round(Math.min(100, avg * 0.85 + scoreBoost));
}

export function caseRecommendedAction(data: FraudCardData): string {
  return data.recommended_action || riskRecommendedAction(data);
}
