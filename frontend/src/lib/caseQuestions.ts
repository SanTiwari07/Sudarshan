import type { FraudCardData } from '../App';
import { isInconclusive } from './decision';

/**
 * What is worth asking about *this* case.
 *
 * The assistant offered eight fixed prompts to every case it had ever seen,
 * including "Which MITRE techniques apply?" - jargon offered to a reader who
 * has not yet been told what the app is - and "Did it steal OTP messages?" on
 * samples with no SMS capability at all. A suggestion that does not apply is
 * worse than no suggestion: it implies the system found something it did not,
 * and it wastes the one affordance that teaches a new reader what the
 * assistant is for.
 *
 * These are derived from the case. A question only appears when the evidence
 * to answer it exists, so every chip is a promise the assistant can keep.
 */

export type CaseQuestion = {
  /** The question, as the reader would ask it. */
  text: string;
  /** Grouping for the UI - decision first, then evidence, then action. */
  kind: 'decision' | 'evidence' | 'action' | 'impact' | 'evasion' | 'network';
};

export function buildCaseQuestions(data: FraudCardData): CaseQuestion[] {
  const q: CaseQuestion[] = [];
  const inconclusive = isInconclusive(data);

  // ── Decision: what a reader who has just arrived wants ─────────────────
  q.push({ text: 'Is this app safe to install?', kind: 'decision' });

  if (inconclusive) {
    // The most important question on an uncertifiable case, and the one a
    // reader is least likely to think to ask.
    q.push({ text: 'Was the malware actually executed?', kind: 'decision' });
    q.push({ text: 'Why is the analysis incomplete?', kind: 'decision' });
  } else {
    q.push({ text: 'Explain the risk score in plain English.', kind: 'decision' });
  }

  // ── Evidence: only what this case actually has ─────────────────────────
  if (data.fraud_workflow?.fraud_sequence_detected) {
    q.push({ text: 'What is this app trying to steal?', kind: 'impact' });
    q.push({ text: 'Walk me through the attack step by step.', kind: 'evidence' });
  }

  if (data.vide?.visual_impersonation_detected) {
    const bank = data.vide.visual_impersonation_institution;
    q.push({
      text: bank
        ? `How do we know it is impersonating ${bank}?`
        : 'Which bank is it impersonating, and how do we know?',
      kind: 'evidence',
    });
  }

  if (data.has_sms_read_write) {
    q.push({ text: 'Did it intercept OTP messages?', kind: 'impact' });
  }

  if (data.has_accessibility_abuse) {
    q.push({ text: 'What did it do with accessibility access?', kind: 'evasion' });
  }

  if (data.targets_indian_banks || (data.intelligence_report?.affected_banking_apps ?? []).length) {
    q.push({ text: 'Which banking apps are targeted?', kind: 'impact' });
  }

  const hasNetwork =
    (data.hardcoded_urls_ips ?? []).length > 0 ||
    (data.threat_correlation?.suspicious_domains ?? []).length > 0 ||
    (data.dynamic_analysis?.network_logs ?? []).length > 0;
  if (hasNetwork) {
    q.push({ text: 'What servers did the app contact?', kind: 'network' });
  }

  const family = data.family_classification;
  if (family && family !== 'Unknown') {
    q.push({ text: `What is the ${family} family known for?`, kind: 'evidence' });
  }

  // ── Action: what to do about it ────────────────────────────────────────
  q.push({ text: 'What should the SOC team do next?', kind: 'action' });
  // The audience switch. One product serving an executive and an engineer
  // means the reader can ask for the register they need rather than being
  // assigned one.
  q.push({ text: 'Explain this investigation to a bank manager.', kind: 'action' });

  return q;
}

/**
 * A short opening message, in place of a capability inventory.
 *
 * The assistant used to greet every case with a nine-bullet list of everything
 * it could theoretically discuss - malware behaviour, runtime hooks, IOCs,
 * mitmproxy flows, decompiled findings - which is a menu, not an answer, and
 * the same wall of options the rest of this work exists to remove.
 */
export function buildChatGreeting(data: FraudCardData): string {
  const name = data.app_name || data.package_name;
  const inconclusive = isInconclusive(data);

  if (inconclusive) {
    return (
      `I have the evidence for **${name}** indexed.\n\n` +
      'Note that this analysis did not exercise the sample, so I can tell you what ' +
      'was observed but not that the app is safe. Ask me anything about the case.'
    );
  }

  return (
    `I have the evidence for **${name}** indexed, and I answer only from it.\n\n` +
    'Ask me anything about this case - I will show you which records each answer came from.'
  );
}
