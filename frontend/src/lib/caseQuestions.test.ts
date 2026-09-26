import { describe, it, expect } from 'vitest';
import type { FraudCardData } from '../types/case';
import { buildCaseQuestions, buildChatGreeting } from './caseQuestions';

/**
 * The assistant offered eight fixed prompts to every case, including
 * "Did it steal OTP messages?" on samples with no SMS capability at all. A
 * suggestion that does not apply implies a finding that was never made.
 */

function caseOf(over: Partial<FraudCardData> = {}): FraudCardData {
  return {
    sha256: 'a'.repeat(64),
    package_name: 'com.example.app',
    app_name: 'Example App',
    analysis_mode: 'dynamic',
    family_classification: 'Unknown',
    base_score: 0,
    ai_confidence_multiplier: 1,
    final_risk_score: 40,
    risk_band: 'Suspicious',
    confidence: 60,
    recommended_action: '',
    all_permissions: [],
    hardcoded_urls_ips: [],
    targets_indian_banks: false,
    has_accessibility_abuse: false,
    has_sms_read_write: false,
    has_system_alert_window: false,
    dynamic_available: true,
    manifest_findings: [],
    code_findings: [],
    dangerous_permissions: [],
    activities: [],
    services: [],
    receivers: [],
    certificate: {},
    domains: {},
    hardcoded_secrets: [],
    executive_view: {
      risk_badge: 'Suspicious',
      plain_english_narrative: '',
      recommended_actions: [],
      customer_advisory_draft: '',
    },
    technical_view: {
      permissions_fired: [],
      strings_fired: [],
      apis_fired: [],
      matched_rule: '',
      decoded_manifest_excerpts: [],
    },
    ...over,
  } as FraudCardData;
}

const texts = (d: FraudCardData) => buildCaseQuestions(d).map((q) => q.text);

const WORKFLOW = {
  stages: [],
  fraud_sequence_detected: true,
  sequence_label: 'FULL_ACCOUNT_TAKEOVER',
  chain_confidence: 0.87,
  total_events_analyzed: 100,
  stage_count: 3,
};

describe('buildCaseQuestions - a chip is a promise the assistant can keep', () => {
  it('never offers an OTP question for a sample with no SMS capability', () => {
    expect(texts(caseOf())).not.toContain('Did it intercept OTP messages?');
  });

  it('offers it when the sample does read SMS', () => {
    expect(texts(caseOf({ has_sms_read_write: true }))).toContain(
      'Did it intercept OTP messages?',
    );
  });

  it('offers the attack walkthrough only when a chain was reconstructed', () => {
    expect(texts(caseOf())).not.toContain('Walk me through the attack step by step.');
    expect(
      texts(caseOf({ fraud_workflow: WORKFLOW as FraudCardData['fraud_workflow'] })),
    ).toContain('Walk me through the attack step by step.');
  });

  it('names the impersonated bank when VIDE identified one', () => {
    const q = texts(
      caseOf({
        vide: {
          visual_impersonation_detected: true,
          visual_impersonation_institution: 'State Bank of India',
        } as FraudCardData['vide'],
      }),
    );
    expect(q).toContain('How do we know it is impersonating State Bank of India?');
  });

  it('falls back to a generic impersonation question when no bank is named', () => {
    const q = texts(
      caseOf({ vide: { visual_impersonation_detected: true } as FraudCardData['vide'] }),
    );
    expect(q).toContain('Which bank is it impersonating, and how do we know?');
  });

  it('offers a family question only for a named family', () => {
    expect(texts(caseOf())).not.toContain('What is the Unknown family known for?');
    expect(texts(caseOf({ family_classification: 'Anatsa' }))).toContain(
      'What is the Anatsa family known for?',
    );
  });

  it('offers a network question only when there is network evidence', () => {
    expect(texts(caseOf())).not.toContain('What servers did the app contact?');
    expect(texts(caseOf({ hardcoded_urls_ips: ['hxxp://evil.test'] }))).toContain(
      'What servers did the app contact?',
    );
  });
});

describe('buildCaseQuestions - the inconclusive case', () => {
  const incomplete = caseOf({ verdict: 'INCOMPLETE_EXERCISE' });

  it('leads with the question the reader is least likely to think to ask', () => {
    const q = texts(incomplete);
    expect(q).toContain('Was the malware actually executed?');
    expect(q).toContain('Why is the analysis incomplete?');
  });

  it('does not offer to explain a score it cannot stand behind', () => {
    expect(texts(incomplete)).not.toContain('Explain the risk score in plain English.');
    expect(texts(caseOf())).toContain('Explain the risk score in plain English.');
  });
});

describe('buildCaseQuestions - always present', () => {
  it('always offers the decision and the audience switch', () => {
    for (const d of [caseOf(), caseOf({ verdict: 'INCOMPLETE_EXERCISE' })]) {
      const q = texts(d);
      expect(q).toContain('Is this app safe to install?');
      expect(q).toContain('Explain this investigation to a bank manager.');
      expect(q).toContain('What should the SOC team do next?');
    }
  });

  it('assigns every question one of the declared kinds', () => {
    for (const q of buildCaseQuestions(caseOf({ has_sms_read_write: true }))) {
      expect(['decision', 'evidence', 'action', 'impact', 'evasion', 'network']).toContain(q.kind);
    }
  });

  it('produces no duplicates', () => {
    const q = texts(
      caseOf({
        has_sms_read_write: true,
        has_accessibility_abuse: true,
        targets_indian_banks: true,
        family_classification: 'Anatsa',
        fraud_workflow: WORKFLOW as FraudCardData['fraud_workflow'],
      }),
    );
    expect(new Set(q).size).toBe(q.length);
  });
});

describe('buildChatGreeting', () => {
  it('is short, and does not list capabilities', () => {
    // It used to open with a nine-bullet inventory of everything the assistant
    // could theoretically discuss - a menu, not an answer.
    const g = buildChatGreeting(caseOf());
    expect(g).toContain('Example App');
    expect(g.split('\n').filter((l) => l.trim().startsWith('*'))).toHaveLength(0);
    expect(g.length).toBeLessThan(400);
  });

  it('warns up front when the analysis could not certify the sample', () => {
    const g = buildChatGreeting(caseOf({ verdict: 'INCOMPLETE_EXERCISE' }));
    expect(g).toMatch(/did not exercise the sample/i);
    expect(g).toMatch(/not that the app is safe/i);
  });
});
