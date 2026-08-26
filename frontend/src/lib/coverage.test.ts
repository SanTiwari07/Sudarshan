import { describe, it, expect } from 'vitest';
import type { FraudCardData } from '../App';
import { buildCoverage } from './coverage';

/**
 * These lock the safety requirement: the product must never let a sandbox run
 * that could not certify a sample read as one that did.
 *
 * They were render tests against a CoverageNotice banner. The banner is gone -
 * it repeated the sentence the verdict's own override note already carried -
 * but the rules it encoded are the same, and testing the model rather than the
 * markup means they survive the next layout change too.
 */

function caseOf(over: Partial<FraudCardData> = {}): FraudCardData {
  return {
    sha256: 'a'.repeat(64),
    package_name: 'com.example.app',
    analysis_mode: 'dynamic',
    family_classification: 'Unknown',
    base_score: 0,
    ai_confidence_multiplier: 1,
    final_risk_score: 8,
    risk_band: 'Suspicious',
    confidence: 35,
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

describe('buildCoverage', () => {
  it('reports nothing when the run was complete and conclusive', () => {
    expect(
      buildCoverage(
        caseOf({
          risk_band: 'Safe',
          verdict: 'Safe',
          frs_breakdown: {
            dynamic_ran: true,
            dynamic_conclusive: true,
          } as FraudCardData['frs_breakdown'],
        }),
      ),
    ).toBeNull();
  });

  it('states that an incomplete run is not proof of safety', () => {
    const c = buildCoverage(caseOf({ verdict: 'INCOMPLETE_EXERCISE' }))!;
    expect(c.level).toBe('incomplete');
    expect(c.headline).toBe('Incomplete');
    expect(c.meaning).toMatch(/must not be interpreted as proof of safety/i);
  });

  it('explains why a sterile run produces silence', () => {
    const c = buildCoverage(caseOf({ verdict: 'INCOMPLETE_EXERCISE' }))!;
    expect(c.why).toMatch(/wait for a targeted app|accessibility grant|incoming message/i);
  });

  it('treats evasion as a signal rather than an absence', () => {
    const c = buildCoverage(
      caseOf({
        frs_breakdown: {
          dynamic_ran: true,
          dynamic_conclusive: false,
          verdict_floored_for_evasion: true,
        } as FraudCardData['frs_breakdown'],
      }),
    )!;
    expect(c.meaning).toMatch(/Evasion is not evidence of safety/i);
  });

  it('says the score understates risk when a payload was concealed', () => {
    const c = buildCoverage(
      caseOf({
        frs_breakdown: {
          dynamic_ran: true,
          dynamic_conclusive: false,
          concealed_payload: true,
        } as FraudCardData['frs_breakdown'],
      }),
    )!;
    expect(c.headline).toMatch(/payload concealed/i);
    expect(c.meaning).toMatch(/understates/i);
  });

  it('reports a merely inconclusive run as partial', () => {
    const c = buildCoverage(
      caseOf({
        frs_breakdown: {
          dynamic_ran: true,
          dynamic_conclusive: false,
        } as FraudCardData['frs_breakdown'],
      }),
    )!;
    expect(c.level).toBe('partial');
    expect(c.meaning).toMatch(/describes what was observed/i);
  });

  it('stays silent on a legacy conclusive case rather than crying wolf', () => {
    // No assertion matrix, but the run reached a conclusion. A permanent
    // warning on every historical case would train readers to ignore the one
    // component that has to land when coverage is genuinely bad.
    expect(
      buildCoverage(
        caseOf({
          risk_band: 'Safe',
          verdict: 'Safe',
          execution_assertions: undefined,
          frs_breakdown: {
            dynamic_ran: true,
            dynamic_conclusive: true,
          } as FraudCardData['frs_breakdown'],
        }),
      ),
    ).toBeNull();
  });

  it('never describes an inconclusive run in language that implies safety', () => {
    for (const data of [
      caseOf({ verdict: 'INCOMPLETE_EXERCISE' }),
      caseOf({
        frs_breakdown: {
          dynamic_ran: true,
          dynamic_conclusive: false,
        } as FraudCardData['frs_breakdown'],
      }),
    ]) {
      const c = buildCoverage(data)!;
      const text = `${c.headline} ${c.meaning} ${c.why}`;
      expect(text).not.toMatch(/\bis safe\b|\bno significant\b|\bminimal risk\b/i);
    }
  });
});
