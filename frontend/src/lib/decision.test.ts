import { describe, it, expect } from 'vitest';
import type { FraudCardData } from '../App';
import { getDecision, isInconclusive } from './decision';

/**
 * Regression tests for the safety model.
 *
 * The bug these exist to prevent: the decision was derived by branching on
 * `band === 'critical' | 'high' | 'medium' | 'low'`, but the risk engine emits
 * `Critical | High | Suspicious | Safe`. 'Suspicious' matched nothing, fell
 * through to a score threshold, and a case the engine had explicitly floored
 * because it refused to certify it rendered as
 * "ALLOW - Minimal risk detected. No significant fraud indicators".
 */

function caseOf(over: Partial<FraudCardData> = {}): FraudCardData {
  return {
    sha256: 'a'.repeat(64),
    package_name: 'com.example.app',
    analysis_mode: 'static',
    family_classification: 'Unknown',
    base_score: 0,
    ai_confidence_multiplier: 1,
    final_risk_score: 0,
    risk_band: 'Safe',
    confidence: 70,
    recommended_action: '',
    all_permissions: [],
    hardcoded_urls_ips: [],
    targets_indian_banks: false,
    has_accessibility_abuse: false,
    has_sms_read_write: false,
    has_system_alert_window: false,
    dynamic_available: false,
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
      risk_badge: 'Safe',
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

/**
 * Affirmative clean-bill language, which must never appear for a case the
 * engine declined to certify.
 *
 * Deliberately does not match a bare "safe": "DO NOT TREAT AS SAFE" is the
 * copy we want, and a blunter regex would fail the correct string.
 */
const CLEAN_BILL_LANGUAGE =
  /\ballow\b|\bis safe\b|\bno significant\b|\bminimal risk\b|\bno threats found\b/i;

describe('getDecision - the false ALLOW regression', () => {
  it('does not render ALLOW for a Suspicious case that scored below 10', () => {
    // The exact shape that produced the bug: the engine floored Safe ->
    // Suspicious for incomplete exercise, leaving a very low raw score.
    const d = getDecision(
      caseOf({
        risk_band: 'Suspicious',
        final_risk_score: 8,
        verdict: 'INCOMPLETE_EXERCISE',
      }),
    );

    expect(d.action).not.toBe('ALLOW');
    expect(d.action).toBe('INCONCLUSIVE');
    expect(d.inconclusive).toBe(true);
    expect(d.headline).not.toMatch(CLEAN_BILL_LANGUAGE);
    expect(d.rationale).not.toMatch(/no significant|minimal risk/i);
  });

  it('maps a plain Suspicious band to REVIEW, never to ALLOW', () => {
    const d = getDecision(caseOf({ risk_band: 'Suspicious', final_risk_score: 8 }));
    expect(d.action).toBe('REVIEW');
    expect(d.headline).toBe('Review before installing');
  });

  it('treats evasion and incomplete-exercise floors as disqualifying', () => {
    // These two floors mean the analysis itself failed to produce a reliable
    // answer: either the sandbox was actively sabotaged (evasion) or the trigger
    // conditions were never reached (incomplete exercise). The score gauge must
    // show "No score assigned" for both.
    //
    // verdict_floored_for_visibility and verdict_floored_for_static_evidence are
    // NOT inconclusive: they conservatively raise a band from Safe→Suspicious
    // when the engine cannot certify a clean result, but the computed score is
    // still valid and should be displayed normally.
    const disqualifyingFloors = [
      'verdict_floored_for_evasion',
      'verdict_floored_for_incomplete_exercise',
    ] as const;

    for (const floor of disqualifyingFloors) {
      const data = caseOf({
        risk_band: 'Suspicious',
        final_risk_score: 2,
        frs_breakdown: { [floor]: true } as FraudCardData['frs_breakdown'],
      });
      expect(isInconclusive(data), floor).toBe(true);
      expect(getDecision(data).action, floor).toBe('INCONCLUSIVE');
      expect(getDecision(data).inconclusive, floor).toBe(true);
    }
  });

  it('does NOT treat visibility floor as inconclusive - score is valid', () => {
    // verdict_floored_for_visibility: concealed payload + no sandbox → band raised
    // Safe→Suspicious, but the STEI score is perfectly valid and must be shown.
    const data = caseOf({
      risk_band: 'Suspicious',
      final_risk_score: 21,
      frs_breakdown: {
        verdict_floored_for_visibility: true,
        stei: 46,
      } as FraudCardData['frs_breakdown'],
    });
    expect(isInconclusive(data)).toBe(false);
    expect(getDecision(data).action).toBe('REVIEW');
    expect(getDecision(data).inconclusive).toBe(false);
  });

  it('refuses a clean bill of health when the sandbox ran but was inconclusive', () => {
    const d = getDecision(
      caseOf({
        risk_band: 'Safe',
        final_risk_score: 3,
        frs_breakdown: {
          dynamic_ran: true,
          dynamic_conclusive: false,
        } as FraudCardData['frs_breakdown'],
      }),
    );
    expect(d.action).toBe('ALLOW WITH CAUTION');
    expect(d.rationale).toMatch(/not conclusive/i);
  });
});

describe('getDecision - the ordinary bands', () => {
  it('maps Critical to BLOCK', () => {
    const d = getDecision(caseOf({ risk_band: 'Critical', final_risk_score: 94 }));
    expect(d.action).toBe('BLOCK');
    expect(d.headline).toBe('Block and isolate');
    expect(d.inconclusive).toBe(false);
  });

  it('maps High to ESCALATE', () => {
    const d = getDecision(caseOf({ risk_band: 'High', final_risk_score: 71 }));
    expect(d.action).toBe('ESCALATE');
  });

  it('allows a genuinely clean case with a conclusive run', () => {
    const d = getDecision(
      caseOf({
        risk_band: 'Safe',
        final_risk_score: 2,
        frs_breakdown: {
          dynamic_ran: true,
          dynamic_conclusive: true,
        } as FraudCardData['frs_breakdown'],
      }),
    );
    expect(d.action).toBe('ALLOW');
    expect(d.inconclusive).toBe(false);
  });

  it('downgrades a low-scoring case that still holds fraud capability', () => {
    const d = getDecision(
      caseOf({
        risk_band: 'Safe',
        final_risk_score: 4,
        has_accessibility_abuse: true,
        frs_breakdown: {
          dynamic_ran: true,
          dynamic_conclusive: true,
        } as FraudCardData['frs_breakdown'],
      }),
    );
    expect(d.action).toBe('ALLOW WITH CAUTION');
  });

  it('reports coverage in the inconclusive rationale when assertions exist', () => {
    const d = getDecision(
      caseOf({
        risk_band: 'Suspicious',
        final_risk_score: 8,
        verdict: 'INCOMPLETE_EXERCISE',
        execution_assertions: {
          verdict: 'INCOMPLETE_EXERCISE',
          incomplete_exercise: true,
          dynamic_ran: true,
          threat_events_observed: 0,
          coverage_ratio: 0.44,
          fired_count: 4,
          total_count: 9,
          assertions: [],
          unfired_keys: [],
        },
      }),
    );
    expect(d.rationale).toContain('4 of 9');
  });
});
