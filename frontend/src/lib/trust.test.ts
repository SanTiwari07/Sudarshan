import { describe, it, expect } from 'vitest';
import type { FraudCardData } from '../types/case';
import { assessTrust } from './trust';

/**
 * The rule under test is the one the product keeps having to relearn: a low
 * score off a run that never woke the sample up must never read as good news.
 * `assessTrust` is the surface that answers "can I act on this", so it is the
 * last place a reassuring sentence could slip through.
 */

const REASSURING = /\b(safe|clean|no threat|benign|yes\b[^-]*$)/i;

function caseOf(over: Partial<FraudCardData> = {}): FraudCardData {
  return {
    sha256: 'a'.repeat(64),
    package_name: 'com.example.app',
    final_risk_score: 14.1,
    risk_band: 'Safe',
    confidence: 90,
    family_classification: 'Unknown',
    frs_breakdown: { dynamic_ran: true, dynamic_conclusive: true } as FraudCardData['frs_breakdown'],
    ...over,
  } as FraudCardData;
}

describe('assessTrust', () => {
  it('refuses to endorse an evasion or incomplete-exercise run, however high the confidence', () => {
    // These two floors mean the analysis itself failed — the score cannot be
    // trusted. assessTrust must return 'unreliable' and refuse any positive framing.
    for (const floor of [
      'verdict_floored_for_incomplete_exercise',
      'verdict_floored_for_evasion',
    ] as const) {
      const t = assessTrust(
        caseOf({ confidence: 99, frs_breakdown: { [floor]: true } as FraudCardData['frs_breakdown'] }),
      );
      expect(t.level, floor).toBe('unreliable');
      expect(t.confidenceLabel, floor).toBe('Low');
      expect(t.answer, floor).toMatch(/^No\b/);
      expect(t.answer, floor).not.toMatch(REASSURING);
    }
  });

  it('returns provisional (not unreliable) for a visibility floor - score is valid', () => {
    // verdict_floored_for_visibility raises a band conservatively (Safe→Suspicious)
    // because a concealed payload was found. The computed score is still valid and
    // actionable. assessTrust should return 'provisional', not 'unreliable'.
    const t = assessTrust(
      caseOf({ confidence: 99, frs_breakdown: { verdict_floored_for_visibility: true } as FraudCardData['frs_breakdown'] }),
    );
    expect(t.level).toBe('provisional');
    expect(t.answer).not.toMatch(REASSURING);
  });

  it('counts trigger coverage into the reason when the engine reported it', () => {
    const t = assessTrust(
      caseOf({
        verdict: 'INCOMPLETE_EXERCISE',
        execution_assertions: { fired_count: 1, total_count: 7 } as FraudCardData['execution_assertions'],
      }),
    );
    expect(t.detail).toMatch(/1 of 7/);
  });

  it('downgrades to provisional when the runtime axis was excluded', () => {
    const t = assessTrust(
      caseOf({ frs_breakdown: { dynamic_ran: true, dynamic_conclusive: false } as FraudCardData['frs_breakdown'] }),
    );
    expect(t.level).toBe('provisional');
    expect(t.detail).toMatch(/runtime axis was excluded/i);
    // Static still counted, so the detail must say what the verdict does rest on.
    expect(t.detail).toMatch(/static analysis/i);
  });

  it('names only the axes that actually contributed', () => {
    const conclusive = assessTrust(caseOf({ family_classification: 'trojan.rewardsteal' }));
    expect(conclusive.detail).toMatch(/runtime behaviour/i);
    expect(conclusive.detail).toMatch(/threat intelligence/i);

    const staticOnly = assessTrust(
      caseOf({ frs_breakdown: { dynamic_ran: false } as FraudCardData['frs_breakdown'] }),
    );
    expect(staticOnly.detail).not.toMatch(/runtime behaviour/i);
  });

  it('endorses a case only when every axis ran and confidence is high', () => {
    const t = assessTrust(caseOf({ confidence: 88, family_classification: 'trojan.rewardsteal' }));
    expect(t.level).toBe('reliable');
    expect(t.confidenceLabel).toBe('High');
  });

  it('asks for a second look at moderate confidence rather than endorsing', () => {
    const t = assessTrust(caseOf({ confidence: 65, family_classification: 'trojan.rewardsteal' }));
    expect(t.level).toBe('provisional');
    expect(t.confidenceLabel).toBe('Moderate');
  });
});
