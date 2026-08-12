import { describe, expect, it } from 'vitest';
import { buildFindingExplanation, confidenceTierLabel, findingHeadline } from './findingExplanation';
import type { InvestigationEvidence } from '../types/investigation';

function ev(partial: Partial<InvestigationEvidence> & Pick<InvestigationEvidence, 'id' | 'title'>): InvestigationEvidence {
  return {
    severity: 'info',
    confidence: 88,
    category: 'static',
    sourceEngine: 'Static Engine',
    ...partial,
  };
}

describe('findingExplanation', () => {
  it('explains logging without repeating title three times', () => {
    const evidence = ev({
      id: 'STAT-CODE-0',
      title: 'The App logs information.',
      description: 'Sensitive information should never be logged.',
    });
    const ex = buildFindingExplanation(evidence);
    expect(ex.whatWasFound.toLowerCase()).toContain('log');
    expect(ex.whatWasFound).not.toBe(evidence.title);
    expect(ex.evidenceInterpretation.toLowerCase()).toContain('does not by itself prove');
    const { title, subtitle } = findingHeadline(evidence);
    expect(title).toBe(evidence.title);
    expect(subtitle).toBe(evidence.description);
  });

  it('maps confidence tiers without changing value', () => {
    expect(confidenceTierLabel(88)).toBe('High confidence');
    expect(confidenceTierLabel(95)).toBe('Very high confidence');
    expect(confidenceTierLabel(40)).toBe('Low confidence');
  });

  it('distinguishes static SQL from confirmed exploit', () => {
    const evidence = ev({
      id: 'STAT-CODE-1',
      title: 'App uses SQLite and raw SQL query',
      description: 'Untrusted user input in raw SQL queries can cause SQL Injection.',
    });
    const ex = buildFindingExplanation(evidence);
    expect(ex.evidenceInterpretation.toLowerCase()).toContain('does not by itself prove');
    expect(ex.summary.toLowerCase()).toContain('sql');
  });

  it('uses runtime wording for runtime category', () => {
    const evidence = ev({
      id: 'RUN-1',
      title: 'Hook observed',
      category: 'runtime',
      hookNames: ['SmsManager.sendTextMessage'],
    });
    const ex = buildFindingExplanation(evidence);
    expect(ex.evidenceInterpretation.toLowerCase()).toContain('sandbox');
  });
});
