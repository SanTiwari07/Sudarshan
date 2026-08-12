import { describe, expect, it } from 'vitest';
import {
  illustratedByEvidenceId,
  isTimelineEligibleVisual,
  executiveVisualEntries,
} from './visualEvidence';
import type { ScreenshotManifestEntry } from './screenshotManifest';

const entry = (overrides: Partial<ScreenshotManifestEntry>): ScreenshotManifestEntry => ({
  screenshot_id: 'SCR-001',
  filename: 'screenshots/a.png',
  visual_evidence: {
    screenshot_id: 'SCR-001',
    investigative_claim: 'Claim',
    quality: 'B',
    correlation_status: 'causal',
    linked_evidence_ids: ['EVID-001'],
    timeline_eligible: true,
    report_tier: 'executive_key',
  },
  ...overrides,
});

describe('visualEvidence', () => {
  it('timeline eligibility requires A/B and meaningful correlation', () => {
    expect(isTimelineEligibleVisual(entry({}))).toBe(true);
    expect(
      isTimelineEligibleVisual(
        entry({
          visual_evidence: {
            quality: 'C',
            correlation_status: 'causal',
            timeline_eligible: true,
          },
        }),
      ),
    ).toBe(false);
    expect(
      isTimelineEligibleVisual(
        entry({
          visual_evidence: {
            quality: 'A',
            correlation_status: 'unresolved',
            timeline_eligible: true,
          },
        }),
      ),
    ).toBe(false);
  });

  it('illustratedByEvidenceId matches linked EVID', () => {
    const list = [entry({})];
    expect(illustratedByEvidenceId('EVID-001', list)).toHaveLength(1);
    expect(illustratedByEvidenceId('EVID-999', list)).toHaveLength(0);
  });

  it('executiveVisualEntries caps at two', () => {
    const list = [
      entry({ screenshot_id: 'SCR-001' }),
      entry({ screenshot_id: 'SCR-002' }),
      entry({ screenshot_id: 'SCR-003' }),
    ];
    expect(executiveVisualEntries(list)).toHaveLength(2);
  });
});
