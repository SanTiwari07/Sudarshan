import { describe, expect, it } from 'vitest';
import {
  illustratedByEvidenceId,
  isTimelineEligibleVisual,
  executiveVisualEntries,
  visualFromEntry,
} from './visualEvidence';
import { screenshotDescription, type ScreenshotManifestEntry } from './screenshotManifest';

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

  // The evidence modal used to print the investigative claim under "Visual
  // observation" AND again under "Why it matters", so an uncorroborated frame
  // showed the same generic sentence twice and described the picture neither
  // time. These carry the fields that keep the three questions apart.
  it('carries the visual observation alongside the claim', () => {
    const ve = visualFromEntry(
      entry({
        visual_evidence: undefined,
        claim_type: 'inconclusive_visual',
        investigative_claim: 'Visual capture completed but insufficient corroborating…',
        visual_observation: 'Bank login screen (LoginActivity) showing 2 input fields.',
        screen_summary: 'Bank login screen (LoginActivity)',
        corroboration_summary: 'No runtime hook fired while this screen was displayed.',
      }),
    );
    expect(ve?.visual_observation).toBe(
      'Bank login screen (LoginActivity) showing 2 input fields.',
    );
    expect(ve?.visual_observation).not.toBe(ve?.investigative_claim);
    expect(ve?.corroboration_summary).not.toBe(ve?.visual_observation);
  });

  it('captions a tile with the screen it shows, not the capture reason', () => {
    expect(
      screenshotDescription({
        screenshot_id: 'SCR-001',
        filename: 'screenshots/a.png',
        label: 'state_state-002_bank_login',
        reason: 'SUSPICIOUS_UI',
        screen_summary: 'Bank login screen (LoginActivity)',
      }),
    ).toBe('Bank login screen (LoginActivity)');
  });

  it('falls back to the old label when no summary was recorded', () => {
    expect(
      screenshotDescription({
        screenshot_id: 'SCR-001',
        filename: 'screenshots/a.png',
        label: '01_app_opened',
      }),
    ).toBe('01_app_opened');
  });
});
