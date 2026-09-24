import { describe, it, expect } from 'vitest';
import type { FraudCardData, WorkflowStage } from '../types/case';
import type { ScreenshotManifestEntry } from './screenshotManifest';
import { buildAttackStory, explainMissingStory } from './attackStory';

function stage(over: Partial<WorkflowStage> = {}): WorkflowStage {
  return {
    label: 'Accessibility Service Activation',
    technique_id: 'T1417',
    description: 'Hooks AccessibilityService.onAccessibilityEvent.',
    start_ms: 0,
    end_ms: 1200,
    evidence_ids: ['EVID-001', 'EVID-002'],
    hook_names: ['AccessibilityService.onAccessibilityEvent'],
    confidence: 0.92,
    ...over,
  };
}

function caseOf(workflow: FraudCardData['fraud_workflow']): FraudCardData {
  return {
    sha256: 'a'.repeat(64),
    package_name: 'com.example.app',
    analysis_mode: 'dynamic',
    family_classification: 'Unknown',
    base_score: 0,
    ai_confidence_multiplier: 1,
    final_risk_score: 90,
    risk_band: 'Critical',
    confidence: 90,
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
    fraud_workflow: workflow,
    executive_view: {
      risk_badge: 'Critical',
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
  } as FraudCardData;
}

function shot(over: Partial<ScreenshotManifestEntry> = {}): ScreenshotManifestEntry {
  return {
    screenshot_id: 'S1',
    filename: 'shot1.png',
    label: 'Screen',
    ...over,
  } as ScreenshotManifestEntry;
}

const detectedWorkflow = (stages: WorkflowStage[]) => ({
  stages,
  fraud_sequence_detected: true,
  sequence_label: 'FULL_ACCOUNT_TAKEOVER',
  chain_confidence: 0.87,
  total_events_analyzed: 1284,
  stage_count: stages.length,
});

describe('buildAttackStory', () => {
  it('returns null when the engine detected no sequence', () => {
    expect(
      buildAttackStory(caseOf({ ...detectedWorkflow([stage()]), fraud_sequence_detected: false })),
    ).toBeNull();
  });

  it('returns null when there is no workflow at all', () => {
    expect(buildAttackStory(caseOf(undefined))).toBeNull();
  });

  it('gives every stage a plain-English sentence, not the analyst description', () => {
    const story = buildAttackStory(caseOf(detectedWorkflow([stage()])))!;
    expect(story.stages[0].plain).toMatch(/control over the device screen/i);
    // The engine's own wording is preserved, just demoted.
    expect(story.stages[0].plain).not.toContain('onAccessibilityEvent');
    expect(story.stages[0].detail).toContain('onAccessibilityEvent');
  });

  it('falls back to the engine description for an unknown stage label', () => {
    // A label the engine adds later must not silently get the wrong gloss.
    const story = buildAttackStory(
      caseOf(detectedWorkflow([stage({ label: 'Some Future Stage', description: 'Engine text.' })])),
    )!;
    expect(story.stages[0].plain).toBe('Engine text.');
  });

  it('humanises the composite sequence label', () => {
    const story = buildAttackStory(caseOf(detectedWorkflow([stage()])))!;
    expect(story.sequenceLabel).toBe('Full account takeover');
  });

  it('never grades a sandbox setup step as critical', () => {
    // These describe the harness acting, not the malware, so they are not
    // accusations however confident the engine is.
    const story = buildAttackStory(
      caseOf(
        detectedWorkflow([
          stage({ label: 'Accessibility Enabled by Sandbox', confidence: 0.99 }),
        ]),
      ),
    )!;
    expect(story.stages[0].severity).toBe('SUSPICIOUS');
  });

  it('grades a high-confidence malware stage as critical', () => {
    const story = buildAttackStory(caseOf(detectedWorkflow([stage({ confidence: 0.92 })])))!;
    expect(story.stages[0].severity).toBe('CRITICAL');
  });
});

describe('buildAttackStory - screenshot association never fabricates', () => {
  const twoStages = detectedWorkflow([
    stage({ label: 'Accessibility Service Activation', start_ms: 0, end_ms: 1000 }),
    stage({ label: 'Phishing Overlay Deployment', start_ms: 2000, end_ms: 3000 }),
  ]);

  it('attaches no screenshot when none can be matched', () => {
    const story = buildAttackStory(caseOf(twoStages), [
      shot({ screenshot_id: 'S9', timestamp_ms: 99_000 }),
    ])!;
    expect(story.stages.every((s) => s.screenshot === null)).toBe(true);
  });

  it('prefers an explicit stage label over a timestamp coincidence', () => {
    const story = buildAttackStory(caseOf(twoStages), [
      shot({ screenshot_id: 'BY_TIME', timestamp_ms: 500 }),
      shot({ screenshot_id: 'BY_LABEL', workflow_stage_label: 'Accessibility Service Activation' }),
    ])!;
    expect(story.stages[0].screenshot?.screenshot_id).toBe('BY_LABEL');
  });

  it('matches on linked evidence ids', () => {
    const story = buildAttackStory(caseOf(twoStages), [
      shot({ screenshot_id: 'BY_EVIDENCE', linked_evidence_ids: ['EVID-002'] }),
    ])!;
    expect(story.stages[0].screenshot?.screenshot_id).toBe('BY_EVIDENCE');
  });

  it('never shows one screenshot as proof of two different stages', () => {
    const story = buildAttackStory(caseOf(twoStages), [
      shot({ screenshot_id: 'ONLY', linked_evidence_ids: ['EVID-001'] }),
    ])!;
    const used = story.stages.map((s) => s.screenshot?.screenshot_id).filter(Boolean);
    expect(used).toEqual(['ONLY']);
    expect(new Set(used).size).toBe(used.length);
  });

  it('does not match on a zero-width time window', () => {
    const story = buildAttackStory(
      caseOf(detectedWorkflow([stage({ start_ms: 500, end_ms: 500, evidence_ids: [] })])),
      [shot({ screenshot_id: 'COINCIDENCE', timestamp_ms: 500 })],
    )!;
    expect(story.stages[0].screenshot).toBeNull();
  });
});

describe('explainMissingStory', () => {
  it('distinguishes "never ran" from "ran and found nothing"', () => {
    const neverRan = explainMissingStory(caseOf(undefined))!;
    expect(neverRan.uninformative).toBe(true);
    expect(neverRan.detail).toMatch(/statement about the analysis/i);

    const ranFoundNothing = explainMissingStory(
      caseOf({ ...detectedWorkflow([]), fraud_sequence_detected: false, total_events_analyzed: 1284 }),
    )!;
    expect(ranFoundNothing.uninformative).toBe(false);
    expect(ranFoundNothing.detail).toMatch(/1,284 runtime events/);
  });

  it('treats a zero-event run as uninformative', () => {
    const r = explainMissingStory(
      caseOf({ ...detectedWorkflow([]), fraud_sequence_detected: false, total_events_analyzed: 0 }),
    )!;
    expect(r.uninformative).toBe(true);
    expect(r.detail).toMatch(/not evidence that the application is safe/i);
  });

  it('returns null when a story does exist', () => {
    expect(explainMissingStory(caseOf(detectedWorkflow([stage()])))).toBeNull();
  });
});
