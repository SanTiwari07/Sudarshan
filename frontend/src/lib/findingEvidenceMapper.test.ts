import { describe, expect, it } from 'vitest';
import type { FraudCardData } from '../App';
import { buildTechnicalFindingViewModel } from './buildTechnicalFindingViewModel';
import {
  computeEvidenceBasis,
  evidenceBasisBadge,
  mapFindingEvidence,
} from './findingEvidenceMapper';
import { buildInvestigationBundle } from '../hooks/useInvestigationModel';

function minimalData(overrides: Partial<FraudCardData> = {}): FraudCardData {
  return {
    sha256: 'a'.repeat(64),
    package_name: 'com.test.app',
    analysis_mode: 'static',
    family_classification: 'Unknown',
    base_score: 50,
    ai_confidence_multiplier: 1,
    final_risk_score: 50,
    risk_band: 'High Risk',
    confidence: 80,
    recommended_action: 'Review',
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
      risk_badge: 'High Risk',
      plain_english_narrative: 'Test',
      recommended_actions: [],
      customer_advisory_draft: '',
    },
    technical_view: {
      permissions_fired: [],
      strings_fired: [],
      apis_fired: [],
      matched_rule: 'test',
      decoded_manifest_excerpts: [],
    },
    ...overrides,
  };
}

describe('findingEvidenceMapper', () => {
  it('maps accessibility static evidence when flag set', () => {
    const data = minimalData({ has_accessibility_abuse: true });
    const bundle = buildInvestigationBundle(data, []);
    const items = mapFindingEvidence('accessibility_abuse', data, bundle, []);
    expect(items.some((i) => i.id === 'STAT-A11Y')).toBe(true);
    expect(computeEvidenceBasis(items)).toBe('static_only');
    expect(evidenceBasisBadge(computeEvidenceBasis(items))).toBe('STATIC');
  });

  it('labels static and dynamic when runtime accessibility present', () => {
    const data = minimalData({ has_accessibility_abuse: true });
    const bundle = buildInvestigationBundle(data, []);
    const raw = [
      {
        finding_id: 'EVID-001',
        category: 'accessibility',
        description: 'AccessibilityManager event',
        timestamp_ms: 1000,
      },
    ];
    const items = mapFindingEvidence('accessibility_abuse', data, bundle, raw);
    expect(computeEvidenceBasis(items)).toBe('static_and_dynamic');
    expect(evidenceBasisBadge(computeEvidenceBasis(items))).toBe('STATIC + DYNAMIC');
  });

  it('does not fabricate overlay evidence when not detected', () => {
    const data = minimalData({ has_system_alert_window: false });
    const items = mapFindingEvidence('overlay_capability', data, null, []);
    expect(items.length).toBe(0);
  });

  it('maps runtime code loading from apis_fired not obfuscation alone', () => {
    const data = minimalData({
      obfuscation_score: 0.9,
      technical_view: {
        permissions_fired: [],
        strings_fired: [],
        apis_fired: ['DexClassLoader'],
        matched_rule: 'test',
        decoded_manifest_excerpts: [],
      },
    });
    const items = mapFindingEvidence('runtime_code_loading', data, null, []);
    expect(items.some((i) => i.title.includes('DexClassLoader'))).toBe(true);
  });
});

describe('buildTechnicalFindingViewModel risk inputs unchanged', () => {
  it('does not mutate fraud card scores when building view model', () => {
    const data = minimalData({
      has_accessibility_abuse: true,
      final_risk_score: 77,
      frs_breakdown: {
        stei: 80,
        dynamic: 0,
        correlation: 0,
        banking_impact: 0,
        formula_used: 'static_only_frs',
        dynamic_available: false,
      },
    });
    const before = data.final_risk_score;
    const vm = buildTechnicalFindingViewModel('accessibility_abuse', data, buildInvestigationBundle(data, []), []);
    expect(data.final_risk_score).toBe(before);
    expect(vm.severityLabel).toMatch(/Critical/i);
  });
});
