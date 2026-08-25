import { describe, it, expect } from 'vitest';
import { deriveBehaviorTags } from './BehaviorTags';
import type { FraudCardData } from '../../App';

/**
 * The tags compress a whole analysis into a few words, which is exactly why
 * they are the easiest place in the UI to overstate a finding.
 *
 * The rule these tests defend: a tag names a CAPABILITY, and its basis says
 * whether we watched it happen or only read it in the manifest. A declared
 * permission must never render as observed behaviour.
 */

function card(overrides: Partial<FraudCardData> = {}): FraudCardData {
  return {
    sha256: 'a'.repeat(64),
    package_name: 'com.test.app',
    analysis_mode: 'static',
    family_classification: 'Unknown',
    base_score: 0,
    ai_confidence_multiplier: 1,
    final_risk_score: 0,
    risk_band: 'Low',
    confidence: 1,
    recommended_action: 'none',
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
    ...overrides,
  } as FraudCardData;
}

describe('deriveBehaviorTags', () => {
  it('returns nothing for a sample with no capabilities', () => {
    expect(deriveBehaviorTags(card())).toEqual([]);
  });

  it('marks a manifest-only SMS permission as declared, not observed', () => {
    const tags = deriveBehaviorTags(
      card({ all_permissions: ['android.permission.READ_SMS'] }),
    );
    const sms = tags.find((t) => t.label === 'sms-permission');
    expect(sms).toBeDefined();
    expect(sms!.basis).toBe('declared');
    expect(tags.some((t) => t.label === 'reads-sms')).toBe(false);
  });

  it('marks an SMS API call caught at runtime as observed', () => {
    const tags = deriveBehaviorTags(
      card({
        dynamic_available: true,
        all_permissions: ['android.permission.READ_SMS'],
        dynamic_analysis: {
          runtime_events: [{ hook: 'SmsMessage.getMessageBody' }],
        },
      } as Partial<FraudCardData>),
    );
    const sms = tags.find((t) => t.label === 'reads-sms');
    expect(sms).toBeDefined();
    expect(sms!.basis).toBe('observed');
    // The weaker declared tag must not also appear - one capability, one claim.
    expect(tags.some((t) => t.label === 'sms-permission')).toBe(false);
  });

  it('does not report runtime observations when dynamic analysis never ran', () => {
    const tags = deriveBehaviorTags(
      card({
        dynamic_available: false,
        dynamic_analysis: {
          runtime_events: [{ hook: 'SmsMessage.getMessageBody' }],
        },
      } as Partial<FraudCardData>),
    );
    expect(tags.some((t) => t.basis === 'observed')).toBe(false);
  });

  it('reports a dropped APK as observed', () => {
    const tags = deriveBehaviorTags(
      card({
        dynamic_available: true,
        dynamic_analysis: {
          secondary_apks: [{ filename: 'payload.apk' }],
        },
      } as Partial<FraudCardData>),
    );
    const drop = tags.find((t) => t.label === 'drops-apk');
    expect(drop).toBeDefined();
    expect(drop!.basis).toBe('observed');
  });

  it('never emits a duplicate tag', () => {
    const tags = deriveBehaviorTags(
      card({
        all_permissions: [
          'android.permission.ACCESS_FINE_LOCATION',
          'android.permission.ACCESS_COARSE_LOCATION',
        ],
      }),
    );
    expect(tags.filter((t) => t.label === 'location')).toHaveLength(1);
  });

  it('every tag carries an explanation for its presence', () => {
    const tags = deriveBehaviorTags(
      card({
        all_permissions: ['android.permission.CAMERA'],
        has_system_alert_window: true,
      }),
    );
    expect(tags.length).toBeGreaterThan(0);
    for (const tag of tags) expect(tag.title.length).toBeGreaterThan(0);
  });
});
