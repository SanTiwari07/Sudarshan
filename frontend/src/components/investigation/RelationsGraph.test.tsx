import { describe, it, expect } from 'vitest';
import { buildRelationNodes } from './RelationsGraph';
import type { FraudCardData } from '../../types/case';

/**
 * The graph merges three IOC sources onto one canvas. The risk in doing that is
 * flattening the difference between "this string appears in the binary" and
 * "the sample actually contacted this host" - so the observed flag, and the
 * ordering that protects it under truncation, are what these tests pin.
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

describe('buildRelationNodes', () => {
  it('returns nothing when there are no indicators', () => {
    expect(buildRelationNodes(card()).nodes).toEqual([]);
  });

  it('marks a statically extracted host as not observed', () => {
    const { nodes } = buildRelationNodes(
      card({ hardcoded_urls_ips: ['evil.test'] }),
    );
    expect(nodes).toHaveLength(1);
    expect(nodes[0].observed).toBe(false);
  });

  it('marks a host seen in network logs as observed', () => {
    const { nodes } = buildRelationNodes(
      card({
        dynamic_analysis: { network_logs: [{ url: 'https://evil.test/beacon' }] },
      } as Partial<FraudCardData>),
    );
    expect(nodes).toHaveLength(1);
    expect(nodes[0].observed).toBe(true);
  });

  it('a host both hardcoded and contacted counts once, as observed', () => {
    const { nodes, total } = buildRelationNodes(
      card({
        hardcoded_urls_ips: ['evil.test'],
        dynamic_analysis: { network_logs: [{ url: 'https://evil.test/x' }] },
      } as Partial<FraudCardData>),
    );
    expect(total).toBe(1);
    expect(nodes[0].observed).toBe(true);
  });

  it('classifies IPs, domains and dropped APKs distinctly', () => {
    const { nodes } = buildRelationNodes(
      card({
        hardcoded_urls_ips: ['192.168.1.5', 'evil.test'],
        dynamic_analysis: { secondary_apks: [{ filename: 'payload.apk' }] },
      } as Partial<FraudCardData>),
    );
    const kinds = Object.fromEntries(nodes.map((n) => [n.label, n.kind]));
    expect(kinds['192.168.1.5']).toBe('ip');
    expect(kinds['evil.test']).toBe('domain');
    expect(kinds['payload.apk']).toBe('apk');
  });

  it('keeps observed nodes when the ring is truncated', () => {
    // Truncation must not silently drop what actually happened in favour of
    // strings that were merely present in the binary.
    const { nodes, total } = buildRelationNodes(
      card({
        hardcoded_urls_ips: Array.from({ length: 30 }, (_, i) => `static${i}.test`),
        dynamic_analysis: { network_logs: [{ url: 'https://real.test/a' }] },
      } as Partial<FraudCardData>),
      5,
    );
    expect(total).toBe(31);
    expect(nodes).toHaveLength(5);
    expect(nodes[0].label).toBe('real.test');
    expect(nodes[0].observed).toBe(true);
  });

  it('shortens a long URL to its host', () => {
    const { nodes } = buildRelationNodes(
      card({ hardcoded_urls_ips: ['https://evil.test/very/long/path?q=1'] }),
    );
    expect(nodes[0].label).toBe('evil.test');
  });
});
