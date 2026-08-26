import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import type { FraudCardData } from '../../App';
import type { IntelApiPayload } from '../../lib/threatIntelModel';
import IntelligenceSourcesPanel from './IntelligenceSourcesPanel';

/**
 * The defect these lock out: this panel derived its own status from result
 * counts and never read `sources_status`, so a feed that was never queried -
 * because no API key is configured - rendered as "Unavailable" beside an IOC
 * row reading "No indicators matched external feeds". Both read as findings
 * about the sample. Neither was earned.
 */

function caseOf(over: Partial<FraudCardData> = {}): FraudCardData {
  return {
    sha256: 'a'.repeat(64),
    package_name: 'com.example.app',
    analysis_mode: 'dynamic',
    family_classification: 'Unknown',
    base_score: 0,
    ai_confidence_multiplier: 1,
    final_risk_score: 40,
    risk_band: 'Suspicious',
    confidence: 60,
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

function intelOf(sourcesStatus: IntelApiPayload['sources_status']): IntelApiPayload {
  return {
    sources_status: sourcesStatus,
    iocs: [],
    malware_family: 'Unknown',
    virus_total: { available: false, malicious: 0, total: 71, ratio: 0, vendors: [] },
    alienvault: { available: false, pulse_count: 0, campaign: 'None', pulses: [] },
    abuseipdb: { available: false, confidence: 0, reports: 0 },
  } as unknown as IntelApiPayload;
}

const draw = (intel: IntelApiPayload, data = caseOf()) =>
  render(<IntelligenceSourcesPanel intel={intel} data={data} bundle={null} />);

/** The whole card for a source, not just the header row its name sits in. */
const cardFor = (name: string) =>
  screen.getByText(name).closest('div.rounded-lg') as HTMLElement;

describe('IntelligenceSourcesPanel', () => {
  it('says "Not queried" for a source with no API key, never "No match"', () => {
    draw(
      intelOf([
        { name: 'VirusTotal', status: 'missing_key', message: 'No VT API key configured' },
      ]),
    );

    const vt = cardFor('VirusTotal');
    expect(vt.textContent).toContain('Not queried');
    expect(vt.textContent).not.toContain('No match');
  });

  it('distinguishes a real clean result from an unasked question', () => {
    draw(
      intelOf([
        { name: 'VirusTotal', status: 'active', message: 'ok' },
        { name: 'AbuseIPDB', status: 'missing_key', message: 'No key' },
      ]),
    );

    const vt = cardFor('VirusTotal');
    const abuse = cardFor('AbuseIPDB');

    expect(vt.textContent).toContain('No match');
    expect(vt.textContent).toMatch(/Queried; 0 of 71/);
    expect(abuse.textContent).toContain('Not queried');
  });

  it('warns that an unqueried source is not evidence of safety', () => {
    draw(intelOf([{ name: 'VirusTotal', status: 'missing_key', message: 'No key' }]));
    expect(
      screen.getByText(/Absence of a match from an unqueried source is not evidence of safety/i),
    ).toBeInTheDocument();
  });

  it('omits the caveat when every source actually answered', () => {
    draw(
      intelOf([
        { name: 'VirusTotal', status: 'active', message: 'ok' },
        { name: 'AlienVault OTX', status: 'active', message: 'ok' },
        { name: 'AbuseIPDB', status: 'active', message: 'ok' },
      ]),
      caseOf({ dynamic_available: true }),
    );
    expect(screen.queryByText(/not evidence of safety/i)).not.toBeInTheDocument();
  });

  it('treats an unrecognised backend status as unqueried rather than clean', () => {
    // Guessing here would reintroduce the original defect in a new place.
    draw(intelOf([{ name: 'VirusTotal', status: 'something-new', message: '' }]));
    const vt = cardFor('VirusTotal');
    expect(vt.textContent).toContain('Not queried');
  });

  it('reports a lookup failure as a failure, not as a clean result', () => {
    draw(intelOf([{ name: 'VirusTotal', status: 'error', message: 'Upstream timeout' }]));
    const vt = cardFor('VirusTotal');
    expect(vt.textContent).toContain('Lookup failed');
    expect(vt.textContent).not.toContain('No match');
  });

  it('counts how many sources actually returned a result', () => {
    draw(
      intelOf([
        { name: 'VirusTotal', status: 'active', message: 'ok' },
        { name: 'AlienVault OTX', status: 'missing_key', message: '' },
        { name: 'AbuseIPDB', status: 'missing_key', message: '' },
      ]),
    );
    // 4 internal engines + VirusTotal answered; OTX and AbuseIPDB did not.
    expect(screen.getByText(/5 of 7 sources returned a result/i)).toBeInTheDocument();
  });

  it('does not claim runtime corroboration when the sandbox never ran', () => {
    draw(intelOf([]), caseOf({ dynamic_available: false }));
    const runtime = cardFor('Runtime analysis');
    expect(runtime.textContent).toContain('Not queried');
    expect(runtime.textContent).toContain('Sandbox did not run');
  });
});
