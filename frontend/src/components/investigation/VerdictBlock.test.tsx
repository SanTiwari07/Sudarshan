import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import type { FraudCardData } from '../../types/case';
import VerdictBlock from './VerdictBlock';
import { InvestigationUIProvider } from '../../context/InvestigationUIContext';

/**
 * The identity strip beside the verdict.
 *
 * It replaced a band-override note that had become the third statement of the
 * same coverage caveat on one screen. Its rules: show only facts that exist,
 * never repeat a fact the heading already carries, and never print a pipeline
 * internal - it briefly read "Analysis androguard+mobsf", which names the tools
 * that ran rather than telling the reader anything about the application.
 */

function caseOf(over: Partial<FraudCardData> = {}): FraudCardData {
  return {
    sha256: 'd17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af',
    package_name: 'com.tjmonh.android',
    analysis_mode: 'androguard+mobsf',
    family_classification: 'trojan.rewardsteal',
    base_score: 0,
    ai_confidence_multiplier: 1,
    final_risk_score: 14.1,
    risk_band: 'Safe',
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
    frs_breakdown: {
      dynamic_ran: true,
      dynamic_conclusive: false,
    } as FraudCardData['frs_breakdown'],
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

const draw = (data = caseOf()) =>
  render(
    <MemoryRouter>
      <InvestigationUIProvider>
        <VerdictBlock data={data} />
      </InvestigationUIProvider>
    </MemoryRouter>,
  );

describe('VerdictBlock identity strip', () => {
  it('shows the full hash, not a truncation', () => {
    // It is the identifier an analyst pastes into other tooling.
    const data = caseOf();
    draw(data);
    expect(screen.getByText(data.sha256)).toBeInTheDocument();
  });

  it('never prints which tools ran', () => {
    const { container } = draw();
    expect(container.textContent).not.toMatch(/androguard|mobsf/i);
  });

  it('omits facts the analysis does not have, rather than printing dashes', () => {
    const { container } = draw();
    expect(container.textContent).not.toMatch(/Version|Size|Target SDK|Signed by/);
  });

  it('shows the facts it does have', () => {
    draw(
      caseOf({
        app_name: 'Example App',
        version_name: '3.2.1',
        all_permissions: ['a', 'b', 'c'],
        dangerous_permissions: [{ permission: 'READ_SMS' }] as FraudCardData['dangerous_permissions'],
        activities: ['x', 'y'],
        services: ['z'],
      }),
    );
    expect(screen.getByText('Version')).toBeInTheDocument();
    expect(screen.getByText('3.2.1')).toBeInTheDocument();
    expect(screen.getByText('3 · 1 dangerous')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument(); // components
  });

  it('does not repeat the package when the heading already shows it', () => {
    // With no app name the h1 falls back to the package, so a Package row would
    // print the same string twice, two lines apart.
    const { container } = draw(caseOf({ app_name: undefined }));
    expect(container.textContent).not.toMatch(/Package/);
  });

  it('shows the package once an app name occupies the heading', () => {
    draw(caseOf({ app_name: 'Example App' }));
    expect(screen.getByText('Package')).toBeInTheDocument();
    expect(screen.getByText('com.tjmonh.android')).toBeInTheDocument();
  });

  it('reads a common name out of an X.509 subject', () => {
    draw(
      caseOf({
        certificate: { subject: 'C=IN, ST=MH, O=Acme Ltd, CN=Acme Signing Key' },
      } as Partial<FraudCardData>),
    );
    expect(screen.getByText('Acme Signing Key')).toBeInTheDocument();
  });

  it('falls back to the raw subject when there is no common name', () => {
    draw(caseOf({ certificate: { subject: 'O=Unstructured Signer' } } as Partial<FraudCardData>));
    expect(screen.getByText('O=Unstructured Signer')).toBeInTheDocument();
  });

  it('does not restate the coverage caveat beside the verdict', () => {
    // The headline already reads COVERAGE INCOMPLETE and the score breakdown
    // says the runtime axis was not counted.
    const { container } = draw();
    expect(container.textContent).not.toMatch(
      /Runtime analysis ran but was not conclusive/i,
    );
  });

  /*
   * This asserted that the block led with the decision headline and carried an
   * h1. Both were removed at the product owner's direction - the verdict
   * statement, its confidence meter and the plain-language description of the
   * build are no longer rendered anywhere on the case page.
   *
   * The assertion is inverted rather than deleted, so the removal stays a
   * decision on the record instead of quietly becoming an absence nobody can
   * account for later. If the headline comes back, this test fails and asks.
   */
  it('no longer renders a verdict headline - removed by request', () => {
    const { container } = draw();
    expect(container.querySelector('h1')).toBeNull();
    expect(container.textContent).not.toMatch(/no threat observed/i);
  });
});
