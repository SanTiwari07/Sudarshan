import React from 'react';
import { describe, expect, it } from 'vitest';
import { render, screen, fireEvent, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import CoreFindingsList from './CoreFindingsList';
import FindingExplanationDrawer from './FindingExplanationDrawer';
import FindingEvidenceDrawer from './FindingEvidenceDrawer';
import { InvestigationUIProvider } from '../../context/InvestigationUIContext';
import { AnalysisProvider } from '../../context/AnalysisContext';
import type { FraudCardData } from '../../App';
import { buildInvestigationBundle } from '../../hooks/useInvestigationModel';

const data: FraudCardData = {
  sha256: 'b'.repeat(64),
  package_name: 'com.malware.test',
  analysis_mode: 'static',
  family_classification: 'Unknown',
  base_score: 80,
  ai_confidence_multiplier: 1,
  final_risk_score: 80,
  risk_band: 'Critical',
  confidence: 90,
  recommended_action: 'Block',
  all_permissions: ['android.permission.BIND_ACCESSIBILITY_SERVICE'],
  hardcoded_urls_ips: [],
  targets_indian_banks: false,
  has_accessibility_abuse: true,
  has_sms_read_write: false,
  has_system_alert_window: true,
  obfuscation_score: 0.1,
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
    risk_badge: 'Critical',
    plain_english_narrative: 'Test',
    recommended_actions: [],
    customer_advisory_draft: '',
  },
  technical_view: {
    permissions_fired: [],
    strings_fired: [],
    apis_fired: ['DexClassLoader'],
    matched_rule: 'test',
    decoded_manifest_excerpts: [],
  },
};

function wrap(ui: React.ReactNode) {
  const bundle = buildInvestigationBundle(data, []);
  return (
    <MemoryRouter>
      <AnalysisProvider>
        <InvestigationUIProvider>
          {ui}
          <FindingExplanationDrawer data={data} bundle={bundle} rawRuntime={[]} />
          <FindingEvidenceDrawer data={data} bundle={bundle} rawRuntime={[]} />
        </InvestigationUIProvider>
      </AnalysisProvider>
    </MemoryRouter>
  );
}

describe('CoreFindingsList interactions', () => {
  it('opens explanation drawer when ? is clicked', async () => {
    const bundle = buildInvestigationBundle(data, []);
    render(wrap(<CoreFindingsList data={data} bundle={bundle} />));
    const explainBtn = screen.getAllByLabelText('Explain this finding')[0];
    fireEvent.click(explainBtn);
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('Why Sudarshan flagged this finding')).toBeInTheDocument();
    expect(within(dialog).getByRole('heading', { name: 'Accessibility Service Abuse' })).toBeInTheDocument();
  });

  it('shows overlay-specific explanation for overlay finding', async () => {
    const bundle = buildInvestigationBundle(data, []);
    render(wrap(<CoreFindingsList data={data} bundle={bundle} />));
    const buttons = screen.getAllByLabelText('Explain this finding');
    fireEvent.click(buttons[1]);
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByRole('heading', { name: 'Overlay Window Capability' })).toBeInTheDocument();
    expect(within(dialog).getByText(/SYSTEM_ALERT_WINDOW/)).toBeInTheDocument();
  });

  it('opens evidence drawer from verified evidence link', async () => {
    const bundle = buildInvestigationBundle(data, []);
    render(wrap(<CoreFindingsList data={data} bundle={bundle} />));
    const link = screen.getAllByRole('button', { name: /Verified evidence/i })[0];
    fireEvent.click(link);
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('Summary')).toBeInTheDocument();
    expect(within(dialog).getByText(/observation/i)).toBeInTheDocument();
  });
});
