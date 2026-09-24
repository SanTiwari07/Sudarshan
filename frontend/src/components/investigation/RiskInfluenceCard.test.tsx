import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import type { FraudCardData } from '../../types/case';
import RiskInfluenceCard from './RiskInfluenceCard';
import { InvestigationUIProvider } from '../../context/InvestigationUIContext';

/**
 * This card is an account of how a three-axis score was reached.
 *
 * An axis was briefly filtered out when it contributed nothing, on the
 * reasoning that "NOT INCLUDED" repeated a coverage caveat the verdict already
 * carried. That made the account incomplete rather than shorter - a reader
 * could not tell whether runtime was clean, absent, or never asked - and left a
 * hole in the row. These tests keep every axis on screen.
 */

function caseOf(over: Partial<FraudCardData> = {}): FraudCardData {
  return {
    sha256: 'a'.repeat(64),
    package_name: 'com.example.app',
    analysis_mode: 'dynamic',
    family_classification: 'Unknown',
    base_score: 0,
    ai_confidence_multiplier: 1,
    final_risk_score: 14,
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
      stei: 40,
      dynamic: 0,
      correlation: 71,
      banking_impact: 0,
      formula_used: 'full_frs',
      dynamic_available: true,
      dynamic_ran: true,
      // The shape from the screenshot: the sandbox ran and reached no
      // conclusion, so the axis is excluded from the score.
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
        <RiskInfluenceCard data={data} />
      </InvestigationUIProvider>
    </MemoryRouter>,
  );

describe('RiskInfluenceCard', () => {
  it('shows every axis, including one that contributed nothing', () => {
    draw();
    expect(screen.getByText('Static evidence')).toBeInTheDocument();
    expect(screen.getByText('Threat intelligence')).toBeInTheDocument();
    expect(screen.getByText('Runtime behaviour')).toBeInTheDocument();
  });

  it('says an excluded axis was excluded, rather than omitting it', () => {
    // The reader has to be able to tell "clean" from "not counted".
    draw();
    const runtime = screen.getByText('Runtime behaviour').closest('button')!;
    expect(runtime.textContent).toMatch(/not included/i);
  });

  it('does not award points to an excluded axis', () => {
    draw();
    const runtime = screen.getByText('Runtime behaviour').closest('button')!;
    expect(runtime.textContent).not.toMatch(/\+\d/);
  });

  it('recesses the excluded axis instead of alarming about it', () => {
    // It belongs in the account of the score; it is not a warning. The verdict
    // above already carries the coverage caveat.
    draw();
    const runtime = screen.getByText('Runtime behaviour').closest('button')!;
    expect(runtime.className).toMatch(/bg-slate-50/);
    expect(runtime.className).not.toMatch(/amber|red/);
  });

  it('keeps the axis visible at every reading depth', () => {
    for (const depth of ['summary', 'analyst', 'forensic']) {
      localStorage.setItem('sudarshan_case_depth', depth);
      const { unmount } = draw();
      expect(screen.getByText('Runtime behaviour'), depth).toBeInTheDocument();
      unmount();
    }
    localStorage.clear();
  });

  it('shows the observed runtime score even when it was not counted', () => {
    const { container } = render(
      <MemoryRouter>
        <InvestigationUIProvider>
          <RiskInfluenceCard
            data={caseOf({
              frs_breakdown: {
                stei: 40,
                dynamic: 62,
                correlation: 71,
                banking_impact: 0,
                formula_used: 'full_frs',
                dynamic_available: true,
                dynamic_ran: true,
                dynamic_conclusive: false,
              } as FraudCardData['frs_breakdown'],
            })}
          />
        </InvestigationUIProvider>
      </MemoryRouter>,
    );
    /*
     * Asserted against the intent, not the sentence. The wording changed when
     * the card started showing its arithmetic; what must hold is that an
     * excluded axis still reports the score it observed, and still says that
     * score did not count - so a reader cannot mistake the exclusion for a
     * clean result.
     */
    expect(container.textContent).toMatch(/62\.0 out of 100/i);
    expect(container.textContent).toMatch(/excluded/i);
    expect(container.textContent).toMatch(/not evidence of safety/i);
  });
});
