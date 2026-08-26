import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import type { FraudCardData } from '../../App';
import CoverageNotice from './CoverageNotice';
import { AnalysisProvider } from '../../context/AnalysisContext';

/**
 * These lock the Part 22 safety requirement at the render layer.
 *
 * The banner this replaces was never exercised by a test, which is part of why
 * nobody noticed that the two fields it depended on had never been sent to the
 * frontend at all.
 */

function caseOf(over: Partial<FraudCardData> = {}): FraudCardData {
  return {
    sha256: 'a'.repeat(64),
    package_name: 'com.example.app',
    analysis_mode: 'dynamic',
    family_classification: 'Unknown',
    base_score: 0,
    ai_confidence_multiplier: 1,
    final_risk_score: 8,
    risk_band: 'Suspicious',
    confidence: 35,
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

// CoverageNotice links across to the evidence section of the case it describes,
// so it needs the analysis context to know which case that is.
const draw = (data: FraudCardData) =>
  render(
    <MemoryRouter>
      <AnalysisProvider>
        <CoverageNotice data={data} />
      </AnalysisProvider>
    </MemoryRouter>,
  );

describe('CoverageNotice', () => {
  it('renders nothing when coverage was complete and conclusive', () => {
    const { container } = draw(
      caseOf({
        risk_band: 'Safe',
        verdict: 'Safe',
        frs_breakdown: {
          dynamic_ran: true,
          dynamic_conclusive: true,
        } as FraudCardData['frs_breakdown'],
      }),
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('states that an incomplete run is not proof of safety', () => {
    draw(caseOf({ verdict: 'INCOMPLETE_EXERCISE' }));

    expect(screen.getByRole('heading', { name: /Analysis coverage/i })).toBeInTheDocument();
    expect(screen.getByText(/Incomplete/)).toBeInTheDocument();
    expect(screen.getByText(/must not be interpreted as proof of safety/i)).toBeInTheDocument();
  });

  it('reports how many trigger conditions were reached', () => {
    draw(
      caseOf({
        verdict: 'INCOMPLETE_EXERCISE',
        execution_assertions: {
          verdict: 'INCOMPLETE_EXERCISE',
          incomplete_exercise: true,
          dynamic_ran: true,
          threat_events_observed: 0,
          coverage_ratio: 0.44,
          fired_count: 4,
          total_count: 9,
          assertions: [],
          unfired_keys: [],
        },
      }),
    );
    expect(screen.getByText(/4 of 9 trigger conditions reached/i)).toBeInTheDocument();
  });

  it('explains evasion as a signal rather than as an absence', () => {
    draw(
      caseOf({
        frs_breakdown: {
          dynamic_ran: true,
          dynamic_conclusive: false,
          verdict_floored_for_evasion: true,
        } as FraudCardData['frs_breakdown'],
      }),
    );
    expect(screen.getByText(/Evasion is not evidence of safety/i)).toBeInTheDocument();
  });

  it('stays silent on a legacy conclusive case rather than crying wolf', () => {
    // No assertion matrix, but the run reached a conclusion. A permanent
    // "not assessed" strip on every historical case would train readers to
    // ignore the one component that has to land when coverage is genuinely bad.
    const { container } = draw(
      caseOf({
        risk_band: 'Safe',
        verdict: 'Safe',
        execution_assertions: undefined,
        frs_breakdown: {
          dynamic_ran: true,
          dynamic_conclusive: true,
        } as FraudCardData['frs_breakdown'],
      }),
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('never paints an inconclusive result green', () => {
    const { container } = draw(caseOf({ verdict: 'INCOMPLETE_EXERCISE' }));
    expect(container.innerHTML).not.toMatch(/emerald|-green-/);
  });
});
