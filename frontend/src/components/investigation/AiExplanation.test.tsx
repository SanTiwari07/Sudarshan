import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import type { FraudCardData } from '../../App';
import AiExplanation from './AiExplanation';
import { narrativeSource } from '../../lib/executiveIntelligence';

/**
 * Provenance tests.
 *
 * The card this replaces was branded AI while three of its four sections were
 * deterministic template strings, and it degraded silently when the model
 * failed. These lock the two rules that fixes: say who wrote it, and never
 * imply the model owns the verdict.
 */

const LONG_AI =
  'This application requests accessibility control and reads incoming SMS messages, ' +
  'which together are sufficient to complete a fraudulent transfer without the customer noticing.';

function caseOf(over: Partial<FraudCardData> = {}): FraudCardData {
  return {
    sha256: 'a'.repeat(64),
    package_name: 'com.example.app',
    analysis_mode: 'dynamic',
    family_classification: 'Unknown',
    base_score: 0,
    ai_confidence_multiplier: 1,
    final_risk_score: 94,
    risk_band: 'Critical',
    confidence: 90,
    recommended_action: '',
    all_permissions: [],
    hardcoded_urls_ips: [],
    targets_indian_banks: false,
    has_accessibility_abuse: true,
    has_sms_read_write: true,
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
    ...over,
  } as FraudCardData;
}

describe('narrativeSource', () => {
  it('reports ai only when a model genuinely produced the text', () => {
    expect(
      narrativeSource(
        caseOf({
          intelligence_report: {
            plain_english_narrative: LONG_AI,
          } as FraudCardData['intelligence_report'],
        }),
      ),
    ).toBe('ai');
  });

  it('reports derived when no narrative is available', () => {
    expect(narrativeSource(caseOf())).toBe('derived');
  });

  it('mirrors the renderer when a short AI narrative shadows a long stored one', () => {
    // `||` picks the short AI string, which then fails the length gate, so the
    // renderer falls all the way through to derived. Reporting `stored` here
    // would be a provenance lie of its own.
    expect(
      narrativeSource(
        caseOf({
          intelligence_report: {
            plain_english_narrative: 'Too short.',
          } as FraudCardData['intelligence_report'],
          executive_view: {
            risk_badge: 'Critical',
            plain_english_narrative: LONG_AI,
            recommended_actions: [],
            customer_advisory_draft: '',
          },
        }),
      ),
    ).toBe('derived');
  });
});

describe('AiExplanation', () => {
  it('labels model-written text as an AI explanation', () => {
    render(
      <AiExplanation
        data={caseOf({
          intelligence_report: {
            plain_english_narrative: LONG_AI,
          } as FraudCardData['intelligence_report'],
        })}
      />,
    );
    expect(screen.getByRole('heading', { name: /AI explanation/i })).toBeInTheDocument();
  });

  it('says the explanation is unavailable rather than passing template text off as AI', () => {
    render(<AiExplanation data={caseOf()} />);
    expect(screen.getByRole('heading', { name: /Explanation unavailable/i })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: /^AI explanation$/i })).not.toBeInTheDocument();
  });

  it('states that the verdict is unaffected when the model fails', () => {
    render(<AiExplanation data={caseOf()} />);
    expect(screen.getByText(/verdict is unaffected/i)).toBeInTheDocument();
  });

  it('never claims the model produced the verdict', () => {
    render(
      <AiExplanation
        data={caseOf({
          intelligence_report: {
            plain_english_narrative: LONG_AI,
          } as FraudCardData['intelligence_report'],
        })}
      />,
    );
    expect(
      screen.getByText(/verdict itself is produced by the deterministic risk engine/i),
    ).toBeInTheDocument();
  });

  it('renders the four fixed blocks rather than a paragraph dump', () => {
    render(
      <AiExplanation
        data={caseOf({
          intelligence_report: {
            plain_english_narrative: LONG_AI,
          } as FraudCardData['intelligence_report'],
        })}
      />,
    );
    for (const label of ['What we found', 'What it means', 'Why it matters', 'What to do']) {
      expect(screen.getByRole('heading', { name: label })).toBeInTheDocument();
    }
  });
});
