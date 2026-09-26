import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import ThreatCorrelationPanel from './ThreatCorrelationPanel';
import type { FraudCardData } from '../../types/case';

vi.mock('../../context/InvestigationUIContext', () => ({
  useInvestigationUI: () => ({ openEvidence: vi.fn() }),
}));

/**
 * The panel used to invent risk contributions (+12.5% / +15% / +25% / +30%)
 * and a synthetic "EV-VIDE-01" record whenever the engine had not attributed
 * one - numbers that read as deterministic scores but came from nowhere.
 */
describe('ThreatCorrelationPanel', () => {
  it('shows no fabricated chain when there is no evidence', () => {
    render(
      <ThreatCorrelationPanel
        data={{ targets_indian_banks: true, threat_scenario_table: [] } as unknown as FraudCardData}
        bundle={null}
      />,
    );
    expect(screen.getByText(/No correlated threat chains/i)).toBeInTheDocument();
    expect(screen.queryByText('EV-VIDE-01')).not.toBeInTheDocument();
    expect(screen.queryByText(/\+30\.0%/)).not.toBeInTheDocument();
  });

  it('does not invent a contribution for an unscored scenario row', () => {
    render(
      <ThreatCorrelationPanel
        data={{
          threat_scenario_table: [
            {
              evidence: 'X',
              indicator: 'SMS read',
              threat_scenario: 'OTP theft',
              credential_theft_risk: 'HIGH',
              confidence: 0.9,
            },
          ],
        } as unknown as FraudCardData}
        bundle={null}
      />,
    );
    expect(screen.getByText('Not scored')).toBeInTheDocument();
    expect(screen.queryByText(/\+25\.0%/)).not.toBeInTheDocument();
  });
});
