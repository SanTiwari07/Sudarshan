import type { FraudCardData } from '../App';
import type { LedgerLine, LedgerScope } from '../types/investigation';
import { axisDisplayName } from './evidenceParser';

const STEI_WEIGHTS: Record<string, number> = {
  ct: 0.6,
  bt: 0.2,
  pr: 0.1,
  ob: 0.05,
  ir: 0.05,
};

const DEFAULT_FRS_WEIGHTS: Record<string, number> = {
  stei: 0.25,
  dynamic: 0.35,
  correlation: 0.2,
  banking_impact: 0.2,
};

const COMPONENT_LABELS: Record<string, string> = {
  stei: 'STEI (Static)',
  dynamic: 'Dynamic Sandbox',
  correlation: 'Threat Correlation',
  banking_impact: 'Banking Impact',
};

export function getAxesUsed(data: FraudCardData): Record<string, number> {
  const frs = data.frs_breakdown;
  if (frs?.axes_used && Object.keys(frs.axes_used).length > 0) {
    return frs.axes_used;
  }
  return { ...DEFAULT_FRS_WEIGHTS };
}

export function computeWeightedContribution(
  componentKey: string,
  score: number,
  axesUsed: Record<string, number>,
): number {
  const w = axesUsed[componentKey] ?? 0;
  return score * w;
}

export function buildLedgerLines(data: FraudCardData): LedgerLine[] {
  const lines: LedgerLine[] = [];
  const frs = data.frs_breakdown;
  if (!frs) return lines;

  const axesUsed = getAxesUsed(data);
  const expl = data.risk_explanation;
  const steiAxes = frs.stei_axes || { ct: 0, bt: 0, pr: 0, ob: 0, ir: 0 };

  (['ct', 'bt', 'pr', 'ob', 'ir'] as const).forEach((axis) => {
    const axisScore = steiAxes[axis] ?? 0;
    const steiContrib = axisScore * (STEI_WEIGHTS[axis] ?? 0);
    const axisLines = expl?.stei_evidence_by_axis?.[axis] || [];
    lines.push({
      id: `LEDGER-STEI-${axis}`,
      component: 'stei',
      axis,
      label: axisDisplayName(axis),
      detail: `${axisScore.toFixed(1)} axis score → ${steiContrib.toFixed(1)} toward STEI`,
      contribution: steiContrib,
      contributionLabel: `+${steiContrib.toFixed(1)} STEI`,
      evidenceIds: [],
    });
    axisLines.forEach((line, i) => {
      lines.push({
        id: `LEDGER-STEI-${axis}-${i}`,
        component: 'stei',
        axis,
        label: axisDisplayName(axis),
        detail: line,
        evidenceIds: [],
      });
    });
  });

  const componentScores: Record<string, number> = {
    stei: frs.stei,
    dynamic: frs.dynamic,
    correlation: frs.correlation,
    banking_impact: frs.banking_impact,
  };

  (['stei', 'dynamic', 'correlation', 'banking_impact'] as const).forEach((key) => {
    const score = componentScores[key];
    const weighted = computeWeightedContribution(key, score, axesUsed);
    lines.push({
      id: `LEDGER-FRS-${key}`,
      component: key,
      label: COMPONENT_LABELS[key],
      detail: `${score.toFixed(1)} / 100 × ${(axesUsed[key] ?? 0).toFixed(3)} weight → ${weighted.toFixed(2)} toward FRS`,
      contribution: weighted,
      contributionLabel: weighted.toFixed(2),
      evidenceIds: [],
    });
    const compLines = expl?.component_evidence?.[key === 'banking_impact' ? 'banking' : key] || [];
    compLines.forEach((line, i) => {
      lines.push({
        id: `LEDGER-FRS-${key}-${i}`,
        component: key,
        label: COMPONENT_LABELS[key],
        detail: line,
        evidenceIds: [],
      });
    });
  });

  if (data.dynamic_analysis?.bfci_evidence) {
    data.dynamic_analysis.bfci_evidence.forEach((line, i) => {
      lines.push({
        id: `LEDGER-BFCI-${i}`,
        component: 'dynamic',
        label: 'BFCI',
        detail: line,
        evidenceIds: [],
      });
    });
  }

  const corrSources = data.threat_correlation?.threat_score_sources;
  if (corrSources?.length) {
    corrSources.forEach((line, i) => {
      lines.push({
        id: `LEDGER-CORR-${i}`,
        component: 'correlation',
        label: 'Threat Correlation',
        detail: line,
        evidenceIds: [],
      });
    });
  }

  return lines;
}

export function filterLedgerByScope(lines: LedgerLine[], scope: LedgerScope): LedgerLine[] {
  if (scope === 'full') return lines;
  if (scope === 'stei') return lines.filter((l) => l.component === 'stei');
  if (scope === 'dynamic') return lines.filter((l) => l.component === 'dynamic');
  if (scope === 'correlation') return lines.filter((l) => l.component === 'correlation');
  if (scope === 'banking') return lines.filter((l) => l.component === 'banking_impact');
  return lines.filter((l) => l.axis === scope);
}

export function estimateBaseFrs(data: FraudCardData): number {
  const frs = data.frs_breakdown;
  if (!frs) return data.base_score;
  const axesUsed = getAxesUsed(data);
  return (
    computeWeightedContribution('stei', frs.stei, axesUsed) +
    computeWeightedContribution('dynamic', frs.dynamic, axesUsed) +
    computeWeightedContribution('correlation', frs.correlation, axesUsed) +
    computeWeightedContribution('banking_impact', frs.banking_impact, axesUsed)
  );
}
