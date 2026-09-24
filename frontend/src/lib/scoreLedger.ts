import type { FraudCardData } from '../types/case';
import type { LedgerLine, LedgerScope } from '../types/investigation';
import { axisDisplayName } from './evidenceParser';

/**
 * Nominal STEI axis weights, used only when a case predates the engine
 * publishing the weights it actually scored at.
 *
 * The engine drops axes that a concealed payload made blind and renormalises
 * the rest, so these are the RIGHT weights only for a fully visible sample.
 * Reading them unconditionally understated every surviving axis on exactly the
 * samples the exclusion rule exists to catch - the ledger said "CT 0.60" for a
 * run where CT had been removed from the denominator entirely.
 */
const NOMINAL_STEI_WEIGHTS: Record<string, number> = {
  ct: 0.6,
  bt: 0.2,
  pr: 0.1,
  ob: 0.05,
  ir: 0.05,
};

const STEI_AXES = ['ct', 'bt', 'pr', 'ob', 'ir'] as const;

/**
 * The weight each STEI axis actually carried, from the engine when it published
 * them. The fallback reproduces the engine's own rule - drop the excluded axes,
 * renormalise the remainder - rather than inventing a split of its own.
 */
export function getSteiWeights(data: FraudCardData): Record<string, number> {
  const published = data.frs_breakdown?.stei_weights_used;
  if (published && Object.keys(published).length > 0) return published;

  const excluded = new Set(data.frs_breakdown?.stei_axes_excluded ?? []);
  const scored = STEI_AXES.filter((a) => !excluded.has(a));
  const total = scored.reduce((sum, a) => sum + NOMINAL_STEI_WEIGHTS[a], 0);
  if (!scored.length || total <= 0) return { ...NOMINAL_STEI_WEIGHTS };
  return Object.fromEntries(scored.map((a) => [a, NOMINAL_STEI_WEIGHTS[a] / total]));
}

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
  const steiWeights = getSteiWeights(data);
  const steiExcluded = new Set(frs.stei_axes_excluded ?? []);
  const expl = data.risk_explanation;
  const steiAxes = frs.stei_axes || { ct: 0, bt: 0, pr: 0, ob: 0, ir: 0 };

  STEI_AXES.forEach((axis) => {
    const axisScore = steiAxes[axis] ?? 0;
    const weight = steiWeights[axis] ?? 0;
    const isExcluded = steiExcluded.has(axis);
    const steiContrib = isExcluded ? 0 : axisScore * weight;
    const axisLines = expl?.stei_evidence_by_axis?.[axis] || [];
    lines.push({
      id: `LEDGER-STEI-${axis}`,
      component: 'stei',
      axis,
      label: axisDisplayName(axis),
      detail: isExcluded
        ? 'Axis excluded - the payload is concealed, so this axis could not be measured. It was dropped from the STEI denominator rather than scored as zero.'
        : `${axisScore.toFixed(1)} axis score × ${weight.toFixed(3)} weight → ${steiContrib.toFixed(1)} toward STEI`,
      contribution: isExcluded ? undefined : steiContrib,
      contributionLabel: isExcluded ? 'EXCLUDED' : `+${steiContrib.toFixed(1)} STEI`,
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
