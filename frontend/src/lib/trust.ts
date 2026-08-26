import type { FraudCardData } from '../App';
import { buildCoverage } from './coverage';
import { isInconclusive } from './decision';

/**
 * "Can I act on this?" - the question the verdict never answered.
 *
 * The hero told a reader what the score was and what to do about it, and left
 * them to work out for themselves how much either statement was worth. Those
 * are different questions with different answers: a 14 off a run that
 * exercised the sample and a 14 off a run that never woke it up are the same
 * number and opposite facts, and only one of them is safe to forward to a
 * bank.
 *
 * The rule this module exists to enforce: it never restates the caveat the
 * verdict rationale already carries. `detail` names *which evidence the score
 * actually rests on* - which axes counted, which were excluded and why. That
 * is new information on the page, and it is the honest basis for trusting a
 * result or declining to.
 */

export type TrustLevel = 'reliable' | 'provisional' | 'unreliable';

export type Trust = {
  level: TrustLevel;
  /** The answer, in the fewest words that are still honest. */
  answer: string;
  /** What the verdict rests on. Never a restatement of the rationale. */
  detail: string;
  /** Qualitative confidence. Never a bare percentage. */
  confidenceLabel: 'High' | 'Moderate' | 'Low';
};

/** Which scoring axes actually contributed, in reading order. */
function contributingAxes(data: FraudCardData): string[] {
  const frs = data.frs_breakdown;
  const axes = ['static analysis'];
  if (frs?.dynamic_conclusive) axes.push('runtime behaviour');
  if (data.intelligence_report || (data.family_classification ?? 'Unknown') !== 'Unknown') {
    axes.push('threat intelligence');
  }
  return axes;
}

function list(items: string[]): string {
  if (items.length <= 1) return items[0] ?? '';
  return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
}

export function assessTrust(data: FraudCardData): Trust {
  const inconclusive = isInconclusive(data);
  const pct = Math.min(100, Math.max(0, data.confidence ?? 0));
  const coverage = buildCoverage(data);

  // Same thresholds the confidence meter has always used, in one place now.
  const confidenceLabel: Trust['confidenceLabel'] = inconclusive
    ? 'Low'
    : pct >= 80
      ? 'High'
      : pct >= 60
        ? 'Moderate'
        : 'Low';

  if (inconclusive) {
    const a = data.execution_assertions;
    const reached =
      a && a.total_count > 0
        ? `Only ${a.fired_count} of ${a.total_count} trigger conditions were reached, so `
        : 'The sandbox never reached a trigger condition, so ';
    return {
      level: 'unreliable',
      answer: 'No - treat this sample as unassessed',
      detail: `${reached}the score measures the analysis rather than the application. Nothing here rules anything out.`,
      confidenceLabel,
    };
  }

  if (coverage) {
    const excluded =
      coverage.level === 'incomplete'
        ? 'Runtime behaviour never counted toward it.'
        : coverage.headline.includes('evasion')
          ? 'The runtime axis was excluded: the sample checked for analysis and then went quiet.'
          : coverage.headline.includes('concealed')
            ? 'Part of the code was never readable, so the score covers less than the whole application.'
            : 'The runtime axis was excluded from the score because that run reached no conclusion.';
    return {
      level: 'provisional',
      answer: 'Provisionally - one axis is missing',
      detail: `The verdict rests on ${list(contributingAxes(data))}. ${excluded}`,
      confidenceLabel,
    };
  }

  if (confidenceLabel === 'Low') {
    return {
      level: 'provisional',
      answer: 'Not on its own - have an analyst confirm it',
      detail: `The verdict rests on ${list(contributingAxes(data))}, but too few of those sources corroborated each other for it to stand unreviewed.`,
      confidenceLabel,
    };
  }

  if (confidenceLabel === 'Moderate') {
    return {
      level: 'provisional',
      answer: 'Yes, once the flagged evidence is checked',
      detail: `Every scoring axis ran - ${list(contributingAxes(data))} - and they agree, though not strongly enough to close the case without a look.`,
      confidenceLabel,
    };
  }

  return {
    level: 'reliable',
    answer: 'Yes - this verdict is well supported',
    detail: `${list(contributingAxes(data))} all counted toward this score and reached the same conclusion.`,
    confidenceLabel,
  };
}
