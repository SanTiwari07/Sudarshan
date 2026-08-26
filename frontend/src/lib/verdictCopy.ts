import type { FraudCardData } from '../App';

/**
 * Canonical score rendering.
 *
 * The header rendered `8.7` while the hero ring rendered `9` for the same
 * case, two hundred pixels apart. To a reviewer that reads as two different
 * numbers, or as a rounding bug — either way it costs more credibility than
 * the decimal place is worth. Every surface that prints an FRS goes through
 * here.
 */
export function formatScore(score: number | null | undefined): string {
  if (score === null || score === undefined || Number.isNaN(score)) return '-';
  return score.toFixed(1);
}

/**
 * Why a band can outrank its own number.
 *
 * A score of 8.7 labelled SUSPICIOUS looks like a broken scale until you know
 * the engine floors the verdict when it finds a concealed payload or an
 * evasion-only run: the low number means "we could not measure much", not
 * "this is nearly clean", and the band is what carries that. Returning the
 * specific reason turns an apparent contradiction into the most interesting
 * sentence on the page.
 *
 * Returns null when score and band agree and no explanation is owed.
 */
export function bandOverrideReason(data: FraudCardData): string | null {
  const frs = data.frs_breakdown;
  if (!frs) return null;

  if (frs.verdict_floored_for_evasion) {
    return 'Band raised above the raw score: the sample ran anti-analysis checks and then withheld its behaviour. Evasion is not evidence of safety.';
  }
  if (frs.concealed_payload) {
    return 'Band raised above the raw score: a concealed payload was found in static analysis, so the measured score understates the risk.';
  }
  if (frs.verdict_floored_for_visibility) {
    return 'Band raised above the raw score: too little of the sample was observable to certify it, so the verdict is floored for analyst visibility.';
  }
  if (data.verdict === 'INCOMPLETE_EXERCISE' || data.execution_assertions?.incomplete_exercise) {
    return 'The sandbox never exercised this sample, so the score reflects what could be measured, not what the app can do.';
  }
  return null;
}

/**
 * The single sentence that answers "so what?" above the fold.
 *
 * Prefers the engine's own first evidence line over the AI narrative: it is
 * shorter, it is deterministic, and it is the one an analyst can defend.
 */
export function verdictHeadline(data: FraudCardData): string {
  const line = data.risk_explanation?.evidence_lines?.[0];
  if (line) return line;

  const family = data.family_classification;
  if (family && family !== 'Unknown') {
    return `Behaviour and indicators match the ${family} banking-malware family.`;
  }
  return `Static, runtime and threat-intelligence evidence place this sample in the ${(
    data.risk_band || 'unknown'
  ).toLowerCase()} band.`;
}
