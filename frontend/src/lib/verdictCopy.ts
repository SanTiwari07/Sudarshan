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

  /*
   * Ordered most-specific first.
   *
   * The engine emits four floor flags. Only two of them were declared on the
   * TypeScript type and only two were read here, so a case floored for
   * incomplete exercise or for strong static evidence showed a band that
   * outranked its own score with nothing on screen explaining why - which reads
   * as a broken scale rather than as the most interesting sentence on the page.
   */
  if (data.verdict === 'INCOMPLETE_EXERCISE' || data.execution_assertions?.incomplete_exercise) {
    const a = data.execution_assertions;
    const coverage =
      a && a.total_count > 0
        ? ` Only ${a.fired_count} of ${a.total_count} trigger conditions were reached.`
        : '';
    return (
      'The sandbox ran but never exercised this sample, so no threat behaviour could be ' +
      'observed. The score reflects what could be measured, not what the app can do.' +
      coverage
    );
  }
  if (!frs) return null;

  if (frs.verdict_floored_for_incomplete_exercise) {
    return 'Band raised above the raw score: no fraud trigger condition was reached during the sandbox run, so the absence of malicious behaviour is unexplained rather than exonerating.';
  }
  if (frs.verdict_floored_for_evasion) {
    return 'Band raised above the raw score: the sample ran anti-analysis checks and then withheld its behaviour. Evasion is not evidence of safety.';
  }
  if (frs.concealed_payload) {
    return 'Band raised above the raw score: a concealed payload was found in static analysis, so the measured score understates the risk.';
  }
  if (frs.verdict_floored_for_visibility) {
    return 'Band raised above the raw score: too little of the sample was observable to certify it, so the verdict is floored for analyst visibility.';
  }
  if (frs.verdict_floored_for_static_evidence) {
    return 'Band raised above the raw score: static analysis found capability strong enough to outweigh a quiet runtime result.';
  }
  if (frs.dynamic_ran && !frs.dynamic_conclusive) {
    return 'Runtime analysis ran but was not conclusive, so this score describes what was observed rather than what the application can do.';
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
