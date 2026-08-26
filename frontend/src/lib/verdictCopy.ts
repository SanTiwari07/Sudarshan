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
 * The engine's band thresholds, and where a score sits against them.
 *
 * These numbers were written into `getDecision`'s unknown-band fallback and
 * again into the hero dial's tick marks, so the notches on the ring and the
 * sentence beside it could disagree about where Suspicious begins. One list.
 *
 * The sentence exists because a ring on its own is decoration: it shows a
 * fraction of a circle and leaves the reader to know from memory whether 14
 * is good. What a reader wants from a low score is how much room is left
 * before it stops being low.
 */
export const BAND_THRESHOLDS = [
  { at: 35, name: 'Suspicious' },
  { at: 60, name: 'High' },
  { at: 80, name: 'Critical' },
] as const;

export function scalePosition(score: number | null | undefined): string {
  const s = typeof score === 'number' && !Number.isNaN(score) ? score : 0;
  const next = BAND_THRESHOLDS.find((t) => s < t.at);
  if (!next) return `At or above the Critical threshold of ${BAND_THRESHOLDS[2].at}`;
  const gap = Math.round(next.at - s);
  return `${gap} point${gap === 1 ? '' : 's'} below the ${next.name} threshold of ${next.at}`;
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
  /*
   * An inconclusive runtime result is deliberately not reported here.
   *
   * Every other branch answers one question - why does the band outrank its own
   * number - and each names a floor the engine applied. "Runtime was not
   * conclusive" is a statement about coverage, not about a band raise, and
   * returning it from a function called `bandOverrideReason` put a coverage
   * caveat beside the verdict for a third time: the headline already reads
   * COVERAGE INCOMPLETE, and the runtime axis in the score breakdown already
   * says it was not counted.
   */
  return null;
}

/**
 * The single sentence that answers "so what?" above the fold.
 *
 * Prefers the engine's own first evidence line over the AI narrative: it is
 * shorter, it is deterministic, and it is the one an analyst can defend.
 */
export function verdictHeadline(data: FraudCardData): string {
  /*
   * What this application is, and what it can do.
   *
   * This used to return `risk_explanation.evidence_lines[0]` verbatim, so the
   * largest sentence under the verdict read "1 dangerous permission(s) (+20
   * PR)" - the engine's own scoring notation, complete with the axis
   * abbreviation and the points it contributed. That is a note the engine
   * writes to itself while adding up a score, not a description of an
   * application, and it was the first full sentence a bank manager met.
   *
   * Built from capability rather than from score arithmetic: what the app can
   * reach, who it resembles, and who it targets. Nothing here mentions which
   * part of the analysis succeeded or failed - the verdict above already
   * carries that, and repeating it turns a description of the sample into a
   * status report about the sandbox.
   */
  const caps: string[] = [];
  if (data.has_accessibility_abuse) caps.push('control the screen through accessibility services');
  if (data.has_sms_read_write) caps.push('read incoming SMS, including one-time passwords');
  if (data.has_system_alert_window) caps.push('draw its own screens over other applications');

  const family = data.family_classification;
  const named = Boolean(family && family !== 'Unknown');

  const banks = (data.intelligence_report?.affected_banking_apps ?? []).filter(Boolean);
  const targets = banks.length > 0
    ? ` It references ${banks.slice(0, 3).join(', ')}${banks.length > 3 ? ' and others' : ''}.`
    : data.targets_indian_banks
      ? ' It references Indian banking applications.'
      : '';

  if (caps.length > 0) {
    const list =
      caps.length === 1
        ? caps[0]
        : `${caps.slice(0, -1).join(', ')} and ${caps[caps.length - 1]}`;
    const attribution = named ? `Its behaviour matches the ${family} family. ` : '';
    return `${attribution}This application can ${list}.${targets}`;
  }

  if (named) {
    return `Indicators from this application match the ${family} family.${targets}`;
  }

  // No fraud capability and no family. Say what the app is rather than
  // reaching for the score.
  const dangerous = (data.dangerous_permissions ?? []).length;
  const iocs = data.threat_correlation?.ioc_reputation?.length ?? 0;

  if (dangerous > 0 && iocs > 0) {
    return `This application requests ${dangerous} dangerous permission${
      dangerous === 1 ? '' : 's'
    } and contacts ${iocs} external indicator${iocs === 1 ? '' : 's'} known to threat intelligence.${targets}`;
  }
  if (dangerous > 0) {
    return `This application requests ${dangerous} dangerous permission${
      dangerous === 1 ? '' : 's'
    }, but none of the fraud capabilities SUDARSHAN screens for were found.${targets}`;
  }
  if (iocs > 0) {
    return `No fraud capability was found in this application, though ${iocs} of the indicators it contacts are known to threat intelligence.`;
  }
  return 'None of the fraud capabilities SUDARSHAN screens for were found in this application.';
}
