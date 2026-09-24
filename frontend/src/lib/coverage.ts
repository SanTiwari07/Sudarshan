import type { FraudCardData } from '../types/case';

/**
 * How much of this application did we actually get to look at?
 *
 * The engine has computed an Execution Assertion Matrix for some time, but
 * `verdict` and `execution_assertions` were dropped between the risk engine and
 * the response payload, so the product had no defence against reading a sterile
 * sandbox run as a clean bill of health.
 *
 * The shape answers the question a non-technical reader actually asks, in
 * order, rather than exposing `dynamic_conclusive = false`:
 *
 *   headline  ->  Incomplete / Partial
 *   meaning   ->  this is not proof of safety
 *   why       ->  the app waited for something the sandbox never did
 *
 * This started as a banner above the verdict. It rendered the same sentence the
 * verdict's own override note already carried, so a partial run stated its
 * caveat twice before the reader reached the score. The model stayed; the
 * banner did not - VerdictBlock renders it inline, once.
 */

export type Coverage = {
  level: 'incomplete' | 'partial';
  headline: string;
  why: string;
  meaning: string;
};

export function buildCoverage(data: FraudCardData): Coverage | null {
  const frs = data.frs_breakdown;
  const assertions = data.execution_assertions;
  const incomplete =
    data.verdict === 'INCOMPLETE_EXERCISE' ||
    assertions?.incomplete_exercise ||
    frs?.verdict_floored_for_incomplete_exercise;

  if (incomplete) {
    return {
      level: 'incomplete',
      headline: 'Incomplete',
      why:
        'The application did not trigger its expected behaviour during sandbox execution. ' +
        'Banking trojans commonly wait for a targeted app to open, for an accessibility ' +
        'grant, or for an incoming message - a sterile run meets none of those conditions.',
      meaning:
        'This result must not be interpreted as proof of safety. The silence describes the ' +
        'analysis, not the application.',
    };
  }

  if (frs?.verdict_floored_for_evasion) {
    return {
      level: 'partial',
      headline: 'Partial - evasion detected',
      why:
        'The sample performed anti-analysis checks and then produced no observable behaviour. ' +
        'It appears to have detected the sandbox and withheld its payload.',
      meaning:
        'Evasion is not evidence of safety. An application that hides from analysis has told ' +
        'us something, and it is not that it is benign.',
    };
  }

  if (frs?.verdict_floored_for_visibility || frs?.concealed_payload) {
    return {
      level: 'partial',
      headline: 'Partial - payload concealed',
      why:
        'A concealed or dynamically loaded payload was found, so a significant part of the ' +
        'application\'s code was never available for analysis.',
      meaning:
        'The measured score reflects the code we could read. It understates what the ' +
        'application may be capable of.',
    };
  }

  if (frs?.dynamic_ran && !frs?.dynamic_conclusive) {
    return {
      level: 'partial',
      headline: 'Partial',
      why: 'Runtime analysis ran but did not reach a conclusive result.',
      meaning:
        'This result describes what was observed during one run rather than everything the ' +
        'application can do.',
    };
  }

  /*
   * Everything below here is a run that reached a conclusion.
   *
   * A legacy case can be conclusive and still carry no assertion matrix, since
   * the matrix postdates it. That is deliberately not surfaced: the run
   * observed enough behaviour to score the dynamic axis, so coverage was
   * adequate on the only measure that mattered at the time, and a permanent
   * "not assessed" strip on every historical case would be noise that trains
   * readers to ignore this component - which is the one place a real coverage
   * warning has to land.
   */
  return null;
}
