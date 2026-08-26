import { useState } from 'react';
import { ChevronDown, SearchX, TriangleAlert } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { FraudCardData } from '../../App';
import { TYPOGRAPHY } from '../../theme/typography';
import { SEVERITY } from '../../theme/severity';
import { useCaseLinks } from '../../hooks/useCaseLinks';

/**
 * How much of this application did we actually get to look at?
 *
 * This replaces a banner that had never rendered. The engine has computed an
 * Execution Assertion Matrix since it was written, but `verdict` and
 * `execution_assertions` were dropped between the risk engine and the response
 * payload, so the branch was permanently dead and the product silently lost its
 * only defence against reading a sterile sandbox run as a clean bill of health.
 *
 * The structure follows the question a non-technical reader actually asks, in
 * order, rather than exposing `dynamic_conclusive = false`:
 *
 *   ANALYSIS COVERAGE -> PARTIAL
 *   Why?              -> the app waited for something the sandbox never did
 *   What does it mean?-> this is not proof of safety
 *   (then, for analysts) which specific trigger conditions went unmet
 *
 * It keeps full width, because it changes how every other number on the page
 * reads: when the sandbox never exercised the sample, a low score is a
 * statement about the run, not about the app.
 */

type Coverage = {
  level: 'incomplete' | 'partial';
  headline: string;
  why: string;
  meaning: string;
};

function buildCoverage(data: FraudCardData): Coverage | null {
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

export default function CoverageNotice({ data }: { data: FraudCardData }) {
  const [open, setOpen] = useState(false);
  const links = useCaseLinks();
  const coverage = buildCoverage(data);
  if (!coverage) return null;

  const assertions = data.execution_assertions;
  const token = coverage.level === 'incomplete' ? SEVERITY.INCOMPLETE : SEVERITY.SUSPICIOUS;
  const Icon = coverage.level === 'incomplete' ? SearchX : TriangleAlert;
  const unfired = assertions?.assertions?.filter((a) => !a.fired) ?? [];

  return (
    <section
      aria-label="Analysis coverage"
      className={`rounded-lg border ${token.border} ${token.bg} overflow-hidden`}
    >
      <div className="px-5 py-4 flex flex-col sm:flex-row sm:items-start gap-3">
        <Icon className={`h-4 w-4 shrink-0 mt-0.5 ${token.fg}`} aria-hidden />

        <div className="min-w-0 flex-1 space-y-2">
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <h2 className={TYPOGRAPHY.h3}>Analysis coverage</h2>
            <span className={`${TYPOGRAPHY.badgePill} ${token.badge} border-transparent`}>
              {coverage.headline}
            </span>
            {assertions && assertions.total_count > 0 && (
              <span className={TYPOGRAPHY.label}>
                {assertions.fired_count} of {assertions.total_count} trigger conditions reached
              </span>
            )}
          </div>

          <p className={`${TYPOGRAPHY.body} max-w-[68ch]`}>{coverage.meaning}</p>

          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
            className={`${TYPOGRAPHY.linkAction}`}
          >
            Why?
            <ChevronDown
              className={`h-3.5 w-3.5 transition-transform ${open ? 'rotate-180' : ''}`}
              aria-hidden
            />
          </button>

          {open && (
            <div className="space-y-3 pt-1">
              <p className={`${TYPOGRAPHY.bodySmall} max-w-[68ch]`}>{coverage.why}</p>

              {unfired.length > 0 && (
                <div className="space-y-1.5">
                  <p className={TYPOGRAPHY.label}>Conditions never reached</p>
                  <ul className="space-y-1.5">
                    {unfired.map((a) => (
                      <li key={a.key} className={`${TYPOGRAPHY.bodySmall} flex gap-2`}>
                        <span className="text-slate-400 shrink-0" aria-hidden>
                          &middot;
                        </span>
                        <span>
                          <span className="font-medium text-slate-900">{a.label}</span>
                          {a.remediation && <> &mdash; {a.remediation}</>}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <Link to={`${links.evidence}#dynamic-analysis`} className={TYPOGRAPHY.linkAction}>
                Inspect runtime analysis
              </Link>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
