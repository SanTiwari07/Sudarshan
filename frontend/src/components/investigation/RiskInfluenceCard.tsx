import type { FraudCardData } from '../../App';
import { computeWeightedContribution, getAxesUsed } from '../../lib/scoreLedger';
import {
  buildStaticCardSummary,
  buildThreatCardSummary,
} from '../../lib/scoreInfluenceModel';
import type { ScoreInfluenceAxis } from '../../lib/scoreInfluenceModel';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { TYPOGRAPHY } from '../../theme/typography';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import HelpTerm from './HelpTerm';
import { BarChart2, ChevronRight } from 'lucide-react';

type InfluenceRow = {
  key: string;
  axis: ScoreInfluenceAxis;
  label: string;
  term: string;
  /** Raw axis score, 0-100. Kept for the "observed but excluded" note. */
  score: number;
  /**
   * Points this axis actually put on the final FRS. This is the only number
   * that answers "what influenced the score", and it is the same unit across
   * all three axes, so the rows can honestly be ranked against each other.
   */
  contribution: number;
  summary: string;
  included: boolean;
  /** Why an excluded axis was excluded. Empty when the axis counted. */
  exclusionLabel: string;
  /**
   * The share of the final score this axis is counted at, 0-1.
   *
   * Held so the card can state the arithmetic instead of asserting a number:
   * contribution is raw score x weight, and a reader who is being asked to act
   * on "+17.7 pts" is entitled to see where 17.7 came from.
   */
  weight: number;
};

function buildRows(data: FraudCardData): InfluenceRow[] {
  const frs = data.frs_breakdown;
  if (!frs) return [];
  const axesUsed = getAxesUsed(data);

  const dynamicIncluded = Boolean(frs.dynamic_conclusive && !frs.axes_excluded?.includes('dynamic'));
  const dynamicScore = frs.dynamic ?? 0;
  const dynResult = (
    data.dynamic_result && typeof data.dynamic_result === 'object' && !Array.isArray(data.dynamic_result)
      ? data.dynamic_result
      : data.dynamic_analysis && typeof data.dynamic_analysis === 'object' && !Array.isArray(data.dynamic_analysis)
        ? data.dynamic_analysis
        : undefined
  ) as {
    dynamic_status?: string;
    error?: string;
    runtime_requested?: boolean;
    runtime_attempted?: boolean;
  } | undefined;
  const dynamicStatus = dynResult?.dynamic_status?.toUpperCase();
  const runtimeRequested = Boolean(dynResult?.runtime_requested);
  const runtimeAttempted = Boolean(
    dynResult?.runtime_attempted || frs.dynamic_ran || data.dynamic_available,
  );
  const instrumentationFailed =
    Boolean(frs.dynamic_ran) &&
    !dynamicIncluded &&
    (dynamicStatus === 'INSTRUMENTATION_FAILED' ||
      dynamicStatus === 'FRIDA_ATTACH_FAILED' ||
      Boolean(dynResult?.error));
  const runtimeNotRun = !runtimeAttempted && !runtimeRequested;
  const runtimeFailed =
    runtimeAttempted &&
    !dynamicIncluded &&
    (dynamicStatus === 'FAILED' ||
      dynamicStatus === 'EMULATOR_UNAVAILABLE' ||
      dynamicStatus === 'INSTALL_FAILED' ||
      dynamicStatus === 'FRIDA_ATTACH_FAILED' ||
      dynamicStatus === 'INSTRUMENTATION_FAILED' ||
      instrumentationFailed);
  const exclusionReason = frs.dynamic_exclusion_reason?.toUpperCase();

  const dynamicContribution = dynamicIncluded
    ? computeWeightedContribution('dynamic', dynamicScore, axesUsed)
    : 0;

  /**
   * The card used to read "0.0 pts to FRS" under the caption "Observed sandbox
   * behaviour contributed to the fraud risk score" - a sentence the number
   * directly contradicts. An axis can be included and still contribute
   * nothing: that means the sandbox watched and saw nothing chargeable, which
   * is a real and different result from "the sandbox never ran". Say which.
   */
  const dynamicSummary = dynamicIncluded
    ? dynamicContribution < 0.05
      ? 'The sandbox ran and observed no chargeable threat behaviour, so this axis added nothing to the score. It is counted, not skipped.'
      : 'Behaviour observed in the sandbox was scored and added to the fraud risk score.'
    : runtimeNotRun
      ? 'Runtime analysis was not requested for this case, so this axis was excluded from the final score.'
      : dynamicStatus === 'EMULATOR_UNAVAILABLE'
        ? 'No sandbox emulator was available when dynamic analysis was requested.'
        : runtimeFailed
          ? `Runtime analysis failed (${dynamicStatus || 'FAILED'}). The sandbox did not produce scorable evidence.`
          : exclusionReason === 'INSTRUMENTED_TOO_LATE'
            ? 'The sandbox attached to the app after it had already started, so its startup behaviour was never observed. Excluded from the score - this describes the sandbox, not the app.'
            : exclusionReason === 'NO_UI_RENDERED'
            ? 'The app never rendered a screen in the sandbox, so no runtime behaviour could be observed. Excluded from the score - this is not evidence the app is safe.'
            : exclusionReason === 'EVASION_ONLY'
              ? 'The app ran anti-analysis checks and then did nothing observable. Excluded from the score - evasion is not evidence of safety.'
              : instrumentationFailed
                ? 'Runtime instrumentation failed, so sandbox evidence was excluded from the final score.'
                : 'Runtime execution was inconclusive, so this axis was excluded from the final score.';

  const staticIncluded = !frs.axes_excluded?.includes('stei');
  const correlationIncluded = !frs.axes_excluded?.includes('correlation');
  const correlationScore = frs.correlation ?? data.threat_correlation?.threat_score ?? 0;

  const rows: InfluenceRow[] = [
    {
      key: 'stei',
      axis: 'static',
      label: 'Static evidence',
      term: 'STEI',
      score: frs.stei ?? 0,
      contribution: staticIncluded
        ? computeWeightedContribution('stei', frs.stei ?? 0, axesUsed)
        : 0,
      summary: buildStaticCardSummary(data),
      included: staticIncluded,
      weight: axesUsed['stei'] ?? 0,
      exclusionLabel: staticIncluded ? '' : 'Not included',
    },
    {
      key: 'dynamic',
      axis: 'dynamic',
      label: 'Runtime behaviour',
      term: 'BFCI',
      score: dynamicScore,
      contribution: dynamicContribution,
      summary: dynamicSummary,
      included: dynamicIncluded,
      weight: axesUsed['dynamic'] ?? 0,
      exclusionLabel: dynamicIncluded
        ? ''
        : runtimeFailed
          ? 'Failed'
          : runtimeNotRun
            ? 'Not requested'
            : 'Not included',
    },
    {
      key: 'correlation',
      axis: 'threat_intel',
      label: 'Threat intelligence',
      term: 'Threat Intelligence',
      score: correlationScore,
      contribution: correlationIncluded
        ? computeWeightedContribution('correlation', correlationScore, axesUsed)
        : 0,
      summary: buildThreatCardSummary(data),
      included: correlationIncluded,
      weight: axesUsed['correlation'] ?? 0,
      exclusionLabel: correlationIncluded ? '' : 'Not included',
    },
  ];

  // Rank by actual influence. The heading asks "what influenced the score?",
  // so the biggest influence has to be the first thing read, not the axis that
  // happens to come first alphabetically in the engine.
  return rows.sort((a, b) => b.contribution - a.contribution);
}

function InfluenceRowItem({
  row,
  max,
  onOpen,
}: {
  row: InfluenceRow;
  max: number;
  onOpen: () => void;
}) {
  const pct = max > 0 ? Math.max(2, (row.contribution / max) * 100) : 0;

  return (
    <button
      type="button"
      onClick={onOpen}
      aria-label={`View ${row.label.toLowerCase()} details`}
      // Roomier now that it carries its own arithmetic: the card radius from
      // the tokens, and 20px of padding rather than 14px.
      className={`flex h-full w-full cursor-pointer flex-col rounded-[var(--card-radius)] border p-5 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-1 ${
        row.included
          ? 'border-slate-200 bg-white hover:border-blue-300 hover:bg-blue-50/30'
          : // Recessed rather than alarmed: it belongs in the account of the
            // score, but it did not move it.
            'border-slate-200 bg-slate-50/70 hover:border-slate-300 hover:bg-slate-50'
      }`}
    >
      {/*
        Fixed-height header row.

        One card carries a "+3.7 pts" numeral and another a "NOT INCLUDED"
        badge, and the two set different line boxes - so the meters underneath
        them started at different heights across a row whose entire purpose is
        side-by-side comparison.
      */}
      <div className="flex min-h-[1.75rem] items-center justify-between gap-2">
        <span className={row.included ? TYPOGRAPHY.h3 : `${TYPOGRAPHY.h3} text-slate-600`}>
          <HelpTerm term={row.term}>{row.label}</HelpTerm>
        </span>
        {row.included ? (
          <span className="font-sans text-base font-semibold text-slate-900 tabular-nums tracking-[-0.02em] shrink-0">
            {row.contribution >= 0.05 ? `+${row.contribution.toFixed(1)}` : '0'}
            <span className={`${TYPOGRAPHY.label} ml-1`}>pts</span>
          </span>
        ) : (
          <span className={`${TYPOGRAPHY.badge} text-slate-500 bg-slate-100 border-slate-200`}>
            {row.exclusionLabel}
          </span>
        )}
      </div>

      {/* One bar per axis, scaled to the largest contributor. Ranking you can
          see beats ranking you have to read. */}
      <div className="mt-2 h-1 w-full rounded-full bg-slate-100 overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ${
            row.included ? 'bg-blue-600' : 'bg-slate-300'
          }`}
          style={{ width: `${row.included ? pct : 100}%`, opacity: row.included ? 1 : 0.35 }}
        />
      </div>

      <p className={`${TYPOGRAPHY.bodySmall} mt-3`}>{row.summary}</p>

      {/*
        Where the number came from, in a sentence.
        
        The card asserted "+17.7 pts" and left the reader to trust it. The
        contribution is raw axis score multiplied by the share that axis is
        counted at, and both halves are in the payload - so the card can show
        the working instead. On a console whose claim is that every score
        traces to evidence, the arithmetic behind the headline figure is the
        last place to ask for trust.
      */}
      <p className={`${TYPOGRAPHY.caption} mt-3 border-t border-slate-200 pt-3`}>
        {row.included ? (
          <>
            Scored{' '}
            <span className="font-medium tabular-nums text-slate-700">
              {row.score.toFixed(1)}
            </span>{' '}
            out of 100 on this axis, counted at{' '}
            <span className="font-medium tabular-nums text-slate-700">
              {Math.round(row.weight * 100)}%
            </span>{' '}
            of the final score
            {row.contribution >= 0.05 ? (
              <>
                {' '}— adding{' '}
                <span className="font-medium tabular-nums text-slate-700">
                  {row.contribution.toFixed(1)}
                </span>{' '}
                points.
              </>
            ) : (
              <> — adding nothing, because the axis scored nothing.</>
            )}
          </>
        ) : row.score > 0 ? (
          <>
            Scored{' '}
            <span className="font-medium tabular-nums text-slate-700">
              {row.score.toFixed(1)}
            </span>{' '}
            out of 100, but excluded — so it added nothing, and its absence is
            not evidence of safety.
          </>
        ) : (
          <>Never scored, so it could neither raise nor lower the result.</>
        )}
      </p>

      <span className={`${TYPOGRAPHY.linkAction} mt-auto pt-4`}>
        View details
        <ChevronRight className="h-3.5 w-3.5" aria-hidden />
      </span>
    </button>
  );
}

export default function RiskInfluenceCard({
  data,
  embedded = false,
  bare = false,
}: {
  data: FraudCardData;
  embedded?: boolean;
  bare?: boolean;
}) {
  const { openInfluenceDetail, openLedger } = useInvestigationUI();
  const allRows = buildRows(data);

  /*
   * Every axis, always - including one that contributed nothing.
   *
   * These were briefly filtered to the axes that moved the score, on the
   * reasoning that "Runtime behaviour - NOT INCLUDED" was another telling of a
   * coverage caveat the verdict already carries. That was the wrong cut. This
   * card is an account of how a three-axis score was reached, and an account
   * that silently omits an axis is not a shorter account, it is an incomplete
   * one: the reader cannot tell whether runtime was clean, absent, or never
   * asked. It also left a hole in the row.
   *
   * The repetition the summary reader did not need was the alarm - the amber
   * block and the duplicate "Runtime limited" tile. Those are gone. The axis
   * stays, stated plainly.
   */
  const rows = allRows;
  if (rows.length === 0) return null;
  const max = Math.max(...rows.map((r) => r.contribution), 0);

  /*
   * Side by side, not stacked.
   *
   * These three axes exist to be compared, and comparison is what a vertical
   * stack in a narrow column makes hardest - the bars never share a baseline
   * and the eye has to hold each value while it travels. Across a row they read
   * against each other directly.
   */
  const body = (
    <div className={embedded || bare ? 'space-y-3' : 'p-4 space-y-3'}>
      <div
        className={
          embedded
            ? 'space-y-2.5'
            : 'grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3 items-stretch'
        }
      >
        {rows.map((row) => (
          <InfluenceRowItem
            key={row.key}
            row={row}
            max={max}
            onOpen={() => openInfluenceDetail(row.axis)}
          />
        ))}
      </div>
      {!embedded && (
        <button
          type="button"
          onClick={() => openLedger('full')}
          className={`${TYPOGRAPHY.buttonSm} text-blue-700 px-3 py-2 border border-blue-200 hover:bg-blue-50`}
        >
          View score breakdown
        </button>
      )}
    </div>
  );

  /*
   * `bare` is the row of axis cards with no surface of its own and no header -
   * for a caller that supplies its own heading and wants the three cards to
   * sit directly on the page. `embedded` stacks them in a narrow column;
   * `bare` keeps the three-across grid. Neither wraps them in a card, because
   * each axis is already one.
   */
  if (bare) return body;

  if (embedded) {
    return (
      <div className="flex flex-col">
        <div className="mb-3">
          <p className={TYPOGRAPHY.h2}>What influenced the score</p>
          <p className={`${TYPOGRAPHY.caption} mt-0.5`}>
            Ranked by how much each raised the risk score.
          </p>
        </div>
        {body}
      </div>
    );
  }

  return (
    <SocCard>
      {/* No download button here: the verdict block directly above owns the
          one primary action, and two of them side by side made the page look
          like it was offering two different reports. */}
      <SectionHeader
        icon={<BarChart2 className="h-4 w-4" />}
        title="What influenced the score"
        subtitle="Ranked by how much each raised the risk score."
        className="border-b-0"
      />
      {body}
    </SocCard>
  );
}
