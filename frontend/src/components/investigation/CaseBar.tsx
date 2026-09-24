import { Link, useLocation } from 'react-router-dom';
import { FileText, Database, Globe, Sparkles, type LucideIcon } from 'lucide-react';
import type { FraudCardData } from '../../types/case';
import { TYPOGRAPHY } from '../../theme/typography';
import AnimatedBackground from '../motion/AnimatedBackground';
import { caseSeverity } from '../../theme/severity';
import { isInconclusive } from '../../lib/decision';
import { formatScore } from '../../lib/verdictCopy';
import {
  CASE_SECTIONS,
  SECTION_LABELS,
  activeCaseSection,
  caseSectionPath,
  type CaseSection,
} from '../../lib/caseRoutes';

/**
 * Persistent case identity, section navigation and verdict.
 *
 * Replaces PersistentCaseBar, which carried identity but no navigation - the
 * four views were reachable only from the global application header, so moving
 * between them read as leaving the case rather than turning a page inside it.
 *
 * Its band colours were also wrong in a way worth naming: the lookup table had
 * entries for `medium`, `low` and `minimal`, none of which the risk engine
 * emits, and no entry for `suspicious` or `safe`, which it does. Both real
 * bands fell through to grey. Same defect as the score-threshold cascade in the
 * old executive card - a colour table written against an imagined vocabulary.
 *
 * The bar is one row of three zones rather than two stacked rows: who this case
 * is on the left, where you can go in the middle, what the engine concluded on
 * the right. Two rows cost twice the vertical space at the top of every view,
 * and they split the two things a reader needs at the same moment - the verdict
 * and the means to interrogate it - onto separate lines.
 */

const SECTION_ICONS: Record<CaseSection, LucideIcon> = {
  summary: FileText,
  evidence: Database,
  intel: Globe,
  ask: Sparkles,
};

/**
 * The score, as a ring.
 *
 * A bare numeral says 14.1 and leaves the reader to recall what the scale was;
 * an arc says "about a seventh of the way round" before the digits are read at
 * all. The track is the rest of the scale, so the value and the proportion
 * arrive together.
 *
 * An inconclusive run draws no arc. A partial analysis has not earned a
 * position on the scale, and a short arc would say "low risk" when what
 * actually happened is "we could not tell".
 */
function ScoreRing({
  score,
  colour,
  inconclusive,
}: {
  score: number;
  colour: string;
  inconclusive: boolean;
}) {
  const r = 16;
  const circumference = 2 * Math.PI * r;
  const fraction = Math.max(0, Math.min(100, score)) / 100;

  return (
    <div
      className={`relative h-10 w-10 shrink-0 ${inconclusive ? 'text-slate-400' : colour}`}
    >
      <svg viewBox="0 0 40 40" className="h-full w-full -rotate-90" aria-hidden>
        <circle
          cx="20"
          cy="20"
          r={r}
          fill="none"
          strokeWidth="3"
          stroke="currentColor"
          className="text-slate-200"
        />
        {!inconclusive && (
          <circle
            cx="20"
            cy="20"
            r={r}
            fill="none"
            strokeWidth="3"
            strokeLinecap="round"
            stroke="currentColor"
            strokeDasharray={circumference}
            strokeDashoffset={circumference * (1 - fraction)}
            className="transition-[stroke-dashoffset] duration-700 ease-out"
          />
        )}
      </svg>
      <span className="absolute inset-0 flex items-center justify-center font-sans text-[13px] font-semibold tabular-nums tracking-[-0.02em] text-slate-900">
        {inconclusive ? '-' : formatScore(score)}
      </span>
    </div>
  );
}

function CaseTabs({ sha256 }: { sha256: string }) {
  const { pathname } = useLocation();
  const active = activeCaseSection(pathname) ?? 'summary';

  return (
    <nav
      aria-label="Case sections"
      className="flex min-w-0 items-center overflow-x-auto scrollbar-hidden rounded-full bg-slate-100 p-1"
    >
      <AnimatedBackground value={active} className="rounded-full bg-slate-900">
        {CASE_SECTIONS.map((section) => {
          const Icon = SECTION_ICONS[section];
          const selected = section === active;
          return (
            <Link
              key={section}
              data-id={section}
              aria-current={selected ? 'page' : undefined}
              to={caseSectionPath(sha256, section)}
              title={SECTION_LABELS[section].hint}
              className={`relative flex items-center gap-2 whitespace-nowrap rounded-full px-4 py-2 font-sans text-[15px] font-semibold tracking-[-0.01em] transition-colors duration-150 active:scale-[0.97] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                selected ? 'text-white' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Icon className="h-4 w-4 shrink-0" aria-hidden />
              {SECTION_LABELS[section].label}
            </Link>
          );
        })}
      </AnimatedBackground>
    </nav>
  );
}

export function CaseBar({ data }: { data: FraudCardData }) {
  const inconclusive = isInconclusive(data);
  const token = caseSeverity(data.risk_band, inconclusive);
  const score = Number(data.final_risk_score) || 0;

  /*
   * Pinned to the true top of the page, and opaque.
   *
   * Two separate defects produced one symptom. `bg-white/95 backdrop-blur` let
   * the page read through the bar, and `top-0` did not put it at the top: a
   * sticky element is inset by its scroll container's padding, so inside
   * `.analyst-main`'s `p-4` the bar parked 16px down and the verdict headline
   * scrolled through the strip above it.
   *
   * The negative `top` cancels that padding, and the matching negative margin
   * and padding keep the bar's own content where it was while its background
   * covers all the way to the edge.
   */
  return (
    <div className="sticky -top-3 z-40 -mx-4 -mt-3 mb-6 border-b border-slate-200 bg-white px-4 pb-3 pt-3 shadow-[0_1px_3px_rgba(15,23,42,0.06)] sm:-top-4 sm:-mt-4 sm:pt-4">
      <div className="flex flex-wrap items-center gap-x-5 gap-y-3">
        {/* Who this case is. */}
        <Link
          to={caseSectionPath(data.sha256, 'summary')}
          className="group flex min-w-0 shrink items-baseline gap-2"
          title="Back to case summary"
        >
          <span className="truncate font-sans text-[15px] font-semibold tracking-[-0.01em] text-slate-900 group-hover:text-blue-700">
            {data.app_name || data.package_name || 'Unknown package'}
          </span>
          <span className={`${TYPOGRAPHY.hash} shrink-0`}>{data.sha256?.slice(0, 12)}</span>
        </Link>

        {/*
          Where you can go.

          Centred between the identity and the verdict on a wide bar, and the
          first of the three to drop onto its own line when the bar runs out of
          room - a truncated package name or a hidden verdict costs the reader
          more than a nav that wraps.
        */}
        <div className="order-last w-full sm:order-none sm:mx-auto sm:w-auto">
          <CaseTabs sha256={data.sha256} />
        </div>

        {/* What the engine concluded. */}
        <div className="ml-auto flex shrink-0 items-center gap-2.5 sm:ml-0">
          <ScoreRing score={score} colour={token.fg} inconclusive={inconclusive} />
          <span className={TYPOGRAPHY.label}>
            {inconclusive ? 'No score' : 'Risk score'}
          </span>
        </div>

        {/* The ring carries the proportion visually; this states it outright. */}
        <span className="sr-only">
          {inconclusive
            ? 'Analysis inconclusive, no risk score available.'
            : `Risk score ${formatScore(score)} out of 100. ${token.label}.`}
        </span>
      </div>
    </div>
  );
}

export default CaseBar;

