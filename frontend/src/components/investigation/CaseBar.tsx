import { Link, useLocation } from 'react-router-dom';
import type { FraudCardData } from '../../App';
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
} from '../../lib/caseRoutes';
import {
  CASE_DEPTHS,
  useInvestigationUI,
  type CaseDepth,
} from '../../context/InvestigationUIContext';

/**
 * Persistent case identity, section navigation and reading depth.
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
 */

const DEPTH_LABELS: Record<CaseDepth, { label: string; hint: string }> = {
  summary: { label: 'Summary', hint: 'Verdict, story and recommended action' },
  analyst: { label: 'Analyst', hint: 'Adds evidence, indicators and score breakdown' },
  forensic: { label: 'Forensic', hint: 'Adds raw records, logs and instrumentation' },
};

function DepthSwitch() {
  const { depth, setDepth } = useInvestigationUI();

  return (
    <div className="flex items-center gap-1.5 shrink-0">
      <span className={TYPOGRAPHY.label} id="case-depth-label">
        Detail
      </span>
      <div
        role="radiogroup"
        aria-labelledby="case-depth-label"
        className="flex items-center rounded-md border border-slate-200 bg-slate-50 p-0.5"
      >
        <AnimatedBackground
          value={depth}
          className="rounded bg-white shadow-[0_1px_2px_rgba(15,23,42,0.08)]"
        >
          {CASE_DEPTHS.map((d) => (
            <button
              key={d}
              data-id={d}
              type="button"
              role="radio"
              aria-checked={d === depth}
              title={DEPTH_LABELS[d].hint}
              onClick={() => setDepth(d)}
              className={`relative px-2.5 py-1 rounded text-[11px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                d === depth ? 'text-slate-900' : 'text-slate-500 hover:text-slate-900'
              }`}
            >
              {DEPTH_LABELS[d].label}
            </button>
          ))}
        </AnimatedBackground>
      </div>
      {/*
        A depth change rewrites what the page shows without moving focus or
        scroll, so a screen-reader user gets no signal that anything happened.
      */}
      <span aria-live="polite" className="sr-only">
        {DEPTH_LABELS[depth].label} detail: {DEPTH_LABELS[depth].hint}
      </span>
    </div>
  );
}

function CaseTabs({ sha256 }: { sha256: string }) {
  const { pathname } = useLocation();
  const active = activeCaseSection(pathname) ?? 'summary';

  return (
    <nav aria-label="Case sections" className="flex items-center gap-0.5 min-w-0 overflow-x-auto">
      <AnimatedBackground value={active} className="rounded-md bg-slate-900">
        {CASE_SECTIONS.map((section) => (
          <Link
            key={section}
            data-id={section}
            aria-current={section === active ? 'page' : undefined}
            to={caseSectionPath(sha256, section)}
            title={SECTION_LABELS[section].hint}
            className={`relative px-3 py-1.5 rounded-md whitespace-nowrap font-display text-[13px] font-semibold tracking-[-0.01em] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
              section === active ? 'text-white' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            {SECTION_LABELS[section].label}
          </Link>
        ))}
      </AnimatedBackground>
    </nav>
  );
}

export function CaseBar({ data }: { data: FraudCardData }) {
  const inconclusive = isInconclusive(data);
  const token = caseSeverity(data.risk_band, inconclusive);
  const Icon = token.icon;

  return (
    <div className="sticky top-0 z-30 -mx-4 px-4 py-2.5 mb-6 bg-white/95 backdrop-blur border-b border-slate-200">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2.5">
        {/* Identity */}
        <Link
          to={caseSectionPath(data.sha256, 'summary')}
          className="flex items-baseline gap-2 min-w-0 group"
          title="Back to case summary"
        >
          <span className="font-display text-sm font-semibold text-slate-900 truncate group-hover:text-blue-700">
            {data.app_name || data.package_name || 'Unknown package'}
          </span>
          <span className={`${TYPOGRAPHY.hash} shrink-0`}>{data.sha256?.slice(0, 12)}</span>
        </Link>

        {/* Verdict, always on screen */}
        <div className="flex items-center gap-2 shrink-0">
          <span className="font-display text-lg font-semibold tabular-nums text-slate-900">
            {formatScore(data.final_risk_score)}
          </span>
          <span className={TYPOGRAPHY.label}>/ 100</span>
          <span
            className={`${TYPOGRAPHY.badgePill} ${token.badge} border-transparent inline-flex items-center gap-1`}
            title={token.meaning}
          >
            <Icon className="h-3 w-3" aria-hidden />
            {inconclusive ? 'Inconclusive' : token.label}
          </span>
        </div>

        <div className="flex-1" />

        <DepthSwitch />
      </div>

      <div className="flex items-center justify-between gap-4 mt-2">
        <CaseTabs sha256={data.sha256} />
      </div>
    </div>
  );
}

export default CaseBar;
