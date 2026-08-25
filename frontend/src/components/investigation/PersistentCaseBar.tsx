import { Link } from 'react-router-dom';
import type { FraudCardData } from '../../App';
import BehaviorTags from './BehaviorTags';

/**
 * Condensed, always-visible case identity.
 *
 * The full CaseHeader renders only on the summary route, so on every other
 * view - technical, evidence, chat - the score and even which sample you were
 * looking at scrolled away. Analysts kept the summary tab open in parallel
 * just to keep the number in sight.
 *
 * This is deliberately the condensed form and renders only where CaseHeader
 * does not. Two headers on one page would be worse than none: the reader has
 * to work out which one is authoritative.
 *
 * The score is shown as a number out of 100 rather than a band alone. A band
 * is a bucket, and "Critical" tells an analyst less than "96.8" does when they
 * are comparing two samples that both land in it.
 */

const BAND_STYLE: Record<string, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-amber-400 text-amber-950',
  low: 'bg-sky-500 text-white',
  minimal: 'bg-slate-400 text-white',
};

function bandClass(band: string): string {
  return BAND_STYLE[(band || '').toLowerCase()] ?? 'bg-slate-500 text-white';
}

export function PersistentCaseBar({ data }: { data: FraudCardData }) {
  const score = Number.isFinite(data.final_risk_score)
    ? data.final_risk_score.toFixed(1)
    : '—';
  // INCOMPLETE_EXERCISE means the sandbox ran but never exercised the sample.
  // Showing the band alone there would present a score we do not stand behind.
  const incomplete = data.verdict === 'INCOMPLETE_EXERCISE';

  return (
    <div className="sticky top-0 z-30 -mx-4 px-4 py-2 mb-4 bg-white/95 backdrop-blur border-b border-slate-200">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <Link
          to="/fraud-card"
          className="flex items-baseline gap-2 min-w-0 group"
          title="Back to case summary"
        >
          <span className="font-mono text-sm text-slate-800 truncate group-hover:text-sky-700">
            {data.app_name || data.package_name || 'Unknown package'}
          </span>
          <span className="font-mono text-[11px] text-slate-400 shrink-0">
            {data.sha256?.slice(0, 12)}
          </span>
        </Link>

        <div className="flex items-center gap-2 shrink-0">
          <span className="text-lg font-semibold tabular-nums text-slate-900">
            {score}
          </span>
          <span className="text-[11px] text-slate-400">/ 100</span>
          <span
            className={`text-[11px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded ${bandClass(
              data.risk_band,
            )}`}
          >
            {incomplete ? 'Incomplete exercise' : data.risk_band || 'Unscored'}
          </span>
        </div>

        <div className="min-w-0 flex-1">
          <BehaviorTags data={data} max={6} />
        </div>
      </div>
    </div>
  );
}

export default PersistentCaseBar;
