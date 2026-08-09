import { Link } from 'react-router-dom';
import type { FraudCardData } from '../../App';
import {
  resolveRuntimeDynamicStatus,
  runtimeStatusHeadline,
  runtimeStatusExplanation,
} from '../../lib/investigationRuntime';
import { riskBandPlainEnglish } from '../../lib/analystCopy';

export default function CompactCaseContext({
  data,
  page,
}: {
  data: FraudCardData;
  page: 'live' | 'threat';
}) {
  const runtime = resolveRuntimeDynamicStatus(data);
  const band = riskBandPlainEnglish(data.risk_band);

  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50/80 px-4 py-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
      <div className="min-w-0">
        <p className="text-[10px] font-bold uppercase tracking-wide text-slate-500">Active case</p>
        <p className="text-sm font-semibold text-slate-900 truncate">{data.package_name || data.sha256.slice(0, 16)}</p>
        <p className="text-xs text-slate-600 mt-0.5">
          FRS {data.final_risk_score.toFixed(0)} / 100 · {band}
          {page === 'live' ? (
            <>
              {' '}
              · Runtime{' '}
              <span className="font-mono font-semibold">{runtimeStatusHeadline(runtime)}</span>
            </>
          ) : null}
        </p>
        {page === 'live' && (
          <p className="text-xs text-slate-500 mt-1 max-w-xl">{runtimeStatusExplanation(runtime)}</p>
        )}
      </div>
      <div className="flex flex-wrap gap-2 shrink-0">
        {page === 'live' ? (
          <Link to="/" className="text-xs font-semibold text-blue-700 hover:underline">
            Investigation conclusion →
          </Link>
        ) : (
          <>
            <Link to="/technical" className="text-xs font-semibold text-blue-700 hover:underline">
              Inspect runtime evidence →
            </Link>
            <Link to="/" className="text-xs font-semibold text-slate-600 hover:text-blue-700">
              Dashboard →
            </Link>
          </>
        )}
      </div>
    </div>
  );
}
