import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import { riskBandPlainEnglish } from '../../lib/analystCopy';
import { getRiskStyle } from '../../theme/colors';
import CopyButton from '../ui/CopyButton';
import { PipelineStatusChip } from './FindingIndicators';

function pipelineStates(data: FraudCardData, bundle: InvestigationBundle) {
  const frs = data.frs_breakdown;
  const staticDone =
    bundle.counts.staticFindings > 0 ||
    (frs?.stei ?? 0) > 0 ||
    bundle.evidenceRecords.some((e) => e.category === 'static');

  let dynamic: 'complete' | 'inconclusive' | 'failed' | 'pending' = 'pending';
  if (frs?.dynamic_ran) {
    if (frs.dynamic_conclusive) dynamic = 'complete';
    else dynamic = 'inconclusive';
  } else if (data.dynamic_available || data.dynamic_analysis) {
    dynamic = 'inconclusive';
  }

  const threatDone =
    data.family_classification !== 'Unknown' ||
    (data.threat_correlation?.ioc_reputation?.length ?? 0) > 0 ||
    (data.threat_correlation?.threat_score ?? 0) > 0 ||
    bundle.evidenceRecords.some((e) => e.category === 'scenario');

  return {
    static: staticDone ? 'complete' : 'pending',
    dynamic,
    threat: threatDone ? 'complete' : 'pending',
  } as const;
}

export default function InvestigationHeader({
  data,
  bundle,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle;
}) {
  const packageTitle = data.package_name || data.sha256;
  const bandLabel = riskBandPlainEnglish(data.risk_band);
  const riskText = getRiskStyle(data.risk_band).textDark;
  const score = data.final_risk_score.toFixed(0);
  const pipe = pipelineStates(data, bundle);

  return (
    <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs mb-2">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        {/* Left column */}
        <div className="min-w-0 space-y-1.5">
          <div className="text-[10px] font-bold uppercase tracking-widest text-slate-500">
            FRAUD INVESTIGATION
          </div>
          <h1 className="text-xl sm:text-2xl font-bold font-mono text-slate-900 tracking-tight leading-tight truncate">
            {packageTitle}
          </h1>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-500 font-mono">
            <span className="text-slate-400 font-semibold">SHA256</span>
            <span className="text-slate-700 truncate max-w-[min(100%,22rem)]" title={data.sha256}>
              {data.sha256.slice(0, 24)}…
            </span>
            <CopyButton value={data.sha256} />
            {data.analysis_mode && (
              <span className="px-2 py-0.5 text-[10px] font-sans font-semibold bg-blue-50 text-blue-700 border border-blue-200 rounded-md">
                {data.analysis_mode}
              </span>
            )}
            {data.family_classification && data.family_classification !== 'Unknown' && (
              <span className="px-2 py-0.5 text-[10px] font-sans font-semibold bg-red-50 text-red-700 border border-red-200 rounded-md">
                Family: {data.family_classification}
              </span>
            )}
          </div>
        </div>

        {/* Right column */}
        <div className="flex flex-col items-start sm:items-end gap-1.5 shrink-0 sm:border-l sm:border-slate-100 sm:pl-6">
          <div className="flex items-baseline gap-1.5">
            <span className={`font-mono text-3xl sm:text-4xl font-black tabular-nums leading-none ${riskText}`}>
              {score}
            </span>
            <span className="text-xs font-medium text-slate-400">/ 100</span>
          </div>
          <span className={`text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded-md ${
            data.final_risk_score > 60
              ? 'bg-red-50 text-red-700 border border-red-200'
              : data.final_risk_score > 30
                ? 'bg-amber-50 text-amber-800 border border-amber-200'
                : 'bg-emerald-50 text-emerald-800 border border-emerald-200'
          }`}>
            {bandLabel}
          </span>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 pt-1 border-t border-slate-100 mt-1 w-full justify-start sm:justify-end">
            <PipelineStatusChip label="Static" state={pipe.static} />
            <PipelineStatusChip label="Dynamic" state={pipe.dynamic} />
            <PipelineStatusChip label="Threat Intel" state={pipe.threat} />
          </div>
        </div>
      </div>
    </div>
  );
}
