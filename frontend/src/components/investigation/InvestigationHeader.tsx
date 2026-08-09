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
    <header className="py-4 border-b border-slate-200">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0 space-y-1">
          <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-slate-500">
            Fraud investigation
          </p>
          <h1 className="text-xl sm:text-[22px] font-semibold text-slate-900 tracking-tight leading-snug truncate">
            {packageTitle}
          </h1>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-slate-500">
            <span className="font-medium uppercase tracking-wide text-slate-400">SHA256</span>
            <span className="font-mono text-slate-600 truncate max-w-[min(100%,20rem)]" title={data.sha256}>
              {data.sha256.slice(0, 18)}…
            </span>
            <CopyButton value={data.sha256} />
          </div>
        </div>

        <div className="flex flex-col items-start lg:items-end gap-2 shrink-0">
          <div className="flex items-baseline gap-2">
            <span className={`text-3xl font-semibold tabular-nums leading-none ${riskText}`}>{score}</span>
            <span className="text-sm text-slate-400 font-medium">/ 100</span>
          </div>
          <p className={`text-xs font-bold uppercase tracking-wide ${riskText}`}>{bandLabel}</p>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 pt-1">
            <PipelineStatusChip label="Static" state={pipe.static} />
            <PipelineStatusChip label="Dynamic" state={pipe.dynamic} />
            <PipelineStatusChip label="Threat Intel" state={pipe.threat} />
          </div>
        </div>
      </div>
    </header>
  );
}
