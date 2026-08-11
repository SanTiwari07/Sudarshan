import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import {
  isCriticalSeverity,
  overallAnalysisConfidence,
} from '../../lib/findingAnalystView';
import SocCard from '../ui/Card';

function MetricBlock({
  label,
  value,
  sub,
  highlight = false,
}: {
  label: string;
  value: string;
  sub: string;
  highlight?: boolean;
}) {
  return (
    <div className="p-4 sm:p-5 flex flex-col justify-between h-full bg-white">
      <span className="text-[10px] font-bold uppercase tracking-widest text-slate-500">
        {label}
      </span>
      <div className="my-2">
        <span className={`font-mono text-2xl sm:text-3xl font-bold tabular-nums leading-none ${highlight ? 'text-amber-600' : 'text-slate-900'}`}>
          {value}
        </span>
      </div>
      <span className="text-xs text-slate-500 leading-snug truncate">
        {sub}
      </span>
    </div>
  );
}

export default function TechnicalOverviewMetrics({
  data,
  bundle,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle;
}) {
  const records = bundle.evidenceRecords;
  const total = records.length;
  const critical = records.filter((r) => isCriticalSeverity(r.severity)).length;
  const staticCount = records.filter((r) => r.category === 'static').length;
  const runtimeCount = records.filter((r) => r.category === 'runtime').length;
  const threatCount = records.filter(
    (r) => r.category === 'scenario' || r.category === 'intel',
  ).length;
  const confidence = overallAnalysisConfidence(records, data);

  return (
    <SocCard className="overflow-hidden">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-slate-200">
        <MetricBlock
          label="Total Findings"
          value={String(total)}
          sub="verified evidence"
        />
        <MetricBlock
          label="Critical"
          value={String(critical)}
          sub={critical > 0 ? `${critical} requires review` : 'None flagged critical'}
          highlight={critical > 0}
        />
        <div className="p-4 sm:p-5 flex flex-col justify-between h-full bg-white">
          <span className="text-[10px] font-bold uppercase tracking-widest text-slate-500">
            By Source
          </span>
          <div className="my-2 flex flex-wrap items-center gap-1.5">
            <div className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-slate-50 border border-slate-200/80 rounded-md">
              <span className="text-[11px] font-medium text-slate-600">Static</span>
              <span className="font-mono text-xs font-bold text-slate-900">{staticCount}</span>
            </div>
            <div className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-slate-50 border border-slate-200/80 rounded-md">
              <span className="text-[11px] font-medium text-slate-600">Runtime</span>
              <span className="font-mono text-xs font-bold text-slate-900">{runtimeCount}</span>
            </div>
            <div className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-slate-50 border border-slate-200/80 rounded-md">
              <span className="text-[11px] font-medium text-slate-600">Threat</span>
              <span className="font-mono text-xs font-bold text-slate-900">{threatCount}</span>
            </div>
          </div>
          <span className="text-xs text-slate-500 leading-snug truncate">
            evidence sources
          </span>
        </div>
        <MetricBlock
          label="Confidence"
          value={`${confidence}%`}
          sub="verified evidence"
        />
      </div>
    </SocCard>
  );
}
