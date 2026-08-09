import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import {
  isCriticalSeverity,
  overallAnalysisConfidence,
} from '../../lib/findingAnalystView';

function Metric({
  label,
  value,
  sub,
}: {
  label: string;
  value: string;
  sub: string;
}) {
  return (
    <div className="min-w-0 px-4 py-3 first:pl-0">
      <p className="text-[10px] font-bold uppercase tracking-[0.12em] text-slate-400">{label}</p>
      <p className="text-2xl font-semibold text-slate-900 tabular-nums leading-tight mt-1">{value}</p>
      <p className="text-[11px] text-slate-500 mt-0.5 leading-snug">{sub}</p>
    </div>
  );
}

export default function TechnicalAnalysisSummary({
  data,
  bundle,
  embedded = false,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle;
  embedded?: boolean;
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

  const strip = (
    <div className="flex flex-col sm:flex-row sm:items-stretch divide-y sm:divide-y-0 sm:divide-x divide-slate-200">
      <Metric label="Total findings" value={String(total)} sub="Verified evidence records" />
      <Metric
        label="Critical"
        value={String(critical)}
        sub={critical > 0 ? 'Requires review' : 'None flagged critical'}
      />
      <Metric
        label="By source"
        value={`${staticCount} · ${runtimeCount} · ${threatCount}`}
        sub="Static · Runtime · Threat"
      />
      <Metric label="Confidence" value={`${confidence}%`} sub="Verified evidence" />
    </div>
  );

  if (embedded) {
    return <div className="py-3 border-b border-slate-200">{strip}</div>;
  }

  return <div className="space-y-4">{strip}</div>;
}
