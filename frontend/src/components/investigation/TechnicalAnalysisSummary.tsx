import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import {
  isCriticalSeverity,
  overallAnalysisConfidence,
} from '../../lib/findingAnalystView';
import { AlertTriangle, FileSearch, Layers, ShieldCheck } from 'lucide-react';

function MetricCell({
  icon,
  label,
  value,
  sub,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  sub?: string;
}) {
  return (
    <div className="px-4 py-4 border-b sm:border-b-0 sm:border-r border-slate-100 last:border-0 min-w-0">
      <div className="flex items-center gap-2 text-slate-500 mb-1.5">
        {icon}
        <span className="text-xs font-medium">{label}</span>
      </div>
      <div className="text-2xl font-semibold text-slate-900 tabular-nums leading-none">{value}</div>
      {sub && <p className="text-xs text-slate-500 mt-1.5 leading-relaxed">{sub}</p>}
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

  const grid = (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4">
      <MetricCell icon={<FileSearch className="h-4 w-4" />} label="Total findings" value={String(total)} />
      <MetricCell
        icon={<AlertTriangle className="h-4 w-4" />}
        label="Critical"
        value={String(critical)}
        sub={critical > 0 ? 'Review in registry below' : 'None flagged critical'}
      />
      <MetricCell
        icon={<Layers className="h-4 w-4" />}
        label="By source"
        value={`${staticCount} · ${runtimeCount} · ${threatCount}`}
        sub="Static · runtime · threat"
      />
      <MetricCell
        icon={<ShieldCheck className="h-4 w-4" />}
        label="Confidence"
        value={`${confidence}%`}
        sub="From verified evidence"
      />
    </div>
  );

  if (embedded) {
    return <div className="border-b border-slate-100">{grid}</div>;
  }

  return <div className="space-y-4">{grid}</div>;
}
