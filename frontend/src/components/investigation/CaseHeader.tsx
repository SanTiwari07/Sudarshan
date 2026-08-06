import type { FraudCardData } from '../../App';
import { getRiskStyle } from '../../theme/colors';
import { dynamicRuntimeLabel, riskBandPlainEnglish } from '../../lib/analystCopy';
import CopyButton from '../ui/CopyButton';
import Badge from '../ui/Badge';
import { Package } from 'lucide-react';

export default function CaseHeader({
  data,
  onExplainScore,
}: {
  data: FraudCardData;
  onExplainScore: () => void;
}) {
  const riskStyle = getRiskStyle(data.risk_band);
  const displayName = data.app_name || data.package_name || 'Unknown application';
  const runtimeLabel = dynamicRuntimeLabel(data);

  return (
    <div className="bg-white border border-slate-200 rounded-xl shadow-sm px-5 py-4 mb-4">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex items-start gap-3">
          <span className="p-2.5 rounded-xl bg-blue-50 text-blue-700 border border-blue-100">
            <Package className="h-5 w-5" />
          </span>
          <div className="min-w-0">
            <h1 className="text-lg font-bold text-slate-900">Fraud Analyst Intelligence</h1>
            <p className="text-sm text-slate-700 font-medium truncate mt-0.5">{displayName}</p>
            <p className="text-xs text-slate-500 mt-1">
              Bank of India fraud investigation workspace — evidence-backed assessment.
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-2 px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg">
            <span className={`text-xl font-black tabular-nums ${riskStyle.text}`}>
              {data.final_risk_score.toFixed(0)}
            </span>
            <span className="text-xs text-slate-400">/ 100</span>
            <Badge label={riskBandPlainEnglish(data.risk_band)} className={riskStyle.badge} />
          </div>
          <span className="text-[10px] font-semibold text-slate-600 uppercase px-2.5 py-2 bg-slate-100 rounded-lg border border-slate-200">
            {runtimeLabel}
          </span>
          <button
            type="button"
            onClick={onExplainScore}
            className="text-xs font-semibold px-3 py-2 bg-blue-700 text-white rounded-lg hover:bg-blue-800"
          >
            View score breakdown
          </button>
        </div>
      </div>
      <div className="mt-3 pt-3 border-t border-slate-100 flex flex-wrap items-center gap-3 text-xs text-slate-600">
        <span className="font-mono truncate max-w-[min(100%,28rem)]" title={data.sha256}>
          SHA256 {data.sha256.slice(0, 16)}…
        </span>
        <CopyButton value={data.sha256} />
        <Badge label={data.analysis_mode} className="bg-blue-50 text-blue-700 border border-blue-200" />
        {data.family_classification !== 'Unknown' && (
          <span>
            Family: <strong className="text-slate-800">{data.family_classification}</strong>
          </span>
        )}
      </div>
    </div>
  );
}
