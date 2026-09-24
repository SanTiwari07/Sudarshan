import { Calendar, Clock } from 'lucide-react';
import type { FraudCardData } from '../../App';
import { caseSeverity } from '../../theme/severity';
import { isInconclusive } from '../../lib/decision';

export default function CaseHeader({ data }: { data: FraudCardData }) {
  const token = caseSeverity(data.risk_band, isInconclusive(data));

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col">
        <span className="text-[11px] font-semibold tracking-widest text-slate-500 uppercase mb-1">
          CASE
        </span>
        <h1 className="text-2xl font-bold text-slate-900 tracking-tight leading-tight">
          {data.package_name}
        </h1>
        <div className="flex items-center gap-2 mt-2">
          <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ${token.bg} ${token.fg} ${token.border} border`}>
            {token.label}
          </span>
          <span className="text-sm font-mono text-slate-500">
            SHA-256 {data.sha256}
          </span>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm text-slate-600 mt-2 border-t border-slate-100 pt-4">
        {data.version_name && (
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">Version</span>
            <span className="font-medium text-slate-900">{data.version_name}</span>
          </div>
        )}
        {data.apk_size && (
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">Size</span>
            <span className="font-medium text-slate-900">{data.apk_size}</span>
          </div>
        )}
        <div className="flex items-center gap-1.5">
          <span className="text-slate-400">Permissions</span>
          <span className="font-medium text-slate-900">{data.all_permissions?.length || 0} total</span>
        </div>
        {data.created_at && (
          <div className="flex items-center gap-1.5">
            <Calendar className="h-4 w-4 text-slate-400" />
            <span className="font-medium text-slate-900">
              {new Date(data.created_at).toLocaleDateString()}
            </span>
          </div>
        )}
        <div className="flex items-center gap-1.5">
          <Clock className="h-4 w-4 text-slate-400" />
          <span className="font-medium text-slate-900 capitalize">
            {data.analysis_mode} analysis
          </span>
        </div>
      </div>
    </div>
  );
}
