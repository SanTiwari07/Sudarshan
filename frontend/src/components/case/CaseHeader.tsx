import { useState } from 'react';
import { Calendar, Clock, Copy, Check, Building2, Shield, HardDrive, KeyRound } from 'lucide-react';
import type { FraudCardData } from '../../types/case';
import { caseSeverity } from '../../theme/severity';
import { isInconclusive } from '../../lib/decision';

export default function CaseHeader({ data }: { data: FraudCardData }) {
  const [copiedSha, setCopiedSha] = useState(false);
  const token = caseSeverity(data.risk_band, isInconclusive(data));

  const targetBank =
    data.vide?.visual_impersonation_institution ||
    data.vide?.corpus_compare?.institution_display ||
    data.intelligence_report?.affected_banking_apps?.[0] ||
    (data as any).target_bank;

  const handleCopyHash = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (data.sha256) {
      navigator.clipboard.writeText(data.sha256);
      setCopiedSha(true);
      setTimeout(() => setCopiedSha(false), 2000);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      {/* Top Identity Row */}
      <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-[11px] font-bold tracking-widest text-slate-500 uppercase font-mono">
              INVESTIGATION RECORD
            </span>
            <span className="text-slate-300">•</span>
            <span className="text-[11px] font-semibold text-slate-600">
              {data.app_name || 'Android Application Package'}
            </span>
            {targetBank && (
              <>
                <span className="text-slate-300">•</span>
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-bold bg-red-50 text-red-700 border border-red-200">
                  <Building2 className="h-3 w-3" />
                  Target: {targetBank}
                </span>
              </>
            )}
          </div>

          <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight break-all">
            {data.package_name}
          </h1>

          <div className="flex flex-wrap items-center gap-2 mt-3">
            {/* Severity Tag */}
            <span
              className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-bold uppercase tracking-wider ${token.bg} ${token.fg} ${token.border} border shadow-2xs`}
            >
              <Shield className="h-3.5 w-3.5" />
              {token.label}
            </span>

            {/* Copyable SHA-256 */}
            <div className="inline-flex items-center rounded-md border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs font-mono text-slate-700">
              <span className="text-slate-500 mr-1.5 font-sans font-semibold text-[11px]">SHA-256:</span>
              <span className="truncate max-w-[200px] sm:max-w-[340px] md:max-w-none">
                {data.sha256}
              </span>
              <button
                type="button"
                onClick={handleCopyHash}
                className="ml-2 inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-white hover:bg-slate-100 text-slate-700 border border-slate-200 transition-colors shadow-2xs cursor-pointer focus:outline-none focus:ring-1 focus:ring-blue-500"
                title="Copy full SHA-256 to clipboard"
              >
                {copiedSha ? (
                  <>
                    <Check className="h-3 w-3 text-emerald-600" />
                    <span className="text-[10px] font-bold text-emerald-700">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-3 w-3 text-slate-500" />
                    <span className="text-[10px] font-semibold">Copy</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Meta Bar */}
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-xs text-slate-600 mt-1 border-t border-slate-100 pt-3.5">
        {data.version_name && (
          <div className="flex items-center gap-1.5">
            <span className="text-slate-500">Version:</span>
            <span className="font-semibold text-slate-800">{data.version_name}</span>
          </div>
        )}
        {data.apk_size && (
          <div className="flex items-center gap-1.5">
            <HardDrive className="h-3.5 w-3.5 text-slate-400" />
            <span className="text-slate-500">Size:</span>
            <span className="font-semibold text-slate-800">{data.apk_size}</span>
          </div>
        )}
        <div className="flex items-center gap-1.5">
          <KeyRound className="h-3.5 w-3.5 text-slate-400" />
          <span className="text-slate-500">Permissions:</span>
          <span className="font-semibold text-slate-800">
            {data.all_permissions?.length || 0} declared
          </span>
        </div>
        {data.created_at && (
          <div className="flex items-center gap-1.5">
            <Calendar className="h-3.5 w-3.5 text-slate-400" />
            <span className="text-slate-500">Analyzed:</span>
            <span className="font-semibold text-slate-800">
              {new Date(data.created_at).toLocaleString()}
            </span>
          </div>
        )}
        <div className="flex items-center gap-1.5">
          <Clock className="h-3.5 w-3.5 text-blue-500" />
          <span className="text-slate-500">Engine Mode:</span>
          <span className="font-semibold text-blue-700 uppercase tracking-wide">
            {data.analysis_mode} analysis
          </span>
        </div>
      </div>
    </div>
  );
}
