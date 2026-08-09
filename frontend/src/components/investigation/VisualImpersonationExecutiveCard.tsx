import { Link } from 'react-router-dom';
import type { FraudCardData } from '../../App';
import SocCard from '../ui/Card';
import {
  formatVideConfidence,
  getVideUiState,
  resolveVideFromData,
  VIDE_BASELINE_SHORT_NAMES,
  videConfidenceValue,
  videEvidenceSources,
} from '../../lib/videUi';
import { AlertTriangle, Eye, ShieldAlert } from 'lucide-react';

export default function VisualImpersonationExecutiveCard({ data }: { data: FraudCardData }) {
  const vide = resolveVideFromData(data);
  const state = getVideUiState(vide);

  if (state === 'missing') {
    return (
      <SocCard className="border-slate-200/80">
        <div className="px-4 sm:px-5 py-4 flex items-start gap-3">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-slate-600 border border-slate-200/80">
            <Eye className="h-4 w-4" />
          </span>
          <div className="min-w-0">
            <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">Visual impersonation</p>
            <p className="text-sm font-semibold text-slate-800 mt-0.5">Analysis unavailable</p>
            <p className="text-xs text-slate-500 mt-1">VIDE results were not included in this case payload.</p>
          </div>
        </div>
      </SocCard>
    );
  }

  const compare = vide!.vide_compare;
  const confidence = videConfidenceValue(vide!);

  if (state === 'unavailable') {
    return (
      <SocCard className="border-slate-200/80">
        <div className="px-4 sm:px-5 py-4 flex items-start gap-3">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-slate-600 border border-slate-200/80">
            <Eye className="h-4 w-4" />
          </span>
          <div className="min-w-0">
            <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">Visual impersonation</p>
            <p className="text-sm font-semibold text-slate-800 mt-0.5">Analysis unavailable</p>
            <p className="text-xs text-slate-500 mt-1">
              {vide!.error?.trim() || `VIDE status: ${vide!.status || 'UNAVAILABLE'}`}
            </p>
          </div>
        </div>
      </SocCard>
    );
  }

  if (state === 'analyzed') {
    const evidence = videEvidenceSources(vide!);
    return (
      <SocCard className="border-slate-200/80">
        <div className="px-4 sm:px-5 py-4 flex items-start gap-3">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-slate-600 border border-slate-200/80">
            <Eye className="h-4 w-4" />
          </span>
          <div className="min-w-0 flex-1">
            <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">Visual impersonation</p>
            <p className="text-sm font-semibold text-slate-800 mt-0.5">No banking-app impersonation detected</p>
            <p className="text-xs text-slate-600 mt-1">
              VIDE compared the application interface against available laboratory banking UI baselines.
            </p>
            <p className="text-xs text-slate-600 mt-1">
              {VIDE_BASELINE_SHORT_NAMES.length} baselines checked
              {confidence != null ? (
                <>
                  {' '}
                  · Confidence <span className="font-semibold tabular-nums">{formatVideConfidence(confidence)}</span>
                </>
              ) : null}
            </p>
            <p className="text-xs text-slate-500 mt-1">No sufficiently similar interface was identified.</p>
            {evidence.length > 0 && (
              <p className="text-[11px] text-slate-500 mt-1">Evidence: {evidence.join(' · ')}</p>
            )}
            <Link
              to="/technical"
              className="inline-flex items-center gap-1 text-xs text-blue-700 font-semibold hover:underline mt-2"
            >
              View visual evidence
              <span aria-hidden>→</span>
            </Link>
          </div>
        </div>
      </SocCard>
    );
  }

  const institution =
    compare?.institution_display || vide!.visual_impersonation_institution || 'Laboratory banking-style baseline';
  const ruleId = compare?.rule_id || 'VIDE-F001';

  const caps: string[] = [];
  if (data.has_accessibility_abuse) caps.push('Accessibility abuse');
  if (data.has_system_alert_window) caps.push('Overlay capability');
  if (data.has_sms_read_write) caps.push('SMS read/write');

  return (
    <SocCard className="border-red-200/60">
      <div className="px-4 sm:px-5 py-4 border-b border-slate-200/80 bg-gradient-to-r from-red-50/80 via-white to-slate-50">
        <div className="flex items-start gap-3">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-red-100 text-red-700 border border-red-200/80">
            <Eye className="h-4 w-4" />
          </span>
          <div className="min-w-0 flex-1">
            <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">Visual impersonation</p>
            <p className="text-lg font-bold text-slate-900 truncate">{institution}</p>
            <p className="text-sm text-slate-600 mt-0.5">
              <span className="font-semibold tabular-nums">{formatVideConfidence(confidence)}</span> similarity
            </p>
          </div>
        </div>
      </div>

      <div className="px-4 sm:px-5 py-3 space-y-3 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono font-bold text-red-700 bg-red-50 border border-red-200 px-2 py-1 rounded">
            {ruleId}
          </span>
          <span className="text-slate-700 font-medium">Matched laboratory baseline</span>
        </div>

        {vide!.critical_visual_cluster && (
          <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2.5">
            <div className="flex items-center gap-2 font-semibold text-red-800">
              <ShieldAlert className="h-3.5 w-3.5 shrink-0" />
              Critical visual cluster
            </div>
            <p className="text-red-900/90 mt-1.5">Visual impersonation</p>
            {caps.length > 0 ? (
              <ul className="list-disc list-inside text-red-900/80 mt-1">
                {caps.map((c) => (
                  <li key={c}>{c}</li>
                ))}
              </ul>
            ) : (
              <p className="text-red-900/80 mt-1">Plus qualifying high-risk capability evidence</p>
            )}
          </div>
        )}

        {vide!.signer_impersonation?.detected && (
          <div className="flex items-center gap-2 text-amber-800">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
            CH06 signer impersonation signal
          </div>
        )}

        <Link
          to="/technical"
          className="inline-flex items-center gap-1 text-blue-700 font-semibold hover:underline"
        >
          View evidence
          <span aria-hidden>→</span>
        </Link>
      </div>
    </SocCard>
  );
}
