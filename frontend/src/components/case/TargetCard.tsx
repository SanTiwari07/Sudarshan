import { Building2, ShieldAlert, ChevronRight, Eye } from 'lucide-react';
import type { FraudCardData } from '../../types/case';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { useNavigate } from 'react-router-dom';

export default function TargetCard({ data }: { data: FraudCardData }) {
  const { openTargetDetail } = useInvestigationUI();
  const navigate = useNavigate();

  const isTargeted = data.targets_indian_banks;
  const vide = data.vide;
  const bankName =
    vide?.visual_impersonation_institution ||
    vide?.corpus_compare?.institution_display ||
    vide?.corpus_compare?.bank ||
    data.intelligence_report?.affected_banking_apps?.[0] ||
    (data as any).target_bank;

  if (bankName || isTargeted) {
    const displayName = bankName || 'Indian Financial Institution';

    return (
      <div
        role="button"
        tabIndex={0}
        onClick={() => openTargetDetail()}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            openTargetDetail();
          }
        }}
        aria-label={`Targeted Banking Identity: ${displayName}. Click to open target analysis.`}
        className="rounded-2xl border border-red-200 bg-red-50/40 hover:bg-red-50/70 hover:border-red-400 p-5 shadow-xs h-full flex flex-col justify-between transition-all cursor-pointer group focus:outline-none focus:ring-2 focus:ring-red-500"
      >
        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="text-[11px] font-bold uppercase tracking-widest text-red-700 flex items-center gap-1.5">
              <Building2 className="h-3.5 w-3.5 text-red-600" />
              Targeted Bank Identity
            </span>
            <span className="text-[10px] font-extrabold uppercase tracking-wider px-2 py-0.5 rounded bg-red-100 text-red-700 border border-red-200">
              TARGET DETECTED
            </span>
          </div>

          <h3 className="text-lg font-extrabold text-slate-900 tracking-tight mt-1">
            {displayName}
          </h3>

          <div className="mt-2 flex items-center gap-2 text-xs text-red-800 font-medium">
            <ShieldAlert className="h-4 w-4 text-red-600 shrink-0" />
            <span>
              {vide?.visual_impersonation_detected
                ? 'Visual impersonation detected. UI layout and overlay spoofing confirmed.'
                : 'Indicators suggest active targeting of banking customer assets.'}
            </span>
          </div>
        </div>

        <div className="mt-4 pt-2.5 border-t border-red-200/60 flex items-center justify-between text-xs">
          <span className="text-red-700 font-semibold inline-flex items-center gap-1">
            <Eye className="h-3.5 w-3.5" />
            <span>Target analysis drawer</span>
          </span>
          <span className="text-slate-600 font-semibold inline-flex items-center gap-0.5 group-hover:translate-x-0.5 transition-transform">
            <span>Inspect overlay</span>
            <ChevronRight className="h-3.5 w-3.5 text-red-600" />
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-xs h-full flex flex-col justify-between">
      <div>
        <div className="flex items-center justify-between mb-2">
          <span className="text-[11px] font-bold uppercase tracking-widest text-slate-500 flex items-center gap-1.5">
            <Building2 className="h-3.5 w-3.5 text-slate-400" />
            Target Banking Identity
          </span>
          <span className="text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded bg-slate-100 text-slate-500 border border-slate-200">
            NO MATCH
          </span>
        </div>
        <p className="text-sm font-semibold text-slate-700 mt-2">
          No specific financial institution target identified
        </p>
        <p className="text-xs text-slate-500 mt-1">
          Sample does not exhibit targeted banking logos or credential phishing overlays matching known institutional baselines.
        </p>
      </div>

      <div className="mt-4 pt-2.5 border-t border-slate-100 flex items-center justify-between text-xs text-slate-400">
        <span>Generic or non-targeted payload</span>
        <button
          type="button"
          onClick={() => navigate(`/case/${data.sha256}/evidence?section=visual`)}
          className="text-blue-600 hover:text-blue-700 font-medium inline-flex items-center gap-1"
        >
          <span>Visual evidence</span>
          <ChevronRight className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
}
