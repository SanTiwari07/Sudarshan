import { Building2, ShieldAlert, ChevronRight, Eye } from 'lucide-react';
import CardTitle from '../ui/CardTitle';
import type { FraudCardData } from '../../types/case';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { useNavigate } from 'react-router-dom';

const getBankLogo = (bankName: string) => {
  const lower = bankName.toLowerCase();
  if (lower.includes('hdfc')) return <img src="https://upload.wikimedia.org/wikipedia/commons/2/28/HDFC_Bank_Logo.svg" alt="HDFC" className="h-6 w-6 object-contain rounded" />;
  if (lower.includes('sbi')) return <img src="https://upload.wikimedia.org/wikipedia/commons/c/cc/SBI-logo.svg" alt="SBI" className="h-6 w-6 object-contain rounded" />;
  if (lower.includes('icici')) return <img src="https://upload.wikimedia.org/wikipedia/commons/1/12/ICICI_Bank_Logo.svg" alt="ICICI" className="h-6 w-6 object-contain rounded" />;
  if (lower.includes('axis')) return <img src="https://upload.wikimedia.org/wikipedia/commons/1/12/Axis_Bank_logo.svg" alt="Axis" className="h-6 w-6 object-contain rounded" />;
  if (lower.includes('pnb')) return <img src="https://upload.wikimedia.org/wikipedia/en/5/58/Punjab_National_Bank_logo.svg" alt="PNB" className="h-6 w-6 object-contain rounded" />;
  if (lower.includes('kotak')) return <img src="https://upload.wikimedia.org/wikipedia/commons/c/c5/Kotak_Mahindra_Bank_logo.svg" alt="Kotak" className="h-6 w-6 object-contain rounded" />;
  if (lower.includes('yono')) return <img src="https://upload.wikimedia.org/wikipedia/commons/c/cc/SBI-logo.svg" alt="YONO SBI" className="h-6 w-6 object-contain rounded" />;
  if (lower.includes('boi') || lower.includes('bank of india')) return <img src="https://upload.wikimedia.org/wikipedia/commons/5/5c/Bank_of_India_logo.svg" alt="Bank of India" className="h-6 w-6 object-contain rounded" />;
  if (lower.includes('canara')) return <img src="https://upload.wikimedia.org/wikipedia/commons/6/69/Canara_Bank_Logo.svg" alt="Canara" className="h-6 w-6 object-contain rounded" />;
  if (lower.includes('union')) return <img src="https://upload.wikimedia.org/wikipedia/commons/2/2b/Union_Bank_of_India_Logo.svg" alt="Union Bank" className="h-6 w-6 object-contain rounded" />;
  if (lower.includes('bob') || lower.includes('bank of baroda')) return <img src="https://upload.wikimedia.org/wikipedia/commons/e/ee/Bank_of_Baroda_logo.svg" alt="Bank of Baroda" className="h-6 w-6 object-contain rounded" />;
  if (lower.includes('paytm')) return <img src="https://upload.wikimedia.org/wikipedia/commons/2/24/Paytm_Logo_%28standalone%29.svg" alt="Paytm" className="h-6 w-6 object-contain rounded" />;
  
  return null;
};

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
    const BankLogo = bankName ? getBankLogo(bankName) : null;

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
            <CardTitle icon={Building2} title="Targeted bank" tone="red" info="Whether the app pretends to be a specific bank's app, judged by matching its name, logos and screens against known banking apps. A match is a strong sign of a phishing or overlay attack." infoAlign="right" />
            <span className="text-[10px] font-extrabold uppercase tracking-wider px-2 py-0.5 rounded bg-red-100 text-red-700 border border-red-200">
              TARGET DETECTED
            </span>
          </div>

          <div className="flex items-center gap-2 mt-1">
            {BankLogo}
            <h3 className="text-lg font-extrabold text-slate-900 tracking-tight">
              {displayName}
            </h3>
          </div>

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
          <CardTitle icon={Building2} title="Targeted bank" tone="red" info="Whether the app pretends to be a specific bank's app, judged by matching its name, logos and screens against known banking apps. A match is a strong sign of a phishing or overlay attack." infoAlign="right" />
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
