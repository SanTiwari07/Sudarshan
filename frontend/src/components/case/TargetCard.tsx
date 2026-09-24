import { Building, ShieldAlert } from 'lucide-react';
import type { FraudCardData } from '../../App';

export default function TargetCard({ data }: { data: FraudCardData }) {
  const isTargeted = data.targets_indian_banks;
  const videTarget = data.vide?.corpus_compare?.institution_display || data.vide?.corpus_compare?.bank;

  if (isTargeted || videTarget) {
    return (
      <div className="rounded-xl border border-red-200 bg-red-50/50 p-5 shadow-sm">
        <div className="flex items-start gap-4">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-red-100 text-red-600">
            <Building className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-[11px] font-bold uppercase tracking-widest text-red-600 mb-1">
              TARGETED BANK
            </h2>
            <p className="text-lg font-semibold text-slate-900">
              {videTarget || 'Indian Banking Applications'}
            </p>
            <div className="mt-2 flex items-center gap-2 text-sm text-red-700">
              <ShieldAlert className="h-4 w-4" />
              <span>
                {videTarget 
                  ? 'Visual impersonation detected. UI layout closely matches banking baseline.' 
                  : 'Indicators suggest targeting of Indian banking applications.'}
              </span>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex items-start gap-4">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-slate-100 text-slate-500">
          <Building className="h-5 w-5" />
        </div>
        <div>
          <h2 className="text-[11px] font-bold uppercase tracking-widest text-slate-500 mb-1">
            TARGET
          </h2>
          <p className="text-base font-medium text-slate-900">
            No specific banking target identified
          </p>
        </div>
      </div>
    </div>
  );
}
