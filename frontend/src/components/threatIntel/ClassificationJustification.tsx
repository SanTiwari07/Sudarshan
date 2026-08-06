import { useState } from 'react';
import { ShieldCheck, ChevronDown, ChevronRight } from 'lucide-react';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { IntelCard, IntelCardBody, IntelSectionHeader } from './IntelCard';
import { INTEL } from './intelTokens';

type Props = {
  family: string;
  matchedRules: string[];
  ruleRefs: string[];
  confidence: number;
  ruleText: string;
};

export default function ClassificationJustification({
  family,
  matchedRules,
  ruleRefs,
  confidence,
  ruleText,
}: Props) {
  const [open, setOpen] = useState(true);
  const { openEvidence } = useInvestigationUI();

  return (
    <IntelCard>
      <IntelSectionHeader
        icon={<ShieldCheck className="h-4 w-4" />}
        title="Classification justification"
        subtitle="Why this family label was applied"
      />
      <IntelCardBody>
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          className="w-full flex items-center justify-between text-left text-sm font-bold text-slate-800"
        >
          <span>{family} classification</span>
          {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </button>
        {open && (
          <div className="mt-4 space-y-4 text-xs">
            <div>
              <div className={INTEL.caption}>Matched rules</div>
              <ul className="space-y-1 mt-2">
                {matchedRules.length ? (
                  matchedRules.map((r) => (
                    <li key={r} className="flex items-center gap-2 text-slate-800">
                      <span className="text-emerald-600">✓</span> {r}
                    </li>
                  ))
                ) : (
                  <li className="text-slate-500">No specific family signature matched.</li>
                )}
              </ul>
            </div>
            <div>
              <div className={INTEL.caption}>Evidence references</div>
              <div className="flex flex-wrap gap-2 mt-2">
                {ruleRefs.map((ref) => (
                  <button
                    key={ref}
                    type="button"
                    onClick={() => openEvidence(ref)}
                    className="px-2 py-1 rounded-md border border-slate-200 bg-slate-50 font-mono text-[10px] hover:border-blue-400 hover:text-blue-800 transition-colors"
                  >
                    {ref}
                  </button>
                ))}
              </div>
            </div>
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg">
              <div className={INTEL.caption}>Engine rule</div>
              <p className="mt-2 text-slate-800 leading-relaxed">{ruleText}</p>
            </div>
            <div className="flex items-center justify-between pt-2 border-t border-slate-100">
              <span className={INTEL.meta}>Family confidence</span>
              <span className="text-xl font-bold text-blue-800 tabular-nums">{confidence}%</span>
            </div>
          </div>
        )}
      </IntelCardBody>
    </IntelCard>
  );
}
