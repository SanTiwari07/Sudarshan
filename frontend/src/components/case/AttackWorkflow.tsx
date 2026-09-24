import { AlertCircle } from 'lucide-react';
import type { FraudCardData } from '../../types/case';

export default function AttackWorkflow({ data }: { data: FraudCardData }) {
  const stages = data.fraud_workflow?.stages || [];

  if (stages.length === 0) {
    return (
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm h-full">
        <h2 className="text-[11px] font-bold uppercase tracking-widest text-slate-500 mb-4">
          ATTACK WORKFLOW
        </h2>
        <div className="flex flex-col items-center justify-center py-8 text-center">
          <AlertCircle className="h-8 w-8 text-slate-300 mb-3" />
          <p className="text-sm text-slate-500 max-w-[200px]">
            No causal workflow reconstructed from available evidence.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm h-full flex flex-col">
      <h2 className="text-[11px] font-bold uppercase tracking-widest text-slate-500 mb-6">
        ATTACK WORKFLOW
      </h2>
      
      <div className="flex-1 relative">
        <div className="absolute left-[11px] top-2 bottom-2 w-px bg-slate-200" />
        
        <div className="space-y-6 relative">
          {stages.map((stage, idx) => (
            <div key={idx} className="flex gap-4 relative">
              <div className="relative mt-1">
                <div className="h-6 w-6 rounded-full border-2 border-white bg-slate-800 flex items-center justify-center shadow-sm relative z-10">
                  <div className="h-2 w-2 rounded-full bg-white" />
                </div>
              </div>
              <div className="flex-1 pt-0.5">
                <div className="text-sm font-semibold text-slate-900">{stage.label}</div>
                {stage.description && (
                  <div className="text-xs text-slate-500 mt-1 line-clamp-2">
                    {stage.description}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
