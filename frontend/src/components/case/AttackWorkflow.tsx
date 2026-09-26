import { AlertCircle, GitCommit, ChevronRight, Clock } from 'lucide-react';
import CardTitle from '../ui/CardTitle';
import type { FraudCardData } from '../../types/case';
import { useInvestigationUI } from '../../context/InvestigationUIContext';

export default function AttackWorkflow({ data }: { data: FraudCardData }) {
  const { openWorkflowStage } = useInvestigationUI();
  const stages = data.fraud_workflow?.stages || [];

  if (stages.length === 0) {
    return (
      <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-xs h-full flex flex-col justify-between">
        <div className="mb-4"><CardTitle icon={GitCommit} title="Attack sequence" tone="orange" info="When several findings link together into an attack (for example: ask for permissions, show a fake login screen, then send the stolen data out), the steps are shown here in order." infoAlign="right" /></div>
        <div className="flex flex-col items-center justify-center py-8 text-center my-auto">
          <AlertCircle className="h-8 w-8 text-slate-300 mb-2" />
          <p className="text-sm font-medium text-slate-700">No attack sequence found</p>
          <p className="text-xs text-slate-500 max-w-[280px] leading-relaxed mt-1">
            The evidence did not link into a multi-step attack chain, so each finding is assessed on its own.
          </p>
        </div>
        <div className="pt-2 border-t border-slate-100 text-[11px] text-slate-400">
          Individual events evaluated independently
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-xs h-full flex flex-col justify-between">
      <div className="flex items-center justify-between mb-4">
        <CardTitle icon={GitCommit} title="Attack sequence" tone="orange" info="When several findings link together into an attack (for example: ask for permissions, show a fake login screen, then send the stolen data out), the steps are shown here in order." infoAlign="right" />
        <span className="text-xs font-medium text-slate-600 bg-slate-100 px-2.5 py-0.5 rounded-full whitespace-nowrap">
          {stages.length} Stages Identified
        </span>
      </div>

      <div className="flex-1 relative space-y-2.5">
        <div className="absolute left-[17px] top-4 bottom-4 w-0.5 bg-slate-200" />

        {stages.map((stage, idx) => {
          const duration = Math.max(0.1, (stage.end_ms - stage.start_ms) / 1000).toFixed(1);

          return (
            <button
              key={idx}
              type="button"
              onClick={() => openWorkflowStage(idx)}
              className="w-full text-left flex items-start gap-3.5 p-2.5 rounded-xl border border-transparent hover:border-blue-200 hover:bg-blue-50/30 transition-all cursor-pointer group relative z-10 focus:outline-none focus:ring-1 focus:ring-blue-500"
            >
              <div className="relative mt-0.5 shrink-0">
                <div className="h-7 w-7 rounded-full border-2 border-white bg-slate-900 group-hover:bg-blue-600 text-white flex items-center justify-center text-xs font-bold tabular-nums shadow-xs transition-colors">
                  {idx + 1}
                </div>
              </div>

              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-bold text-slate-900 group-hover:text-blue-700 transition-colors truncate">
                    {stage.label}
                  </span>
                  <div className="flex items-center gap-1.5 shrink-0">
                    {stage.technique_id && (
                      <span className="font-mono text-[11px] font-semibold text-slate-600 bg-slate-100 px-1.5 py-0.5 rounded whitespace-nowrap">
                        {stage.technique_id}
                      </span>
                    )}
                    <ChevronRight className="h-3.5 w-3.5 text-slate-400 group-hover:text-blue-600 group-hover:translate-x-0.5 transition-all" />
                  </div>
                </div>

                <p className="text-[11px] text-slate-500 line-clamp-1 mt-0.5 font-normal">
                  {stage.description}
                </p>

                <div className="flex items-center gap-3 mt-1 text-[10px] text-slate-400">
                  <span className="flex items-center gap-1">
                    <Clock className="h-2.5 w-2.5" />
                    {(stage.start_ms / 1000).toFixed(1)}s - {(stage.end_ms / 1000).toFixed(1)}s ({duration}s)
                  </span>
                  {stage.evidence_ids?.length > 0 && (
                    <span className="text-blue-600 font-medium">
                      {stage.evidence_ids.length} evidence {stage.evidence_ids.length === 1 ? 'record' : 'records'}
                    </span>
                  )}
                </div>
              </div>
            </button>
          );
        })}
      </div>

      <div className="mt-3 pt-2.5 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-400">
        <span>Click any stage node to inspect full timeline evidence</span>
        <span>Causal sequence</span>
      </div>
    </div>
  );
}
