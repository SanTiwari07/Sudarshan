import { Check } from 'lucide-react';
import { INVESTIGATION_STAGES, type InvestigationStageStatus } from '../investigationStages';

type StageTimelineProps = {
  statuses: InvestigationStageStatus[];
};

export default function StageTimeline({ statuses }: StageTimelineProps) {
  return (
    <section className="py-8 border-t border-slate-200/80">
      <h2 className="text-sm font-medium text-slate-900 mb-5">Investigation progress</h2>
      <ul className="space-y-3" aria-label="Investigation stages">
        {INVESTIGATION_STAGES.map((stage, i) => {
          const status = statuses[i] ?? 'pending';
          return (
            <li key={stage.id} className="flex items-center gap-3 text-sm">
              <StageGlyph status={status} />
              <span
                className={
                  status === 'complete'
                    ? 'text-slate-500'
                    : status === 'active'
                      ? 'text-slate-900 font-medium'
                      : 'text-slate-400'
                }
              >
                {capitalizeStageTitle(stage.title)}
              </span>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

function StageGlyph({ status }: { status: InvestigationStageStatus }) {
  if (status === 'complete') {
    return (
      <span className="flex h-5 w-5 items-center justify-center rounded-full bg-emerald-50 text-emerald-600 shrink-0">
        <Check className="h-3.5 w-3.5" strokeWidth={2.5} aria-hidden />
      </span>
    );
  }
  if (status === 'active') {
    return (
      <span
        className="h-2.5 w-2.5 rounded-full bg-blue-600 shrink-0 ml-[5px] mr-[5px] investigation-stage-dot"
        aria-hidden
      />
    );
  }
  return (
    <span
      className="h-2.5 w-2.5 rounded-full border border-slate-300 shrink-0 ml-[5px] mr-[5px]"
      aria-hidden
    />
  );
}

function capitalizeStageTitle(title: string): string {
  return title
    .split(' ')
    .map((w, i) => (i === 0 ? w.charAt(0).toUpperCase() + w.slice(1) : w))
    .join(' ');
}
