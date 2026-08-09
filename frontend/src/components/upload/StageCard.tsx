import type { LucideIcon } from 'lucide-react';
import {
  UploadCloud,
  ScanSearch,
  Cpu,
  Globe2,
  Gauge,
  Sparkles,
  FileCheck,
  CheckCircle2,
  Loader2,
  Circle,
} from 'lucide-react';
import { WORKFLOW_CARDS, type StageStatus } from './pipelineStages';

const ICONS: Record<string, LucideIcon> = {
  upload: UploadCloud,
  static: ScanSearch,
  dynamic: Cpu,
  threat: Globe2,
  risk: Gauge,
  ai: Sparkles,
  report: FileCheck,
};

type StageCardProps = {
  title: string;
  description: string;
  icon: keyof typeof ICONS;
  status?: StageStatus;
  compact?: boolean;
  /** Upload page pipeline grid - larger, equal-height cards */
  overview?: boolean;
};

export default function StageCard({ title, description, icon, status, compact, overview }: StageCardProps) {
  const Icon = ICONS[icon] ?? ScanSearch;

  const statusIcon =
    status === 'complete' ? (
      <CheckCircle2 className="h-4 w-4 text-emerald-500" aria-label="Complete" />
    ) : status === 'active' ? (
      <Loader2 className="h-4 w-4 text-blue-600 animate-spin" aria-label="In progress" />
    ) : status === 'pending' ? (
      <Circle className="h-3.5 w-3.5 text-slate-300" aria-label="Pending" />
    ) : null;

  if (overview) {
    return (
      <div
        className="group flex h-full flex-col gap-4 rounded-xl border border-slate-200/90 bg-white p-5 shadow-sm transition-all duration-200 hover:border-slate-300 hover:shadow-md"
      >
        <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-slate-100 text-slate-600 transition-colors group-hover:bg-blue-50 group-hover:text-blue-700">
          <Icon className="h-5 w-5" aria-hidden />
        </div>
        <div className="min-w-0 flex-1 flex flex-col">
          <h4 className="text-[15px] font-semibold text-slate-900 leading-snug">{title}</h4>
          <p className="text-sm text-slate-500 mt-2 leading-relaxed flex-1">{description}</p>
        </div>
      </div>
    );
  }

  return (
    <div
      className={`relative flex gap-3 rounded-xl border bg-white shadow-sm transition-all duration-300 ${
        status === 'active'
          ? 'border-blue-300 ring-2 ring-blue-100 upload-stage-pulse'
          : status === 'complete'
            ? 'border-emerald-200'
            : 'border-slate-200'
      } ${compact ? 'p-3' : 'p-4'}`}
    >
      <div
        className={`shrink-0 flex items-center justify-center rounded-lg ${
          compact ? 'h-9 w-9' : 'h-11 w-11'
        } ${status === 'active' ? 'bg-blue-100 text-blue-700' : 'bg-slate-100 text-slate-600'}`}
      >
        <Icon className={compact ? 'h-4 w-4' : 'h-5 w-5'} aria-hidden />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <h4 className={`font-semibold text-slate-900 ${compact ? 'text-xs' : 'text-sm'}`}>{title}</h4>
          {statusIcon}
        </div>
        <p className={`text-slate-500 mt-0.5 ${compact ? 'text-[11px] leading-snug' : 'text-xs'}`}>
          {description}
        </p>
      </div>
    </div>
  );
}

export function WorkflowPipelineColumn() {
  return (
    <div className="flex flex-col items-stretch gap-0 max-w-md mx-auto">
      {WORKFLOW_CARDS.map((card, i) => (
        <div key={card.title} className="flex flex-col items-center">
          <StageCard title={card.title} description={card.description} icon={card.icon} />
          {i < WORKFLOW_CARDS.length - 1 && (
            <div className="py-1 text-slate-300 font-bold text-lg select-none" aria-hidden>
              ↓
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
