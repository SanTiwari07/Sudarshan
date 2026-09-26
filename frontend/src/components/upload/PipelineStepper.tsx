import type { LucideIcon } from 'lucide-react';
import { ScanSearch, Cpu, Globe2, Gauge, Sparkles, FileCheck, Check } from 'lucide-react';
import type { StageStatus } from './pipelineStages';
import { TYPOGRAPHY } from '../../theme/typography';

/**
 * The six pipeline stages, as a stepper.
 *
 * This was a grid of six 185px cards that never changed until an upload
 * started - a feature list dressed as a dashboard, occupying more of the
 * landing page than the drop zone it was explaining. As a stepper it costs a
 * fifth of the height, and the same markup that describes the pipeline at rest
 * narrates it while a case is running.
 */
export type PipelineStage = {
  title: string;
  description: string;
  icon: keyof typeof ICONS;
};

const ICONS = {
  static: ScanSearch,
  dynamic: Cpu,
  threat: Globe2,
  risk: Gauge,
  ai: Sparkles,
  report: FileCheck,
} satisfies Record<string, LucideIcon>;

type PipelineStepperProps = {
  stages: readonly PipelineStage[];
  /** Per-stage status. `undefined` renders the at-rest state. */
  statusOf: (index: number) => StageStatus | undefined;
  /** Stack the stages as a timeline, for a narrow side column. */
  vertical?: boolean;
};

export default function PipelineStepper({ stages, statusOf, vertical = false }: PipelineStepperProps) {
  if (vertical) {
    return (
      <ol className="relative" role="list">
        {stages.map((stage, index) => {
          const status = statusOf(index);
          const Icon = ICONS[stage.icon] ?? ScanSearch;
          const isLast = index === stages.length - 1;

          const node =
            status === 'complete'
              ? 'bg-blue-600 text-white'
              : status === 'active'
                ? 'bg-white text-blue-600 ring-2 ring-blue-600 shadow-[0_0_0_6px_rgba(37,99,235,0.12)]'
                : status === 'error'
                  ? 'bg-red-50 text-red-600 ring-1 ring-red-300'
                  : 'bg-slate-100 text-slate-500';

          return (
            <li key={stage.title} className="relative flex gap-4 pb-6 last:pb-0">
              {!isLast && (
                <span
                  className={`absolute left-[17px] top-10 bottom-1 w-px transition-colors duration-500 ${
                    status === 'complete' ? 'bg-blue-600' : 'bg-slate-200'
                  }`}
                  aria-hidden
                />
              )}
              <span
                className={`relative z-10 flex h-9 w-9 shrink-0 items-center justify-center rounded-xl transition-all duration-300 ${node}`}
              >
                {status === 'complete' ? (
                  <Check className="h-4 w-4" aria-hidden />
                ) : (
                  <Icon className="h-4 w-4" aria-hidden />
                )}
              </span>
              <div className="min-w-0 pt-1">
                <p
                  className={`text-[15px] font-semibold leading-tight ${
                    status === 'active' ? 'text-blue-700' : 'text-slate-900'
                  }`}
                >
                  {stage.title}
                  {status === 'active' && (
                    <span className="ml-2 inline-flex items-center rounded-full bg-blue-50 px-2 py-0.5 text-[11px] font-semibold text-blue-700 align-middle">
                      Running
                    </span>
                  )}
                </p>
                <p className="mt-0.5 text-[13px] text-slate-500 leading-snug">{stage.description}</p>
              </div>
            </li>
          );
        })}
      </ol>
    );
  }

  return (
    <ol className="flex flex-col sm:flex-row sm:items-start gap-x-0 gap-y-3" role="list">
      {stages.map((stage, index) => {
        const status = statusOf(index);
        const Icon = ICONS[stage.icon] ?? ScanSearch;
        const isLast = index === stages.length - 1;

        const ring =
          status === 'complete'
            ? 'bg-blue-600 border-blue-600 text-white'
            : status === 'active'
              ? 'bg-white border-blue-600 text-blue-700 ring-4 ring-blue-100'
              : status === 'error'
                ? 'bg-white border-red-400 text-red-600'
                : 'bg-white border-slate-300 text-slate-400';

        return (
          <li key={stage.title} className="flex-1 min-w-0 flex sm:flex-col gap-3 sm:gap-0">
            {/* Node + connector. The connector is the element that carries
                progress, so it is coloured by the stage behind it. */}
            <div className="flex sm:w-full items-center flex-col sm:flex-row shrink-0">
              <span
                className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full border-2 transition-colors duration-300 ${ring}`}
              >
                {status === 'complete' ? (
                  <Check className="h-4 w-4" aria-hidden />
                ) : (
                  <Icon className="h-4 w-4" aria-hidden />
                )}
              </span>
              {!isLast && (
                <span
                  className={`w-0.5 sm:w-full flex-1 sm:h-0.5 sm:min-h-0 min-h-[1.5rem] sm:mx-2 rounded-full transition-colors duration-500 ${
                    status === 'complete' ? 'bg-blue-600' : 'bg-slate-200'
                  }`}
                  aria-hidden
                />
              )}
            </div>

            <div className="min-w-0 sm:mt-3 sm:pr-4 pb-1">
              <p
                className={`${TYPOGRAPHY.h3} ${
                  status === 'active' ? 'text-blue-700' : status ? 'text-slate-900' : 'text-slate-600'
                }`}
              >
                {stage.title}
              </p>
              <p className={`${TYPOGRAPHY.caption} mt-0.5`}>{stage.description}</p>
            </div>
          </li>
        );
      })}
    </ol>
  );
}
