import { AlertTriangle } from 'lucide-react';
import ProgressHeader from './ProgressHeader';
import CurrentStageCard from './CurrentStageCard';
import StageTimeline from './StageTimeline';
import NextStepsCard from './NextStepsCard';
import {
  INVESTIGATION_STAGES,
  activeStageIndex,
  stageStatesForProgress,
} from '../investigationStages';

type InvestigationProgressProps = {
  fileName: string;
  progress: number;
  error: string | null;
  onRetry?: () => void;
  stageTitle?: string;
  stageDescription?: string;
};

export default function InvestigationProgress({
  fileName,
  progress,
  error,
  onRetry,
  stageTitle,
  stageDescription,
}: InvestigationProgressProps) {
  const useBackend = Boolean(stageTitle && stageDescription);
  const statuses = stageStatesForProgress(progress);
  const activeIdx = activeStageIndex(progress);
  const activeStage = INVESTIGATION_STAGES[activeIdx];
  const displayTitle = useBackend ? stageTitle! : activeStage.title;
  const displayDescription = useBackend ? stageDescription! : activeStage.description;

  return (
    <div className="upload-fade-in w-full flex justify-center px-4 py-10 sm:py-16">
      <div className="w-full max-w-[42rem]">
        <ProgressHeader fileName={fileName} progress={progress} />
        <CurrentStageCard
          key={useBackend ? stageTitle : activeStage.id}
          stage={{ ...activeStage, title: displayTitle, description: displayDescription }}
          isActive={statuses[activeIdx] === 'active' || useBackend}
        />
        <StageTimeline statuses={statuses} />
        <NextStepsCard steps={activeStage.nextSteps} />

        {error && (
          <div className="mt-8 pt-8 border-t border-slate-200/80 space-y-4">
            <div className="flex items-start gap-3 text-red-800">
              <AlertTriangle className="h-5 w-5 shrink-0 mt-0.5" aria-hidden />
              <div>
                <p className="font-medium text-sm">Investigation could not be completed</p>
                <p className="text-sm mt-1 text-red-700">{error}</p>
              </div>
            </div>
            {onRetry && (
              <button
                type="button"
                onClick={onRetry}
                className="text-sm font-medium text-blue-700 hover:text-blue-800 focus:outline-none focus-visible:underline"
              >
                Try again
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
