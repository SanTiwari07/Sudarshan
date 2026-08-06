import type { InvestigationStage } from '../investigationStages';

type CurrentStageCardProps = {
  stage: InvestigationStage;
  isActive: boolean;
};

export default function CurrentStageCard({ stage, isActive }: CurrentStageCardProps) {
  return (
    <section
      className={`py-8 border-t border-slate-200/80 transition-opacity duration-500 ${
        isActive ? 'opacity-100' : 'opacity-90'
      }`}
      aria-live="polite"
      aria-atomic="true"
    >
      <p className="text-xs text-slate-500 mb-2">Current stage</p>
      <h2
        className={`text-xl sm:text-2xl font-semibold text-slate-900 mb-3 ${
          isActive ? 'investigation-stage-active' : ''
        }`}
      >
        {stage.title}
      </h2>
      <p className="text-sm sm:text-base text-slate-600 leading-relaxed max-w-2xl">{stage.description}</p>
    </section>
  );
}
