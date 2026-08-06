import { buildEvidencePipelineTimeline } from '../../lib/executiveIntelligence';
import type { FraudCardData } from '../../App';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import { GitBranch, CheckCircle2, AlertTriangle, CircleDot } from 'lucide-react';

const TONE = {
  done: { icon: CheckCircle2, border: 'border-emerald-400', bg: 'bg-emerald-50', iconClass: 'text-emerald-600' },
  active: { icon: CircleDot, border: 'border-blue-500', bg: 'bg-blue-50', iconClass: 'text-blue-600' },
  warn: { icon: AlertTriangle, border: 'border-amber-400', bg: 'bg-amber-50', iconClass: 'text-amber-600' },
};

export default function EvidencePipelineTimeline({ data }: { data: FraudCardData }) {
  const steps = buildEvidencePipelineTimeline(data);

  return (
    <SocCard className="upload-fade-in" id="evidence-timeline">
      <SectionHeader
        icon={<GitBranch className="h-4 w-4" />}
        title="Evidence Timeline"
        subtitle="How verified evidence flowed from analysis to recommendation."
      />
      <div className="p-5 sm:p-6">
        <div className="relative max-w-2xl mx-auto">
          {steps.map((step, i) => {
            const tone = TONE[step.tone];
            const Icon = tone.icon;
            const isLast = i === steps.length - 1;
            return (
              <div key={step.phase} className="flex gap-4 evidence-timeline-step" style={{ animationDelay: `${i * 80}ms` }}>
                <div className="flex flex-col items-center w-9 shrink-0">
                  <div className={`p-1.5 rounded-full border-2 ${tone.border} ${tone.bg}`}>
                    <Icon className={`h-4 w-4 ${tone.iconClass}`} />
                  </div>
                  {!isLast && <div className="w-0.5 flex-1 min-h-[2.5rem] bg-gradient-to-b from-slate-300 to-slate-200 my-1" />}
                </div>
                <div className={`pb-6 min-w-0 ${isLast ? 'pb-0' : ''}`}>
                  <div className="text-sm font-bold text-slate-900">{step.phase}</div>
                  <p className="text-xs text-slate-600 mt-1 leading-relaxed">{step.detail}</p>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </SocCard>
  );
}
