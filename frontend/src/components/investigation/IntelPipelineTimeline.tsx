import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import { Activity } from 'lucide-react';

type IntelTimelineStep = {
  step?: string;
  status?: string;
  timestamp?: string;
  detail?: string;
};

export default function IntelPipelineTimeline({ timeline }: { timeline: IntelTimelineStep[] }) {
  if (!timeline?.length) return null;

  return (
    <SocCard>
      <SectionHeader
        icon={<Activity className="h-4 w-4" />}
        title="Intel pipeline timeline"
        subtitle="External enrichment — not Frida forensic timeline"
      />
      <div className="p-4 space-y-2 text-xs">
        {timeline.map((step, i) => (
          <div key={i} className="flex gap-3 border-l-2 border-slate-200 pl-3 py-1">
            <span className="text-[10px] text-slate-400 w-20 shrink-0">{step.timestamp?.slice(11, 19) || '—'}</span>
            <div>
              <div className="font-semibold text-slate-800">{step.step}</div>
              <div className="text-slate-600">{step.detail}</div>
              <div className="text-[10px] text-slate-400">{step.status}</div>
            </div>
          </div>
        ))}
      </div>
    </SocCard>
  );
}
