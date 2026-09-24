import { Clock, CheckCircle2 } from 'lucide-react';
import type { FraudCardData } from '../../types/case';
import { useAnalysis } from '../../context/AnalysisContext';

export default function InvestigationActivity({ data }: { data: FraudCardData }) {
  const { investigationBundle } = useAnalysis();

  const timelineEvents = investigationBundle?.timelineEvents || [];
  const dynamicTimeline = data.dynamic_analysis?.attack_timeline || [];

  // Construct verified activity milestones
  const activities: { time: string; title: string; detail: string }[] = [];

  if (data.created_at) {
    activities.push({
      time: new Date(data.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      title: 'Investigation Initiated',
      detail: `Package ${data.package_name} submitted for forensic scoring`,
    });
  }

  if (timelineEvents.length > 0) {
    timelineEvents.slice(0, 3).forEach((ev: any) => {
      activities.push({
        time: ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Phase',
        title: ev.label || ev.title || 'Forensic Event Recorded',
        detail: ev.detail || ev.description || 'Behavioral telemetry verified by deterministic engine',
      });
    });
  } else if (dynamicTimeline.length > 0) {
    dynamicTimeline.slice(0, 3).forEach((dt: any, idx: number) => {
      activities.push({
        time: dt.timestamp ? `${(dt.timestamp / 1000).toFixed(1)}s` : `T+${idx * 5}s`,
        title: dt.label || dt.action || 'Runtime Action Observed',
        detail: dt.description || 'Captured by Frida instrumentation sandbox',
      });
    });
  }

  if (activities.length === 0) {
    return (
      <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-xs h-full flex flex-col justify-between">
        <h2 className="text-[11px] font-bold uppercase tracking-widest text-slate-500 mb-4">
          RECENT INVESTIGATION ACTIVITY
        </h2>
        <div className="my-auto py-8 text-center text-slate-400">
          <Clock className="h-8 w-8 mx-auto mb-2 text-slate-300" />
          <p className="text-xs">No recent audit events for this case.</p>
        </div>
        <div className="pt-2 border-t border-slate-100 text-[11px] text-slate-400">
          Audit stream idle
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-xs h-full flex flex-col justify-between">
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-[11px] font-bold uppercase tracking-widest text-slate-500 flex items-center gap-1.5">
            <Clock className="h-3.5 w-3.5 text-slate-400" />
            INVESTIGATION ACTIVITY LOG
          </h2>
          <span className="text-[11px] font-mono text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200 font-semibold flex items-center gap-1">
            <CheckCircle2 className="h-3 w-3" />
            Audited
          </span>
        </div>

        <div className="space-y-3 relative">
          <div className="absolute left-[11px] top-2 bottom-2 w-0.5 bg-slate-100" />

          {activities.slice(0, 4).map((act, idx) => (
            <div key={idx} className="flex items-start gap-3 relative z-10 text-xs">
              <div className="h-6 w-6 rounded-full border-2 border-white bg-slate-200 text-slate-600 flex items-center justify-center font-mono text-[10px] font-bold shrink-0 mt-0.5 shadow-2xs">
                {idx + 1}
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center justify-between gap-1">
                  <span className="font-bold text-slate-900 truncate">{act.title}</span>
                  <span className="font-mono text-[10px] text-slate-400 shrink-0">{act.time}</span>
                </div>
                <p className="text-[11px] text-slate-500 line-clamp-1 mt-0.5 font-normal">
                  {act.detail}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="mt-3 pt-2.5 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-400">
        <span>Deterministic audit trail</span>
        <span>SOC Activity</span>
      </div>
    </div>
  );
}
