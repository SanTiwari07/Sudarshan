import type { InvestigationBundle } from '../../types/investigation';
import { formatTimelineOffset } from '../../lib/timelineMerge';
import { humanizeTimelineLabel, timelineTone } from '../../lib/analystCopy';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import HelpTerm from './HelpTerm';
import { CheckCircle2, AlertTriangle, CircleDot, Clock } from 'lucide-react';

const TONE_STYLES = {
  completed: {
    border: 'border-emerald-400',
    bg: 'bg-emerald-50',
    icon: <CheckCircle2 className="h-4 w-4 text-emerald-600" />,
    text: 'text-slate-800',
  },
  active: {
    border: 'border-blue-500',
    bg: 'bg-blue-50',
    icon: <CircleDot className="h-4 w-4 text-blue-600" />,
    text: 'text-slate-900',
  },
  warning: {
    border: 'border-amber-400',
    bg: 'bg-amber-50',
    icon: <AlertTriangle className="h-4 w-4 text-amber-600" />,
    text: 'text-amber-950',
  },
};

const STORY_OPENING: { label: string; tone: 'completed' | 'active' | 'warning' }[] = [
  { label: 'APK received for fraud investigation', tone: 'completed' },
  { label: 'Code inspection started (static analysis)', tone: 'completed' },
  { label: 'Permissions and manifest extracted', tone: 'completed' },
];

export default function InvestigationTimeline({ bundle }: { bundle: InvestigationBundle }) {
  const { openEvidence, setTimelineFocus } = useInvestigationUI();
  const events = bundle.timelineEvents;
  const base = events[0]?.timestampMs ?? 0;
  const closingLabel =
    events.length > 0 && events[events.length - 1].category === 'score'
      ? 'Fraud intelligence report produced'
      : null;

  return (
    <SocCard>
      <SectionHeader
        icon={<Clock className="h-4 w-4" />}
        title="Investigation Timeline"
        subtitle={
          <>
            Chronological sequence of this case —{' '}
            <HelpTerm term="Verified Evidence">not raw system logs</HelpTerm>.
          </>
        }
      />
      <div className="p-5 max-h-[28rem] overflow-y-auto">
        <div className="relative pl-2">
          {STORY_OPENING.map((step, i) => {
            const style = TONE_STYLES[step.tone];
            const isLastStory = i === STORY_OPENING.length - 1 && events.length === 0;
            return (
              <div key={step.label} className="flex gap-0">
                <div className="flex flex-col items-center w-8 shrink-0">
                  <div className={`p-1 rounded-full border-2 ${style.border} ${style.bg}`}>{style.icon}</div>
                  {!isLastStory && <div className="w-0.5 flex-1 min-h-[2rem] bg-slate-200 my-1" />}
                </div>
                <div className="flex-1 text-left pb-5">
                  <div className="text-sm font-semibold text-slate-800">{step.label}</div>
                </div>
              </div>
            );
          })}
          {events.map((ev, i) => {
            const tone = timelineTone(ev, i, events.length);
            const style = TONE_STYLES[tone];
            const label = humanizeTimelineLabel(ev.label);
            const isLast = i === events.length - 1;

            return (
              <div key={ev.id} className="flex gap-0">
                <div className="flex flex-col items-center w-8 shrink-0">
                  <div className={`p-1 rounded-full border-2 ${style.border} ${style.bg}`}>{style.icon}</div>
                  {!isLast && <div className="w-0.5 flex-1 min-h-[2rem] bg-slate-200 my-1" />}
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setTimelineFocus(ev.timestampMs);
                    if (ev.evidenceIds[0]) openEvidence(ev.evidenceIds[0]);
                  }}
                  className={`flex-1 text-left pb-5 ${isLast ? 'pb-0' : ''}`}
                >
                  <div className="font-mono text-[10px] text-slate-500 mb-0.5">
                    {formatTimelineOffset(ev.timestampMs, base)}
                  </div>
                  <div className={`text-sm font-semibold ${style.text}`}>{label}</div>
                  {ev.contributionLabel && (
                    <span className="text-[10px] font-mono text-amber-700">{ev.contributionLabel}</span>
                  )}
                  {ev.evidenceIds.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-1">
                      {ev.evidenceIds.slice(0, 3).map((id) => (
                        <span key={id} className="font-mono text-[9px] px-1.5 py-0.5 bg-blue-50 text-blue-700 rounded">
                          {id}
                        </span>
                      ))}
                    </div>
                  )}
                </button>
              </div>
            );
          })}
          {closingLabel && (
            <div className="flex gap-0">
              <div className="flex flex-col items-center w-8 shrink-0">
                <div className={`p-1 rounded-full border-2 ${TONE_STYLES.active.border} ${TONE_STYLES.active.bg}`}>
                  {TONE_STYLES.active.icon}
                </div>
              </div>
              <div className="flex-1 text-left pb-0">
                <div className="text-sm font-semibold text-slate-900">{closingLabel}</div>
              </div>
            </div>
          )}
        </div>
      </div>
    </SocCard>
  );
}
