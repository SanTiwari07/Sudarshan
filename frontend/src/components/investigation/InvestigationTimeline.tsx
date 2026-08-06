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
    icon: <CheckCircle2 className="h-5 w-5 text-emerald-600" />,
    text: 'text-slate-800',
    chip: 'bg-emerald-50 text-emerald-800 border-emerald-200',
  },
  active: {
    border: 'border-blue-500',
    bg: 'bg-blue-50',
    icon: <CircleDot className="h-5 w-5 text-blue-600" />,
    text: 'text-slate-900',
    chip: 'bg-blue-50 text-blue-800 border-blue-200',
  },
  warning: {
    border: 'border-amber-400',
    bg: 'bg-amber-50',
    icon: <AlertTriangle className="h-5 w-5 text-amber-600" />,
    text: 'text-amber-950',
    chip: 'bg-amber-50 text-amber-900 border-amber-200',
  },
};

const STORY_OPENING: { label: string; tone: 'completed' | 'active' | 'warning' }[] = [
  { label: 'APK received for fraud investigation', tone: 'completed' },
  { label: 'Code inspection started (static analysis)', tone: 'completed' },
  { label: 'Permissions and manifest extracted', tone: 'completed' },
];

export default function InvestigationTimeline({
  bundle,
  embedded = false,
}: {
  bundle: InvestigationBundle;
  embedded?: boolean;
}) {
  const { openEvidence, setTimelineFocus } = useInvestigationUI();
  const events = bundle.timelineEvents;
  const base = events[0]?.timestampMs ?? 0;
  const closingLabel =
    events.length > 0 && events[events.length - 1].category === 'score'
      ? 'Fraud intelligence report produced'
      : null;

  const timelineBody = (
    <div className="px-4 sm:px-5 py-4 max-h-[28rem] overflow-y-auto scrollbar-hidden">
        <div className="relative">
          {STORY_OPENING.map((step, i) => {
            const style = TONE_STYLES[step.tone];
            const isLastStory = i === STORY_OPENING.length - 1 && events.length === 0;
            return (
              <div key={step.label} className="flex gap-4">
                <div className="flex flex-col items-center w-10 shrink-0">
                  <div className={`flex h-10 w-10 items-center justify-center rounded-full border-2 ${style.border} ${style.bg}`}>
                    {style.icon}
                  </div>
                  {!isLastStory && <div className="w-px flex-1 min-h-[1.5rem] bg-slate-200 my-1" />}
                </div>
                <div className="flex-1 text-left pb-6 min-w-0">
                  <div className="text-sm font-semibold text-slate-800 leading-snug">{step.label}</div>
                  <span className={`inline-flex mt-1 text-[10px] font-medium px-2 py-0.5 rounded-full border ${style.chip}`}>
                    Complete
                  </span>
                </div>
              </div>
            );
          })}
          {events.map((ev, i) => {
            const tone = timelineTone(ev, i, events.length);
            const style = TONE_STYLES[tone];
            const label = humanizeTimelineLabel(ev.label);
            const isLast = i === events.length - 1 && !closingLabel;

            return (
              <div key={ev.id} className="flex gap-4">
                <div className="flex flex-col items-center w-10 shrink-0">
                  <div className={`flex h-10 w-10 items-center justify-center rounded-full border-2 ${style.border} ${style.bg}`}>
                    {style.icon}
                  </div>
                  {!isLast && <div className="w-px flex-1 min-h-[1.5rem] bg-slate-200 my-1" />}
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setTimelineFocus(ev.timestampMs);
                    if (ev.evidenceIds[0]) openEvidence(ev.evidenceIds[0]);
                  }}
                  className={`flex-1 text-left pb-6 min-w-0 rounded-lg -ml-1 pl-1 pr-2 transition-colors duration-200 hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${isLast ? 'pb-0' : ''}`}
                >
                  <div className="font-mono text-[11px] text-slate-500 mb-1 tabular-nums">
                    {formatTimelineOffset(ev.timestampMs, base)}
                  </div>
                  <div className={`text-sm font-semibold leading-snug ${style.text}`}>{label}</div>
                  {ev.contributionLabel && (
                    <span className="text-[11px] font-mono text-amber-700 mt-0.5 block">{ev.contributionLabel}</span>
                  )}
                  {ev.evidenceIds.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {ev.evidenceIds.slice(0, 3).map((id) => (
                        <span key={id} className="font-mono text-[10px] px-1.5 py-0.5 bg-blue-50 text-blue-700 rounded-md border border-blue-100">
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
            <div className="flex gap-4">
              <div className="flex flex-col items-center w-10 shrink-0">
                <div className={`flex h-10 w-10 items-center justify-center rounded-full border-2 ${TONE_STYLES.active.border} ${TONE_STYLES.active.bg}`}>
                  {TONE_STYLES.active.icon}
                </div>
              </div>
              <div className="flex-1 text-left min-w-0">
                <div className="text-sm font-semibold text-slate-900 leading-snug">{closingLabel}</div>
              </div>
            </div>
          )}
        </div>
      </div>
  );

  if (embedded) {
    return (
      <div className="relative static">
        <div className="px-4 sm:px-5 py-3 border-t border-slate-100">
          <h3 className="text-sm font-semibold text-slate-900">Investigation timeline</h3>
          <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">
            Chronological sequence —{' '}
            <HelpTerm term="Verified Evidence">verified evidence only</HelpTerm>.
          </p>
        </div>
        {timelineBody}
      </div>
    );
  }

  return (
    <SocCard className="relative static">
      <SectionHeader
        icon={<Clock className="h-4 w-4" />}
        title="Investigation timeline"
        subtitle={
          <>
            Chronological sequence —{' '}
            <HelpTerm term="Verified Evidence">verified evidence only</HelpTerm>, not raw system logs.
          </>
        }
      />
      {timelineBody}
    </SocCard>
  );
}
