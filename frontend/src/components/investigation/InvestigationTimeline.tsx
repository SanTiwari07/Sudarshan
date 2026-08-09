import { useMemo, type ReactNode } from 'react';
import type { FraudCardData } from '../../App';
import type { InvestigationBundle, TimelineEvent } from '../../types/investigation';
import { formatTimelineOffset } from '../../lib/timelineMerge';
import { humanizeTimelineLabel, timelineTone } from '../../lib/analystCopy';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { useAnalysis } from '../../context/AnalysisContext';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import HelpTerm from './HelpTerm';
import TimelineScreenshotThumb from './TimelineScreenshotThumb';
import { Clock } from 'lucide-react';

type TimelineStatus = 'COMPLETE' | 'INCONCLUSIVE' | 'FAILED' | 'PENDING' | 'ACTIVE';

const STORY_OPENING: { label: string; support?: string; offsetSec: number }[] = [
  { label: 'APK received', support: 'Fraud investigation initialized', offsetSec: 0 },
  { label: 'Code inspection started', support: 'Static analysis pipeline engaged', offsetSec: 2 },
  { label: 'Permissions and manifest extracted', offsetSec: 5 },
];

function timelineGroupLabel(ev: TimelineEvent): string {
  if (ev.kind === 'score' || ev.category === 'score') return 'RISK ASSESSMENT';
  if (ev.category === 'runtime' || ev.source === 'FRIDA') return 'DYNAMIC ANALYSIS';
  if (ev.category === 'scenario' || ev.category === 'intel') return 'THREAT INTELLIGENCE';
  if (ev.kind === 'workflow') return 'REPORTING';
  return 'STATIC ANALYSIS';
}

function eventStatus(tone: 'completed' | 'active' | 'warning'): TimelineStatus {
  if (tone === 'warning') return 'INCONCLUSIVE';
  if (tone === 'active') return 'ACTIVE';
  return 'COMPLETE';
}

function statusClass(status: TimelineStatus): string {
  if (status === 'COMPLETE') return 'text-emerald-700';
  if (status === 'INCONCLUSIVE') return 'text-amber-700';
  if (status === 'FAILED') return 'text-red-700';
  if (status === 'ACTIVE') return 'text-slate-700';
  return 'text-slate-400';
}

function TimelineRow({
  timeLabel,
  title,
  support,
  status,
  onClick,
  isLast,
  visualExtra,
}: {
  timeLabel: string;
  title: string;
  support?: string;
  status: TimelineStatus;
  onClick?: () => void;
  isLast?: boolean;
  visualExtra?: ReactNode;
}) {
  const content = (
    <div className="grid grid-cols-[5.25rem_1fr] gap-x-4 gap-y-0.5 py-3 min-h-[4rem]">
      <div className="relative flex items-start gap-2">
        <div className="flex flex-col items-center shrink-0 w-3">
          <span className="mt-1.5 h-2 w-2 rounded-full bg-slate-400 shrink-0" aria-hidden />
          {!isLast && <div className="w-px flex-1 min-h-[2rem] bg-slate-200 mt-1" aria-hidden />}
        </div>
        <span className="font-mono text-[11px] text-slate-500 tabular-nums pt-0.5">{timeLabel}</span>
      </div>
      <div className="min-w-0 pb-1">
        <p className="text-[13px] font-semibold text-slate-900 leading-snug">{title}</p>
        {support && <p className="text-[12px] text-slate-500 mt-0.5 leading-relaxed">{support}</p>}
        {visualExtra}
        <p className={`mt-1 text-[10px] font-bold uppercase tracking-wide ${statusClass(status)}`}>
          {status}
        </p>
      </div>
    </div>
  );

  if (onClick) {
    return (
      <button
        type="button"
        onClick={onClick}
        className="w-full text-left rounded-md hover:bg-slate-50/80 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-slate-300"
      >
        {content}
      </button>
    );
  }

  return <div>{content}</div>;
}

function GroupBlock({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="mb-4 last:mb-0">
      <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-slate-400 mb-1 pl-[5.25rem]">
        {label}
      </p>
      {children}
    </div>
  );
}

export default function InvestigationTimeline({
  data,
  bundle,
  embedded = false,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle;
  embedded?: boolean;
}) {
  const { openEvidence, setTimelineFocus } = useInvestigationUI();
  const { screenshotManifestEntries } = useAnalysis();
  const events = bundle.timelineEvents;
  const base = events[0]?.timestampMs ?? 0;

  const groupedEvents = useMemo(() => {
    const map = new Map<string, TimelineEvent[]>();
    events.forEach((ev) => {
      const g = timelineGroupLabel(ev);
      const list = map.get(g) || [];
      list.push(ev);
      map.set(g, list);
    });
    return map;
  }, [events]);

  const timelineBody = (
    <div className="max-w-[1050px] py-4">
      <GroupBlock label="INGESTION">
        {STORY_OPENING.map((step, i) => (
          <TimelineRow
            key={step.label}
            timeLabel={formatTimelineOffset(step.offsetSec * 1000, 0)}
            title={step.label}
            support={step.support}
            status="COMPLETE"
            isLast={i === STORY_OPENING.length - 1 && events.length === 0}
          />
        ))}
      </GroupBlock>

      {['STATIC ANALYSIS', 'DYNAMIC ANALYSIS', 'THREAT INTELLIGENCE', 'RISK ASSESSMENT', 'REPORTING'].map(
        (groupName) => {
          const groupEvents = groupedEvents.get(groupName);
          if (!groupEvents?.length) return null;
          return (
            <GroupBlock key={groupName} label={groupName}>
              {groupEvents.map((ev, i) => {
                const tone = timelineTone(ev, i, groupEvents.length);
                const status = eventStatus(tone);
                const label = humanizeTimelineLabel(ev.label);
                const support = ev.contributionLabel || undefined;
                const isLast = i === groupEvents.length - 1;
                const shotEntry = ev.screenshotId
                  ? screenshotManifestEntries.find((e) => e.screenshot_id === ev.screenshotId)
                  : undefined;
                const visualExtra =
                  shotEntry && data.sha256 ? (
                    <TimelineScreenshotThumb sha256={data.sha256} entry={shotEntry} />
                  ) : undefined;
                return (
                  <TimelineRow
                    key={ev.id}
                    timeLabel={formatTimelineOffset(ev.timestampMs, base)}
                    title={label}
                    support={support}
                    status={status}
                    isLast={isLast}
                    visualExtra={visualExtra}
                    onClick={
                      ev.evidenceIds[0]
                        ? () => {
                            setTimelineFocus(ev.timestampMs);
                            openEvidence(ev.evidenceIds[0]);
                          }
                        : undefined
                    }
                  />
                );
              })}
            </GroupBlock>
          );
        },
      )}
    </div>
  );

  if (embedded) {
    return (
      <section className="pt-4 border-t border-slate-200" aria-labelledby="investigation-timeline-title">
        <h3 id="investigation-timeline-title" className="text-[15px] font-semibold text-slate-900">
          Investigation timeline
        </h3>
        <p className="text-[12px] text-slate-500 mt-0.5">
          Chronological sequence ·{' '}
          <HelpTerm term="Verified Evidence">verified evidence only</HelpTerm>
        </p>
        {timelineBody}
      </section>
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
      <div className="px-4 sm:px-5">{timelineBody}</div>
    </SocCard>
  );
}
