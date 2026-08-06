import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import SocCard from '../ui/Card';
import HelpTerm from './HelpTerm';
import { FileCode2, PlayCircle } from 'lucide-react';
import { useInvestigationUI } from '../../context/InvestigationUIContext';

function PhaseCard({
  title,
  term,
  description,
  icon,
  progress,
  findingsLabel,
  items,
  onOpen,
}: {
  title: string;
  term: string;
  description: string;
  icon: React.ReactNode;
  progress: number;
  findingsLabel: string;
  items: string[];
  onOpen: () => void;
}) {
  return (
    <SocCard className="h-full flex flex-col">
      <button type="button" onClick={onOpen} className="text-left flex-1 flex flex-col">
        <div className="px-5 py-4 border-b border-slate-200 flex items-start gap-3">
          <span className="p-2 rounded-lg bg-blue-50 text-blue-700">{icon}</span>
          <div className="min-w-0">
            <h3 className="text-sm font-bold text-slate-900">
              <HelpTerm term={term}>{title}</HelpTerm>
            </h3>
            <p className="text-xs text-slate-500 mt-1">{description}</p>
          </div>
        </div>
        <div className="p-5 flex-1 flex flex-col gap-4">
          <div>
            <div className="flex justify-between text-[11px] text-slate-500 mb-1">
              <span>Coverage</span>
              <span className="font-semibold text-slate-700">{findingsLabel}</span>
            </div>
            <div className="w-full h-2 bg-slate-100 rounded-full overflow-hidden">
              <div
                className="h-full bg-blue-600 rounded-full transition-all"
                style={{ width: `${Math.min(100, progress)}%` }}
              />
            </div>
          </div>
          <ul className="text-xs text-slate-600 space-y-1.5">
            {items.map((item) => (
              <li key={item} className="flex items-center gap-2">
                <span className="w-1 h-1 rounded-full bg-blue-500 shrink-0" />
                {item}
              </li>
            ))}
          </ul>
        </div>
      </button>
    </SocCard>
  );
}

export default function IntelligencePhaseCards({
  data,
  bundle,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle | null;
}) {
  const { openLedger } = useInvestigationUI();
  const staticCount = bundle?.counts.staticFindings ?? 0;
  const runtimeCount = bundle?.counts.runtimeBehaviors ?? 0;
  const frs = data.frs_breakdown;
  const staticProgress = Math.min(100, staticCount > 0 ? 40 + staticCount * 4 : 25);
  const dynamicProgress = frs?.dynamic_ran
    ? frs.dynamic_conclusive
      ? Math.min(100, 50 + runtimeCount * 5)
      : 35
    : 0;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      <PhaseCard
        title="Static Intelligence"
        term="Code Inspection"
        description="Inspects application files without executing the APK."
        icon={<FileCode2 className="h-5 w-5" />}
        progress={staticProgress}
        findingsLabel={`${staticCount} findings`}
        items={[
          'Permissions & manifest',
          'Hardcoded URLs & certificates',
          'Banking target references',
          'Dangerous API usage',
        ]}
        onOpen={() => openLedger('stei')}
      />
      <PhaseCard
        title="Dynamic Intelligence"
        term="Dynamic Analysis"
        description="Executes the application inside a secure sandbox and observes behaviour."
        icon={<PlayCircle className="h-5 w-5" />}
        progress={dynamicProgress}
        findingsLabel={
          frs?.dynamic_ran
            ? `${runtimeCount} runtime behaviours`
            : 'Sandbox not run'
        }
        items={[
          'Network traffic',
          'Runtime APIs & UI interaction',
          'SMS-related events',
          'Accessibility & Frida signals',
        ]}
        onOpen={() => openLedger('dynamic')}
      />
    </div>
  );
}
