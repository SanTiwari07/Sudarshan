import type { ReactNode } from 'react';
import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import {
  buildKeyObservations,
  buildOverallAssessment,
  buildPotentialFraudImpact,
  buildRecommendedAnalystActions,
} from '../../lib/intelligentOverview';
import {
  AlertTriangle,
  ClipboardList,
  ListChecks,
  ScanSearch,
  Sparkles,
} from 'lucide-react';

function SectionBlock({
  icon,
  title,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  children: ReactNode;
}) {
  return (
    <div className="py-4 first:pt-0 last:pb-0">
      <div className="flex items-center gap-2 mb-2">
        <span className="text-slate-500">{icon}</span>
        <h3 className="text-sm font-semibold text-slate-900">{title}</h3>
      </div>
      {children}
    </div>
  );
}

export default function IntelligentOverview({
  data,
  bundle,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle | null;
}) {
  const assessment = buildOverallAssessment(data, bundle);
  const observations = buildKeyObservations(data, bundle);
  const fraudImpact = buildPotentialFraudImpact(data, bundle);
  const actions = buildRecommendedAnalystActions(data, bundle);

  return (
    <section
      className="rounded-xl border border-slate-200/80 bg-white shadow-sm overflow-hidden"
      aria-labelledby="intelligent-overview-title"
    >
      <div className="px-4 sm:px-5 py-4 border-b border-slate-100">
        <div className="flex items-start gap-3">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-50 text-blue-700 border border-slate-100">
            <Sparkles className="h-4 w-4" aria-hidden />
          </span>
          <div>
            <h2 id="intelligent-overview-title" className="text-base font-semibold text-slate-900 tracking-tight">
              Intelligent Overview
            </h2>
            <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">
              Evidence-backed case summary - derived only from static analysis, runtime analysis, threat correlation,
              and the deterministic risk engine.
            </p>
          </div>
        </div>
      </div>

      <div className="px-4 sm:px-5 divide-y divide-slate-100">
        <SectionBlock icon={<ScanSearch className="h-4 w-4" aria-hidden />} title="Overall assessment">
          <p className="text-sm text-slate-700 leading-relaxed">{assessment}</p>
        </SectionBlock>

        <SectionBlock icon={<ListChecks className="h-4 w-4" aria-hidden />} title="Key observations">
          <ul className="space-y-2">
            {observations.map((obs) => (
              <li key={obs.id} className="flex flex-col sm:flex-row sm:gap-3 text-sm leading-relaxed">
                <span className="text-slate-500 sm:w-44 shrink-0">{obs.label}</span>
                <span className="text-slate-800 font-medium min-w-0 break-words">{obs.value}</span>
              </li>
            ))}
          </ul>
        </SectionBlock>

        <SectionBlock icon={<AlertTriangle className="h-4 w-4" aria-hidden />} title="Potential fraud impact">
          <p className="text-sm text-slate-700 leading-relaxed">{fraudImpact}</p>
        </SectionBlock>

        <SectionBlock icon={<ClipboardList className="h-4 w-4" aria-hidden />} title="Recommended analyst actions">
          <ol className="space-y-2 list-decimal list-inside text-sm text-slate-700 leading-relaxed marker:text-slate-500">
            {actions.map((action, i) => (
              <li key={i} className="pl-0.5">
                {action}
              </li>
            ))}
          </ol>
        </SectionBlock>
      </div>
    </section>
  );
}
