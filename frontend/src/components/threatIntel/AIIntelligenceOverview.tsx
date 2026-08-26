import type { ReactNode } from 'react';
import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import type { AnalystAction, IntelApiPayload } from '../../lib/threatIntelModel';
import {
  buildEvidenceSourceChips,
  buildRecommendedActionBullets,
  buildThreatIntelExecutiveNarrative,
  buildWhatWasDiscovered,
  buildWhySudarshanConcluded,
  qualitativeConfidence,
} from '../../lib/threatIntelOverview';
import { SearchX, BadgeCheck, BrainCircuit, ClipboardCheck, ShieldAlert, Sparkles } from 'lucide-react';
import { isInconclusive } from '../../lib/decision';

function InsightBlock({
  icon,
  title,
  items,
}: {
  icon: ReactNode;
  title: string;
  items: string[];
}) {
  return (
    <div className="rounded-xl border border-slate-200/70 bg-white/80 p-5 sm:p-6 transition-shadow duration-200 hover:shadow-md hover:border-blue-200/50">
      <div className="flex items-center gap-2.5 mb-4">
        <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-slate-50 text-blue-700 border border-slate-100">
          {icon}
        </span>
        <h3 className="text-sm font-semibold text-slate-900 tracking-tight">{title}</h3>
      </div>
      <ul className="space-y-2.5">
        {items.map((item) => (
          <li key={item} className="text-sm text-slate-600 leading-relaxed pl-0 flex gap-2">
            <span className="text-slate-300 select-none" aria-hidden> - </span>
            <span>{item}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function AIIntelligenceOverview({
  data,
  intel,
  bundle,
  evidenceConfidence,
  actions,
}: {
  data: FraudCardData;
  intel: IntelApiPayload;
  bundle: InvestigationBundle | null;
  evidenceConfidence: number;
  actions: AnalystAction[];
}) {
  const inconclusive = isInconclusive(data);
  const narrative = buildThreatIntelExecutiveNarrative(data, intel, bundle, evidenceConfidence);
  const discovered = buildWhatWasDiscovered(data, intel);
  const why = buildWhySudarshanConcluded(data, intel, bundle);
  const recommended = buildRecommendedActionBullets(data, intel, actions);
  const chips = buildEvidenceSourceChips(data, intel, bundle);
  const confLabel = qualitativeConfidence(evidenceConfidence);
  const frs = data.frs_breakdown;
  const family =
    intel.malware_family && intel.malware_family !== 'Unknown'
      ? intel.malware_family
      : data.family_classification !== 'Unknown'
        ? data.family_classification
        : null;
  const runtimeLabel = frs?.dynamic_conclusive
    ? 'Included in score'
    : frs?.dynamic_ran
      ? 'Inconclusive - excluded'
      : 'Not run';

  return (
    <section
      className="rounded-2xl border border-blue-200/50 bg-gradient-to-br from-white via-white to-blue-50/40 shadow-sm overflow-hidden transition-shadow duration-200 hover:shadow-md"
      aria-labelledby="ai-intel-overview-title"
    >
      <div className="px-5 sm:px-8 pt-6 sm:pt-8 pb-4">
        <div className="flex items-start gap-3 min-w-0">
          <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-blue-50 text-blue-700 border border-blue-100">
            <Sparkles className="h-5 w-5" aria-hidden />
          </span>
          <div className="min-w-0">
            <h2 id="ai-intel-overview-title" className="text-xl sm:text-2xl font-semibold text-slate-900 tracking-tight">
              AI Intelligence Overview
            </h2>
            <p className="text-sm text-slate-500 mt-1 leading-relaxed">
              Analyst-style briefing synthesized from verified pipeline outputs.
            </p>
          </div>
        </div>
      </div>

      <div className="px-5 sm:px-8 pb-6 sm:pb-8 grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_minmax(220px,280px)] gap-6 lg:gap-8 items-start">
        <p className="text-base sm:text-[1.05rem] text-slate-700 leading-[1.75] min-w-0">
          {narrative}
        </p>

        <aside
          className="rounded-xl border border-slate-200/80 bg-white/90 shadow-sm p-4 sm:p-5 space-y-4 lg:sticky lg:top-4"
          aria-label="Briefing snapshot"
        >
          {/*
            This badge was unconditional - every case, however inconclusive its
            run, was crowned "Evidence verified" in green. It now reports what
            the analysis actually earned.
          */}
          {inconclusive ? (
            <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-slate-300 bg-slate-50 text-slate-700 text-xs font-semibold w-full justify-center sm:justify-start">
              <SearchX className="h-3.5 w-3.5 shrink-0" aria-hidden />
              Coverage incomplete
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-emerald-200 bg-emerald-50 text-emerald-800 text-xs font-semibold w-full justify-center sm:justify-start">
              <BadgeCheck className="h-3.5 w-3.5 shrink-0" aria-hidden />
              Evidence verified
            </span>
          )}

          <dl className="space-y-3 text-sm">
            <div>
              <dt className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                Evidence confidence
              </dt>
              <dd className="mt-0.5 font-semibold text-slate-900">
                {Math.round(evidenceConfidence)}%
                <span className="text-slate-500 font-normal"> · {confLabel}</span>
              </dd>
            </div>
            {family && (
              <div>
                <dt className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                  Malware family
                </dt>
                <dd className="mt-0.5 font-medium text-slate-800 leading-snug">{family}</dd>
              </div>
            )}
            <div>
              <dt className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                Runtime behaviour
              </dt>
              <dd className="mt-0.5 text-slate-700 leading-snug">{runtimeLabel}</dd>
            </div>
          </dl>
        </aside>
      </div>

      <div className="border-t border-slate-200/80 mx-5 sm:mx-8" />

      <div className="px-5 sm:px-8 py-8 grid grid-cols-1 lg:grid-cols-3 gap-4 sm:gap-5">
        <InsightBlock
          icon={<ShieldAlert className="h-4 w-4" aria-hidden />}
          title="What was discovered"
          items={discovered}
        />
        <InsightBlock
          icon={<BrainCircuit className="h-4 w-4" aria-hidden />}
          title="Why Sudarshan reached this conclusion"
          items={why}
        />
        <InsightBlock
          icon={<ClipboardCheck className="h-4 w-4" aria-hidden />}
          title="Recommended analyst action"
          items={recommended}
        />
      </div>

      <div className="border-t border-slate-200/80 bg-slate-50/50 px-5 sm:px-8 py-5 sm:py-6">
        <p className="text-xs font-semibold text-slate-500 tracking-wide mb-3">Evidence sources used</p>
        <div className="flex flex-wrap gap-2">
          {chips
            .filter((c) => c.active)
            .map((chip) => (
              <span
                key={chip.id}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium bg-white border border-slate-200 text-slate-700 shadow-sm"
              >
                <span className="text-emerald-600" aria-hidden>
                  ✓
                </span>
                {chip.label}
              </span>
            ))}
        </div>
      </div>
    </section>
  );
}
