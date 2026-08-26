import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { buildTechnicalFindingViewModel } from '../../lib/buildTechnicalFindingViewModel';
import {
  evidenceBasisBadge,
  formatEvidenceCardInterpretation,
  summarizeEvidenceForDrawer,
} from '../../lib/findingEvidenceMapper';
import { useAnalysis } from '../../context/AnalysisContext';
import { illustratedByFinding } from '../../lib/visualEvidence';
import VisualEvidenceCard from './VisualEvidenceCard';
import FindingDrawerShell, { FindingSection } from './FindingDrawerShell';

export default function FindingEvidenceDrawer({
  data,
  bundle,
  rawRuntime,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle | null;
  rawRuntime: Record<string, unknown>[];
}) {
  const { findingEvidenceId, closeFindingEvidence, openEvidence } = useInvestigationUI();
  const { screenshotManifestEntries } = useAnalysis();

  if (!findingEvidenceId) return null;

  const vm = buildTechnicalFindingViewModel(findingEvidenceId, data, bundle, rawRuntime);
  const illustrated = illustratedByFinding(findingEvidenceId, screenshotManifestEntries);

  return (
    <FindingDrawerShell
      open
      onClose={closeFindingEvidence}
      title={vm.title}
      subtitle={`${vm.sections?.evidenceCount ?? 0} observation${(vm.sections?.evidenceCount ?? 0) === 1 ? '' : 's'}`}
      headerExtra={
        vm.sections?.evidenceBasis && vm.sections.evidenceBasis !== 'none' ? (
          <span className="inline-block mt-2 text-[12px] font-bold uppercase px-2 py-0.5 rounded border border-slate-300 bg-slate-50 text-slate-700">
            {evidenceBasisBadge(vm.sections.evidenceBasis || '')}
          </span>
        ) : null
      }
    >
      <FindingSection label="Summary">{summarizeEvidenceForDrawer(vm.evidence || [])}</FindingSection>

      {Array.isArray(illustrated) && illustrated.length > 0 && (
        <FindingSection label="Visual evidence">
          <div className="space-y-2">
            {(illustrated as any[]).map((entry: any) => (
              <VisualEvidenceCard key={entry.screenshot_id || entry.id} sha256={data.sha256} entry={entry} />
            ))}
          </div>
          <p className="text-[13px] text-slate-500 mt-2">
            Illustrated by: {(illustrated as any[]).map((e: any) => e.screenshot_id || e.id).join(', ')}
          </p>
        </FindingSection>
      )}

      {(!vm.evidence || vm.evidence.length === 0) ? (
        <p className="text-sm text-slate-500 py-4">No supporting evidence records are currently available.</p>
      ) : (
        <div className="space-y-3">
          {vm.evidence.map((item: any, index: number) => (
            <div
              key={`${item.id}-${index}`}
              className="rounded-xl border border-slate-200 p-4 bg-white space-y-2"
            >
              <div className="flex flex-wrap items-start justify-between gap-2">
                <p className="text-sm font-semibold text-slate-900">{item.title}</p>
                <span
                  className={`text-[11px] font-bold uppercase px-1.5 py-0.5 rounded border ${
                    item.category === 'dynamic'
                      ? 'bg-violet-50 text-violet-800 border-violet-200'
                      : 'bg-slate-100 text-slate-700 border-slate-200'
                  }`}
                >
                  {item.category === 'dynamic' ? 'Dynamic' : 'Static'}
                </span>
              </div>
              <dl className="grid grid-cols-2 gap-x-3 gap-y-1 text-[13px]">
                <div>
                  <dt className="text-slate-500">Source</dt>
                  <dd className="text-slate-800">{item.source}</dd>
                </div>
                {item.confidence != null && (
                  <div>
                    <dt className="text-slate-500">Confidence</dt>
                    <dd className="text-slate-800 tabular-nums">{item.confidence}%</dd>
                  </div>
                )}
                {item.timestampMs != null && (
                  <div className="col-span-2">
                    <dt className="text-slate-500">Timestamp</dt>
                    <dd className="text-slate-800 font-mono text-[12px]">{item.timestampMs}</dd>
                  </div>
                )}
              </dl>
              {item.rawDescription && (
                <p className="text-[13px] font-mono text-slate-600 break-words bg-white border border-slate-100 rounded p-2">
                  {item.rawDescription}
                </p>
              )}
              <div>
                <p className="text-[12px] font-semibold uppercase text-slate-500 mb-1">Explanation</p>
                <p className="text-xs text-slate-700 leading-relaxed">{formatEvidenceCardInterpretation(item)}</p>
              </div>
              {item.evidence && (
                <button
                  type="button"
                  onClick={() => openEvidence(item.evidence!.id)}
                  className="text-[13px] font-semibold text-blue-700 hover:underline"
                >
                  Open raw evidence record
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </FindingDrawerShell>
  );
}
