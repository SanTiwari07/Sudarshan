import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { buildTechnicalFindingViewModel } from '../../lib/buildTechnicalFindingViewModel';
import { COLORS } from '../../theme/colors';
import FindingDrawerShell, { FindingSection } from './FindingDrawerShell';

export default function FindingExplanationDrawer({
  data,
  bundle,
  rawRuntime,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle | null;
  rawRuntime: Record<string, unknown>[];
}) {
  const { explanationFindingId, closeFindingExplanation } = useInvestigationUI();

  if (!explanationFindingId) return null;

  const vm = buildTechnicalFindingViewModel(explanationFindingId, data, bundle, rawRuntime);
  const sevClass = COLORS.severity[vm.severity] || COLORS.severity.info;

  const sec = vm.sections || {};

  return (
    <FindingDrawerShell
      open
      onClose={closeFindingExplanation}
      title={vm.title}
      subtitle={vm.summary}
      headerExtra={
        <div className="flex flex-wrap items-center gap-2 mt-2">
          <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${sevClass}`}>
            {vm.severityLabel}
          </span>
          {vm.confidencePercent != null && (
            <span className="text-[10px] text-slate-600">
              Confidence <span className="font-bold tabular-nums">{vm.confidencePercent}%</span>
            </span>
          )}
        </div>
      }
    >
      <FindingSection label="What it is">{sec.whatItIs}</FindingSection>
      <FindingSection label="Why it matters">{sec.whyItMatters}</FindingSection>

      <FindingSection label="What Sudarshan detected">
        {(sec.whatDetected?.length ?? 0) > 0 ? (
          <ul className="list-disc pl-4 space-y-1">
            {(sec.whatDetected ?? []).map((line: string) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        ) : (
          <p className="text-slate-500 italic">No mapped observations for this sample.</p>
        )}
        {(sec.evidenceCount ?? 0) > 0 && (
          <p className="text-slate-600 mt-2 tabular-nums">{sec.evidenceCount} supporting observations</p>
        )}
      </FindingSection>

      <FindingSection label="Evidence basis">
        <div className="flex flex-wrap items-center gap-2 mb-2">
          <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded border border-slate-300 bg-slate-50 text-slate-700">
            {sec.evidenceBasisBadge}
          </span>
          <span className="text-slate-600">{sec.evidenceBasisLabel}</span>
        </div>
        {sec.runtimeNote && (
          <p className="text-slate-500 italic mt-1">{sec.runtimeNote}</p>
        )}
      </FindingSection>

      <FindingSection label="What this proves">{sec.whatItProves}</FindingSection>
      <FindingSection label="What this does not prove">{sec.whatItDoesNotProve}</FindingSection>

      <FindingSection label="Risk impact">
        <p className="font-semibold text-slate-900 mb-1">{vm.severityLabel}</p>
        <p>{sec.riskImpact}</p>
      </FindingSection>

      {sec.mitre && (
        <FindingSection label="MITRE ATT&CK">
          <span className="font-mono text-blue-800">{sec.mitre}</span>
        </FindingSection>
      )}

      <FindingSection label="Analyst takeaway">{sec.analystTakeaway}</FindingSection>
    </FindingDrawerShell>
  );
}
