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

  return (
    <FindingDrawerShell
      open
      onClose={closeFindingExplanation}
      title={vm.title}
      subtitle={vm.subtitle}
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
      <FindingSection label="What it is">{vm.sections.whatItIs}</FindingSection>
      <FindingSection label="Why it matters">{vm.sections.whyItMatters}</FindingSection>

      <FindingSection label="What Sudarshan detected">
        {vm.sections.whatDetected.length > 0 ? (
          <ul className="list-disc pl-4 space-y-1">
            {vm.sections.whatDetected.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        ) : (
          <p className="text-slate-500 italic">No mapped observations for this sample.</p>
        )}
        {vm.sections.evidenceCount > 0 && (
          <p className="text-slate-600 mt-2 tabular-nums">{vm.sections.evidenceCount} supporting observations</p>
        )}
      </FindingSection>

      <FindingSection label="Evidence basis">
        <div className="flex flex-wrap items-center gap-2 mb-2">
          <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded border border-slate-300 bg-slate-50 text-slate-700">
            {vm.sections.evidenceBasisBadge}
          </span>
          <span className="text-slate-600">{vm.sections.evidenceBasisLabel}</span>
        </div>
        {vm.sections.runtimeNote && (
          <p className="text-slate-500 italic mt-1">{vm.sections.runtimeNote}</p>
        )}
      </FindingSection>

      <FindingSection label="What this proves">{vm.sections.whatItProves}</FindingSection>
      <FindingSection label="What this does not prove">{vm.sections.whatItDoesNotProve}</FindingSection>

      <FindingSection label="Risk impact">
        <p className="font-semibold text-slate-900 mb-1">{vm.severityLabel}</p>
        <p>{vm.sections.riskImpact}</p>
      </FindingSection>

      {vm.sections.mitre && (
        <FindingSection label="MITRE ATT&CK">
          <span className="font-mono text-blue-800">{vm.sections.mitre}</span>
        </FindingSection>
      )}

      <FindingSection label="Analyst takeaway">{vm.sections.analystTakeaway}</FindingSection>
    </FindingDrawerShell>
  );
}
