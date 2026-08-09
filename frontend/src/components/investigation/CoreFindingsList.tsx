import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import { useAnalysis } from '../../context/AnalysisContext';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { mapFindingEvidence } from '../../lib/findingEvidenceMapper';
import {
  isFindingDetected,
  SEVERITY_DISPLAY,
  visibleFindingDefinitions,
  type TechnicalFindingId,
} from '../../lib/technicalFindings';
import ExplainFindingButton from './ExplainFindingButton';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import { AlertTriangle } from 'lucide-react';
import { COLORS } from '../../theme/colors';

export default function CoreFindingsList({
  data,
  bundle,
}: {
  data: FraudCardData;
  bundle?: InvestigationBundle | null;
}) {
  const { openFindingEvidence, openFindingExplanation } = useInvestigationUI();
  const { runtimeEvidenceRaw } = useAnalysis();

  const definitions = visibleFindingDefinitions(data);
  const detected = definitions.filter((d) => isFindingDetected(d.id, data));
  const clear = definitions.filter((d) => !isFindingDetected(d.id, data));

  const evidenceCount = (id: TechnicalFindingId) =>
    mapFindingEvidence(id, data, bundle ?? null, runtimeEvidenceRaw).length;

  return (
    <SocCard>
      <SectionHeader
        icon={<AlertTriangle className="h-4 w-4" />}
        title="Technical Findings"
        subtitle="Key fraud techniques with one-line explanations for non-security stakeholders."
      />
      <div className="p-5 sm:p-6 space-y-3">
        {detected.length === 0 && (
          <div className="text-center py-8 px-4 rounded-xl border border-dashed border-slate-200 bg-slate-50">
            <p className="text-sm text-slate-700">No high-priority fraud patterns were flagged on this case.</p>
            <p className="text-xs text-slate-500 mt-2">Review verified evidence and threat indicators before clearing.</p>
          </div>
        )}
        {detected.map((row) => {
          const count = evidenceCount(row.id);
          const sevClass = COLORS.severity[row.severity] || COLORS.severity.info;
          return (
            <div
              key={row.id}
              className="w-full text-left rounded-xl border border-slate-200 p-4 hover:border-blue-300 hover:bg-blue-50/30 transition-colors"
            >
              <div
                className="cursor-pointer"
                role="button"
                tabIndex={0}
                onClick={() => openFindingExplanation(row.id)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    openFindingExplanation(row.id);
                  }
                }}
              >
                <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                  <h3 className="text-sm font-bold text-slate-900 inline-flex items-center gap-1">
                    {row.title}
                    <ExplainFindingButton findingId={row.id} />
                  </h3>
                  <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${sevClass}`}>
                    {SEVERITY_DISPLAY[row.severity] || 'Risk'}
                  </span>
                </div>
                <p className="text-xs text-slate-600 leading-relaxed">{row.summary}</p>
              </div>
              <button
                type="button"
                onClick={() => openFindingEvidence(row.id)}
                className="text-[11px] text-blue-700 font-semibold mt-3 hover:underline"
              >
                Verified evidence · {count} observation{count === 1 ? '' : 's'}
              </button>
            </div>
          );
        })}
        {clear.length > 0 && detected.length > 0 && (
          <div className="pt-2 border-t border-slate-100">
            <div className="text-[10px] font-bold uppercase text-slate-400 mb-2">Not detected</div>
            <div className="flex flex-wrap gap-2">
              {clear.map((row) => (
                <button
                  key={row.id}
                  type="button"
                  onClick={() => openFindingExplanation(row.id)}
                  className="text-[11px] px-2.5 py-1 rounded-lg bg-slate-50 border border-slate-200 text-slate-600 hover:bg-slate-100"
                >
                  {row.title}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </SocCard>
  );
}
