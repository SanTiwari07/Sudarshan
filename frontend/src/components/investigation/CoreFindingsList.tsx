import type { FraudCardData } from '../../types/case';
import type { InvestigationBundle } from '../../types/investigation';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { mapFindingEvidence } from '../../lib/findingEvidenceMapper';
import { TYPOGRAPHY } from '../../theme/typography';
import {
  isFindingDetected,
  SEVERITY_DISPLAY,
  visibleFindingDefinitions,
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
  void bundle;

  const definitions = visibleFindingDefinitions(data);
  const detected = definitions.filter((d: any) => isFindingDetected(d.id, data));
  const clear = definitions.filter((d: any) => !isFindingDetected(d.id, data));

  const evidenceCount = (id: any) => {
    const ev = mapFindingEvidence(id, data, bundle);
    return Array.isArray(ev) ? ev.length : 1;
  };

  return (
    <SocCard>
      <SectionHeader
        icon={<AlertTriangle className="h-4 w-4" />}
        title="Technical Findings"
        subtitle="Key fraud techniques with one-line explanations for non-security stakeholders."
      />
      <div className="p-5 sm:p-6 space-y-3">
        {detected.length === 0 && (
          <div className="text-center py-8 px-4 rounded-xl border border-dashed border-slate-200 bg-white">
            <p className={TYPOGRAPHY.body}>No high-priority fraud patterns were flagged on this case.</p>
            <p className={`${TYPOGRAPHY.caption} mt-2`}>Review verified evidence and threat indicators before clearing.</p>
          </div>
        )}
        {detected.map((row: any) => {
          const count = evidenceCount(row.id);
          const sevClass = (COLORS.severity as Record<string, string>)[row.severity] || COLORS.severity.info;
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
                  <h3 className={`${TYPOGRAPHY.h3} inline-flex items-center gap-1`}>
                    {row.title}
                    <ExplainFindingButton findingId={row.id} />
                  </h3>
                  <span className={`${TYPOGRAPHY.badge} ${sevClass}`}>
                    {SEVERITY_DISPLAY[row.severity] || 'Risk'}
                  </span>
                </div>
                <p className={TYPOGRAPHY.bodySmall}>{row.summary}</p>
              </div>
              <button
                type="button"
                onClick={() => openFindingEvidence(row.id)}
                className={`${TYPOGRAPHY.linkAction} mt-3`}
              >
                Verified evidence · {count} observation{count === 1 ? '' : 's'}
              </button>
            </div>
          );
        })}
        {clear.length > 0 && detected.length > 0 && (
          <div className="pt-2 border-t border-slate-100">
            <div className={`${TYPOGRAPHY.label} mb-2`}>Not detected</div>
            <div className="flex flex-wrap gap-2">
              {clear.map((row: any) => (
                <button
                  key={row.id}
                  type="button"
                  onClick={() => openFindingExplanation(row.id)}
                  className={`${TYPOGRAPHY.buttonSm} bg-slate-50 border border-slate-200 text-slate-600 hover:bg-slate-100`}
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
