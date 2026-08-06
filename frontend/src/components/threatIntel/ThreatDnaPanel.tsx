import { Dna } from 'lucide-react';
import type { DnaTrait } from '../../lib/threatIntelModel';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { IntelCard, IntelCardBody, IntelSectionHeader } from './IntelCard';
import { INTEL, INTEL_THEME } from './intelTokens';
import IntelBadge, { toneFromPercent } from './IntelBadge';

export default function ThreatDnaPanel({ traits }: { traits: DnaTrait[] }) {
  const { openEvidence } = useInvestigationUI();
  const top = traits.slice(0, 9);

  return (
    <IntelCard>
      <IntelSectionHeader
        icon={<Dna className="h-4 w-4" />}
        title="Threat DNA"
        subtitle="Behavioural fingerprint derived from static and runtime evidence"
      />
      <IntelCardBody>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-4">
          {top.map((t) => (
            <div
              key={t.label}
              className="group rounded-lg border border-transparent hover:border-slate-200 hover:bg-slate-50/50 px-2 py-2 -mx-2 transition-colors"
            >
              <div className="flex justify-between items-center gap-2 mb-2">
                <span className="text-xs font-semibold text-slate-800">{t.label}</span>
                <IntelBadge tone={toneFromPercent(t.percent)}>{t.percent}%</IntelBadge>
              </div>
              <div className="h-2.5 bg-blue-100 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full ${INTEL_THEME.barGradient} transition-all duration-700 ease-out opacity-90 group-hover:opacity-100`}
                  style={{ width: `${Math.min(100, t.percent)}%` }}
                />
              </div>
              <p className={`${INTEL.caption} mt-2`}>{t.rationale}</p>
              {t.evidenceIds.length > 0 && (
                <div className="flex gap-2 mt-2 flex-wrap">
                  {t.evidenceIds.map((id) => (
                    <button
                      key={id}
                      type="button"
                      onClick={() => openEvidence(id)}
                      className="text-[10px] font-medium text-blue-700 hover:text-blue-900 hover:underline"
                    >
                      View evidence · {id}
                    </button>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </IntelCardBody>
    </IntelCard>
  );
}
