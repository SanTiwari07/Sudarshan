import { Link } from 'react-router-dom';
import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import {
  buildInvestigationConclusion,
  filterPillarEvidenceIds,
} from '../../lib/investigationConclusion';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import SocCard from '../ui/Card';
import { AlertTriangle, Brain, Shield } from 'lucide-react';

export default function InvestigationConclusionCard({
  data,
  bundle,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle | null;
}) {
  const { openEvidence } = useInvestigationUI();
  const model = buildInvestigationConclusion(data, bundle);

  return (
    <SocCard className="upload-fade-in overflow-hidden border border-slate-200 rounded-md">
      <div className="px-4 py-3 border-b border-slate-200 bg-white flex items-center gap-2.5">
        <span className="p-1.5 rounded bg-blue-100 text-blue-700 border border-blue-200/80 shrink-0">
          <Brain className="h-4 w-4" />
        </span>
        <div>
          <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900 font-mono">Case Synopsis & Investigation Conclusion</h2>
        </div>
      </div>

      <div className="p-4 sm:p-5 space-y-5">
        <section className="border-l-2 border-slate-900 pl-3">
          <p className="text-[10px] font-bold uppercase tracking-widest text-slate-400 font-mono">Verdict Label</p>
          <p className="text-base font-bold text-slate-900 mt-0.5">{model.verdictLabel}</p>
          <p className="text-xs text-slate-700 mt-1 leading-relaxed max-w-4xl">{model.headline}</p>
        </section>

        {model.pillars.length > 0 && (
          <section className="space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 font-mono">Pillars of Grounded Evidence</h3>
            <ol className="space-y-3">
              {model.pillars.map((pillar, index) => {
                const evidenceIds = filterPillarEvidenceIds(pillar, bundle);
                return (
                  <li key={pillar.id} className="flex gap-2.5 items-start">
                    <span className="text-xs font-mono font-bold text-slate-400 pt-0.5 w-5 shrink-0">
                      {String(index + 1).padStart(2, '0')}.
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="text-xs font-bold text-slate-900">{pillar.title}</p>
                      <p className="text-xs text-slate-600 mt-0.5 leading-relaxed">{pillar.detail}</p>
                      {evidenceIds.length > 0 && (
                        <div className="flex flex-wrap gap-1.5 mt-1.5">
                          {evidenceIds.map((id) => (
                            <button
                              key={id}
                              type="button"
                              onClick={() => openEvidence(id)}
                              className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-blue-50 text-blue-800 border border-blue-100 hover:bg-blue-100/80 transition-colors"
                            >
                              {id}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  </li>
                );
              })}
            </ol>
          </section>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <section className="rounded border border-slate-200 bg-white p-3.5">
            <h3 className="text-xs font-bold text-slate-900 flex items-center gap-1.5 font-mono uppercase tracking-wider">
              <Shield className="h-3.5 w-3.5 text-blue-700" />
              Confidence
            </h3>
            <p className="text-xs font-bold text-slate-800 mt-1.5">{model.confidenceLabel}</p>
            <p className="text-[11px] text-slate-600 mt-1 leading-relaxed">{model.confidenceDetail}</p>
          </section>

          {model.limitations.length > 0 && (
            <section className="rounded border border-amber-200 bg-amber-50/50 p-3.5">
              <h3 className="text-xs font-bold text-amber-950 flex items-center gap-1.5 font-mono uppercase tracking-wider">
                <AlertTriangle className="h-3.5 w-3.5 text-amber-700" />
                Investigation Limitations
              </h3>
              <ul className="mt-1.5 space-y-1 text-[11px] text-amber-900/90 list-disc pl-4 leading-relaxed">
                {model.limitations.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
            </section>
          )}
        </div>

        <section className="bg-white border border-slate-200 rounded p-3.5">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 font-mono mb-1">Recommended Response Strategy</h3>
          <p className="text-xs text-slate-700 leading-relaxed">{model.recommendedAction}</p>
        </section>

        <div className="flex flex-wrap gap-4 pt-3 border-t border-slate-100 text-xs font-mono">
          <Link
            to="/technical"
            className="text-blue-700 font-bold hover:text-blue-800 hover:underline"
          >
            → Inspect Live Analysis
          </Link>
          <Link
            to="/threat-intel"
            className="text-blue-700 font-bold hover:text-blue-800 hover:underline"
          >
            → Threat Intelligence
          </Link>
          <Link
            to="/technical"
            className="text-blue-700 font-bold hover:text-blue-800 hover:underline"
          >
            → Technical Evidence Registry
          </Link>
        </div>
      </div>
    </SocCard>
  );
}
