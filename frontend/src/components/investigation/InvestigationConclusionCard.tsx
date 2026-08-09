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
    <SocCard className="upload-fade-in overflow-hidden">
      <div className="px-5 sm:px-6 py-4 border-b border-slate-200 bg-gradient-to-r from-slate-50 via-white to-slate-50">
        <div className="flex items-center gap-3">
          <span className="p-2 rounded-xl bg-blue-100 text-blue-700 border border-blue-200 shrink-0">
            <Brain className="h-5 w-5" />
          </span>
          <div>
            <h2 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">Intelligent Overview</h2>
            <p className="text-[11px] text-slate-500 mt-0.5">Investigation conclusion - grounded in case evidence only</p>
          </div>
        </div>
      </div>

      <div className="p-5 sm:p-6 space-y-6">
        <section>
          <p className="text-[10px] font-bold uppercase tracking-wide text-slate-500">Investigation conclusion</p>
          <p className="text-lg font-semibold text-slate-900 mt-1">{model.verdictLabel}</p>
          <p className="text-sm text-slate-700 mt-2 leading-relaxed max-w-3xl">{model.headline}</p>
        </section>

        {model.pillars.length > 0 && (
          <section className="space-y-4">
            <h3 className="text-sm font-bold text-slate-900">Why we believe this</h3>
            <ol className="space-y-4">
              {model.pillars.map((pillar, index) => {
                const evidenceIds = filterPillarEvidenceIds(pillar, bundle);
                return (
                  <li key={pillar.id} className="flex gap-3">
                    <span className="text-xs font-mono font-bold text-slate-400 pt-0.5 w-6 shrink-0">
                      {String(index + 1).padStart(2, '0')}
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-semibold text-slate-900">{pillar.title}</p>
                      <p className="text-sm text-slate-600 mt-1 leading-relaxed">{pillar.detail}</p>
                      {evidenceIds.length > 0 && (
                        <div className="flex flex-wrap gap-2 mt-2">
                          {evidenceIds.map((id) => (
                            <button
                              key={id}
                              type="button"
                              onClick={() => openEvidence(id)}
                              className="text-[10px] font-mono font-bold px-2 py-1 rounded-md bg-blue-50 text-blue-800 border border-blue-200 hover:bg-blue-100"
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

        <section className="rounded-xl border border-slate-200 bg-slate-50/60 p-4">
          <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
            <Shield className="h-4 w-4 text-blue-600" />
            Confidence
          </h3>
          <p className="text-sm font-semibold text-slate-800 mt-2">{model.confidenceLabel}</p>
          <p className="text-sm text-slate-600 mt-1 leading-relaxed">{model.confidenceDetail}</p>
        </section>

        {model.limitations.length > 0 && (
          <section className="rounded-xl border border-amber-200/80 bg-amber-50/70 p-4">
            <h3 className="text-sm font-bold text-amber-950 flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" />
              Investigation limitations
            </h3>
            <ul className="mt-2 space-y-1.5 text-sm text-amber-950/90 list-disc pl-5">
              {model.limitations.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          </section>
        )}

        <section>
          <h3 className="text-sm font-bold text-slate-900">Recommended action</h3>
          <p className="text-sm text-slate-700 mt-2 leading-relaxed">{model.recommendedAction}</p>
        </section>

        <div className="flex flex-wrap gap-3 pt-2 border-t border-slate-100">
          <Link
            to="/technical"
            className="text-xs font-semibold text-blue-700 hover:underline"
          >
            Inspect live analysis →
          </Link>
          <Link
            to="/threat-intel"
            className="text-xs font-semibold text-blue-700 hover:underline"
          >
            View threat intelligence →
          </Link>
          <Link
            to="/technical"
            className="text-xs font-semibold text-blue-700 hover:underline"
          >
            Browse technical evidence →
          </Link>
        </div>
      </div>
    </SocCard>
  );
}
