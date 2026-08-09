import { Link } from 'react-router-dom';
import {
  buildEvidenceConfidence,
  buildOverallAssessmentParagraphs,
  buildRecommendedNextSteps,
  buildWhyThisMattersParagraphs,
} from '../../lib/executiveIntelligence';
import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import SocCard from '../ui/Card';
import { Brain, MessageSquare, Shield, Sparkles } from 'lucide-react';

function ConfidenceBar({ label, percent, detail }: { label: string; percent: number; detail: string }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-slate-50/60 px-3 py-2.5">
      <div className="flex items-center justify-between gap-2 mb-1.5">
        <span className="text-xs font-semibold text-slate-800">{label}</span>
        <span className="text-xs font-mono font-bold text-blue-700">{percent}%</span>
      </div>
      <div className="h-1.5 bg-slate-200 rounded-full overflow-hidden">
        <div
          className="h-full bg-blue-600 rounded-full transition-all duration-700"
          style={{ width: `${Math.min(100, percent)}%` }}
        />
      </div>
      <p className="text-[10px] text-slate-500 mt-1.5">{detail}</p>
    </div>
  );
}

export default function ExecutiveIntelligenceOverview({
  data,
  bundle,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle | null;
}) {
  const assessment = buildOverallAssessmentParagraphs(data);
  const why = buildWhyThisMattersParagraphs(data);
  const confidence = buildEvidenceConfidence(data, bundle);
  const steps = buildRecommendedNextSteps(data);

  const analystFlags: string[] = [];
  const frs = data.frs_breakdown;
  if (frs?.concealed_payload) analystFlags.push('Concealed payload detected in static analysis');
  if (frs?.dynamic_ran && !frs.dynamic_conclusive) {
    analystFlags.push('Runtime inconclusive - sandbox evidence not used in final score');
  }
  if (frs?.verdict_floored_for_visibility) analystFlags.push('Verdict floored for analyst visibility');
  if (frs?.axes_excluded?.length) analystFlags.push(`Excluded axes: ${frs.axes_excluded.join(', ')}`);

  return (
    <SocCard className="upload-fade-in overflow-hidden">
      <div className="px-5 sm:px-6 py-4 border-b border-slate-200 bg-gradient-to-r from-blue-50 via-white to-slate-50">
        <div className="flex items-center gap-3">
          <span className="p-2 rounded-xl bg-blue-100 text-blue-700 border border-blue-200 shrink-0">
            <Brain className="h-5 w-5" />
          </span>
          <div>
            <h2 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">Intelligent Overview</h2>
            <p className="text-[11px] text-slate-500 mt-0.5">
              Evidence-grounded synthesis from static, runtime, threat correlation, and risk engine - no speculative
              claims.
            </p>
          </div>
        </div>
      </div>

      <div className="p-5 sm:p-6 space-y-8">
        {analystFlags.length > 0 && (
          <div className="rounded-lg border border-amber-200/80 bg-amber-50/80 px-4 py-3 text-xs text-amber-950">
            <div className="font-bold uppercase tracking-wide text-[10px] text-amber-800 mb-1">Analyst notes</div>
            <ul className="list-disc pl-4 space-y-0.5">
              {analystFlags.map((f) => (
                <li key={f}>{f}</li>
              ))}
            </ul>
          </div>
        )}

        <section className="space-y-3">
          <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-blue-600" />
            Overall Assessment
          </h3>
          {assessment.map((para, i) => (
            <p key={i} className="text-sm text-slate-700 leading-relaxed max-w-4xl">
              {para}
            </p>
          ))}
        </section>

        <section className="space-y-3 rounded-xl border border-slate-200 bg-slate-50/50 p-4 sm:p-5">
          <h3 className="text-sm font-bold text-slate-900">Why this matters</h3>
          {why.map((para, i) => (
            <p key={i} className="text-sm text-slate-700 leading-relaxed">
              {para}
            </p>
          ))}
        </section>

        <section className="space-y-3">
          <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
            <Shield className="h-4 w-4 text-blue-600" />
            Evidence Confidence
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {confidence.map((row) => (
              <ConfidenceBar key={row.label} label={row.label} percent={row.percent} detail={row.detail} />
            ))}
          </div>
        </section>

        <section className="space-y-3">
          <h3 className="text-sm font-bold text-slate-900">Recommended Next Steps</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
            {steps.map((step, i) => (
              <div
                key={`${step.title}-${i}`}
                className="rounded-xl border border-slate-200 bg-white p-4 hover:border-blue-200 hover:shadow-sm transition-all"
              >
                <div className="text-xs font-bold text-blue-800 uppercase tracking-wide">{step.title}</div>
                <p className="text-xs text-slate-600 mt-2 leading-relaxed">{step.description}</p>
              </div>
            ))}
          </div>
        </section>

        <div className="border-t border-slate-200 pt-6 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <p className="text-sm font-semibold text-slate-900">Still have questions?</p>
            <p className="text-xs text-slate-500 mt-1">
              Ask the AI Investigation Assistant anything about this APK - answers stay grounded in case evidence.
            </p>
          </div>
          <Link
            to={`/chat?q=${encodeURIComponent('Explain this APK in more detail')}`}
            className="inline-flex items-center justify-center gap-2 px-4 py-2.5 text-xs font-semibold text-white bg-blue-700 rounded-lg hover:bg-blue-800 transition-colors shrink-0"
          >
            <MessageSquare className="h-4 w-4" />
            Open AI Investigation Assistant
          </Link>
        </div>
      </div>
    </SocCard>
  );
}
