import { CheckCircle2, XCircle, BarChart3 } from 'lucide-react';
import type { CoverageItem } from '../../lib/threatIntelModel';
import { IntelCard, IntelCardBody, IntelSectionHeader } from './IntelCard';
import { INTEL, INTEL_THEME } from './intelTokens';

export default function AnalysisCoveragePanel({
  percent,
  completed,
  missing,
}: {
  percent: number;
  completed: CoverageItem[];
  missing: CoverageItem[];
}) {
  return (
    <IntelCard>
      <IntelSectionHeader
        icon={<BarChart3 className="h-4 w-4" />}
        title="Analysis coverage"
        subtitle={`${percent}% completed`}
      />
      <IntelCardBody>
        <div className="h-2.5 bg-blue-100 rounded-full overflow-hidden mb-6">
          <div className={`h-full ${INTEL_THEME.bar} rounded-full transition-all duration-700`} style={{ width: `${percent}%` }} />
        </div>
        <div className="grid sm:grid-cols-2 gap-6 text-xs">
          <div>
            <div className={INTEL.caption}>Completed</div>
            <ul className="space-y-2 mt-2">
              {completed.map((c) => (
                <li key={c.label} className="flex items-center gap-2 text-slate-700">
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 shrink-0" />
                  {c.label}
                  {c.detail && <span className="text-slate-400">({c.detail})</span>}
                </li>
              ))}
            </ul>
          </div>
          <div>
            <div className={INTEL.caption}>Missing</div>
            <ul className="space-y-2 mt-2">
              {missing.length ? (
                missing.map((m) => (
                  <li key={m.label} className="flex items-center gap-2 text-slate-600">
                    <XCircle className="h-3.5 w-3.5 text-slate-400 shrink-0" />
                    {m.label}
                    {m.detail && <span className="text-slate-400">— {m.detail}</span>}
                  </li>
                ))
              ) : (
                <li className="text-emerald-700 flex items-center gap-2">
                  <CheckCircle2 className="h-3.5 w-3.5" /> Full pipeline coverage
                </li>
              )}
            </ul>
          </div>
        </div>
      </IntelCardBody>
    </IntelCard>
  );
}
