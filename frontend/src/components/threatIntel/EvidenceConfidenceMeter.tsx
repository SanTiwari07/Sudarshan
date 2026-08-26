import { Gauge } from 'lucide-react';
import type { ConfidenceSource } from '../../lib/threatIntelModel';
import { IntelCard, IntelCardBody, IntelSectionHeader } from './IntelCard';
import { INTEL, INTEL_THEME } from './intelTokens';

export default function EvidenceConfidenceMeter({
  sources,
  overall,
}: {
  sources: ConfidenceSource[];
  overall: number;
}) {
  return (
    <IntelCard>
      <IntelSectionHeader
        icon={<Gauge className="h-4 w-4" />}
        title="Evidence confidence"
        subtitle="Weighted by available analysis planes"
      />
      <IntelCardBody>
        <div className="flex flex-col lg:flex-row gap-8">
        <div className="flex flex-col items-center justify-center lg:w-40 shrink-0">
          <div className="relative w-28 h-28">
            <svg className="w-full h-full -rotate-90" viewBox="0 0 36 36">
              <path
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                fill="none"
                stroke="#e2e8f0"
                strokeWidth="3"
              />
              <path
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                fill="none"
                stroke={INTEL_THEME.ringStroke}
                strokeWidth="3"
                strokeDasharray={`${overall}, 100`}
                className="transition-all duration-700"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-2xl font-semibold text-blue-800 tabular-nums">{overall}%</span>
              <span className="text-[11px] uppercase text-slate-500">Overall</span>
            </div>
          </div>
        </div>
        <div className="flex-1 space-y-3">
          {sources.map((s) => (
            <div key={s.label}>
              <div className="flex justify-between text-xs mb-1">
                <span className="font-semibold text-slate-800">{s.label}</span>
                <span className="font-mono text-slate-600">
                  {s.percent != null ? `${s.percent}%` : 'Unavailable'}
                </span>
              </div>
              <div className="h-1.5 bg-slate-100 rounded-full overflow-hidden">
                {s.percent != null ? (
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${
                      s.status === 'ok' ? INTEL_THEME.bar : s.status === 'partial' ? 'bg-amber-500' : 'bg-slate-300'
                    }`}
                    style={{ width: `${s.percent}%` }}
                  />
                ) : (
                  <div className="h-full w-full bg-slate-200" />
                )}
              </div>
              <p className={`${INTEL.caption} mt-1`}>{s.detail}</p>
            </div>
          ))}
        </div>
      </div>
      </IntelCardBody>
    </IntelCard>
  );
}
