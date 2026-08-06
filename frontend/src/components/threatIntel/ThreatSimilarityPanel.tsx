import { Layers } from 'lucide-react';
import type { FamilySimilarity } from '../../lib/threatIntelModel';
import { IntelCard, IntelCardBody, IntelSectionHeader } from './IntelCard';
import { INTEL_THEME } from './intelTokens';

export default function ThreatSimilarityPanel({ items }: { items: FamilySimilarity[] }) {
  if (!items.length) {
    return (
      <IntelCard>
        <IntelSectionHeader
          icon={<Layers className="h-4 w-4" />}
          title="Threat similarity"
          subtitle="Signature overlap vs known families"
        />
        <IntelCardBody>
          <p className="text-xs text-slate-500 text-center py-4">No signature overlap with known family rules.</p>
        </IntelCardBody>
      </IntelCard>
    );
  }

  return (
    <IntelCard>
      <IntelSectionHeader
        icon={<Layers className="h-4 w-4" />}
        title="Threat similarity"
        subtitle="Deterministic rule overlap (not VT labels)"
      />
      <IntelCardBody>
        <div className="space-y-3">
          {items.map((item) => (
            <div
              key={item.family}
              className={`p-3 rounded-lg border transition-colors ${
                item.isAssigned ? 'border-blue-300 bg-blue-50/60' : 'border-slate-200 bg-white hover:border-slate-300'
              }`}
            >
              <div className="flex justify-between items-center text-xs">
                <span className="font-bold text-slate-800">
                  {item.family}
                  {item.isAssigned && (
                    <span className="ml-2 text-[10px] font-semibold text-blue-700 uppercase">Assigned</span>
                  )}
                </span>
                <span className="font-mono font-bold text-blue-800 tabular-nums">{item.percent}%</span>
              </div>
              <div className="h-1.5 bg-blue-100 rounded-full mt-2 overflow-hidden">
                <div className={`h-full ${INTEL_THEME.bar} rounded-full transition-all`} style={{ width: `${item.percent}%` }} />
              </div>
              <ul className="mt-2 space-y-0.5">
                {item.reasons.map((r) => (
                  <li key={r} className="text-[10px] text-slate-600 font-mono">
                    {r}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </IntelCardBody>
    </IntelCard>
  );
}
