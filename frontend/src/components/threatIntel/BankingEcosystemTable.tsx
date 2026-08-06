import { Landmark } from 'lucide-react';
import type { BankingRow } from '../../lib/threatIntelModel';
import { IntelCard, IntelSectionHeader } from './IntelCard';
import IntelBadge, { type IntelBadgeTone } from './IntelBadge';

const STATUS_TONE: Record<BankingRow['status'], { label: string; tone: IntelBadgeTone }> = {
  detected: { label: 'Detected', tone: 'critical' },
  possible: { label: 'Possible', tone: 'medium' },
  unknown: { label: 'Unknown', tone: 'neutral' },
  not_targeted: { label: 'Not targeted', tone: 'safe' },
};

export default function BankingEcosystemTable({ rows }: { rows: BankingRow[] }) {
  return (
    <IntelCard>
      <IntelSectionHeader
        icon={<Landmark className="h-4 w-4" />}
        title="Targeted banking ecosystem"
        subtitle="India-focused wallet and bank corpus matching"
      />
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead className="bg-slate-50 text-[10px] uppercase tracking-wide text-slate-600 border-b border-slate-200">
            <tr>
              <th className="text-left px-6 py-3">Institution</th>
              <th className="text-left px-6 py-3">Status</th>
              <th className="text-right px-6 py-3">Evidence count</th>
              <th className="text-left px-6 py-3">Rationale</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {rows.map((row) => {
              const st = STATUS_TONE[row.status];
              return (
                <tr key={row.id} className="hover:bg-slate-50/80 transition-colors">
                  <td className="px-6 py-3 font-semibold text-slate-900">{row.label}</td>
                  <td className="px-6 py-3">
                    <IntelBadge tone={st.tone}>{st.label}</IntelBadge>
                  </td>
                  <td className="px-6 py-3 text-right font-mono tabular-nums">{row.evidenceCount}</td>
                  <td className="px-6 py-3 text-slate-600 max-w-md">{row.evidenceHint}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </IntelCard>
  );
}
