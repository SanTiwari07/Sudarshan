import type { ThreatScenarioRow } from '../../App';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import { Target } from 'lucide-react';
import { useInvestigationUI } from '../../context/InvestigationUIContext';

export default function ThreatScenarioTable({ rows }: { rows: ThreatScenarioRow[] }) {
  const { openEvidence } = useInvestigationUI();
  if (!rows.length) return null;

  return (
    <SocCard>
      <SectionHeader icon={<Target className="h-4 w-4" />} title="Threat scenario mapping" subtitle={`${rows.length} scenario(s)`} />
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead className="bg-slate-50 text-slate-500 uppercase text-[10px]">
            <tr>
              <th className="px-3 py-2 text-left">Indicator</th>
              <th className="px-3 py-2 text-left">Scenario</th>
              <th className="px-3 py-2">Cred theft</th>
              <th className="px-3 py-2">Confidence</th>
              <th className="px-3 py-2 text-left">Evidence</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row, i) => (
              <tr key={i} className="border-t border-slate-100 hover:bg-slate-50">
                <td className="px-3 py-2 font-medium text-slate-800">{row.indicator}</td>
                <td className="px-3 py-2 text-slate-700">{row.threat_scenario}</td>
                <td className="px-3 py-2 text-center font-semibold text-red-700">{row.credential_theft_risk}</td>
                <td className="px-3 py-2 text-center">{row.confidence}%</td>
                <td className="px-3 py-2">
                  <button
                    type="button"
                    onClick={() => openEvidence(`SCEN-${i}`)}
                    className="text-blue-700 hover:underline text-left"
                  >
                    {row.evidence.slice(0, 80)}{row.evidence.length > 80 ? '…' : ''}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </SocCard>
  );
}
