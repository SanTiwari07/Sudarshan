import type { InvestigationBundle } from '../../types/investigation';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import { List } from 'lucide-react';

export default function FindingsRegistryTable({ bundle }: { bundle: InvestigationBundle }) {
  const { openEvidence } = useInvestigationUI();

  return (
    <SocCard>
      <SectionHeader
        icon={<List className="h-4 w-4" />}
        title="Findings registry"
        subtitle={`${bundle.evidenceRecords.length} indexed records`}
      />
      <div className="overflow-x-auto max-h-[480px]">
        <table className="w-full text-xs">
          <thead className="bg-slate-50 text-slate-500 uppercase text-[10px] sticky top-0">
            <tr>
              <th className="px-3 py-2 text-left">ID</th>
              <th className="px-3 py-2 text-left">Finding</th>
              <th className="px-3 py-2">Severity</th>
              <th className="px-3 py-2">Source</th>
              <th className="px-3 py-2">Conf.</th>
            </tr>
          </thead>
          <tbody>
            {bundle.evidenceRecords.map((row) => (
              <tr
                key={row.id}
                className="border-t border-slate-100 hover:bg-blue-50/50 cursor-pointer"
                onClick={() => openEvidence(row.id)}
              >
                <td className="px-3 py-2 font-mono text-blue-700">{row.id}</td>
                <td className="px-3 py-2 text-slate-800 max-w-xs truncate">{row.title}</td>
                <td className="px-3 py-2 text-center font-semibold text-red-700">{row.severity}</td>
                <td className="px-3 py-2 text-slate-600">{row.sourceEngine}</td>
                <td className="px-3 py-2 text-center">{row.confidence}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </SocCard>
  );
}
