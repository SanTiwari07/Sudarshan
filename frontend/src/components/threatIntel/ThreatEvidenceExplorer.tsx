import { useState } from 'react';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import { FileSearch, ChevronDown, ChevronRight } from 'lucide-react';
import { useInvestigationUI } from '../../context/InvestigationUIContext';

type Group = { group: string; items: { id: string; title: string; subtitle: string }[] };

export default function ThreatEvidenceExplorer({ groups }: { groups: Group[] }) {
  const { openEvidence } = useInvestigationUI();
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  if (!groups.length) {
    return (
      <SocCard>
        <SectionHeader icon={<FileSearch className="h-4 w-4" />} title="Evidence explorer" />
        <p className="p-6 text-xs text-slate-500 text-center">No expandable evidence bundles for this case.</p>
      </SocCard>
    );
  }

  return (
    <SocCard>
      <SectionHeader
        icon={<FileSearch className="h-4 w-4" />}
        title="Evidence explorer"
        subtitle="View evidence behind each claim - full-width registry"
      />
      <div className="divide-y divide-slate-100">
        {groups.map((g) => {
          const open = expanded[g.group] ?? true;
          return (
            <div key={g.group} className="px-4 sm:px-5 py-4">
              <button
                type="button"
                className="flex items-center gap-2 text-xs font-bold text-slate-800 w-full text-left"
                onClick={() => setExpanded((e) => ({ ...e, [g.group]: !open }))}
              >
                {open ? <ChevronDown className="h-4 w-4 shrink-0" /> : <ChevronRight className="h-4 w-4 shrink-0" />}
                {g.group}
                <span className="text-slate-500 font-normal">({g.items.length})</span>
              </button>
              {open && (
                <div className="mt-3 overflow-x-auto rounded-lg border border-slate-200">
                  <table className="w-full min-w-[640px] text-xs">
                    <thead className="bg-slate-50 border-b border-slate-200 text-[12px] uppercase tracking-wide text-slate-500">
                      <tr>
                        <th className="px-3 py-2 text-left font-semibold w-[38%]">Finding</th>
                        <th className="px-3 py-2 text-left font-semibold">Source / detail</th>
                        <th className="px-3 py-2 text-right font-semibold w-24">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {g.items.map((item) => {
                        const disabled = item.id.startsWith('VT-');
                        return (
                          <tr key={item.id} className="hover:bg-slate-50/80">
                            <td className="px-3 py-2.5 font-semibold text-slate-900 align-top">{item.title}</td>
                            <td className="px-3 py-2.5 text-slate-600 align-top">{item.subtitle}</td>
                            <td className="px-3 py-2.5 text-right align-top">
                              <button
                                type="button"
                                onClick={() => !disabled && openEvidence(item.id)}
                                disabled={disabled}
                                className="text-[13px] font-semibold text-blue-700 hover:text-blue-900 disabled:text-slate-500 disabled:cursor-default"
                              >
                                {disabled ? '-' : 'Open'}
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </SocCard>
  );
}
