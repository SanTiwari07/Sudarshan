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
      <SectionHeader icon={<FileSearch className="h-4 w-4" />} title="Evidence explorer" subtitle="View evidence behind each claim" />
      <div className="divide-y divide-slate-100">
        {groups.map((g) => {
          const open = expanded[g.group] ?? true;
          return (
            <div key={g.group} className="p-4">
              <button
                type="button"
                className="flex items-center gap-2 text-xs font-bold text-slate-800 w-full text-left"
                onClick={() => setExpanded((e) => ({ ...e, [g.group]: !open }))}
              >
                {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                {g.group}
                <span className="text-slate-400 font-normal">({g.items.length})</span>
              </button>
              {open && (
                <ul className="mt-2 space-y-1 max-h-48 overflow-y-auto">
                  {g.items.map((item) => (
                    <li key={item.id}>
                      <button
                        type="button"
                        onClick={() => item.id.startsWith('VT-') ? undefined : openEvidence(item.id)}
                        className="w-full text-left px-2 py-1.5 rounded hover:bg-slate-50 text-xs"
                        disabled={item.id.startsWith('VT-')}
                      >
                        <span className="font-semibold text-slate-900">{item.title}</span>
                        <span className="block text-[10px] text-slate-500">{item.subtitle}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          );
        })}
      </div>
    </SocCard>
  );
}
