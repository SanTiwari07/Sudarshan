import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import { ClipboardList } from 'lucide-react';
import type { AnalystAction } from '../../lib/threatIntelModel';

export default function AnalystRecommendationPanel({ actions }: { actions: AnalystAction[] }) {
  return (
    <SocCard>
      <SectionHeader icon={<ClipboardList className="h-4 w-4" />} title="Analyst recommendations" subtitle="Each action linked to evidence" />
      <ul className="p-4 space-y-2">
        {actions.map((a) => (
          <li
            key={`${a.label}-${a.evidenceRef}`}
            className="flex gap-3 p-3 rounded-lg border border-slate-200 hover:border-slate-300 transition-colors"
          >
            <span
              className={`shrink-0 mt-0.5 w-2 h-2 rounded-full ${
                a.priority === 'high' ? 'bg-red-500' : a.priority === 'medium' ? 'bg-amber-500' : 'bg-slate-400'
              }`}
            />
            <div className="text-xs">
              <div className="font-bold text-slate-900">{a.label}</div>
              <div className="text-slate-500 mt-0.5">{a.evidenceRef}</div>
            </div>
          </li>
        ))}
      </ul>
    </SocCard>
  );
}
