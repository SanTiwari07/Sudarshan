import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import { Grid3X3 } from 'lucide-react';
import type { MitreCard } from '../../lib/threatIntelModel';
import { useInvestigationUI } from '../../context/InvestigationUIContext';

export default function MitreAttackCards({ cards }: { cards: MitreCard[] }) {
  const { openEvidence } = useInvestigationUI();

  if (!cards.length) {
    return (
      <SocCard>
        <SectionHeader icon={<Grid3X3 className="h-4 w-4" />} title="MITRE ATT&CK" subtitle="Technique mapping" />
        <p className="p-6 text-xs text-slate-500 text-center">No MITRE techniques mapped for this case.</p>
      </SocCard>
    );
  }

  return (
    <SocCard>
      <SectionHeader icon={<Grid3X3 className="h-4 w-4" />} title="MITRE ATT&CK" subtitle="Hover for mapping rationale" />
      <div className="p-4 grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {cards.map((c, i) => (
          <div
            key={`${c.technique}-${i}`}
            className="group p-3 rounded-lg border border-slate-200 bg-white hover:border-slate-400 hover:shadow-sm transition-all"
            title={c.evidence}
          >
            <div className="text-[10px] font-mono text-blue-800">{c.techniqueId || '—'}</div>
            <div className="text-xs font-bold text-slate-900 mt-1">{c.technique}</div>
            <div className="mt-2 flex justify-between text-[10px] text-slate-500">
              <span>Confidence {c.confidence}%</span>
              <span>{c.source}</span>
            </div>
            <p className="mt-2 text-[10px] text-slate-600 leading-snug opacity-80 group-hover:opacity-100">
              {c.evidence}
            </p>
            {c.evidenceIds.map((id) => (
              <button
                key={id}
                type="button"
                onClick={() => openEvidence(id)}
                className="mt-2 text-[10px] text-blue-700 hover:underline"
              >
                View evidence
              </button>
            ))}
          </div>
        ))}
      </div>
    </SocCard>
  );
}
