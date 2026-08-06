import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import { Database } from 'lucide-react';
import type { IntelApiPayload } from '../../lib/threatIntelModel';
import type { FraudCardData } from '../../App';
import { useInvestigationUI } from '../../context/InvestigationUIContext';

export default function IntelligenceSourcesPanel({
  intel,
  data,
}: {
  intel: IntelApiPayload;
  data: FraudCardData;
}) {
  const { openLedger } = useInvestigationUI();

  const sources = [
    ...intel.sources_status.map((s) => ({
      name: s.name,
      status: s.status,
      message: s.message,
      clickable: s.status === 'active',
    })),
    {
      name: 'MITRE',
      status: (data.intelligence_report?.mitre_techniques_used?.length || 0) > 0 ? 'active' : 'no_match',
      message:
        (data.intelligence_report?.mitre_techniques_used?.length || 0) > 0
          ? `${data.intelligence_report!.mitre_techniques_used.length} techniques`
          : 'No MITRE mapping in report',
      clickable: true,
    },
    {
      name: 'YARA',
      status: 'active',
      message: 'Export YARA from report suite',
      clickable: false,
    },
    {
      name: 'Internal Corpus',
      status: data.threat_scenario_table?.length ? 'active' : 'no_match',
      message: `${data.threat_scenario_table?.length || 0} threat scenarios`,
      clickable: true,
    },
    {
      name: 'Historical Cases',
      status: 'active',
      message: 'See similar investigations below',
      clickable: false,
    },
    {
      name: 'Local Rules',
      status: data.technical_view?.matched_rule ? 'active' : 'no_match',
      message: data.technical_view?.matched_rule || 'No local rule match',
      clickable: true,
    },
  ];

  return (
    <SocCard>
      <SectionHeader icon={<Database className="h-4 w-4" />} title="Intelligence sources" subtitle="Configured feeds and internal engines" />
      <div className="p-4 grid sm:grid-cols-2 lg:grid-cols-3 gap-2">
        {sources.map((s) => (
          <button
            key={s.name}
            type="button"
            disabled={!s.clickable}
            onClick={() => s.clickable && openLedger(s.name.includes('Correlation') ? 'correlation' : 'full')}
            className={`text-left p-3 rounded-lg border text-xs transition-all ${
              s.status === 'active'
                ? 'border-slate-300 bg-white hover:border-slate-500 hover:shadow-sm'
                : 'border-slate-100 bg-slate-50 text-slate-500'
            } ${!s.clickable ? 'cursor-default' : ''}`}
          >
            <div className="font-bold text-slate-900 flex justify-between gap-2">
              {s.name}
              <span className="text-[9px] uppercase font-semibold text-slate-500">{s.status}</span>
            </div>
            <p className="mt-1 text-[10px] text-slate-600 leading-snug">{s.message}</p>
          </button>
        ))}
      </div>
    </SocCard>
  );
}
