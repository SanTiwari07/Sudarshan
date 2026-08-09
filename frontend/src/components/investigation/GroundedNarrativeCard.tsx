import { useState } from 'react';
import { MessageSquare } from 'lucide-react';
import type { FraudCardData } from '../../App';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import HelpTerm from './HelpTerm';
import { useInvestigationUI } from '../../context/InvestigationUIContext';

export default function GroundedNarrativeCard({ data }: { data: FraudCardData }) {
  const [tab, setTab] = useState(0);
  const { openLedger } = useInvestigationUI();
  const tabs = ['Executive narrative', 'Banking impact', 'Recommended actions', 'Customer advisory'];
  const intel = data.intelligence_report;

  return (
    <SocCard>
      <SectionHeader
        icon={<MessageSquare className="h-4 w-4" />}
        title="Why we believe this"
        subtitle="Evidence-grounded synthesis - always verify against the score ledger."
      />
      <div className="px-4 py-2 bg-slate-100 border-b border-slate-200 text-[10px] flex items-center justify-between">
        <span className="text-slate-600">
          AI-assisted explanation layered on <HelpTerm term="Verified Evidence">verified evidence</HelpTerm>
        </span>
        <button type="button" onClick={() => openLedger('full')} className="text-blue-700 font-semibold">
          Open score ledger
        </button>
      </div>
      <div className="flex border-b border-slate-200 overflow-x-auto">
        {tabs.map((t, i) => (
          <button
            key={t}
            onClick={() => setTab(i)}
            className={`px-4 py-2.5 text-xs font-medium whitespace-nowrap border-b-2 ${
              tab === i ? 'border-blue-600 text-blue-700 bg-blue-50' : 'border-transparent text-slate-500'
            }`}
          >
            {t}
          </button>
        ))}
      </div>
      <div className="p-5 text-sm">
        {tab === 0 && (
          <p className="text-slate-800 leading-relaxed bg-blue-50/50 p-4 rounded-lg border border-blue-100">
            {intel?.plain_english_narrative || data.executive_view.plain_english_narrative}
          </p>
        )}
        {tab === 1 && (
          <div className="space-y-3">
            <p className="leading-relaxed text-slate-700">
              {intel?.banking_impact_assessment || 'No banking impact assessment was generated for this case.'}
            </p>
            {intel?.affected_banking_apps?.length ? (
              <div className="flex flex-wrap gap-1.5">
                {intel.affected_banking_apps.map((app) => (
                  <code
                    key={app}
                    className="text-xs bg-red-50 text-red-700 border border-red-200 px-2 py-0.5 rounded font-mono"
                  >
                    {app}
                  </code>
                ))}
              </div>
            ) : null}
          </div>
        )}
        {tab === 2 && (
          <div className="space-y-2">
            {(intel?.recommended_actions || data.executive_view.recommended_actions).map((act, i) => (
              <div key={i} className="flex gap-2 p-3 bg-slate-50 rounded-lg border text-sm">
                <span className="w-5 h-5 rounded-full bg-blue-700 text-white text-xs flex items-center justify-center font-bold shrink-0">
                  {i + 1}
                </span>
                {act}
              </div>
            ))}
          </div>
        )}
        {tab === 3 && (
          <div className="p-4 bg-amber-50 border-l-4 border-amber-400 rounded-r italic text-slate-800">
            {intel?.customer_advisory_draft || data.executive_view.customer_advisory_draft}
          </div>
        )}
      </div>
    </SocCard>
  );
}
