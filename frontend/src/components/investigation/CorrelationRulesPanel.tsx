import type { FraudCardData } from '../../App';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import { Globe } from 'lucide-react';

export default function CorrelationRulesPanel({ data }: { data: FraudCardData }) {
  const { openLedger } = useInvestigationUI();
  const corr = data.threat_correlation;
  const frs = data.frs_breakdown;

  if (!corr && !frs) return null;

  const sources = corr?.threat_score_sources || [];
  const iocs = corr?.ioc_reputation || [];

  return (
    <SocCard>
      <SectionHeader icon={<Globe className="h-4 w-4" />} title="Correlation rules" subtitle="External + FRS alignment" />
      <div className="p-4 space-y-3 text-xs">
        <div className="grid grid-cols-2 gap-3">
          <div className="p-2 bg-white rounded border">
            <div className="text-slate-500">FRS correlation</div>
            <div className="font-mono font-bold">{frs?.correlation?.toFixed(1) ?? '-'}</div>
          </div>
          <div className="p-2 bg-white rounded border">
            <div className="text-slate-500">Intel threat_score</div>
            <div className="font-mono font-bold">{corr?.threat_score?.toFixed(1) ?? '-'}</div>
          </div>
        </div>
        {sources.length > 0 && (
          <div>
            <div className="text-[10px] uppercase text-slate-500 mb-1">Score sources</div>
            <ul className="space-y-1">
              {sources.map((line, i) => (
                <li key={i} className="p-2 bg-blue-50/50 border border-blue-100 rounded">{line}</li>
              ))}
            </ul>
          </div>
        )}
        {iocs.length > 0 && (
          <div>
            <div className="text-[10px] uppercase text-slate-500 mb-1">IOC matches ({iocs.length})</div>
            <ul className="space-y-1 max-h-40 overflow-y-auto">
              {iocs.slice(0, 8).map((ioc) => (
                <li key={ioc.indicator} className="font-mono text-[10px] truncate">
                  {ioc.type}: {ioc.indicator} - {ioc.reputation} ({ioc.source})
                </li>
              ))}
            </ul>
          </div>
        )}
        <button type="button" onClick={() => openLedger('correlation')} className="text-blue-700 font-semibold">
          Full correlation ledger
        </button>
      </div>
    </SocCard>
  );
}
