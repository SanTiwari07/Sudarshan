import type { FraudCardData } from '../../App';
import { computeWeightedContribution, getAxesUsed } from '../../lib/scoreLedger';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import HelpTerm from './HelpTerm';
import { BarChart2 } from 'lucide-react';

const ITEMS = [
  { key: 'stei' as const, label: 'Code Inspection (STEI)', term: 'Code Inspection', color: 'bg-red-500' },
  { key: 'dynamic' as const, label: 'Dynamic Sandbox', term: 'Dynamic Analysis', color: 'bg-purple-500' },
  { key: 'correlation' as const, label: 'Threat Correlation', term: 'Threat Correlation', color: 'bg-blue-500' },
  { key: 'banking_impact' as const, label: 'Banking Impact', term: 'Risk Score', color: 'bg-orange-500' },
];

export default function ScoreEntryCard({ data }: { data: FraudCardData }) {
  const frs = data.frs_breakdown;
  const { openLedger } = useInvestigationUI();
  if (!frs) return null;

  const axesUsed = getAxesUsed(data);

  return (
    <SocCard>
      <SectionHeader
        icon={<BarChart2 className="h-4 w-4" />}
        title="Score breakdown"
        subtitle="How each evidence axis contributed to the fraud risk score."
      />
      <div className="p-4 space-y-3">
        {ITEMS.map((b) => {
          const score = frs[b.key];
          const weight = axesUsed[b.key] ?? 0;
          const weighted = computeWeightedContribution(b.key, score, axesUsed);
          const unavailable = b.key === 'dynamic' && frs.dynamic_ran && !frs.dynamic_conclusive;
          const excluded = frs.axes_excluded?.includes(b.key);
          return (
            <button
              key={b.key}
              type="button"
              onClick={() => openLedger(b.key === 'banking_impact' ? 'banking' : b.key)}
              className="w-full text-left rounded-lg p-2 hover:bg-slate-50 border border-transparent hover:border-slate-200 transition-colors"
            >
              <div className="flex justify-between items-center mb-1 text-xs">
                <span className="text-slate-600">
                  <HelpTerm term={b.term}>{b.label}</HelpTerm>{' '}
                  <span className="text-slate-400">({(weight * 100).toFixed(0)}% weight)</span>
                </span>
                <span className="font-bold text-slate-800 font-mono">{score.toFixed(1)} / 100</span>
              </div>
              <div className="flex justify-between text-[10px] text-slate-500 mb-1">
                <span>Contribution to score</span>
                <span className="font-mono">{weighted.toFixed(2)}</span>
              </div>
              <div className="w-full h-1.5 bg-slate-100 rounded-full overflow-hidden">
                <div
                  className={`h-full ${excluded || unavailable ? 'bg-slate-300' : b.color} rounded-full`}
                  style={{ width: `${Math.min(score, 100)}%` }}
                />
              </div>
              {unavailable && (
                <div className="text-[10px] text-amber-700 mt-1">Runtime inconclusive — axis not used in final score</div>
              )}
              {excluded && <div className="text-[10px] text-amber-700 mt-1">Axis excluded (no data)</div>}
            </button>
          );
        })}
      </div>
    </SocCard>
  );
}
