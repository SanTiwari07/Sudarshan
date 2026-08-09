import type { FraudCardData } from '../../App';
import { computeWeightedContribution, getAxesUsed } from '../../lib/scoreLedger';
import {
  buildStaticCardSummary,
  buildThreatCardSummary,
  influenceLabel,
} from '../../lib/scoreInfluenceModel';
import type { ScoreInfluenceAxis } from '../../lib/scoreInfluenceModel';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import HelpTerm from './HelpTerm';
import { BarChart2, ChevronRight } from 'lucide-react';

type InfluenceRow = {
  key: string;
  axis: ScoreInfluenceAxis;
  label: string;
  term: string;
  score: number;
  influence: string;
  summary: string;
  included: boolean;
  contributionLabel: string;
};

function buildRows(data: FraudCardData): InfluenceRow[] {
  const frs = data.frs_breakdown;
  if (!frs) return [];
  const axesUsed = getAxesUsed(data);

  const dynamicIncluded = frs.dynamic_conclusive && !frs.axes_excluded?.includes('dynamic');
  const dynamicScore = frs.dynamic ?? 0;
  const dynamicContribution = dynamicIncluded
    ? computeWeightedContribution('dynamic', dynamicScore, axesUsed)
    : 0;

  return [
    {
      key: 'stei',
      axis: 'static',
      label: 'Static evidence',
      term: 'STEI',
      score: frs.stei ?? 0,
      influence: influenceLabel(frs.stei ?? 0, !frs.axes_excluded?.includes('stei')),
      summary: buildStaticCardSummary(data),
      included: !frs.axes_excluded?.includes('stei'),
      contributionLabel: `${(frs.stei ?? 0).toFixed(0)} / 100`,
    },
    {
      key: 'dynamic',
      axis: 'runtime',
      label: 'Runtime behaviour',
      term: 'BFCI',
      score: dynamicScore,
      influence: dynamicIncluded ? influenceLabel(dynamicScore, true) : 'Not included',
      summary: dynamicIncluded
        ? 'Observed sandbox behaviour contributed to the fraud risk score.'
        : 'Runtime execution was inconclusive, so this axis was excluded from the final score.',
      included: Boolean(dynamicIncluded),
      contributionLabel: dynamicIncluded
        ? `${dynamicContribution.toFixed(1)} pts to FRS`
        : 'Not included',
    },
    {
      key: 'correlation',
      axis: 'threat',
      label: 'Threat intelligence',
      term: 'Threat Intelligence',
      score: frs.correlation ?? 0,
      influence: influenceLabel(frs.correlation ?? 0, !frs.axes_excluded?.includes('correlation')),
      summary: buildThreatCardSummary(data),
      included: !frs.axes_excluded?.includes('correlation'),
      contributionLabel: `${(frs.correlation ?? 0).toFixed(0)} / 100`,
    },
  ];
}

export default function RiskInfluenceCard({ data, embedded = false }: { data: FraudCardData; embedded?: boolean }) {
  const { openInfluenceDetail, openLedger } = useInvestigationUI();
  const rows = buildRows(data);
  if (rows.length === 0) return null;

  const body = (
    <div className={embedded ? 'space-y-4' : 'p-4 space-y-4'}>
      {rows.map((row) => (
        <button
          key={row.key}
          type="button"
          onClick={() => openInfluenceDetail(row.axis)}
          aria-label={`View ${row.label.toLowerCase()} details`}
          className="w-full text-left rounded-lg border border-slate-100 p-3 cursor-pointer hover:border-blue-200 hover:bg-slate-50/80 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
        >
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <span className="text-sm font-semibold text-slate-900">
              <HelpTerm term={row.term}>{row.label}</HelpTerm>
            </span>
            <span className="text-xs font-semibold text-blue-800">{row.influence}</span>
          </div>
          <p className="text-xs font-mono text-slate-600 mt-1">{row.contributionLabel}</p>
          <p className="text-xs text-slate-600 mt-2 leading-relaxed">{row.summary}</p>
          {row.key === 'dynamic' && !row.included && row.score > 0 && (
            <p className="text-[10px] text-amber-800 mt-2">
              Observed runtime score {row.score.toFixed(1)} / 100 - excluded from final FRS because evidence was
              inconclusive.
            </p>
          )}
          <div className="flex items-center justify-end gap-1 mt-2 text-[10px] font-semibold text-blue-700">
            View details
            <ChevronRight className="h-3.5 w-3.5" aria-hidden />
          </div>
        </button>
      ))}
      {!embedded && (
        <button
          type="button"
          onClick={() => openLedger('full')}
          className="w-full text-center text-xs font-semibold text-blue-700 py-2 rounded-lg border border-blue-100 hover:bg-blue-50"
        >
          View score breakdown
        </button>
      )}
    </div>
  );

  if (embedded) {
    return (
      <div>
        <p className="text-xs font-bold text-slate-800 mb-3">What influenced the score?</p>
        {body}
      </div>
    );
  }

  return (
    <SocCard>
      <SectionHeader
        icon={<BarChart2 className="h-4 w-4" />}
        title="What influenced the score?"
        subtitle="Analyst view - open the score ledger for raw weights and contributions."
      />
      {body}
    </SocCard>
  );
}
