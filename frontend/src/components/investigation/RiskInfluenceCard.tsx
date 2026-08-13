import type { FraudCardData } from '../../App';
import { computeWeightedContribution, getAxesUsed } from '../../lib/scoreLedger';
import {
  buildStaticCardSummary,
  buildThreatCardSummary,
  influenceLabel,
} from '../../lib/scoreInfluenceModel';
import type { ScoreInfluenceAxis } from '../../lib/scoreInfluenceModel';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { TYPOGRAPHY } from '../../theme/typography';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import HelpTerm from './HelpTerm';
import DownloadReportButton from './DownloadReportButton';
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
  value: string;
  unit: string;
  contributionLabel: string;
};

function buildRows(data: FraudCardData): InfluenceRow[] {
  const frs = data.frs_breakdown;
  if (!frs) return [];
  const axesUsed = getAxesUsed(data);

  const dynamicIncluded = frs.dynamic_conclusive && !frs.axes_excluded?.includes('dynamic');
  const dynamicScore = frs.dynamic ?? 0;
  const dynResult = (
    data.dynamic_result && typeof data.dynamic_result === 'object' && !Array.isArray(data.dynamic_result)
      ? data.dynamic_result
      : data.dynamic_analysis && typeof data.dynamic_analysis === 'object' && !Array.isArray(data.dynamic_analysis)
        ? data.dynamic_analysis
        : undefined
  ) as { dynamic_status?: string; error?: string } | undefined;
  const dynamicStatus = dynResult?.dynamic_status?.toUpperCase();
  const instrumentationFailed =
    Boolean(frs.dynamic_ran) &&
    !dynamicIncluded &&
    (dynamicStatus === 'INSTRUMENTATION_FAILED' || Boolean(dynResult?.error));
  const runtimeNotRun = !frs.dynamic_ran && !data.dynamic_available;
  const exclusionReason = frs.dynamic_exclusion_reason?.toUpperCase();
  const dynamicSummary = dynamicIncluded
    ? 'Observed sandbox behaviour contributed to the fraud risk score.'
    : runtimeNotRun
      ? 'Runtime analysis did not run for this case, so this axis was excluded from the final score.'
      : exclusionReason === 'NO_UI_RENDERED'
        ? 'The app never rendered a screen in the sandbox, so no runtime behaviour could be observed. Excluded from the score - this is not evidence the app is safe.'
        : exclusionReason === 'EVASION_ONLY'
          ? 'The app ran anti-analysis checks and then did nothing observable. Excluded from the score - evasion is not evidence of safety.'
          : instrumentationFailed
            ? 'Runtime instrumentation failed, so sandbox evidence was excluded from the final score.'
            : 'Runtime execution was inconclusive, so this axis was excluded from the final score.';
  const dynamicContribution = dynamicIncluded
    ? computeWeightedContribution('dynamic', dynamicScore, axesUsed)
    : 0;

  const staticIncluded = !frs.axes_excluded?.includes('stei');
  const correlationIncluded = !frs.axes_excluded?.includes('correlation');
  const correlationScore = frs.correlation ?? data.threat_correlation?.threat_score ?? 0;

  return [
    {
      key: 'stei',
      axis: 'static',
      label: 'Static evidence',
      term: 'STEI',
      score: frs.stei ?? 0,
      influence: influenceLabel(frs.stei ?? 0, staticIncluded),
      summary: buildStaticCardSummary(data),
      included: staticIncluded,
      value: staticIncluded ? (frs.stei ?? 0).toFixed(0) : 'Not included',
      unit: staticIncluded ? '/ 100' : '',
      contributionLabel: staticIncluded ? `${(frs.stei ?? 0).toFixed(0)} / 100` : 'Not included',
    },
    {
      key: 'dynamic',
      axis: 'dynamic',
      label: 'Runtime behaviour',
      term: 'BFCI',
      score: dynamicScore,
      influence: dynamicIncluded ? influenceLabel(dynamicScore, true) : 'Not included',
      summary: dynamicSummary,
      included: Boolean(dynamicIncluded),
      value: dynamicIncluded ? dynamicContribution.toFixed(1) : 'Not included',
      unit: dynamicIncluded ? 'pts to FRS' : '',
      contributionLabel: dynamicIncluded
        ? `${dynamicContribution.toFixed(1)} pts to FRS`
        : 'Not included',
    },
    {
      key: 'correlation',
      axis: 'threat_intel',
      label: 'Threat intelligence',
      term: 'Threat Intelligence',
      score: correlationScore,
      influence: correlationIncluded ? influenceLabel(correlationScore, true) : 'Not included',
      summary: buildThreatCardSummary(data),
      included: correlationIncluded,
      value: correlationIncluded ? correlationScore.toFixed(0) : 'Not included',
      unit: correlationIncluded ? '/ 100' : '',
      contributionLabel: correlationIncluded
        ? `${correlationScore.toFixed(0)} / 100`
        : 'Not included',
    },
  ];
}

export default function RiskInfluenceCard({ data, embedded = false }: { data: FraudCardData; embedded?: boolean }) {
  const { openInfluenceDetail, openLedger } = useInvestigationUI();
  const rows = buildRows(data);
  if (rows.length === 0) return null;

  const body = (
    <div className={embedded ? 'flex-1 flex flex-col justify-between gap-3.5 sm:gap-4' : 'p-4 space-y-4'}>
      {rows.map((row) => (
        <button
          key={row.key}
          type="button"
          onClick={() => openInfluenceDetail(row.axis)}
          aria-label={`View ${row.label.toLowerCase()} details`}
          className={`w-full text-left rounded-lg border border-slate-200 cursor-pointer bg-white hover:border-blue-300 hover:bg-blue-50/40 transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 shadow-xs ${
            embedded ? 'flex-1 flex flex-col justify-between p-4 sm:p-4.5' : 'p-3.5 sm:p-4'
          }`}
        >
          <div>
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <span className={TYPOGRAPHY.h3}>
                <HelpTerm term={row.term}>{row.label}</HelpTerm>
              </span>
              <span className={`${TYPOGRAPHY.badge} text-blue-800 bg-blue-50 border-blue-200`}>{row.influence}</span>
            </div>
            <div className="mt-2 mb-2.5 flex items-baseline gap-1.5 font-mono">
              {row.included ? (
                <>
                  <span className="text-2xl sm:text-3xl font-bold text-blue-700 leading-none tracking-tight font-mono">
                    {row.value}
                  </span>
                  {row.unit && (
                    <span className="leading-none font-mono">
                      {row.unit.startsWith('/') ? (
                        <span className="inline-flex items-baseline gap-1">
                          <span className="text-xs font-semibold text-slate-400">/</span>
                          <span className="text-sm sm:text-base font-bold text-slate-700">{row.unit.replace('/', '').trim()}</span>
                        </span>
                      ) : (
                        <span className="text-xs sm:text-sm font-semibold text-slate-500 select-none">{row.unit}</span>
                      )}
                    </span>
                  )}
                </>
              ) : (
                <span className={TYPOGRAPHY.caption}>
                  {row.value}
                </span>
              )}
            </div>
            <p className={TYPOGRAPHY.bodySmall}>{row.summary}</p>
            {row.key === 'dynamic' && !row.included && row.score > 0 && (
              <p className={`${TYPOGRAPHY.caption} text-amber-800 mt-2 font-medium`}>
                Observed runtime score {row.score.toFixed(1)} / 100 - excluded from final FRS because evidence was
                inconclusive.
              </p>
            )}
          </div>
          <div className={`flex items-center justify-end gap-1 mt-3 ${TYPOGRAPHY.linkAction}`}>
            View details
            <ChevronRight className="h-4 w-4" aria-hidden />
          </div>
        </button>
      ))}
      {!embedded && (
        <button
          type="button"
          onClick={() => openLedger('full')}
          className={`${TYPOGRAPHY.button} w-full text-blue-700 py-2.5 rounded-lg border border-blue-200 hover:bg-blue-50`}
        >
          View score breakdown
        </button>
      )}
    </div>
  );

  if (embedded) {
    return (
      <div className="h-full flex flex-col justify-between">
        <div className="mb-3 sm:mb-4">
          <p className={TYPOGRAPHY.h2}>What influenced the score?</p>
        </div>
        {body}
      </div>
    );
  }

  return (
    <SocCard>
      <div className="p-4 pb-0 flex items-center justify-between gap-3">
        <SectionHeader
          icon={<BarChart2 className="h-4 w-4" />}
          title="What influenced the score?"
          subtitle="Analyst view - open the score ledger for raw weights and contributions."
        />
        <DownloadReportButton sha256={data.sha256} />
      </div>
      {body}
    </SocCard>
  );
}
