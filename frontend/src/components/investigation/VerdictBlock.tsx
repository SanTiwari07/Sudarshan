import { BarChart2 } from 'lucide-react';
import type { FraudCardData } from '../../App';
import { TYPOGRAPHY } from '../../theme/typography';
import { caseSeverity } from '../../theme/severity';
import { getDecision, isInconclusive } from '../../lib/decision';
import { formatScore, bandOverrideReason, verdictHeadline } from '../../lib/verdictCopy';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import AnimatedNumber from '../motion/AnimatedNumber';
import DownloadReportButton from './DownloadReportButton';
import RiskInfluenceCard from './RiskInfluenceCard';

/**
 * The decision, and the three things that qualify it.
 *
 * What changed and why:
 *
 * The page used to open with a score ring. "94" is not a decision - it is an
 * input to one, and it requires the reader to already know the scale, the
 * bands, and which direction is bad. A bank manager given twenty seconds reads
 * a sentence far faster than they interpret a number, so the imperative
 * ("DO NOT INSTALL") is now the largest thing on the page and the score sits
 * beside it as supporting evidence.
 *
 * Confidence was previously only reachable inside a slide-over. It belongs
 * here: a 94 we are unsure about and a 94 we are certain about call for
 * different actions, and hiding that behind a click means most readers never
 * learn which one they are looking at.
 *
 * The app's own name is the page's `h1`. It was a `<p>`, which left every view
 * in the product without a top-level heading.
 */

function ScoreRing({
  score,
  barClass,
  ringLabel,
}: {
  score: number;
  barClass: string;
  ringLabel: string;
}) {
  const r = 54;
  const c = 2 * Math.PI * r;
  const pct = Math.min(100, Math.max(0, score));
  const offset = c - (pct / 100) * c;

  return (
    // The ring encodes magnitude pre-attentively, which is worth keeping. The
    // accessible name carries the same fact so it is never colour-and-shape
    // only.
    <div
      className="relative w-24 h-24 sm:w-32 sm:h-32 shrink-0"
      role="img"
      aria-label={`Risk score ${formatScore(score)} out of 100. ${ringLabel}.`}
    >
      <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120" aria-hidden>
        <circle
          cx="60"
          cy="60"
          r={r}
          fill="none"
          stroke="currentColor"
          strokeWidth="7"
          className="text-slate-100"
        />
        <circle
          cx="60"
          cy="60"
          r={r}
          fill="none"
          strokeWidth="7"
          strokeLinecap="round"
          className={`transition-[stroke-dashoffset] duration-700 ease-out ${barClass}`}
          stroke="currentColor"
          strokeDasharray={c}
          strokeDashoffset={offset}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-display text-4xl font-semibold tracking-[-0.045em] text-slate-900 tabular-nums leading-none">
          <AnimatedNumber value={score} decimals={0} />
        </span>
        <span className={`${TYPOGRAPHY.displaySub} mt-1`}>/ 100</span>
      </div>
    </div>
  );
}

/** Confidence as a labelled meter. Never a bare percentage. */
function ConfidenceMeter({ confidence, inconclusive }: { confidence: number; inconclusive: boolean }) {
  const pct = Math.min(100, Math.max(0, confidence));
  const label = inconclusive ? 'Low' : pct >= 80 ? 'High' : pct >= 60 ? 'Moderate' : 'Low';
  // Slate whenever the run was not certifiable: a confident-looking meter on an
  // uncertifiable case is the same lie as a green badge.
  const bar = inconclusive
    ? 'bg-slate-400'
    : pct >= 80
      ? 'bg-emerald-600'
      : pct >= 60
        ? 'bg-amber-500'
        : 'bg-orange-500';

  return (
    <div className="space-y-1.5 min-w-[10rem]">
      <div className="flex items-baseline justify-between gap-3">
        <span className={TYPOGRAPHY.label}>Confidence</span>
        <span className={`${TYPOGRAPHY.bodySmall} font-semibold text-slate-900`}>{label}</span>
      </div>
      <div
        className="h-1.5 w-full rounded-full bg-slate-200 overflow-hidden"
        role="img"
        aria-label={`Analysis confidence: ${label}, ${Math.round(pct)} percent`}
      >
        <div className={`h-full rounded-full ${bar}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

export default function VerdictBlock({ data }: { data: FraudCardData }) {
  const { openLedger } = useInvestigationUI();

  const inconclusive = isInconclusive(data);
  const decision = getDecision(data);
  const token = caseSeverity(data.risk_band, inconclusive);
  const overrideReason = bandOverrideReason(data);
  const Icon = token.icon;

  return (
    <section
      aria-label="Verdict"
      className="bg-white border border-slate-300 rounded-lg shadow-[0_2px_8px_rgba(15,23,42,0.06)] overflow-hidden"
    >
      <div className="flex flex-col lg:flex-row lg:items-stretch">
        <div className="flex-1 min-w-0 px-6 py-7 space-y-6">
          {/* Tier 1 - the decision, as a sentence. */}
          <div className="flex flex-col-reverse sm:flex-row sm:items-start gap-6 sm:gap-8">
            <div className="min-w-0 flex-1 space-y-3">
              <div className="flex flex-wrap items-center gap-2.5">
                <span
                  className={`${TYPOGRAPHY.badgePill} ${token.badge} border-transparent inline-flex items-center gap-1.5`}
                >
                  <Icon className="h-3 w-3" aria-hidden />
                  {token.label}
                </span>
                <span className={TYPOGRAPHY.label}>{token.meaning}</span>
              </div>

              <p className="font-display text-3xl sm:text-4xl font-semibold tracking-[-0.03em] text-slate-900 leading-[1.1]">
                {decision.headline}
              </p>

              <h1 className={`${TYPOGRAPHY.h2} break-words`}>
                {data.app_name || data.package_name || 'Unnamed application'}
              </h1>

              <p className="font-sans text-[15px] leading-relaxed text-slate-700 max-w-[62ch]">
                {inconclusive ? decision.rationale : verdictHeadline(data)}
              </p>

              {overrideReason && (
                <p
                  className={`${TYPOGRAPHY.bodySmall} text-amber-900 bg-amber-50/70 border-l-2 border-amber-400 pl-3 py-1.5 max-w-[62ch]`}
                >
                  {overrideReason}
                </p>
              )}
            </div>

            <div className="flex sm:flex-col items-center sm:items-end gap-5 sm:gap-6 shrink-0">
              <ScoreRing
                score={data.final_risk_score}
                barClass={token.fg}
                ringLabel={`${token.label}. ${token.meaning}`}
              />
              <ConfidenceMeter confidence={data.confidence ?? 0} inconclusive={inconclusive} />
            </div>
          </div>

          {/* One primary action. The breakdown is a link, not a rival button. */}
          <div className="flex flex-wrap items-center gap-4">
            <DownloadReportButton
              sha256={data.sha256}
              className={`${TYPOGRAPHY.button} bg-blue-700 hover:bg-blue-800 text-white px-5 py-2.5 shadow-sm`}
            />
            <button
              type="button"
              onClick={() => openLedger('full')}
              className={`${TYPOGRAPHY.linkAction} py-2.5`}
            >
              <BarChart2 className="h-3.5 w-3.5" aria-hidden />
              How this score was calculated
            </button>
          </div>
        </div>

        {/* Tier 2 - why, ranked by how much each axis moved the score. */}
        <div className="w-full lg:w-[22rem] xl:w-[24rem] shrink-0 border-t lg:border-t-0 lg:border-l border-slate-200 bg-slate-50/50 px-5 py-6">
          <RiskInfluenceCard data={data} embedded />
        </div>
      </div>
    </section>
  );
}
