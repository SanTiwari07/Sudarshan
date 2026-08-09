import type { FraudCardData } from '../../App';
import { getRiskStyle } from '../../theme/colors';
import { riskBandPlainEnglish } from '../../lib/analystCopy';
import HelpTerm from './HelpTerm';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import RiskInfluenceCard from './RiskInfluenceCard';
import { useAnalysis } from '../../context/AnalysisContext';
import { executiveVisualEntries } from '../../lib/visualEvidence';
import VisualEvidenceCard from './VisualEvidenceCard';

function ScoreRing({ score, pct, strokeClass }: { score: number; pct: number; strokeClass: string }) {
  const r = 54;
  const c = 2 * Math.PI * r;
  const offset = c - (pct / 100) * c;

  return (
    <div className="relative w-36 h-36 sm:w-40 sm:h-40 shrink-0">
      <svg className="w-full h-full -rotate-90 score-ring-spin" viewBox="0 0 120 120" aria-hidden>
        <circle cx="60" cy="60" r={r} fill="none" stroke="currentColor" strokeWidth="10" className="text-slate-100" />
        <circle
          cx="60"
          cy="60"
          r={r}
          fill="none"
          strokeWidth="10"
          strokeLinecap="round"
          className={`score-ring-progress transition-all duration-1000 ease-out ${strokeClass}`}
          stroke="currentColor"
          strokeDasharray={c}
          strokeDashoffset={offset}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-4xl sm:text-5xl font-black tabular-nums text-slate-900">{score.toFixed(0)}</span>
        <span className="text-xs text-slate-500 font-medium">/ 100</span>
      </div>
    </div>
  );
}

export default function FraudRiskHero({ data }: { data: FraudCardData }) {
  const riskStyle = getRiskStyle(data.risk_band);
  const { openLedger } = useInvestigationUI();
  const { screenshotManifestEntries } = useAnalysis();
  const execShots = executiveVisualEntries(screenshotManifestEntries);
  const score = data.final_risk_score;
  const pct = Math.min(100, Math.max(0, score));

  return (
    <div className="bg-white border border-slate-200 rounded-xl shadow-sm overflow-hidden upload-fade-in">
      <div className="px-5 sm:px-8 py-6 sm:py-8 flex flex-col lg:flex-row lg:items-center gap-6 lg:gap-10">
        <div className="flex flex-col sm:flex-row items-center sm:items-start gap-5 flex-1 min-w-0">
          <ScoreRing score={score} pct={pct} strokeClass={riskStyle.text} />
          <div className="text-center sm:text-left min-w-0">
            <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Fraud Risk Score</p>
            <h2 className={`text-2xl sm:text-3xl font-bold mt-1 ${riskStyle.textDark}`}>
              {riskBandPlainEnglish(data.risk_band)}
            </h2>
            <p className="text-sm text-slate-600 mt-2 max-w-md leading-relaxed">
              <HelpTerm term="Risk Score">Weighted score</HelpTerm> from verified static, runtime, and threat
              intelligence - not a malware verdict alone.
            </p>
            <button
              type="button"
              onClick={() => openLedger('full')}
              className="mt-4 text-xs font-semibold px-4 py-2.5 bg-blue-700 text-white rounded-lg hover:bg-blue-800 transition-colors"
            >
              View score breakdown
            </button>
            {execShots.length > 0 && (
              <div className="mt-5 space-y-2 max-w-md">
                <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Visual evidence</p>
                {execShots.map((entry) => (
                  <VisualEvidenceCard key={entry.screenshot_id} sha256={data.sha256} entry={entry} />
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="w-full lg:max-w-md border-t lg:border-t-0 lg:border-l border-slate-100 pt-5 lg:pt-0 lg:pl-8">
          <RiskInfluenceCard data={data} embedded />
        </div>
      </div>
    </div>
  );
}
