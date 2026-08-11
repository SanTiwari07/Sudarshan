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
    <div className="bg-white border border-slate-200 rounded-md shadow-[0_1px_3px_rgba(0,0,0,0.02)] overflow-hidden upload-fade-in">
      <div className="px-6 py-6 flex flex-col lg:flex-row lg:items-center gap-6 lg:gap-10">
        <div className="flex flex-col sm:flex-row items-center sm:items-start gap-6 flex-1 min-w-0">
          <ScoreRing score={score} pct={pct} strokeClass={riskStyle.text} />
          <div className="text-center sm:text-left min-w-0 flex-1">
            <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 font-mono">Security Metric</p>
            <h2 className={`text-2xl sm:text-3xl font-extrabold mt-1 tracking-tight ${riskStyle.textDark}`}>
              {riskBandPlainEnglish(data.risk_band)}
            </h2>
            <p className="text-xs text-slate-600 mt-2 max-w-md leading-relaxed">
              <HelpTerm term="Risk Score">Fraud Risk Score (FRS)</HelpTerm>: Weighted multi-axis correlation of verified static analysis indicators, runtime behavioral sandbox observations, and external threat intelligence.
            </p>
            <div className="mt-4 flex flex-wrap gap-2 justify-center sm:justify-start">
              <button
                type="button"
                onClick={() => openLedger('full')}
                className="text-[11px] font-mono uppercase tracking-wider font-bold px-3.5 py-1.5 bg-blue-700 hover:bg-blue-800 text-white rounded transition-colors shadow-sm"
              >
                View score breakdown
              </button>
            </div>
            {execShots.length > 0 && (
              <div className="mt-6 space-y-2 max-w-md text-left">
                <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 font-mono">Visual evidence</p>
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
