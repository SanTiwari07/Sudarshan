import type { FraudCardData } from '../../App';
import SocCard from '../ui/Card';
import { getRiskStyle } from '../../theme/colors';
import {
  riskBandPlainEnglish,
  riskLevelMeaning,
  riskRecommendedAction,
} from '../../lib/analystCopy';
import HelpTerm from './HelpTerm';
import { Gauge } from 'lucide-react';
import { useInvestigationUI } from '../../context/InvestigationUIContext';

export default function RiskScorePanel({ data }: { data: FraudCardData }) {
  const riskStyle = getRiskStyle(data.risk_band);
  const { openLedger } = useInvestigationUI();
  const score = data.final_risk_score;
  const pct = Math.min(100, Math.max(0, score));

  return (
    <SocCard>
      <div className="px-5 py-3 border-b border-slate-200 bg-slate-50 flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Gauge className="h-4 w-4 text-blue-700" />
            <h2 className="text-sm font-semibold text-slate-900">Fraud Risk Score</h2>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            <HelpTerm term="Risk Score">Weighted score</HelpTerm> from verified evidence — not a malware verdict alone.
          </p>
        </div>
        <span
          className={`text-[10px] font-bold uppercase tracking-wide px-2.5 py-1 rounded-full ${riskStyle.badge}`}
        >
          {riskBandPlainEnglish(data.risk_band)}
        </span>
      </div>

      <div className="p-5 grid grid-cols-1 md:grid-cols-[auto_1fr] gap-6 items-center">
        <div className="flex items-center gap-4">
          <div className={`text-5xl font-black tabular-nums ${riskStyle.text}`}>
            {score.toFixed(0)}
          </div>
          <div>
            <div className="text-sm text-slate-500 font-medium">/ 100</div>
            <div className="text-xs text-slate-400 mt-1">Risk level</div>
            <div className={`text-sm font-bold ${riskStyle.textDark}`}>
              {riskBandPlainEnglish(data.risk_band)}
            </div>
          </div>
        </div>

        <div className="space-y-3 min-w-0">
          <div className="w-full h-2 bg-slate-100 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all ${riskStyle.bg}`}
              style={{ width: `${pct}%` }}
            />
          </div>
          <p className="text-sm text-slate-700 leading-relaxed">{riskLevelMeaning(data)}</p>
          <div className="p-3 rounded-lg bg-blue-50 border border-blue-100">
            <div className="text-[10px] font-bold uppercase tracking-wide text-blue-800 mb-1">
              Recommended action
            </div>
            <p className="text-sm text-blue-950 leading-relaxed">
              {data.recommended_action || riskRecommendedAction(data)}
            </p>
          </div>
          <button
            type="button"
            onClick={() => openLedger('full')}
            className="text-xs font-semibold px-4 py-2.5 bg-blue-700 text-white rounded-lg hover:bg-blue-800 transition-colors"
          >
            View Score Breakdown
          </button>
        </div>
      </div>
    </SocCard>
  );
}
