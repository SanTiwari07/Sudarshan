import type { FraudCardData } from '../../App';
import SocCard from '../ui/Card';
import { getRiskStyle } from '../../theme/colors';
import {
  riskBandPlainEnglish,
  riskLevelMeaning,
  riskRecommendedAction,
} from '../../lib/analystCopy';
import HelpTerm from './HelpTerm';
import { Gauge, TrendingUp } from 'lucide-react';
import { useInvestigationUI } from '../../context/InvestigationUIContext';

function scoreDrivers(data: FraudCardData): string[] {
  const lines = data.risk_explanation?.evidence_lines?.filter(Boolean) ?? [];
  if (lines.length > 0) return lines.slice(0, 6);

  const drivers: string[] = [];
  if (data.has_accessibility_abuse) drivers.push('Accessibility abuse observed');
  if (data.has_system_alert_window) drivers.push('Overlay / system alert window capability');
  if (data.has_sms_read_write) drivers.push('SMS read/write - OTP interception risk');
  if (data.targets_indian_banks) drivers.push('Banking application targeting');
  if (data.family_classification !== 'Unknown') drivers.push(`Malware family: ${data.family_classification}`);
  const frs = data.frs_breakdown;
  if (frs?.dynamic_ran && frs.dynamic_conclusive) drivers.push('Runtime analysis contributed to score');
  return drivers;
}

export default function RiskScorePanel({ data }: { data: FraudCardData }) {
  const riskStyle = getRiskStyle(data.risk_band);
  const { openLedger } = useInvestigationUI();
  const score = data.final_risk_score;
  const pct = Math.min(100, Math.max(0, score));
  const drivers = scoreDrivers(data);
  const dynamicAxis = data.frs_breakdown?.dynamic;

  return (
    <SocCard>
      <div className="px-4 sm:px-5 py-3 border-b border-slate-200 bg-slate-50 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <Gauge className="h-4 w-4 text-blue-700 shrink-0" />
            <h2 className="text-sm font-semibold text-slate-900">Fraud Risk Score</h2>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            <HelpTerm term="Risk Score">Weighted score</HelpTerm> from verified evidence - not a malware verdict alone.
          </p>
        </div>
        <span
          className={`text-[10px] font-bold uppercase tracking-wide px-2.5 py-1 rounded-full shrink-0 ${riskStyle.badge}`}
        >
          {riskBandPlainEnglish(data.risk_band)}
        </span>
      </div>

      <div className="p-4 sm:p-5 grid grid-cols-1 xl:grid-cols-12 gap-5 xl:gap-6 items-start">
        <div className="xl:col-span-4 flex flex-wrap xl:flex-nowrap items-center gap-4">
          <div className={`text-5xl sm:text-6xl font-black tabular-nums ${riskStyle.text}`}>
            {score.toFixed(0)}
          </div>
          <div className="min-w-0">
            <div className="text-sm text-slate-500 font-medium">/ 100</div>
            <div className={`text-base font-bold mt-1 ${riskStyle.textDark}`}>
              {riskBandPlainEnglish(data.risk_band)}
            </div>
            {dynamicAxis != null && data.frs_breakdown?.dynamic_ran && (
              <div className="flex items-center gap-1 text-[11px] text-slate-500 mt-2">
                <TrendingUp className="h-3.5 w-3.5 text-blue-600" />
                Runtime axis: <span className="font-mono font-semibold text-slate-700">{dynamicAxis.toFixed(1)}</span>
              </div>
            )}
          </div>
        </div>

        <div className="xl:col-span-8 space-y-3 min-w-0">
          <div className="w-full h-2.5 bg-slate-100 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all ${riskStyle.bg}`}
              style={{ width: `${pct}%` }}
            />
          </div>
          <p className="text-sm text-slate-700 leading-relaxed">{riskLevelMeaning(data)}</p>

          {drivers.length > 0 && (
            <div className="rounded-lg border border-slate-200 bg-slate-50/80 px-3 py-2.5">
              <div className="text-[10px] font-bold uppercase tracking-wide text-slate-500 mb-1.5">Based on</div>
              <ul className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1 text-xs text-slate-700">
                {drivers.map((line) => (
                  <li key={line} className="flex items-start gap-2">
                    <span className="w-1 h-1 rounded-full bg-blue-500 mt-1.5 shrink-0" />
                    <span className="min-w-0">{line}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

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
            View score breakdown
          </button>
        </div>
      </div>
    </SocCard>
  );
}
