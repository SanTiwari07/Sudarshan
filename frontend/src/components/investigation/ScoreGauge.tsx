import type { FraudCardData } from '../../types/case';
import { formatScore } from '../../lib/verdictCopy';
import { caseSeverity } from '../../theme/severity';
import { isInconclusive } from '../../lib/decision';
import { scoreTone } from '../../theme/riskTone';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { Calculator, ChevronRight, ShieldAlert } from 'lucide-react';

const TICKS = 44;
/** Degrees swept, centred on straight up. */
const SWEEP = 220;
const START = 90 + SWEEP / 2;

export default function ScoreGauge({ data }: { data: FraudCardData }) {
  const { openLedger } = useInvestigationUI();
  const inconclusive = isInconclusive(data);
  const token = caseSeverity(data.risk_band, inconclusive);
  const raw = Number(data.final_risk_score);
  const score = Number.isFinite(raw) ? Math.max(0, Math.min(100, raw)) : 0;
  const tone = scoreTone(score);

  const cx = 100;
  const cy = 94;
  const rOuter = 86;
  const rInner = 68;

  const ticks = Array.from({ length: TICKS }, (_, i) => {
    const t = i / (TICKS - 1);
    const value = t * 100;
    const deg = START - t * SWEEP;
    const rad = (deg * Math.PI) / 180;
    const cos = Math.cos(rad);
    const sin = Math.sin(rad);
    const reached = !inconclusive && value <= score;
    return {
      key: i,
      x1: cx + rInner * cos,
      y1: cy - rInner * sin,
      x2: cx + rOuter * cos,
      y2: cy - rOuter * sin,
      stroke: reached ? scoreTone(value).mark : '#e2e8f0',
      width: reached ? 3 : 2,
    };
  });

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => openLedger('full')}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          openLedger('full');
        }
      }}
      aria-label="Fraud risk score. Click to view calculation ledger."
      className="w-full h-full flex flex-col items-center justify-between p-5 rounded-2xl border border-slate-200 bg-white shadow-xs hover:border-blue-400 hover:shadow-md transition-all cursor-pointer group text-center focus:outline-none focus:ring-2 focus:ring-blue-500"
    >
      <div className="w-full flex items-center justify-between mb-1">
        <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
          <ShieldAlert className="h-3.5 w-3.5 text-slate-400 group-hover:text-blue-600 transition-colors" />
          Deterministic Risk Score
        </span>
        <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wider ${token.bg} ${token.fg} ${token.border} border`}>
          {token.label}
        </span>
      </div>

      <div className="relative w-[196px] my-1">
        <svg viewBox="0 0 200 128" className="w-full" role="img" aria-hidden>
          {ticks.map((t) => (
            <line
              key={t.key}
              x1={t.x1}
              y1={t.y1}
              x2={t.x2}
              y2={t.y2}
              stroke={t.stroke}
              strokeWidth={t.width}
              strokeLinecap="round"
            />
          ))}
        </svg>

        <p
          className={`absolute inset-x-0 top-[44%] flex items-baseline justify-center whitespace-nowrap font-sans text-[2.25rem] font-extrabold leading-none tracking-[-0.04em] tabular-nums ${
            inconclusive ? 'text-slate-400' : tone.text
          }`}
        >
          {inconclusive ? '-' : formatScore(score)}
          {!inconclusive && (
            <span className="ml-1 text-[1rem] font-semibold tracking-[-0.02em] text-slate-400">
              /100
            </span>
          )}
        </p>
      </div>

      <div className="w-full pt-2 border-t border-slate-100 flex items-center justify-between text-xs">
        <span className="text-slate-500 font-medium">Final deterministic verdict</span>
        <span className="inline-flex items-center gap-1 font-semibold text-blue-600 group-hover:text-blue-700 transition-colors">
          <Calculator className="h-3.5 w-3.5" />
          <span>How this was calculated</span>
          <ChevronRight className="h-3.5 w-3.5 group-hover:translate-x-0.5 transition-transform" />
        </span>
      </div>
    </div>
  );
}
