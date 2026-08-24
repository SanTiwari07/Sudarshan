import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  BadgeCheck,
  Bot,
  Calculator,
  ChevronDown,
  Code,
  Eye,
  FileText,
  Fingerprint,
  Info,
  Landmark,
  Layers,
  MessageSquare,
  PieChart,
  ShieldAlert,
  X,
} from 'lucide-react';
import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import Badge from '../ui/Badge';
import { getRiskStyle } from '../../theme/colors';
import { riskBandPlainEnglish } from '../../lib/analystCopy';
import {
  buildRiskDrivers,
  buildSuspiciousNarrative,
  buildWhatThisMeansNarrative,
  filterDriversByScope,
  type RiskDriver,
} from '../../lib/riskDrivers';
import {
  estimateBaseFrs,
  filterLedgerByScope,
  getAxesUsed,
} from '../../lib/scoreLedger';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { exportLedgerCSV } from '../../utils/derive';

const DRIVER_ICONS: Record<RiskDriver['iconKey'], typeof ShieldAlert> = {
  shield: ShieldAlert,
  layers: Layers,
  code: Code,
  fingerprint: Fingerprint,
  activity: Activity,
  message: MessageSquare,
  landmark: Landmark,
  eye: Eye,
};

function VerifiedBadge() {
  return (
    <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-emerald-700 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded-full">
      <BadgeCheck className="h-3 w-3" />
      Verified
    </span>
  );
}

function SourceBadge({ label }: { label: string }) {
  return (
    <span className="text-[10px] font-medium text-slate-600 bg-slate-100 border border-slate-200 px-2 py-0.5 rounded-md">
      {label}
    </span>
  );
}

function RiskDriverCard({ driver, onEvidence }: { driver: RiskDriver; onEvidence?: (id: string) => void }) {
  const Icon = DRIVER_ICONS[driver.iconKey];
  const impactClass =
    driver.impact === 'High Impact'
      ? 'bg-red-50 text-red-800 border-red-200'
      : driver.impact === 'Medium Impact'
        ? 'bg-amber-50 text-amber-900 border-amber-200'
        : 'bg-blue-50 text-blue-800 border-blue-200';

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm hover:border-blue-200 transition-colors">
      <div className="flex items-start gap-3">
        <div className="p-2 rounded-lg bg-slate-100 text-blue-700 shrink-0">
          <Icon className="h-4 w-4" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2 min-w-0">
              <span className="text-lg font-black text-amber-700 tabular-nums">+{driver.points}</span>
              <h3 className="text-sm font-bold text-slate-900">{driver.title}</h3>
            </div>
            <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${impactClass}`}>
              {driver.impact}
            </span>
          </div>
          <p className="text-xs text-slate-600 leading-relaxed mt-2">{driver.explanation}</p>
          <div className="flex flex-wrap items-center gap-2 mt-3">
            <VerifiedBadge />
            {driver.sources.map((s) => (
              <SourceBadge key={s} label={s} />
            ))}
            {driver.evidenceId && onEvidence && (
              <button
                type="button"
                onClick={() => onEvidence(driver.evidenceId!)}
                className="text-[10px] font-semibold text-blue-700 hover:underline"
              >
                View evidence
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function MathematicalAccordion({
  data,
  bundle,
  ledgerScope,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle;
  ledgerScope: import('../../types/investigation').LedgerScope;
}) {
  const [open, setOpen] = useState(false);
  const lines = filterLedgerByScope(bundle.ledgerLines, ledgerScope);
  const axesUsed = getAxesUsed(data);
  const baseEst = estimateBaseFrs(data);

  return (
    <div className="rounded-xl border border-slate-200 bg-white overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between gap-3 px-4 py-3 text-left hover:bg-slate-100/80 transition-colors"
      >
        <span className="flex items-center gap-2 text-sm font-semibold text-slate-800">
          <Calculator className="h-4 w-4 text-slate-500" />
          View Mathematical Calculation
        </span>
        <ChevronDown className={`h-4 w-4 text-slate-500 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-3 border-t border-slate-200 bg-white">
          <div className="text-xs text-slate-600 space-y-1 pt-3">
            <p>
              Base (deterministic estimate): <strong className="font-mono">{baseEst.toFixed(2)}</strong>
            </p>
            <p>
              AI multiplier: <strong className="font-mono">×{data.ai_confidence_multiplier.toFixed(2)}</strong> → Final{' '}
              <strong className="font-mono">{data.final_risk_score.toFixed(0)}</strong>
            </p>
            <p className="text-slate-500">
              Axis weights:{' '}
              {Object.entries(axesUsed)
                .map(([k, v]) => `${k} ${(v * 100).toFixed(0)}%`)
                .join(' · ')}
            </p>
            <p className="text-[11px] text-slate-500 leading-relaxed">
              FRS combines STEI (static), dynamic sandbox, threat correlation, and banking impact using deterministic
              weights. STEI sub-axes (CT, BT, PR, OB, IR) roll up before FRS weighting.
            </p>
          </div>
          <div className="max-h-64 overflow-y-auto space-y-2">
            {lines.map((line) => (
              <div key={line.id} className="border border-slate-200 rounded-lg p-2.5 text-[11px] bg-white">
                <div className="font-semibold text-slate-800">{line.label}</div>
                <div className="text-slate-600 mt-0.5 font-mono leading-relaxed">{line.detail}</div>
                {line.contributionLabel && (
                  <div className="text-amber-700 font-bold mt-1">{line.contributionLabel}</div>
                )}
              </div>
            ))}
          </div>
          <button
            type="button"
            onClick={() => exportLedgerCSV(data, bundle.ledgerLines)}
            className="w-full text-xs font-semibold py-2 border border-slate-300 rounded-lg hover:bg-slate-50"
          >
            Export ledger CSV
          </button>
        </div>
      )}
    </div>
  );
}

export default function ScoreLedgerSlideOver({
  data,
  bundle,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle;
}) {
  const { ledgerOpen, ledgerScope, closeLedger, openEvidence } = useInvestigationUI();
  if (!ledgerOpen) return null;

  const score = Math.round(data.final_risk_score);
  const riskStyle = getRiskStyle(data.risk_band);
  const allDrivers = buildRiskDrivers(data);
  const drivers = filterDriversByScope(allDrivers, ledgerScope);
  const compositionDrivers = ledgerScope === 'full' ? allDrivers : drivers;
  const suspicious = buildSuspiciousNarrative(data);
  const meaning = buildWhatThisMeansNarrative(data);
  const chatQuery = `Explain why this APK received a Fraud Risk Score of ${score}.`;

  return (
    <div className="fixed inset-0 z-[60] flex justify-end">
      <div className="absolute inset-0 bg-slate-900/40 backdrop-blur-[1px]" onClick={closeLedger} aria-hidden />
      <div
        className="relative w-full max-w-xl sm:max-w-2xl bg-white h-full shadow-2xl border-l border-slate-200 flex flex-col"
        role="dialog"
        aria-label="Score breakdown"
      >
        <div className="px-5 sm:px-6 py-5 border-b border-slate-200 flex items-start justify-between gap-4 shrink-0 bg-white">
          <div className="min-w-0 flex gap-3">
            <div className="p-2 rounded-xl bg-blue-50 text-blue-700 border border-blue-100 shrink-0">
              <ShieldAlert className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <h2 className="text-base font-bold text-slate-900">Why this APK scored {score}/100</h2>
              <p className="text-xs text-slate-500 mt-1 leading-relaxed max-w-md">
                Fraud Risk Score is calculated from verified static analysis, runtime behaviour, threat intelligence and
                deterministic risk models.
              </p>
            </div>
          </div>
          <div className="flex flex-col items-end gap-2 shrink-0">
            <button type="button" onClick={closeLedger} className="p-1.5 rounded-lg hover:bg-slate-100">
              <X className="h-4 w-4 text-slate-600" />
            </button>
            <div className="text-right">
              <div className={`text-2xl font-black tabular-nums ${riskStyle.text}`}>
                {score}
                <span className="text-sm text-slate-400 font-medium"> / 100</span>
              </div>
              <Badge label={riskBandPlainEnglish(data.risk_band)} variant="risk" />
            </div>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto px-5 sm:px-6 py-6 space-y-8">
          <section className="space-y-3">
            <h3 className="flex items-center gap-2 text-sm font-bold text-slate-900">
              <Info className="h-4 w-4 text-blue-600" />
              Why this APK is Suspicious
            </h3>
            <div className="rounded-xl border border-slate-200 bg-white p-4 sm:p-5 space-y-3 shadow-sm">
              {suspicious.map((para, i) => (
                <p key={i} className="text-sm text-slate-700 leading-relaxed">
                  {para}
                </p>
              ))}
            </div>
          </section>

          <section className="space-y-3">
            <h3 className="text-sm font-bold text-slate-900">Why the Score Increased</h3>
            <div className="space-y-3">
              {drivers.length === 0 ? (
                <p className="text-sm text-slate-600">No scoped risk drivers for this view. Open full breakdown.</p>
              ) : (
                drivers.map((driver) => (
                  <RiskDriverCard key={driver.id} driver={driver} onEvidence={openEvidence} />
                ))
              )}
            </div>
          </section>

          <section className="space-y-3">
            <h3 className="flex items-center gap-2 text-sm font-bold text-slate-900">
              <PieChart className="h-4 w-4 text-blue-600" />
              Final Fraud Risk
            </h3>
            <div className="rounded-xl border border-slate-200 bg-white p-4 sm:p-5 shadow-sm space-y-3">
              {compositionDrivers.map((driver) => (
                <div key={driver.id} className="flex items-center justify-between gap-3 text-sm">
                  <span className="text-slate-700">{driver.title}</span>
                  <span className="font-mono font-bold text-amber-700 tabular-nums">+{driver.points}</span>
                </div>
              ))}
              <div className="border-t border-slate-200 pt-4 mt-2 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-bold text-slate-900">Final Fraud Risk Score</span>
                  <div className="text-right">
                    <span className={`text-xl font-black tabular-nums ${riskStyle.text}`}>{score}</span>
                    <span className="text-xs text-slate-400"> / 100</span>
                    <div className="mt-1">
                      <Badge label={riskBandPlainEnglish(data.risk_band)} variant="risk" />
                    </div>
                  </div>
                </div>
                <div className="h-2.5 bg-slate-100 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-700 ${riskStyle.bg}`}
                    style={{ width: `${Math.min(100, score)}%` }}
                  />
                </div>
              </div>
            </div>
          </section>

          <section className="space-y-3">
            <h3 className="flex items-center gap-2 text-sm font-bold text-slate-900">
              <FileText className="h-4 w-4 text-blue-600" />
              What this means
            </h3>
            <div className="rounded-xl border border-blue-100 bg-blue-50/40 p-4 sm:p-5 space-y-3">
              {meaning.map((para, i) => (
                <p key={i} className="text-sm text-slate-800 leading-relaxed">
                  {para}
                </p>
              ))}
            </div>
          </section>

          <section className="space-y-4 pt-2 border-t border-slate-200">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
              <div>
                <p className="flex items-center gap-2 text-sm font-semibold text-slate-900">
                  <Bot className="h-4 w-4 text-blue-600" />
                  Still have questions?
                </p>
                <p className="text-xs text-slate-500 mt-1">
                  Ask the AI Investigation Assistant to explain any finding in more detail.
                </p>
              </div>
              <Link
                to={`/chat?q=${encodeURIComponent(chatQuery)}`}
                onClick={closeLedger}
                className="inline-flex items-center justify-center gap-2 px-4 py-2.5 text-xs font-semibold text-white bg-blue-700 rounded-lg hover:bg-blue-800 transition-colors shrink-0"
              >
                Open AI Investigation Assistant
              </Link>
            </div>
          </section>

          <MathematicalAccordion data={data} bundle={bundle} ledgerScope={ledgerScope} />
        </div>
      </div>
    </div>
  );
}
