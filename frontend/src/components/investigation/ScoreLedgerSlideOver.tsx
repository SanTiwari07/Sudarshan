import { X } from 'lucide-react';
import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import { filterLedgerByScope, getAxesUsed, estimateBaseFrs } from '../../lib/scoreLedger';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { exportLedgerCSV } from '../../utils/derive';

export default function ScoreLedgerSlideOver({
  data,
  bundle,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle;
}) {
  const { ledgerOpen, ledgerScope, closeLedger, openEvidence } = useInvestigationUI();
  if (!ledgerOpen) return null;

  const lines = filterLedgerByScope(bundle.ledgerLines, ledgerScope);
  const axesUsed = getAxesUsed(data);
  const baseEst = estimateBaseFrs(data);

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-slate-900/40" onClick={closeLedger} />
      <div
        className="relative w-full max-w-xl bg-white h-full shadow-2xl border-l border-slate-200 flex flex-col"
        role="dialog"
        aria-label="Score ledger"
      >
        <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between shrink-0">
          <div>
            <h2 className="text-sm font-bold text-slate-900">Score ledger</h2>
            <p className="text-[10px] text-slate-500 font-mono">
              FRS = Σ(component × axes_used weight) · scope: {ledgerScope}
            </p>
          </div>
          <button type="button" onClick={closeLedger} className="p-1.5 rounded hover:bg-slate-100">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="px-5 py-3 bg-slate-50 border-b border-slate-200 text-xs space-y-1">
          <div>
            Base (deterministic est.): <strong>{baseEst.toFixed(2)}</strong>
          </div>
          <div>
            AI multiplier: <strong>×{data.ai_confidence_multiplier.toFixed(2)}</strong> → Final{' '}
            <strong>{data.final_risk_score.toFixed(0)}</strong>
          </div>
          <div className="text-slate-500">
            Weights:{' '}
            {Object.entries(axesUsed)
              .map(([k, v]) => `${k} ${(v * 100).toFixed(0)}%`)
              .join(' · ')}
          </div>
        </div>
        <div className="flex-1 overflow-y-auto p-4 space-y-2">
          {lines.map((line) => (
            <div
              key={line.id}
              className="border border-slate-200 rounded-lg p-3 text-xs bg-white hover:border-blue-200"
            >
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="font-semibold text-slate-800">{line.label}</div>
                  <div className="text-slate-600 mt-1 leading-relaxed">{line.detail}</div>
                </div>
                {line.contributionLabel && (
                  <span className="font-mono text-amber-700 font-bold shrink-0">{line.contributionLabel}</span>
                )}
              </div>
              {line.evidenceIds.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-2">
                  {line.evidenceIds.map((id) => (
                    <button
                      key={id}
                      type="button"
                      onClick={() => openEvidence(id)}
                      className="font-mono text-[10px] px-1.5 py-0.5 bg-blue-50 text-blue-700 rounded border border-blue-100"
                    >
                      {id}
                    </button>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
        <div className="p-4 border-t border-slate-200 shrink-0">
          <button
            type="button"
            onClick={() => exportLedgerCSV(data, bundle.ledgerLines)}
            className="w-full text-xs font-semibold py-2 border border-slate-300 rounded-lg hover:bg-slate-50"
          >
            Export ledger CSV
          </button>
        </div>
      </div>
    </div>
  );
}
