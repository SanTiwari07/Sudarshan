import { ChevronDown } from 'lucide-react';
import { useState } from 'react';
import type { FraudCardData } from '../../../App';
import {
  buildStaticInfluenceView,
  buildFrsAxisTransparency,
  steiAxisRows,
} from '../../../lib/scoreInfluenceModel';
import { DetailSection, FlowSteps, FrsAxisTransparencyTable, MonoBlock } from './InfluenceDetailShell';

export default function StaticEvidenceDetail({ data }: { data: FraudCardData }) {
  const view = buildStaticInfluenceView(data);
  const frsRows = buildFrsAxisTransparency(data);
  const [openId, setOpenId] = useState<string | null>(null);

  if (view.unavailable) {
    return <p className="text-sm text-slate-600">Static analysis unavailable for this case.</p>;
  }

  return (
    <div className="space-y-6">
      <DetailSection title="Why this score exists">
        <p className="text-sm text-slate-700 leading-relaxed">{view.whyScore}</p>
      </DetailSection>

      {view.findings.length > 0 && (
        <DetailSection title="Key findings">
          <ul className="space-y-2">
            {view.findings.map((f) => {
              const open = openId === f.id;
              return (
                <li key={f.id} className="rounded-lg border border-slate-200 bg-white overflow-hidden">
                  <button
                    type="button"
                    onClick={() => setOpenId(open ? null : f.id)}
                    className="w-full flex items-center justify-between gap-2 px-3 py-2.5 text-left hover:bg-slate-50"
                  >
                    <span className="text-sm font-semibold text-slate-900">{f.title}</span>
                    <ChevronDown className={`h-4 w-4 text-slate-400 shrink-0 transition-transform ${open ? 'rotate-180' : ''}`} />
                  </button>
                  {open && (
                    <div className="px-3 pb-3 space-y-2 text-xs border-t border-slate-100">
                      <div>
                        <div className="text-slate-500">What was detected</div>
                        <p className="text-slate-800 mt-0.5">{f.detected}</p>
                      </div>
                      <div>
                        <div className="text-slate-500">Why it matters</div>
                        <p className="text-slate-700 mt-0.5 leading-relaxed">{f.whyItMatters}</p>
                      </div>
                      <div>
                        <div className="text-slate-500">Evidence</div>
                        <MonoBlock>{f.evidence}</MonoBlock>
                      </div>
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        </DetailSection>
      )}

      <DetailSection title="Static analysis sources">
        <div className="space-y-3">
          {view.engines.map((eng) => (
            <div key={eng.name} className="rounded-lg border border-slate-200 p-3">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-semibold text-slate-900">{eng.name}</span>
                <span
                  className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${
                    eng.status === 'available'
                      ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                      : 'bg-slate-50 text-slate-500 border-slate-200'
                  }`}
                >
                  {eng.status === 'available' ? 'Available' : 'Not available'}
                </span>
              </div>
              <ul className="mt-2 space-y-1 text-xs text-slate-600">
                {eng.bullets.map((b) => (
                  <li key={b}>• {b}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </DetailSection>

      <DetailSection title="STEI contribution">
        <p className="text-xs text-slate-600 mb-2 leading-relaxed">
          STEI = 0.60×CT + 0.20×BT + 0.10×PR + 0.05×OB + 0.05×IR (deterministic engine values below).
        </p>
        <div className="space-y-2">
          {steiAxisRows(view.steiAxes).map((row) => (
            <div key={row.key} className="flex items-center justify-between gap-2 text-xs">
              <span className="text-slate-700">
                {row.label} <span className="text-slate-400">({row.weight})</span>
              </span>
              <span className="font-mono font-bold text-slate-900 tabular-nums">{row.value.toFixed(1)}</span>
            </div>
          ))}
          <div className="border-t border-slate-200 pt-2 flex justify-between text-sm font-bold">
            <span>STEI (static score)</span>
            <span className="font-mono tabular-nums">{view.steiTotal.toFixed(1)} / 100</span>
          </div>
        </div>
      </DetailSection>

      <DetailSection title="Evidence → score">
        <FlowSteps
          steps={[
            'Detected evidence (permissions, manifest, code, APIs)',
            'Static capability flags & STEI sub-axes',
            `STEI aggregate: ${view.steiTotal.toFixed(1)} / 100`,
            view.frsContribution != null
              ? `FRS contribution: ~${view.frsContribution.toFixed(2)} pts (weight ${view.frsWeightPct?.toFixed(1) ?? '—'}%)`
              : 'FRS: static axis excluded',
          ]}
        />
      </DetailSection>

      {view.hasVide && view.videSummary && (
        <DetailSection title="Visual impersonation (VIDE)">
          <p className="text-xs text-slate-700 leading-relaxed">{view.videSummary}</p>
          <p className="text-[11px] text-slate-500 mt-2">
            VIDE is deterministic and separate from VirusTotal / OTX / AbuseIPDB. Lab baselines are not production bank
            data.
          </p>
        </DetailSection>
      )}

      <DetailSection title="What this means">
        <p className="text-sm text-slate-700 leading-relaxed">
          This does not mean the APK was observed performing these actions at runtime. It means static indicators and
          capabilities associated with these behaviors are present in the package.
        </p>
      </DetailSection>

      <DetailSection title="Limitations">
        <ul className="text-xs text-slate-600 space-y-1.5 list-disc pl-4">
          <li>Presence of a permission does not prove exploitation.</li>
          <li>A suspicious API reference does not prove execution.</li>
          <li>Banking package references do not automatically prove credential theft.</li>
          <li>Runtime confirmation requires conclusive dynamic evidence.</li>
        </ul>
      </DetailSection>

      <DetailSection title="FRS contribution">
        <FrsAxisTransparencyTable rows={frsRows} />
      </DetailSection>
    </div>
  );
}
