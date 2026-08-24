import type { FraudCardData } from '../../../App';
import type { InvestigationBundle } from '../../../types/investigation';
import { buildFrsAxisTransparency, buildRuntimeInfluenceView } from '../../../lib/scoreInfluenceModel';
import { useInvestigationUI } from '../../../context/InvestigationUIContext';
import { DetailSection, FlowSteps, FrsAxisTransparencyTable } from './InfluenceDetailShell';

export default function RuntimeBehaviourDetail({
  data,
  bundle,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle;
}) {
  const view = buildRuntimeInfluenceView(data, bundle);
  const frsRows = buildFrsAxisTransparency('dynamic', data);
  const { openEvidence } = useInvestigationUI();

  return (
    <div className="space-y-6">
      <DetailSection title="Runtime verdict">
        <div
          className={`rounded-lg border p-4 ${
            view.includedInFrs ? 'border-emerald-200 bg-emerald-50/50' : 'border-amber-200 bg-amber-50/40'
          }`}
        >
          <div className="text-lg font-black tracking-wide text-slate-900">{view.statusHeadline}</div>
          {view.observedScore != null && (
            <p className="text-sm mt-2">
              Observed runtime score:{' '}
              <span className="font-mono font-bold">{view.observedScore.toFixed(1)} / 100</span>
            </p>
          )}
          <p className="text-sm mt-2">
            Included in FRS:{' '}
            <strong className={view.includedInFrs ? 'text-emerald-800' : 'text-amber-900'}>
              {view.includedInFrs ? 'YES' : 'NO'}
            </strong>
          </p>
          {!view.includedInFrs && (
            <p className="text-xs text-amber-900 mt-2 leading-relaxed">
              Observed runtime score ≠ score used in final FRS when the axis is excluded.
            </p>
          )}
        </div>
      </DetailSection>

      {view.telemetry.length > 0 && (
        <DetailSection title="What happened during runtime">
          <dl className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
            {(view.telemetry as any[]).map((t: any) => (
              <div key={t.label} className="rounded-lg border border-slate-200 bg-slate-50/80 p-2.5">
                <dt className="text-[10px] font-bold uppercase text-slate-500">{t.label}</dt>
                <dd className="font-mono font-semibold text-slate-900 mt-0.5">{t.value}</dd>
              </div>
            ))}
          </dl>
        </DetailSection>
      )}

      {view.eventGroups.length > 0 && (
        <DetailSection title="Runtime evidence">
          <div className="space-y-3">
            {(view.eventGroups as any[]).map((g: any) => (
              <div key={g.label} className="rounded-lg border border-slate-200 p-3">
                <div className="flex justify-between text-sm font-semibold text-slate-900">
                  <span>{g.label}</span>
                  <span className="font-mono text-slate-600">{g.count}</span>
                </div>
                <ul className="mt-2 space-y-1">
                  {(g.events || []).slice(0, 5).map((ev: any, idx: number) => {
                    const label = ev.title || ev.label || 'Runtime evidence';
                    return (
                      <li key={ev.id || idx}>
                        <button
                          type="button"
                          onClick={() => openEvidence(ev.id)}
                          aria-label={`View runtime evidence: ${label}`}
                          className="text-left text-xs text-blue-800 hover:underline w-full rounded px-1 py-0.5 cursor-pointer hover:bg-blue-50/60 focus-visible:outline focus-visible:outline-2 focus-visible:outline-blue-500 focus-visible:outline-offset-1"
                        >
                          <span className="font-semibold">{label}</span>
                          {ev.severity && <span className="text-slate-500"> - {ev.severity}</span>}
                        </button>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ))}
          </div>
        </DetailSection>
      )}

      {view.exclusionReason && (
        <DetailSection title="Why was it excluded?">
          <p className="text-sm text-slate-700 leading-relaxed">{view.exclusionReason}</p>
          <div className="mt-3 rounded-lg border border-slate-200 p-3 text-xs space-y-1">
            <div>
              <span className="text-slate-500">Dynamic axis</span>{' '}
              <strong className="text-amber-800">Excluded</strong>
            </div>
            <div>
              <span className="text-slate-500">FRS behavior</span>{' '}
              <span className="text-slate-800">Remaining available axes were renormalized.</span>
            </div>
          </div>
        </DetailSection>
      )}

      <DetailSection title="What would make runtime conclusive?">
        <ul className="text-xs text-slate-600 space-y-1 list-disc pl-4">
          {(view.conclusiveHints as any[]).map((h: any) => (
            <li key={h}>{h}</li>
          ))}
        </ul>
      </DetailSection>

      <DetailSection title="Evidence → score">
        <FlowSteps
          steps={[
            'Sandbox telemetry & hook events',
            'BFCI / dynamic axis score (observed)',
            view.includedInFrs && view.frsContribution != null
              ? `FRS contribution: ~${view.frsContribution.toFixed(2)} pts`
              : 'Dynamic axis excluded from FRS (not scored as zero)',
          ]}
        />
      </DetailSection>

      <DetailSection title="Runtime limitations">
        <p className="text-sm text-slate-700 leading-relaxed">
          Inconclusive runtime evidence does not prove that the APK is benign. It means the available runtime execution
          did not provide sufficient observable evidence for the dynamic axis.
        </p>
      </DetailSection>

      <DetailSection title="FRS contribution">
        <FrsAxisTransparencyTable rows={frsRows} />
      </DetailSection>
    </div>
  );
}
