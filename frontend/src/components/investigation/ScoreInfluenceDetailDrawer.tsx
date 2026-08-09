import { Activity, Code, Globe, X } from 'lucide-react';
import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import type { ScoreInfluenceAxis } from '../../lib/scoreInfluenceModel';
import {
  buildRuntimeInfluenceView,
  buildStaticInfluenceView,
  buildThreatInfluenceView,
} from '../../lib/scoreInfluenceModel';
import { mergeIntelWithCase } from '../../lib/intelPayloadMerge';
import { useIntelPayload } from '../../hooks/useIntelPayload';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import StaticEvidenceDetail from './scoreInfluence/StaticEvidenceDetail';
import RuntimeBehaviourDetail from './scoreInfluence/RuntimeBehaviourDetail';
import ThreatIntelligenceDetail from './scoreInfluence/ThreatIntelligenceDetail';

const AXIS_META: Record<
  ScoreInfluenceAxis,
  { title: string; icon: typeof Code; ledgerScope: 'stei' | 'dynamic' | 'correlation' }
> = {
  static: { title: 'Static evidence', icon: Code, ledgerScope: 'stei' },
  runtime: { title: 'Runtime behaviour', icon: Activity, ledgerScope: 'dynamic' },
  threat: { title: 'Threat intelligence', icon: Globe, ledgerScope: 'correlation' },
};

export default function ScoreInfluenceDetailDrawer({
  data,
  bundle,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle;
}) {
  const { influenceDetailOpen, influenceAxis, closeInfluenceDetail, openLedger } = useInvestigationUI();
  const axis: ScoreInfluenceAxis = influenceAxis ?? 'static';
  const meta = AXIS_META[axis];
  const Icon = meta.icon;

  const intelEnabled = influenceDetailOpen && axis === 'threat';
  const { merged, loading, error } = useIntelPayload({ enabled: intelEnabled, data });

  const threatMerged = merged ?? mergeIntelWithCase(data, null);

  if (!influenceDetailOpen || !influenceAxis) return null;

  let headerScore = '';
  let headerInfluence = '';
  let tagline = '';

  if (axis === 'static') {
    const v = buildStaticInfluenceView(data);
    headerScore = `${v.score.toFixed(0)} / 100`;
    headerInfluence = v.influence;
    tagline = v.tagline;
  } else if (axis === 'runtime') {
    const v = buildRuntimeInfluenceView(data, bundle);
    headerScore = v.includedInFrs && v.observedScore != null ? `${v.observedScore.toFixed(1)} / 100` : 'Not included';
    headerInfluence = v.influence;
    tagline = v.tagline;
  } else {
    const v = buildThreatInfluenceView(data, threatMerged);
    headerScore = v.axisIncluded ? `${v.score.toFixed(0)} / 100` : 'Not included';
    headerInfluence = v.influence;
    tagline = v.tagline;
  }

  return (
    <div className="fixed inset-0 z-[55] flex justify-end">
      <div
        className="absolute inset-0 bg-slate-900/40 backdrop-blur-[1px]"
        onClick={closeInfluenceDetail}
        aria-hidden
      />
      <div
        className="relative w-full max-w-xl sm:max-w-2xl bg-white h-full shadow-2xl border-l border-slate-200 flex flex-col"
        role="dialog"
        aria-labelledby="score-influence-title"
      >
        <div className="px-5 sm:px-6 py-5 border-b border-slate-200 flex items-start justify-between gap-4 shrink-0">
          <div className="flex gap-3 min-w-0">
            <div className="p-2 rounded-xl bg-blue-50 text-blue-700 border border-blue-100 shrink-0">
              <Icon className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <h2 id="score-influence-title" className="text-base font-bold text-slate-900">
                {meta.title}
              </h2>
              <p className="text-xs font-mono text-slate-600 mt-0.5">{headerScore}</p>
              <p className="text-xs font-semibold text-blue-800 mt-1">{headerInfluence}</p>
              <p className="text-xs text-slate-500 mt-2 leading-relaxed">{tagline}</p>
            </div>
          </div>
          <button
            type="button"
            onClick={closeInfluenceDetail}
            className="p-1.5 rounded-lg hover:bg-slate-100 shrink-0"
            aria-label="Close"
          >
            <X className="h-4 w-4 text-slate-600" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-5 sm:px-6 py-6">
          {axis === 'static' && <StaticEvidenceDetail data={data} />}
          {axis === 'runtime' && <RuntimeBehaviourDetail data={data} bundle={bundle} />}
          {axis === 'threat' && (
            <ThreatIntelligenceDetail
              data={data}
              merged={threatMerged}
              fetchState={loading ? 'loading' : error ? 'error' : 'idle'}
              fetchError={error}
            />
          )}
        </div>

        <div className="shrink-0 border-t border-slate-200 px-5 py-4 flex flex-wrap items-center justify-between gap-3 bg-white">
          <button
            type="button"
            onClick={() => openLedger(meta.ledgerScope)}
            className="text-xs font-semibold text-blue-700 hover:underline"
          >
            Open score ledger (this axis)
          </button>
          <button
            type="button"
            onClick={closeInfluenceDetail}
            className="px-4 py-2 text-xs font-semibold text-slate-700 border border-slate-300 rounded-lg hover:bg-slate-50"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
