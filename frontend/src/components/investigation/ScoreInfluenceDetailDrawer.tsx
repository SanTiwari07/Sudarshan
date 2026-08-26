import { Activity, Code, Globe } from 'lucide-react';
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
import DrawerShell from '../ui/DrawerShell';
import { TYPOGRAPHY } from '../../theme/typography';
import StaticEvidenceDetail from './scoreInfluence/StaticEvidenceDetail';
import RuntimeBehaviourDetail from './scoreInfluence/RuntimeBehaviourDetail';
import ThreatIntelligenceDetail from './scoreInfluence/ThreatIntelligenceDetail';

const AXIS_META: Record<
  ScoreInfluenceAxis,
  { title: string; icon: typeof Code; ledgerScope: 'stei' | 'dynamic' | 'correlation' }
> = {
  static: { title: 'Static evidence', icon: Code, ledgerScope: 'stei' },
  dynamic: { title: 'Runtime behaviour', icon: Activity, ledgerScope: 'dynamic' },
  threat_intel: { title: 'Threat intelligence', icon: Globe, ledgerScope: 'correlation' },
  vide: { title: 'Visual evidence', icon: Globe, ledgerScope: 'dynamic' },
};

export default function ScoreInfluenceDetailDrawer({
  data,
  bundle,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle;
}) {
  const { influenceDetailOpen, influenceAxis, closeInfluenceDetail, openLedger, canGoBack } =
    useInvestigationUI();
  const axis: ScoreInfluenceAxis = influenceAxis ?? 'static';
  const meta = AXIS_META[axis];

  const intelEnabled = influenceDetailOpen && axis === 'threat_intel';
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
  } else if (axis === 'dynamic') {
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
    <DrawerShell
      open
      onClose={closeInfluenceDetail}
      onBack={canGoBack ? closeInfluenceDetail : undefined}
      title={meta.title}
      labelledById="score-influence-title"
      subtitle={
        <span className="block space-y-0.5">
          <span className={`block ${TYPOGRAPHY.codeSm}`}>{headerScore}</span>
          <span className="block text-[11px] font-medium text-blue-800">{headerInfluence}</span>
          <span className={`block ${TYPOGRAPHY.caption} pt-1`}>{tagline}</span>
        </span>
      }
      footer={
        <button
          type="button"
          onClick={() => openLedger(meta.ledgerScope)}
          aria-label={`Open score ledger for ${meta.title}`}
          className={TYPOGRAPHY.linkAction}
        >
          Open score ledger for this axis
        </button>
      }
    >
      {axis === 'static' && <StaticEvidenceDetail data={data} />}
      {axis === 'dynamic' && <RuntimeBehaviourDetail data={data} bundle={bundle} />}
      {axis === 'threat_intel' && (
        <ThreatIntelligenceDetail
          data={data}
          merged={threatMerged}
          fetchState={loading ? 'loading' : error ? 'error' : 'idle'}
          fetchError={error}
        />
      )}
    </DrawerShell>
  );
}
