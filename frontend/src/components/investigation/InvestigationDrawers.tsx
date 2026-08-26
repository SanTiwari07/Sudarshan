import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import ScoreLedgerSlideOver from './ScoreLedgerSlideOver';
import EvidenceDrawer from './EvidenceDrawer';
import FindingExplanationDrawer from './FindingExplanationDrawer';
import FindingEvidenceDrawer from './FindingEvidenceDrawer';
import ScoreInfluenceDetailDrawer from './ScoreInfluenceDetailDrawer';

/**
 * The single mount point for investigation overlays.
 *
 * All five drawers used to be mounted unconditionally by InvestigationShell,
 * each self-gating on its own piece of context state. Two costs to that:
 *
 * - Their hooks ran whether or not they were visible. The score-influence
 *   drawer calls `useIntelPayload`, so a closed drawer was participating in
 *   fetch scheduling for a panel nobody had opened.
 * - Nothing enforced that only one was visible, and the state they gated on
 *   did not coordinate, so overlays could genuinely stack.
 *
 * Switching on the top of the drawer stack means exactly one drawer exists at a
 * time, and "which one" is answered in one place rather than inferred from five
 * independent booleans.
 */
export default function InvestigationDrawers({
  data,
  bundle,
  rawRuntime,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle;
  rawRuntime: Record<string, unknown>[];
}) {
  const { activeDrawer } = useInvestigationUI();
  if (!activeDrawer) return null;

  switch (activeDrawer.kind) {
    case 'score-ledger':
      return <ScoreLedgerSlideOver data={data} bundle={bundle} />;
    case 'evidence':
      return <EvidenceDrawer data={data} bundle={bundle} />;
    case 'finding-explanation':
      return <FindingExplanationDrawer data={data} bundle={bundle} rawRuntime={rawRuntime} />;
    case 'finding-evidence':
      return <FindingEvidenceDrawer data={data} bundle={bundle} rawRuntime={rawRuntime} />;
    case 'score-influence':
      return <ScoreInfluenceDetailDrawer data={data} bundle={bundle} />;
    default:
      return null;
  }
}
