import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import ScoreLedgerSlideOver from './ScoreLedgerSlideOver';
import EvidenceDrawer from './EvidenceDrawer';
import FindingExplanationDrawer from './FindingExplanationDrawer';
import FindingEvidenceDrawer from './FindingEvidenceDrawer';
import ScoreInfluenceDetailDrawer from './ScoreInfluenceDetailDrawer';
import TechnicalEvidenceDrawer from './TechnicalEvidenceDrawer';
import AiAssistantDrawer from './AiAssistantDrawer';

export default function InvestigationDrawers({
  data,
  bundle,
  rawRuntime,
}: {
  data: FraudCardData;
  bundle?: InvestigationBundle;
  rawRuntime?: Record<string, unknown>[];
}) {
  const { activeDrawer } = useInvestigationUI();
  if (!activeDrawer) return null;

  switch (activeDrawer.kind) {
    case 'score-ledger':
      return <ScoreLedgerSlideOver data={data} bundle={bundle!} />;
    case 'evidence':
      return <EvidenceDrawer data={data} bundle={bundle!} />;
    case 'finding-explanation':
      return <FindingExplanationDrawer data={data} bundle={bundle!} rawRuntime={rawRuntime || []} />;
    case 'finding-evidence':
      return <FindingEvidenceDrawer data={data} bundle={bundle!} rawRuntime={rawRuntime || []} />;
    case 'score-influence':
      return <ScoreInfluenceDetailDrawer data={data} bundle={bundle!} />;
    case 'technical-evidence':
      return <TechnicalEvidenceDrawer data={data} />;
    case 'ask-ai':
      return <AiAssistantDrawer data={data} />;
    default:
      return null;
  }
}
