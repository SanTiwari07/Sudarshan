import { useEffect } from 'react';
import { Navigate, useLocation, useParams } from 'react-router-dom';
import { LoadingSpinner } from '../ui/Skeleton';
import { useAnalysis } from '../../context/AnalysisContext';
import { InvestigationUIProvider } from '../../context/InvestigationUIContext';
import CaseHeader from './CaseHeader';
import ScoreLedgerSlideOver from './ScoreLedgerSlideOver';
import EvidenceDrawer from './EvidenceDrawer';
import FindingExplanationDrawer from './FindingExplanationDrawer';
import FindingEvidenceDrawer from './FindingEvidenceDrawer';
import ScoreInfluenceDetailDrawer from './ScoreInfluenceDetailDrawer';
import AnalystNotesPanel from './AnalystNotesPanel';

function InvestigationChrome({ children }: { children: React.ReactNode }) {
  const { pathname } = useLocation();
  const { sha256: routeSha } = useParams<{ sha256?: string }>();
  const { analysisResult, investigationBundle, loading, activeSha256, loadCaseByHash, runtimeEvidenceRaw } =
    useAnalysis();

  const showCaseHeader = pathname === '/fraud-card' || pathname.startsWith('/fraud-card/');

  const pendingHash = routeSha || activeSha256;

  useEffect(() => {
    if (!pendingHash) return;
    if (analysisResult?.sha256 === pendingHash) return;
    loadCaseByHash(pendingHash);
  }, [pendingHash, analysisResult?.sha256, loadCaseByHash]);

  if (!analysisResult) {
    if (loading || pendingHash) {
      return <LoadingSpinner label="Loading case…" />;
    }
    return <Navigate to="/" replace />;
  }

  const bundle = investigationBundle;

  return (
    <>
      {showCaseHeader && <CaseHeader data={analysisResult} />}
      {children}
      {bundle && (
        <>
          <ScoreLedgerSlideOver data={analysisResult} bundle={bundle} />
          <EvidenceDrawer data={analysisResult} bundle={bundle} />
          <FindingExplanationDrawer
            data={analysisResult}
            bundle={bundle}
            rawRuntime={runtimeEvidenceRaw}
          />
          <FindingEvidenceDrawer data={analysisResult} bundle={bundle} rawRuntime={runtimeEvidenceRaw} />
          <ScoreInfluenceDetailDrawer data={analysisResult} bundle={bundle} />
        </>
      )}
      <AnalystNotesPanel sha256={analysisResult.sha256} />
    </>
  );
}

export default function InvestigationShell({
  children,
  className = 'analyst-page',
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <InvestigationUIProvider>
      <div className={className}>
        <InvestigationChrome>{children}</InvestigationChrome>
      </div>
    </InvestigationUIProvider>
  );
}
