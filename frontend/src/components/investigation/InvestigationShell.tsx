import { useEffect } from 'react';
import { Navigate, useParams } from 'react-router-dom';
import { LoadingSpinner } from '../ui/Skeleton';
import { useAnalysis } from '../../context/AnalysisContext';
import { InvestigationUIProvider } from '../../context/InvestigationUIContext';
import CaseHeader from './CaseHeader';
import ScoreLedgerSlideOver from './ScoreLedgerSlideOver';
import EvidenceDrawer from './EvidenceDrawer';
import AnalystNotesPanel from './AnalystNotesPanel';

function InvestigationChrome({ children }: { children: React.ReactNode }) {
  const { sha256: routeSha } = useParams<{ sha256?: string }>();
  const { analysisResult, investigationBundle, loading, activeSha256, loadCaseByHash } = useAnalysis();

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
      <CaseHeader data={analysisResult} />
      {children}
      {bundle && (
        <>
          <ScoreLedgerSlideOver data={analysisResult} bundle={bundle} />
          <EvidenceDrawer data={analysisResult} bundle={bundle} />
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
