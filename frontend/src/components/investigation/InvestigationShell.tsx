import { Navigate } from 'react-router-dom';
import { LoadingSpinner } from '../ui/Skeleton';
import { useAnalysis } from '../../context/AnalysisContext';
import { InvestigationUIProvider, useInvestigationUI } from '../../context/InvestigationUIContext';
import CaseHeader from './CaseHeader';
import ScoreLedgerSlideOver from './ScoreLedgerSlideOver';
import EvidenceDrawer from './EvidenceDrawer';
import AnalystNotesPanel from './AnalystNotesPanel';

function InvestigationChrome({ children }: { children: React.ReactNode }) {
  const { analysisResult, investigationBundle, loading } = useAnalysis();
  const { openLedger } = useInvestigationUI();

  if (loading && !analysisResult) {
    return <LoadingSpinner label="Loading case…" />;
  }

  if (!analysisResult) {
    return <Navigate to="/" replace />;
  }

  const bundle = investigationBundle;

  return (
    <>
      <CaseHeader data={analysisResult} onExplainScore={() => openLedger('full')} />
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
