import { useEffect } from 'react';
import { Navigate, useParams } from 'react-router-dom';
import { LoadingSpinner } from '../ui/Skeleton';
import { useAnalysis } from '../../context/AnalysisContext';
import { InvestigationUIProvider } from '../../context/InvestigationUIContext';
import CaseBar from './CaseBar';
import InvestigationDrawers from './InvestigationDrawers';
import AnalystNotesPanel from './AnalystNotesPanel';

function InvestigationChrome({ children }: { children: React.ReactNode }) {
  const { sha256: routeSha } = useParams<{ sha256?: string }>();
  const { analysisResult, investigationBundle, loading, activeSha256, loadCaseByHash, runtimeEvidenceRaw } =
    useAnalysis();

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
      {/*
        One case bar on every section.

        It carries identity, the verdict and the section tabs, so moving between
        Case, Evidence, Intelligence and Ask reads as turning a page inside one
        investigation rather than leaving it. The summary route keeps it too:
        this is thin sticky navigation, not a second hero competing with
        VerdictBlock for the same job.
      */}
      <CaseBar data={analysisResult} />
      {children}
      {bundle && (
        <InvestigationDrawers
          data={analysisResult}
          bundle={bundle}
          rawRuntime={runtimeEvidenceRaw}
        />
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
