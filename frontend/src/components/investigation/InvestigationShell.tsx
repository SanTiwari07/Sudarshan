import { useEffect } from 'react';
import { Navigate, useLocation, useParams } from 'react-router-dom';
import { LoadingSpinner, ErrorState } from '../ui/Skeleton';
import { useAnalysis } from '../../context/AnalysisContext';
import { InvestigationUIProvider } from '../../context/InvestigationUIContext';
import CaseBar from './CaseBar';
import InvestigationDrawers from './InvestigationDrawers';
import AnalystNotesPanel from './AnalystNotesPanel';
import { activeCaseSection } from '../../lib/caseRoutes';

function InvestigationChrome({
  children,
  contentClassName,
}: {
  children: React.ReactNode;
  contentClassName: string;
}) {
  const { sha256: routeSha } = useParams<{ sha256?: string }>();
  const section = activeCaseSection(useLocation().pathname);
  const { analysisResult, investigationBundle, loading, error, activeSha256, loadCaseByHash, runtimeEvidenceRaw } =
    useAnalysis();

  const pendingHash = routeSha || activeSha256;

  useEffect(() => {
    if (!pendingHash) return;
    if (analysisResult?.sha256 === pendingHash) return;
    loadCaseByHash(pendingHash);
  }, [pendingHash, analysisResult?.sha256, loadCaseByHash]);

  if (error) {
    return (
      <div className="w-full max-w-5xl mx-auto p-8">
        <ErrorState title="Case Restore Failed" message={error} />
      </div>
    );
  }

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

        It sits outside the per-section width wrapper. Inside it, the bar
        inherited whatever measure that section wanted - 1280px of centred
        prose on Case, 1920px of tables on Evidence - so the one piece of
        chrome that is meant to be identical everywhere visibly moved and
        resized as you changed tabs.
      */}
      <CaseBar data={analysisResult} />
      <div className={contentClassName}>{children}</div>
      {bundle && (
        <InvestigationDrawers
          data={analysisResult}
          bundle={bundle}
          rawRuntime={runtimeEvidenceRaw}
        />
      )}
      {/*
        Not on Ask.

        The notes launcher is a floating button in the bottom-right corner,
        which on the assistant page lands on top of the composer - a second
        place to type about the case, overlapping the first.
      */}
      {section !== 'ask' && <AnalystNotesPanel sha256={analysisResult.sha256} />}
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
      <InvestigationChrome contentClassName={className}>{children}</InvestigationChrome>
    </InvestigationUIProvider>
  );
}
