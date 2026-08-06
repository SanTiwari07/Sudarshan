import { Link } from 'react-router-dom';
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
      <div className="mb-4 flex flex-wrap gap-2 text-xs">
        <Link to="/fraud-card" className="px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50">
          Fraud analyst
        </Link>
        <Link to="/technical" className="px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50">
          SOC / technical
        </Link>
        <Link to="/threat-intel" className="px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50">
          Threat intel
        </Link>
        <Link to="/chat" className="px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50">
          AI assistant
        </Link>
      </div>
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

export default function InvestigationShell({ children }: { children: React.ReactNode }) {
  return (
    <InvestigationUIProvider>
      <InvestigationChrome>{children}</InvestigationChrome>
    </InvestigationUIProvider>
  );
}
