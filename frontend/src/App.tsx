import { Routes, Route, Navigate, useParams, useLocation, Location } from 'react-router-dom';
import Login from './pages/Login';
import AppShell from './components/layout/AppShell';
import { lazy, Suspense, useEffect } from 'react';
import ErrorBoundary from './components/ErrorBoundary';
import InvestigationShell from './components/investigation/InvestigationShell';
import { AnalysisProvider, useAnalysis } from './context/AnalysisContext';
import { caseSectionPath, type CaseSection } from './lib/caseRoutes';
import { AuthProvider, useAuth } from './context/AuthContext';
import { LoadingSpinner, ErrorState } from './components/ui/Skeleton';
import type { FraudCardData } from './types/case';

function lazyWithRetry<T extends React.ComponentType<any>>(
  componentImport: () => Promise<{ default: T }>
) {
  return lazy(async () => {
    const pageHasBeenRefreshed = JSON.parse(
      window.sessionStorage.getItem('page_has_been_refreshed') || 'false'
    );
    try {
      const component = await componentImport();
      window.sessionStorage.setItem('page_has_been_refreshed', 'false');
      return component;
    } catch (error) {
      if (!pageHasBeenRefreshed) {
        window.sessionStorage.setItem('page_has_been_refreshed', 'true');
        window.location.reload();
        return new Promise(() => {});
      }
      throw error;
    }
  });
}

// Lazy views
const Upload = lazyWithRetry(() => import('./pages/Upload'));
const FraudCard = lazyWithRetry(() => import('./pages/FraudCard'));
const TechnicalView = lazyWithRetry(() => import('./pages/TechnicalView'));
const ThreatIntelView = lazyWithRetry(() => import('./pages/ThreatIntelView'));
const History = lazyWithRetry(() => import('./pages/History'));
const InvestigationChat = lazyWithRetry(() => import('./pages/InvestigationChat'));
const BatchScan = lazyWithRetry(() => import('./pages/BatchScan'));
const BatchDetail = lazyWithRetry(() => import('./pages/BatchDetail'));

export * from './types/case';

// ─── Auth Guard & Wrappers ──────────────────────────────────────────────────

function RouteFallback() {
  return <LoadingSpinner label="Loading view…" />;
}

function AuthLoadingScreen() {
  return (
    <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center text-white">
      <LoadingSpinner label="Initializing authentication..." />
    </div>
  );
}

function RequireAuth({ children, label }: { children: React.ReactNode; label?: string }) {
  const { status } = useAuth();
  const location = useLocation();

  if (status === 'INITIALIZING') {
    return <AuthLoadingScreen />;
  }

  if (status === 'UNAUTHENTICATED') {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return (
    <ErrorBoundary label={label}>
      <Suspense fallback={<RouteFallback />}>{children}</Suspense>
    </ErrorBoundary>
  );
}

function PublicOnlyRoute({ children }: { children: React.ReactNode }) {
  const { status } = useAuth();
  const location = useLocation();

  if (status === 'INITIALIZING') {
    return <AuthLoadingScreen />;
  }

  if (status === 'AUTHENTICATED') {
    const rawFrom = (location.state as { from?: Location })?.from?.pathname || '/';
    const from = rawFrom === '/login' ? '/' : rawFrom;
    return <Navigate to={from} replace />;
  }

  return <>{children}</>;
}

/**
 * A case section.
 *
 * The sha in the URL is authoritative. Previously the four views were case-less
 * paths that read the active sample out of context, so a shared link showed the
 * recipient whatever case they happened to have open - or nothing.
 */
function CaseSectionRoute({
  component: Component,
}: {
  component: React.ComponentType<{ data: FraudCardData | null }>;
}) {
  const { sha256 } = useParams<{ sha256: string }>();
  const { analysisResult, loadCaseByHash, loading, error } = useAnalysis();

  useEffect(() => {
    if (sha256 && analysisResult?.sha256 !== sha256) {
      loadCaseByHash(sha256);
    }
  }, [sha256, analysisResult, loadCaseByHash]);

  if (error) return <ErrorState title="Case Restore Failed" message={error} />;
  if (loading || !analysisResult) {
    return <LoadingSpinner label={`Loading case ${sha256?.slice(0, 12)}…`} />;
  }

  return <Component data={analysisResult} />;
}

/** `/history/:sha256` is an alias for that case's summary. */
function HistoryCaseRedirect() {
  const { sha256 } = useParams<{ sha256: string }>();
  if (!sha256) return <Navigate to="/history" replace />;
  return <Navigate to={caseSectionPath(sha256, 'summary')} replace />;
}

/**
 * Legacy case-less paths, forwarded to the active case.
 *
 * These URLs are in saved links, in PDF reports already delivered, and in the
 * grounded citations the assistant emitted before the move. They keep working
 * indefinitely - a broken evidence trail is a worse outcome than a redirect.
 */
function LegacyCaseRedirect({ section }: { section: CaseSection }) {
  const { analysisResult, activeSha256 } = useAnalysis();
  const location = useLocation();
  const sha = analysisResult?.sha256 || activeSha256;

  if (!sha) return <Navigate to="/history" replace />;
  return (
    <Navigate to={`${caseSectionPath(sha, section)}${location.search}${location.hash}`} replace />
  );
}

// ─── App Structure ──────────────────────────────────────────────────────────

function AppContent() {
  const { setAnalysisResult } = useAnalysis();

  return (
    <AppShell>
      <Routes>
        <Route
          path="/login"
          element={
            <PublicOnlyRoute>
              <Login />
            </PublicOnlyRoute>
          }
        />
        <Route
          path="/"
          element={
            <RequireAuth label="Upload">
              <div className="w-full flex-1 flex flex-col justify-center min-h-0">
                <Upload onAnalysisComplete={setAnalysisResult} />
              </div>
            </RequireAuth>
          }
        />
        {/*
          The case, at /case/:sha256. Four sections named after the question
          each answers, all under one URL that identifies the sample - so a
          link to an investigation is a link to that investigation.
        */}
        <Route
          path="/case/:sha256"
          element={
            <RequireAuth label="Case">
              <InvestigationShell className="case-page">
                <CaseSectionRoute component={FraudCard} />
              </InvestigationShell>
            </RequireAuth>
          }
        />
        <Route
          path="/case/:sha256/evidence"
          element={
            <RequireAuth label="Evidence">
              <InvestigationShell>
                <CaseSectionRoute component={TechnicalView} />
              </InvestigationShell>
            </RequireAuth>
          }
        />
        <Route
          path="/case/:sha256/intel"
          element={
            <RequireAuth label="Intelligence">
              <InvestigationShell>
                <CaseSectionRoute component={ThreatIntelView} />
              </InvestigationShell>
            </RequireAuth>
          }
        />
        <Route
          path="/case/:sha256/ask"
          element={
            <RequireAuth label="Ask SUDARSHAN">
              <InvestigationShell className="analyst-page-tight">
                <CaseSectionRoute component={InvestigationChat} />
              </InvestigationShell>
            </RequireAuth>
          }
        />

        {/* Legacy case-less paths. Kept indefinitely - see caseRoutes.ts. */}
        <Route
          path="/fraud-card"
          element={
            <RequireAuth label="Fraud Card">
              <LegacyCaseRedirect section="summary" />
            </RequireAuth>
          }
        />
        <Route
          path="/technical"
          element={
            <RequireAuth label="Technical View">
              <LegacyCaseRedirect section="evidence" />
            </RequireAuth>
          }
        />
        <Route
          path="/threat-intel"
          element={
            <RequireAuth label="Threat Intelligence">
              <LegacyCaseRedirect section="intel" />
            </RequireAuth>
          }
        />
        <Route
          path="/chat"
          element={
            <RequireAuth label="Investigation Chat">
              <LegacyCaseRedirect section="ask" />
            </RequireAuth>
          }
        />
        <Route
          path="/history"
          element={
            <RequireAuth label="Case History">
              <div className="analyst-page">
                <History />
              </div>
            </RequireAuth>
          }
        />
        {/*
          A case opened from the registry is the same case. Redirecting rather
          than rendering a parallel copy means one canonical URL per sample.
        */}
        <Route path="/history/:sha256" element={<HistoryCaseRedirect />} />
        <Route
          path="/batch"
          element={
            <RequireAuth label="Batch Scan">
              <div className="analyst-page">
                <BatchScan />
              </div>
            </RequireAuth>
          }
        />
        <Route
          path="/batch/:batch_id"
          element={
            <RequireAuth label="Batch Detail">
              <div className="analyst-page">
                <BatchDetail />
              </div>
            </RequireAuth>
          }
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AppShell>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AnalysisProvider>
        <AppContent />
      </AnalysisProvider>
    </AuthProvider>
  );
}
