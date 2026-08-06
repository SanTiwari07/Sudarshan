import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import { LoadingSpinner } from '../ui/Skeleton';
import InvestigationProgressPanel from './InvestigationProgressPanel';
import TechnicalAnalysisSummary from './TechnicalAnalysisSummary';
import FindingsRegistryTable from './FindingsRegistryTable';
import InvestigationTimeline from './InvestigationTimeline';
import { Database } from 'lucide-react';

export default function EvidenceRegistrySection({
  data,
  bundle,
  loading,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle | null;
  loading: boolean;
}) {
  if (loading && !bundle) {
    return <LoadingSpinner label="Loading investigation evidence…" />;
  }

  if (!bundle) {
    return null;
  }

  const recordCount = bundle.evidenceRecords.length;

  return (
    <section
      className="rounded-xl border border-slate-200/80 bg-white shadow-sm overflow-hidden relative static"
      aria-labelledby="evidence-registry-title"
    >
      <header className="px-4 sm:px-5 py-4 border-b border-slate-100">
        <div className="flex items-start gap-3">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-50 text-blue-700 border border-slate-100">
            <Database className="h-4 w-4" aria-hidden />
          </span>
          <div className="min-w-0">
            <h2 id="evidence-registry-title" className="text-base font-semibold text-slate-900 tracking-tight">
              Evidence registry
            </h2>
            <p className="text-sm text-slate-500 mt-1 leading-relaxed">
              Verified findings from static analysis, runtime instrumentation, and threat correlation —{' '}
              {recordCount} record{recordCount === 1 ? '' : 's'} behind the Fraud Risk Score.
            </p>
          </div>
        </div>
      </header>

      <InvestigationProgressPanel data={data} bundle={bundle} embedded />
      <TechnicalAnalysisSummary data={data} bundle={bundle} embedded />
      <FindingsRegistryTable bundle={bundle} data={data} embedded />
      <InvestigationTimeline bundle={bundle} embedded />
    </section>
  );
}
