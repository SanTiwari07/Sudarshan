import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import { LoadingSpinner } from '../ui/Skeleton';
import InvestigationHeader from './InvestigationHeader';
import InvestigationProgressPanel from './InvestigationProgressPanel';
import TechnicalAnalysisSummary from './TechnicalAnalysisSummary';
import FindingsRegistryTable from './FindingsRegistryTable';
import InvestigationTimeline from './InvestigationTimeline';

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

  return (
    <section
      className="investigation-evidence-workspace w-full max-w-[1340px] mx-auto"
      aria-label="Investigation evidence workspace"
    >
      <InvestigationHeader data={data} bundle={bundle} />
      <InvestigationProgressPanel data={data} bundle={bundle} embedded />
      <TechnicalAnalysisSummary data={data} bundle={bundle} embedded />
      <div className="pt-2">
        <FindingsRegistryTable bundle={bundle} embedded />
      </div>
      <InvestigationTimeline data={data} bundle={bundle} embedded />
    </section>
  );
}
