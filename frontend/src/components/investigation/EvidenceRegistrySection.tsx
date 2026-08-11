import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import { LoadingSpinner } from '../ui/Skeleton';
import InvestigationProgressPanel from './InvestigationProgressPanel';
import TechnicalOverviewMetrics from './TechnicalOverviewMetrics';
import FindingsRegistryTable from './FindingsRegistryTable';

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
    <div className="w-full space-y-6">
      <InvestigationProgressPanel data={data} bundle={bundle} embedded />
      <TechnicalOverviewMetrics data={data} bundle={bundle} />
      <FindingsRegistryTable bundle={bundle} embedded />
    </div>
  );
}
