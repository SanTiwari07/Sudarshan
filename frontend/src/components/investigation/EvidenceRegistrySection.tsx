import type { FraudCardData } from '../../types/case';
import type { InvestigationBundle } from '../../types/investigation';
import { LoadingSpinner } from '../ui/Skeleton';
import FindingsRegistryTable from './FindingsRegistryTable';

export default function EvidenceRegistrySection({
  data: _data,
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
      <FindingsRegistryTable bundle={bundle} embedded />
    </div>
  );
}

