import EvidenceInspectionModal from './EvidenceInspectionModal';
import type { ScreenshotManifestEntry } from '../../lib/screenshotManifest';

export default function ScreenshotLightbox({
  sha256,
  entries,
  index,
  onClose,
  onIndexChange,
}: {
  sha256: string;
  entries: ScreenshotManifestEntry[];
  index: number;
  onClose: () => void;
  onIndexChange: (index: number) => void;
}) {
  return (
    <EvidenceInspectionModal
      sha256={sha256}
      entries={entries}
      index={index}
      onClose={onClose}
      onIndexChange={onIndexChange}
    />
  );
}
