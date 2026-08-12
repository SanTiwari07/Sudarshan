import { useState } from 'react';
import type { FraudCardData } from '../../App';
import { useAnalysis } from '../../context/AnalysisContext';
import { executiveVisualEntries } from '../../lib/visualEvidence';
import VisualEvidenceCard from './VisualEvidenceCard';
import EvidenceInspectionModal from './EvidenceInspectionModal';
import { Camera } from 'lucide-react';

export default function ExecutiveVisualEvidenceSection({ data }: { data: FraudCardData }) {
  const { screenshotManifestEntries } = useAnalysis();
  const execShots = executiveVisualEntries(screenshotManifestEntries);
  const [selectedIdx, setSelectedIdx] = useState<number | null>(null);

  if (execShots.length === 0) return null;

  return (
    <>
      <div className="rounded-xl border border-slate-200 bg-white p-5 sm:p-6 shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-slate-200 pb-3">
          <div className="flex items-center gap-2">
            <Camera className="h-4 w-4 sm:h-5 sm:w-5 text-blue-600" />
            <h3 className="text-sm sm:text-base font-extrabold uppercase tracking-wider text-slate-900 font-mono">
              Visual Evidence
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-500 font-medium">
            {execShots.length} screenshot{execShots.length > 1 ? 's' : ''} captured
          </span>
        </div>
        <div className="space-y-3">
          {execShots.map((entry, idx) => (
            <VisualEvidenceCard
              key={entry.screenshot_id || idx}
              sha256={data.sha256}
              entry={entry}
              onExpand={() => setSelectedIdx(idx)}
            />
          ))}
        </div>
      </div>

      {selectedIdx !== null && (
        <EvidenceInspectionModal
          sha256={data.sha256}
          entries={execShots}
          index={selectedIdx}
          onClose={() => setSelectedIdx(null)}
          onIndexChange={(newIdx) => setSelectedIdx(newIdx)}
        />
      )}
    </>
  );
}
