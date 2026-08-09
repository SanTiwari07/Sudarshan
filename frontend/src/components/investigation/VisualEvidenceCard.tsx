import { useEffect, useState } from 'react';
import type { ScreenshotManifestEntry } from '../../lib/screenshotManifest';
import { entryFilename } from '../../lib/screenshotManifest';
import { fetchScreenshotBlob } from '../../lib/screenshots';
import { visualFromEntry } from '../../lib/visualEvidence';
import { formatScreenshotTime } from '../../lib/screenshotManifest';

export default function VisualEvidenceCard({
  sha256,
  entry,
  onExpand,
}: {
  sha256: string;
  entry: ScreenshotManifestEntry;
  onExpand?: () => void;
}) {
  const ve = visualFromEntry(entry);
  const [thumb, setThumb] = useState<string | null>(null);

  useEffect(() => {
    const file = entryFilename(entry);
    if (!file) return;
    let url: string | null = null;
    fetchScreenshotBlob(sha256, file).then((u) => {
      url = u;
      setThumb(u);
    });
    return () => {
      if (url) URL.revokeObjectURL(url);
    };
  }, [sha256, entry]);

  if (!ve) return null;

  return (
    <div className="rounded-xl border border-slate-200 bg-slate-50/60 p-3 space-y-2">
      <div className="flex gap-3">
        {thumb ? (
          <button type="button" onClick={onExpand} className="shrink-0">
            <img src={thumb} alt="" className="h-20 w-20 object-cover rounded-md border border-slate-200" />
          </button>
        ) : (
          <div className="h-20 w-20 rounded-md bg-slate-200 animate-pulse shrink-0" />
        )}
        <div className="min-w-0 flex-1">
          <p className="font-mono text-[11px] text-slate-600">{entry.screenshot_id}</p>
          <p className="text-[12px] text-slate-800 leading-snug mt-1">{ve.investigative_claim}</p>
          <p className="text-[10px] text-slate-500 mt-1">
            Quality {ve.quality} · {ve.correlation_status} · {formatScreenshotTime(entry.timestamp_ms)}
          </p>
          {ve.linked_evidence_ids && ve.linked_evidence_ids.length > 0 && (
            <p className="text-[10px] text-slate-500 mt-0.5">Evidence: {ve.linked_evidence_ids.join(', ')}</p>
          )}
          {ve.workflow_stage_label && (
            <p className="text-[10px] text-slate-500">Workflow: {ve.workflow_stage_label}</p>
          )}
        </div>
      </div>
    </div>
  );
}
