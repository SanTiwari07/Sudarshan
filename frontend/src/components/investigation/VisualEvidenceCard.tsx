import { useEffect, useState } from 'react';
import type { ScreenshotManifestEntry } from '../../lib/screenshotManifest';
import { entryFilename } from '../../lib/screenshotManifest';
import { fetchScreenshotBlob } from '../../lib/screenshots';
import { visualFromEntry } from '../../lib/visualEvidence';
import { formatScreenshotTime } from '../../lib/screenshotManifest';
import { Maximize2 } from 'lucide-react';

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
    <div
      className={`rounded-xl border border-slate-200 bg-slate-50/60 p-3 space-y-2 transition-all duration-150 ${
        onExpand ? 'hover:border-blue-300 hover:bg-slate-50 hover:shadow-xs group' : ''
      }`}
    >
      <div className="flex gap-3 items-start">
        {thumb ? (
          <button
            type="button"
            onClick={onExpand}
            className="shrink-0 relative group/thumb focus:outline-none focus:ring-2 focus:ring-blue-500 rounded-md overflow-hidden"
            title="Click to enlarge screenshot evidence"
          >
            <img
              src={thumb}
              alt={ve.claim || ve.investigative_claim || ''}
              className="h-20 w-20 object-cover rounded-md border border-slate-200 group-hover/thumb:scale-105 transition-transform duration-200"
            />
            <div className="absolute inset-0 bg-slate-900/30 opacity-0 group-hover/thumb:opacity-100 flex items-center justify-center transition-opacity rounded-md">
              <Maximize2 className="h-4 w-4 text-white drop-shadow-md" />
            </div>
          </button>
        ) : (
          <div className="h-20 w-20 rounded-md bg-slate-200 animate-pulse shrink-0" />
        )}
        <div className="min-w-0 flex-1">
          <div className="flex items-center justify-between gap-2">
            <button
              type="button"
              onClick={onExpand}
              className="font-mono text-[13px] font-bold text-slate-800 hover:text-blue-600 transition-colors text-left"
            >
              {entry.screenshot_id || entry.id || 'SCR-000'}
            </button>
            {onExpand && (
              <button
                type="button"
                onClick={onExpand}
                className="text-[12px] font-mono text-blue-600 hover:text-blue-800 hover:underline flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity"
              >
                Inspect
              </button>
            )}
          </div>
          <p
            className={`text-[14px] text-slate-800 leading-snug mt-1 ${
              onExpand ? 'cursor-pointer hover:text-blue-900' : ''
            }`}
            onClick={onExpand}
          >
            {ve.investigative_claim}
          </p>
          <p className="text-[12px] text-slate-500 mt-1 font-mono">
            Quality {ve.quality} · {ve.correlation_status} · {formatScreenshotTime(entry.timestamp_ms)}
          </p>
          {ve.linked_evidence_ids && ve.linked_evidence_ids.length > 0 && (
            <p className="text-[12px] text-slate-500 mt-0.5 font-mono">
              Evidence: {ve.linked_evidence_ids.join(', ')}
            </p>
          )}
          {ve.workflow_stage_label && (
            <p className="text-[12px] text-slate-500 font-mono">Workflow: {ve.workflow_stage_label}</p>
          )}
        </div>
      </div>
    </div>
  );
}
