import { useEffect, useState } from 'react';
import { ChevronLeft, ChevronRight, Download, X, ZoomIn, ZoomOut } from 'lucide-react';
import { fetchScreenshotBlob, screenshotBasename } from '../../lib/screenshots';
import {
  formatScreenshotTime,
  screenshotDescription,
  screenshotStageLabel,
  type ScreenshotManifestEntry,
} from '../../lib/screenshotManifest';

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
  const entry = entries[index];
  const [src, setSrc] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1);

  useEffect(() => {
    setZoom(1);
    let revoked: string | null = null;
    setSrc(null);
    if (!entry) return;
    fetchScreenshotBlob(sha256, entry.filename).then((url) => {
      if (url) {
        revoked = url;
        setSrc(url);
      }
    });
    return () => {
      if (revoked) URL.revokeObjectURL(revoked);
    };
  }, [sha256, entry?.filename, entry]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
      if (e.key === 'ArrowLeft' && index > 0) onIndexChange(index - 1);
      if (e.key === 'ArrowRight' && index < entries.length - 1) onIndexChange(index + 1);
      if (e.key === '+' || e.key === '=') setZoom((z) => Math.min(3, z + 0.25));
      if (e.key === '-') setZoom((z) => Math.max(0.5, z - 0.25));
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [index, entries.length, onClose, onIndexChange]);

  if (!entry) return null;

  const download = () => {
    if (!src) return;
    const a = document.createElement('a');
    a.href = src;
    a.download = screenshotBasename(entry.filename);
    a.click();
  };

  return (
    <div className="fixed inset-0 z-[60] bg-slate-900/95 flex flex-col" onClick={onClose}>
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/10" onClick={(e) => e.stopPropagation()}>
        <div className="text-white text-sm min-w-0">
          <div className="font-semibold truncate">{screenshotDescription(entry)}</div>
          <div className="text-xs text-white/60 mt-0.5">
            {formatScreenshotTime(entry.timestamp_ms)} · {screenshotStageLabel(entry)} · {index + 1} of{' '}
            {entries.length}
          </div>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          <button
            type="button"
            className="p-2 text-white/80 hover:text-white disabled:opacity-30"
            disabled={index <= 0}
            onClick={() => onIndexChange(index - 1)}
            aria-label="Previous screenshot"
          >
            <ChevronLeft className="h-5 w-5" />
          </button>
          <button
            type="button"
            className="p-2 text-white/80 hover:text-white disabled:opacity-30"
            disabled={index >= entries.length - 1}
            onClick={() => onIndexChange(index + 1)}
            aria-label="Next screenshot"
          >
            <ChevronRight className="h-5 w-5" />
          </button>
          <button type="button" className="p-2 text-white/80 hover:text-white" onClick={() => setZoom((z) => Math.max(0.5, z - 0.25))}>
            <ZoomOut className="h-5 w-5" />
          </button>
          <button type="button" className="p-2 text-white/80 hover:text-white" onClick={() => setZoom((z) => Math.min(3, z + 0.25))}>
            <ZoomIn className="h-5 w-5" />
          </button>
          <button type="button" className="p-2 text-white/80 hover:text-white" onClick={download} disabled={!src}>
            <Download className="h-5 w-5" />
          </button>
          <button type="button" className="p-2 text-white/80 hover:text-white" onClick={onClose} aria-label="Close">
            <X className="h-6 w-6" />
          </button>
        </div>
      </div>
      <div className="flex-1 flex items-center justify-center p-4 overflow-auto" onClick={(e) => e.stopPropagation()}>
        {src ? (
          <img
            src={src}
            alt={screenshotDescription(entry)}
            className="max-h-full rounded border border-slate-600 shadow-2xl transition-transform duration-200"
            style={{ transform: `scale(${zoom})` }}
          />
        ) : (
          <div className="text-white text-sm animate-pulse">Loading screenshot…</div>
        )}
      </div>
    </div>
  );
}
