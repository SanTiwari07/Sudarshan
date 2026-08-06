import { useEffect, useState } from 'react';
import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import { useAnalysis } from '../../context/AnalysisContext';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import ScreenshotLightbox from './ScreenshotLightbox';
import ScreenshotDiagnosticsCard from './ScreenshotDiagnosticsCard';
import { fetchScreenshotBlob } from '../../lib/screenshots';
import {
  entryFilename,
  formatScreenshotTime,
  screenshotDescription,
  screenshotStageLabel,
  type ScreenshotManifestEntry,
} from '../../lib/screenshotManifest';
import { useRuntimeScreenshots } from '../../hooks/useRuntimeScreenshots';
import { Camera, Loader2 } from 'lucide-react';

function ScreenshotTile({
  sha256,
  entry,
  title,
  mitre,
  evidenceId,
  onZoom,
}: {
  sha256: string;
  entry: ScreenshotManifestEntry;
  title: string;
  mitre?: string;
  evidenceId?: string;
  onZoom: () => void;
}) {
  const [src, setSrc] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    let objectUrl: string | null = null;
    const file = entryFilename(entry);
    setLoading(true);
    setFailed(false);
    setSrc(null);

    if (!file) {
      setFailed(true);
      setLoading(false);
      return;
    }

    fetchScreenshotBlob(sha256, file).then((url) => {
      if (cancelled) {
        if (url) URL.revokeObjectURL(url);
        return;
      }
      if (url) {
        objectUrl = url;
        setSrc(url);
      } else {
        setFailed(true);
      }
      setLoading(false);
    });

    return () => {
      cancelled = true;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [sha256, entry]);

  if (failed) return null;

  const time = formatScreenshotTime(entry.timestamp_ms);
  const stage = screenshotStageLabel(entry);
  const description = screenshotDescription(entry);

  return (
    <button
      type="button"
      onClick={onZoom}
      className="group text-left rounded-xl border border-slate-200/80 overflow-hidden bg-white hover:border-blue-300 hover:shadow-md transition-all duration-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
    >
      <div className="aspect-[9/16] w-full max-h-[280px] bg-slate-100 relative overflow-hidden">
        {loading && (
          <div className="absolute inset-0 animate-pulse bg-gradient-to-br from-slate-100 to-slate-200" aria-hidden />
        )}
        {src && (
          <img
            src={src}
            alt={title}
            loading="lazy"
            className="w-full h-full object-cover object-top group-hover:scale-[1.02] transition-transform duration-200"
          />
        )}
        <div className="absolute top-2 left-2 flex flex-wrap gap-1">
          {evidenceId && (
            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-blue-700 text-white">{evidenceId}</span>
          )}
          {mitre && (
            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-900/80 text-white">{mitre}</span>
          )}
        </div>
      </div>
      <div className="p-2.5 border-t border-slate-100 dark:border-slate-800 space-y-0.5">
        <div className="flex items-center justify-between gap-2 text-[10px] text-slate-500">
          <span className="font-mono">{time}</span>
          <span className="font-semibold text-blue-700 truncate">{stage}</span>
        </div>
        <div className="text-xs font-semibold text-slate-800 dark:text-slate-100 line-clamp-2">{description}</div>
      </div>
    </button>
  );
}

function CaptureProgress({
  captured,
  expected,
}: {
  captured: number;
  expected: number;
}) {
  const pct = expected > 0 ? Math.min(100, (captured / expected) * 100) : 0;
  return (
    <div className="rounded-lg border border-blue-100 bg-blue-50/60 px-4 py-3 space-y-2">
      <div className="flex items-center gap-2 text-sm font-medium text-blue-900">
        <Loader2 className="h-4 w-4 animate-spin text-blue-600" />
        Capturing runtime screenshots…
      </div>
      <p className="text-xs text-blue-800">
        {captured}/{expected || '—'} screenshots collected
      </p>
      <div className="h-1.5 bg-blue-100 rounded-full overflow-hidden">
        <div className="h-full bg-blue-600 transition-all duration-500" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function SkeletonRow({ count = 4 }: { count?: number }) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="rounded-lg border border-slate-200 overflow-hidden animate-pulse">
          <div className="aspect-[9/16] max-h-[160px] bg-slate-100" />
          <div className="h-10 bg-slate-50" />
        </div>
      ))}
    </div>
  );
}

export default function ScreenshotGallery({
  data,
  bundle,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle | null;
}) {
  const { loading: caseLoading } = useAnalysis();
  const { entries, runtime, loading, capturing, expected, capturedCount } = useRuntimeScreenshots(data.sha256, {
    poll: caseLoading,
    sortOrder: 'newest',
  });
  const [lightboxIndex, setLightboxIndex] = useState<number | null>(null);

  const evidenceByShot = new Map<string, { id: string; mitre?: string; title?: string }>();
  bundle?.evidenceRecords.forEach((e) => {
    if (!e.screenshotRef) return;
    evidenceByShot.set(e.screenshotRef, {
      id: e.id,
      mitre: e.mitreId,
      title: e.title,
    });
  });

  const visibleEntries = entries;
  const activeEntry = lightboxIndex != null ? visibleEntries[lightboxIndex] : null;
  const showCaptureProgress =
    capturing && visibleEntries.length === 0 && (expected > 0 || caseLoading);
  const showDiagnostics = !loading && visibleEntries.length === 0 && !showCaptureProgress;

  return (
    <SocCard id="runtime-screenshots" className="overflow-hidden">
      <SectionHeader
        icon={<Camera className="h-4 w-4" />}
        title="Runtime Screenshots"
        subtitle={
          visibleEntries.length > 0
            ? `${visibleEntries.length} verified capture${visibleEntries.length === 1 ? '' : 's'} · newest first`
            : 'Sandbox visual evidence · validated against artifacts'
        }
      />
      <div className="p-4 sm:p-5 space-y-4">
        {loading && visibleEntries.length === 0 && <SkeletonRow />}

        {showCaptureProgress && <CaptureProgress captured={capturedCount} expected={expected} />}

        {showDiagnostics && (
          <ScreenshotDiagnosticsCard data={data} runtime={runtime} captured={capturedCount} />
        )}

        {visibleEntries.length > 0 && (
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-3">
            {visibleEntries.map((entry, index) => {
              const file = entryFilename(entry);
              const meta = evidenceByShot.get(file) || evidenceByShot.get(entry.screenshot_id || '');
              const title = meta?.title || screenshotDescription(entry);
              return (
                <ScreenshotTile
                  key={entry.id || entry.screenshot_id || file || index}
                  sha256={data.sha256}
                  entry={entry}
                  title={title}
                  mitre={meta?.mitre}
                  evidenceId={meta?.id}
                  onZoom={() => setLightboxIndex(index)}
                />
              );
            })}
          </div>
        )}

        {visibleEntries.length > 0 && capturing && (
          <p className="text-[10px] text-slate-500 flex items-center gap-1">
            <Loader2 className="h-3 w-3 animate-spin" />
            Listening for new captures… ({capturedCount}/{expected || '?'})
          </p>
        )}
      </div>
      {activeEntry && lightboxIndex != null && (
        <ScreenshotLightbox
          sha256={data.sha256}
          entries={visibleEntries}
          index={lightboxIndex}
          onClose={() => setLightboxIndex(null)}
          onIndexChange={setLightboxIndex}
        />
      )}
    </SocCard>
  );
}
