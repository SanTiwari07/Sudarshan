import { useEffect, useMemo, useState } from 'react';
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
import { visualFromEntry } from '../../lib/visualEvidence';
import {
  classifyScreenshotUxState,
  SCREENSHOT_STATE_COPY,
  type ScreenshotUxState,
} from '../../lib/investigationRuntime';
import { Camera, Loader2 } from 'lucide-react';

function ScreenshotTile({
  sha256,
  entry,
  index,
  title,
  mitre,
  evidenceId,
  onZoom,
}: {
  sha256: string;
  entry: ScreenshotManifestEntry;
  index: number;
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

  const time = formatScreenshotTime(entry.timestamp_ms);
  const stage = screenshotStageLabel(entry);
  const description = screenshotDescription(entry);

  if (failed) {
    return (
      <div className="rounded-xl border border-dashed border-amber-200 bg-amber-50/50 p-3 text-center text-[11px] text-amber-900">
        Could not load {screenshotDescription(entry)}
      </div>
    );
  }

  return (
    <button
      type="button"
      onClick={onZoom}
      disabled={!src && loading}
      className="group text-left rounded-md border border-slate-200 overflow-hidden bg-white hover:border-slate-350 hover:shadow-xs transition-all duration-150 focus:outline-none focus-visible:ring-1 focus-visible:ring-blue-500 disabled:opacity-70"
    >
      <div className="aspect-[9/16] w-full max-h-[240px] bg-slate-50 relative overflow-hidden">
        {loading && (
          <div className="absolute inset-0 animate-pulse bg-gradient-to-br from-slate-50 to-slate-100 flex items-center justify-center text-[10px] text-slate-450 font-mono">
            LOADING…
          </div>
        )}
        {src && (
          <img
            src={src}
            alt={title}
            loading="lazy"
            className="w-full h-full object-cover object-top group-hover:scale-[1.01] transition-transform duration-200"
          />
        )}
        <div className="absolute top-1.5 left-1.5 flex flex-wrap gap-1">
          <span className="text-[9px] font-mono font-bold px-1 py-0.2 rounded bg-slate-900/80 text-white">
            {String(index + 1).padStart(2, '0')}
          </span>
          {evidenceId && (
            <span className="text-[9px] font-mono font-bold px-1 py-0.2 rounded bg-blue-700 text-white">{evidenceId}</span>
          )}
          {mitre && (
            <span className="text-[9px] font-mono font-bold px-1 py-0.2 rounded bg-slate-900/90 text-white">{mitre}</span>
          )}
        </div>
      </div>
      <div className="p-2 border-t border-slate-150 space-y-0.5 bg-slate-50/20">
        <div className="flex items-center justify-between gap-2 text-[9px] text-slate-500 font-mono">
          <span>{time}</span>
          <span className="font-bold text-blue-800 uppercase tracking-wider truncate">{stage}</span>
        </div>
        <div className="text-[11px] font-bold text-slate-800 line-clamp-1 leading-tight">{description}</div>
      </div>
    </button>
  );
}

function CaptureProgress({ captured, expected }: { captured: number; expected: number }) {
  const pct = expected > 0 ? Math.min(100, (captured / expected) * 100) : 0;
  return (
    <div className="rounded-lg border border-blue-100 bg-blue-50/60 px-4 py-3 space-y-2">
      <div className="flex items-center gap-2 text-sm font-medium text-blue-900">
        <Loader2 className="h-4 w-4 animate-spin text-blue-600" />
        Capturing runtime screenshots…
      </div>
      <p className="text-xs text-blue-800">
        {captured}/{expected || '-'} screenshots collected
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

function EmptyScreenshotState({
  state,
  data,
  runtime,
  captured,
}: {
  state: ScreenshotUxState;
  data: FraudCardData;
  runtime: import('../../lib/screenshotManifest').RuntimeScreenshotMeta | null;
  captured: number;
}) {
  if (state === 'LOADING' || state === 'AVAILABLE') return null;
  const copy = SCREENSHOT_STATE_COPY[state];
  const showDiagnostics = state === 'CAPTURE_FAILED' || state === 'ARTIFACT_MISSING';

  return (
    <div className="space-y-3">
      <div className="rounded-md border border-slate-200 bg-slate-50/40 p-3.5">
        <p className="text-xs font-bold uppercase tracking-wider text-slate-900">{copy.title}</p>
        <p className="text-xs text-slate-600 mt-1.5 leading-relaxed">{copy.body}</p>
      </div>
      {showDiagnostics && (
        <ScreenshotDiagnosticsCard data={data} runtime={runtime} captured={captured} uxState={state} />
      )}
      {state === 'RUNTIME_INCONCLUSIVE' || state === 'NO_UI_REACHED' ? (
        <ScreenshotDiagnosticsCard data={data} runtime={runtime} captured={captured} uxState={state} compact />
      ) : null}
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
  const { entries, runtime, loading, error, capturing, expected, capturedCount } = useRuntimeScreenshots(
    data.sha256,
    {
      poll: caseLoading,
      sortOrder: 'newest',
    },
  );
  const [lightboxIndex, setLightboxIndex] = useState<number | null>(null);
  const [qualityFilter, setQualityFilter] = useState<string>('all');
  const [correlationFilter, setCorrelationFilter] = useState<string>('all');

  const visibleEntries = useMemo(() => {
    return entries.filter((e) => {
      const ve = visualFromEntry(e);
      if (qualityFilter !== 'all' && ve?.quality !== qualityFilter) return false;
      if (correlationFilter !== 'all' && ve?.correlation_status !== correlationFilter) return false;
      return true;
    });
  }, [entries, qualityFilter, correlationFilter]);

  const uxState = classifyScreenshotUxState({
    loading,
    apiError: error,
    entryCount: entries.length,
    runtime,
    data,
  });

  const evidenceByShot = new Map<string, { id: string; mitre?: string; title?: string }>();
  bundle?.evidenceRecords.forEach((e) => {
    if (!e.screenshotRef) return;
    evidenceByShot.set(e.screenshotRef, {
      id: e.id,
      mitre: e.mitreId,
      title: e.title,
    });
  });

  const activeEntry = lightboxIndex != null ? visibleEntries[lightboxIndex] : null;
  const showCaptureProgress =
    capturing && visibleEntries.length === 0 && (expected > 0 || caseLoading);

  return (
    <SocCard id="runtime-screenshots" className="overflow-hidden">
      <SectionHeader
        icon={<Camera className="h-4 w-4" />}
        title="Screenshot appendix"
        subtitle="Artifact browser - filter by quality, correlation, and claim type"
      />
      <div className="p-4 sm:p-5 space-y-4">
        {entries.some((e) => visualFromEntry(e)) && (
          <div className="flex flex-wrap gap-2 text-[11px]">
            <select
              className="border border-slate-200 rounded px-2 py-1 bg-white"
              value={qualityFilter}
              onChange={(e) => setQualityFilter(e.target.value)}
              aria-label="Filter by quality"
            >
              <option value="all">All quality</option>
              <option value="A">A</option>
              <option value="B">B</option>
              <option value="C">C</option>
              <option value="D">D</option>
            </select>
            <select
              className="border border-slate-200 rounded px-2 py-1 bg-white"
              value={correlationFilter}
              onChange={(e) => setCorrelationFilter(e.target.value)}
              aria-label="Filter by correlation"
            >
              <option value="all">All correlation</option>
              <option value="causal">causal</option>
              <option value="linked">linked</option>
              <option value="temporal">temporal</option>
              <option value="unresolved">unresolved</option>
            </select>
          </div>
        )}
        {uxState === 'LOADING' && visibleEntries.length === 0 && <SkeletonRow />}

        {showCaptureProgress && <CaptureProgress captured={capturedCount} expected={expected} />}

        {uxState !== 'AVAILABLE' && uxState !== 'LOADING' && !showCaptureProgress && (
          <EmptyScreenshotState state={uxState} data={data} runtime={runtime} captured={capturedCount} />
        )}

        {visibleEntries.length > 0 && (
          <>
            <p className="text-xs text-slate-600">Tap a screenshot to inspect the captured application state.</p>
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
                    index={index}
                    title={title}
                    mitre={meta?.mitre}
                    evidenceId={meta?.id}
                    onZoom={() => setLightboxIndex(index)}
                  />
                );
              })}
            </div>
            {visibleEntries.length > 0 && (
              <p className="text-[11px] text-slate-500">Captured during sandbox execution.</p>
            )}
          </>
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
