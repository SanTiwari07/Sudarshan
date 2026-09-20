import { useEffect, useRef, useState } from 'react';
import {
  ChevronLeft,
  ChevronRight,
  Download,
  X,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Clock,
  ShieldAlert,
  FileText,
  Info,
  Maximize2,
} from 'lucide-react';
import { fetchScreenshotBlob, screenshotBasename } from '../../lib/screenshots';
import { useDialogBehavior } from '../../hooks/useDialogBehavior';
import {
  entryFilename,
  formatScreenshotTime,
  screenshotDescription,
  type ScreenshotManifestEntry,
} from '../../lib/screenshotManifest';
import { visualFromEntry } from '../../lib/visualEvidence';

/**
 * Shown under "Why it matters" when nothing corroborated this frame.
 *
 * The backend supplies its own sentence for this case; this only covers a
 * record written before it did. Either way it must be a statement about the
 * RUNTIME evidence - repeating the visual observation here is what made the
 * panel print the same paragraph twice.
 */
const NO_CORROBORATION_NOTE =
  'No runtime hook fired while this screen was displayed. The frame is retained ' +
  'as a visual record of the state the application presented and was reviewed ' +
  'for unauthorized overlays and credential-entry indicators.';

interface EvidenceInspectionModalProps {
  sha256: string;
  entries: ScreenshotManifestEntry[];
  index: number;
  onClose: () => void;
  onIndexChange: (index: number) => void;
}

export default function EvidenceInspectionModal({
  sha256,
  entries,
  index,
  onClose,
  onIndexChange,
}: EvidenceInspectionModalProps) {
  const entry = entries[index] || entries[0];
  const [src, setSrc] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const panelRef = useRef<HTMLDivElement | null>(null);

  // Focus trap, focus restore, scroll lock and Escape. The lightbox had Escape
  // and nothing else, so a keyboard user could tab straight out of an open
  // modal onto the page behind it.
  useDialogBehavior({ open: true, panelRef, onClose });

  const ve = entry ? visualFromEntry(entry) : null;

  // Load screenshot image blob
  useEffect(() => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
    let revoked: string | null = null;
    setLoading(true);
    setSrc(null);

    if (!entry) return;
    const file = entryFilename(entry);
    if (!file) {
      setLoading(false);
      return;
    }

    fetchScreenshotBlob(sha256, file).then((url) => {
      if (url) {
        revoked = url;
        setSrc(url);
      }
      setLoading(false);
    });

    return () => {
      if (revoked) URL.revokeObjectURL(revoked);
    };
  }, [sha256, entry]);

  // Zoom controls
  const handleZoomIn = () => setZoom((z) => Math.min(3.5, z + 0.35));
  const handleZoomOut = () => {
    setZoom((z) => {
      const next = Math.max(1, z - 0.35);
      if (next === 1) setPan({ x: 0, y: 0 });
      return next;
    });
  };
  const handleResetZoom = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  // Keyboard navigation & controls
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Escape is handled by useDialogBehavior, which listens in the capture
      // phase; only the viewer-specific shortcuts live here.
      if (e.key === 'ArrowLeft' && index > 0) {
        onIndexChange(index - 1);
      } else if (e.key === 'ArrowRight' && index < entries.length - 1) {
        onIndexChange(index + 1);
      } else if (e.key === '+' || e.key === '=') {
        handleZoomIn();
      } else if (e.key === '-') {
        handleZoomOut();
      } else if (e.key === '0') {
        handleResetZoom();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [index, entries.length, onClose, onIndexChange]);

  // Mouse pan handlers when zoomed in
  const handleMouseDown = (e: React.MouseEvent) => {
    if (zoom <= 1) return;
    setIsDragging(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging || zoom <= 1) return;
    setPan({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y,
    });
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  // Touch handlers for mobile pan
  const handleTouchStart = (e: React.TouchEvent) => {
    if (zoom <= 1 || e.touches.length !== 1) return;
    setIsDragging(true);
    setDragStart({
      x: e.touches[0].clientX - pan.x,
      y: e.touches[0].clientY - pan.y,
    });
  };

  const handleTouchMove = (e: React.TouchEvent) => {
    if (!isDragging || zoom <= 1 || e.touches.length !== 1) return;
    setPan({
      x: e.touches[0].clientX - dragStart.x,
      y: e.touches[0].clientY - dragStart.y,
    });
  };

  const handleTouchEnd = () => {
    setIsDragging(false);
  };

  const handleDownload = () => {
    if (!src || !entry) return;
    const a = document.createElement('a');
    a.href = src;
    a.download = screenshotBasename(entryFilename(entry));
    a.click();
  };

  if (!entry) return null;

  // Metadata extraction for panel
  const screenshotId = entry.screenshot_id || entry.id || ve?.screenshot_id || 'SCR-000';
  const timestampText = formatScreenshotTime(entry.timestamp_ms);
  const evidenceIds = ve?.linked_evidence_ids && ve.linked_evidence_ids.length > 0
    ? ve.linked_evidence_ids
    : entry.linked_evidence_ids && entry.linked_evidence_ids.length > 0
    ? entry.linked_evidence_ids
    : null;

  const quality = ve?.quality || entry.quality || null;
  const correlationStatus = ve?.correlation_status || entry.correlation_status || null;
  const workflow = ve?.workflow_stage_label || entry.workflow_stage_label || entry.stage || null;
  const captureReason = entry.reason || entry.capture_trigger || ve?.capture_trigger || null;
  // Three distinct questions, three distinct fields. They used to collapse
  // into one: `visualObservation` fell back to the investigative claim, and
  // "Why it matters" fell back to `visualObservation`, so an uncorroborated
  // frame printed "insufficient corroborating runtime evidence..." twice and
  // said nothing about the picture either time.
  //
  //   Visual observation - what is on the screen (from the UI hierarchy
  //                        captured with the frame, or vision captioning).
  //   Investigative claim - what the frame is offered as evidence of.
  //   Why it matters      - whether runtime activity corroborated it.
  const visualObservation =
    entry.visual_observation ||
    ve?.visual_observation ||
    ve?.screen_summary ||
    entry.screen_summary ||
    screenshotDescription(entry);
  const investigativeClaim = ve?.investigative_claim || entry.investigative_claim || null;
  const runtimeObservation = entry.runtime_observation || (
    ve?.linked_evidence_ids && ve.linked_evidence_ids.length > 0
      ? `Linked runtime evidence: ${ve.linked_evidence_ids.join(', ')}`
      : null
  );
  const findingKeys = ve?.linked_finding_keys && ve.linked_finding_keys.length > 0
    ? ve.linked_finding_keys
    : entry.linked_finding_keys && entry.linked_finding_keys.length > 0
    ? entry.linked_finding_keys
    : null;

  const trigger = runtimeObservation || (
    correlationStatus === 'causal' && evidenceIds
      ? evidenceIds.join(', ')
      : null
  );
  const corroboration =
    (entry as any).corroboration_summary || ve?.corroboration_summary || null;
  const analystNote = (entry as any).analyst_note || null;
  const mitreTech = (entry as any).mitre_technique || (entry as any).mitre || null;
  const confidenceVal = (entry as any).phish_confidence
    ? `${Math.round((entry as any).phish_confidence * 100)}%`
    : ve?.priority
    ? `Priority ${ve.priority}`
    : null;

  // Quality badge style helper
  const getQualityBadgeStyle = (q: string | null) => {
    if (!q) return 'bg-slate-100 text-slate-700 border-slate-200';
    const upper = q.toUpperCase();
    if (upper.includes('A') || upper === 'HIGH') return 'bg-emerald-50 text-emerald-700 border-emerald-200';
    if (upper.includes('B') || upper === 'MEDIUM') return 'bg-blue-50 text-blue-700 border-blue-200';
    if (upper.includes('C')) return 'bg-amber-50 text-amber-700 border-amber-200';
    return 'bg-slate-100 text-slate-700 border-slate-200';
  };

  // Correlation badge style helper
  const getCorrelationBadgeStyle = (c: string | null) => {
    if (!c) return 'bg-slate-100 text-slate-700 border-slate-200';
    const lower = c.toLowerCase();
    if (lower.includes('causal')) return 'bg-red-50 text-red-700 border-red-200';
    if (lower.includes('not_applicable') || lower.includes('not applicable'))
      return 'bg-slate-100 text-slate-600 border-slate-200';
    if (lower.includes('unresolved')) return 'bg-amber-50 text-amber-700 border-amber-200';
    return 'bg-blue-50 text-blue-700 border-blue-200';
  };

  return (
    <div
      className="fixed inset-0 z-[100] bg-slate-950/85 backdrop-blur-md flex items-center justify-center p-2 sm:p-4 md:p-6 dialog-backdrop-enter"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Evidence Inspection Modal"
    >
      <div
        ref={panelRef}
        tabIndex={-1}
        className="relative bg-slate-900 border border-slate-700/80 rounded-2xl shadow-2xl overflow-hidden w-full max-w-7xl max-h-[94vh] flex flex-col lg:grid lg:grid-cols-12 lg:h-[88vh] focus:outline-none dialog-panel-enter"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Top Floating Close Button for Mobile */}
        <button
          type="button"
          onClick={onClose}
          className="absolute top-3 right-3 z-30 lg:hidden p-2 rounded-full bg-slate-900/80 text-white/80 hover:text-white border border-slate-700 focus:outline-none"
          aria-label="Close modal"
        >
          <X className="h-5 w-5" />
        </button>

        {/* LEFT COLUMN / TOP: Image Lightbox & Zoom Area (lg:col-span-7 or 8) */}
        <div className="lg:col-span-7 xl:col-span-7 bg-slate-950 flex flex-col justify-between relative overflow-hidden select-none min-h-[340px] sm:min-h-[440px] border-b lg:border-b-0 lg:border-r border-slate-800">
          {/* Header Bar overlay */}
          <div className="flex items-center justify-between px-4 py-3 bg-slate-900/90 border-b border-slate-800/80 z-20 shrink-0">
            <div className="flex items-center gap-2 min-w-0">
              <span className="font-mono text-xs font-semibold px-2 py-0.5 rounded bg-blue-600/30 text-blue-400 border border-blue-500/40">
                {screenshotId}
              </span>
              <span className="text-xs text-slate-500 font-mono hidden sm:inline">
                {timestampText !== '-' ? timestampText : ''}
              </span>
              {workflow && (
                <span className="text-[13px] font-mono uppercase px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 hidden md:inline">
                  {workflow}
                </span>
              )}
            </div>

            {/* Navigation & Zoom Toolbar */}
            <div className="flex items-center gap-1 sm:gap-2">
              <span className="text-xs font-mono text-slate-400 font-medium px-2 py-1 rounded bg-slate-800/60 border border-slate-700/50">
                {index + 1} / {entries.length}
              </span>

              <div className="h-4 w-px bg-slate-800 mx-1 hidden sm:block" />

              <button
                type="button"
                onClick={handleZoomOut}
                disabled={zoom <= 1}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 disabled:opacity-30 transition-colors"
                title="Zoom out (-)"
              >
                <ZoomOut className="h-4 w-4" />
              </button>
              <span className="text-[13px] font-mono text-slate-300 w-10 text-center hidden sm:inline">
                {Math.round(zoom * 100)}%
              </span>
              <button
                type="button"
                onClick={handleZoomIn}
                disabled={zoom >= 3.5}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 disabled:opacity-30 transition-colors"
                title="Zoom in (+)"
              >
                <ZoomIn className="h-4 w-4" />
              </button>
              {zoom > 1 && (
                <button
                  type="button"
                  onClick={handleResetZoom}
                  className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
                  title="Reset zoom (0)"
                >
                  <RotateCcw className="h-4 w-4" />
                </button>
              )}

              <div className="h-4 w-px bg-slate-800 mx-1" />

              <button
                type="button"
                onClick={handleDownload}
                disabled={!src}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 disabled:opacity-30 transition-colors"
                title="Download PNG screenshot"
              >
                <Download className="h-4 w-4" />
              </button>
            </div>
          </div>

          {/* Main Image Stage */}
          <div
            className={`flex-1 relative flex items-center justify-center p-4 overflow-hidden ${
              zoom > 1 ? (isDragging ? 'cursor-grabbing' : 'cursor-grab') : 'cursor-default'
            }`}
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onMouseLeave={handleMouseUp}
            onTouchStart={handleTouchStart}
            onTouchMove={handleTouchMove}
            onTouchEnd={handleTouchEnd}
          >
            {loading ? (
              <div className="flex animate-pulse flex-col items-center gap-2 font-sans text-[13px] text-slate-400">
                <Maximize2 className="h-8 w-8 text-blue-500 animate-spin" />
                <span>Loading screenshot artifact…</span>
              </div>
            ) : src ? (
              <img
                src={src}
                alt={visualObservation}
                className="max-h-full max-w-full object-contain rounded-lg shadow-2xl transition-transform duration-100 ease-out border border-slate-800/80"
                style={{
                  transform: `scale(${zoom}) translate(${pan.x / zoom}px, ${pan.y / zoom}px)`,
                }}
                draggable={false}
              />
            ) : (
              <div className="p-6 text-center font-sans text-[13px] text-slate-400">
                Screenshot artifact unresolvable or unavailable.
              </div>
            )}

            {/* Left Prev Navigation Arrow */}
            <button
              type="button"
              onClick={() => onIndexChange(index - 1)}
              disabled={index <= 0}
              className="absolute left-3 top-1/2 -translate-y-1/2 z-20 p-2.5 rounded-full bg-slate-900/80 hover:bg-blue-600 text-white border border-slate-700/80 shadow-lg disabled:opacity-20 disabled:pointer-events-none transition-all"
              aria-label="Previous screenshot (Left Arrow)"
            >
              <ChevronLeft className="h-5 w-5" />
            </button>

            {/* Right Next Navigation Arrow */}
            <button
              type="button"
              onClick={() => onIndexChange(index + 1)}
              disabled={index >= entries.length - 1}
              className="absolute right-3 top-1/2 -translate-y-1/2 z-20 p-2.5 rounded-full bg-slate-900/80 hover:bg-blue-600 text-white border border-slate-700/80 shadow-lg disabled:opacity-20 disabled:pointer-events-none transition-all"
              aria-label="Next screenshot (Right Arrow)"
            >
              <ChevronRight className="h-5 w-5" />
            </button>
          </div>

          {/* Bottom Thumbnail Strip */}
          {entries.length > 1 && (
            <div className="p-2.5 bg-slate-900/95 border-t border-slate-800/80 overflow-x-auto flex items-center gap-2 z-20 shrink-0 scrollbar-thin">
              {entries.map((item, idx) => {
                const itemSid = item.screenshot_id || item.id || `SCR-${idx + 1}`;
                const isActive = idx === index;
                return (
                  <button
                    key={itemSid + idx}
                    type="button"
                    onClick={() => onIndexChange(idx)}
                    className={`shrink-0 flex items-center gap-2 px-2.5 py-1.5 rounded-md border text-[13px] font-mono transition-all ${
                      isActive
                        ? 'bg-blue-600/20 border-blue-500 text-blue-300 font-semibold'
                        : 'bg-slate-800/60 border-slate-700/60 text-slate-400 hover:bg-slate-800 hover:text-slate-200'
                    }`}
                  >
                    <span>{itemSid}</span>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* RIGHT COLUMN: Clean White Evidence Information Panel (lg:col-span-5) */}
        <div className="lg:col-span-5 xl:col-span-5 bg-white text-slate-900 flex flex-col justify-between overflow-y-auto p-5 sm:p-6 space-y-6">
          {/* Top Panel Header */}
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3">
              <div className="flex items-center gap-2">
                <FileText className="h-5 w-5 text-blue-600 shrink-0" />
                {/*
                  Sans, not mono. Monospace here is for the things an analyst
                  copies verbatim - an evidence id, a package, an activity, a
                  timestamp - because a fixed advance is what makes those
                  comparable character by character. On a title it is costume:
                  it says "forensic" without doing any of the work, and it
                  made the panel's own heading the least legible line in it.
                */}
                <h3 className="font-sans text-base font-semibold tracking-[-0.01em] text-slate-900">
                  Evidence Inspection
                </h3>
              </div>
              <button
                type="button"
                onClick={onClose}
                className="hidden lg:flex p-1.5 rounded-lg text-slate-500 hover:text-slate-700 hover:bg-slate-100 transition-colors"
                aria-label="Close modal"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Main Observation Header */}
            <div className="space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="rounded-full bg-slate-900 px-2.5 py-1 font-mono text-[13px] font-semibold text-white">
                  {screenshotId}
                </span>
                {quality && (
                  <span
                    className={`text-xs font-medium px-2.5 py-0.5 rounded-full border ${getQualityBadgeStyle(
                      quality,
                    )}`}
                  >
                    Quality {quality}
                  </span>
                )}
                {correlationStatus && (
                  <span
                    className={`text-xs font-semibold px-2 py-0.5 rounded border ${getCorrelationBadgeStyle(
                      correlationStatus,
                    )}`}
                  >
                    {correlationStatus.replace(/_/g, ' ')}
                  </span>
                )}
              </div>
              {/* The headline says what the analyst is looking at. It used to
                  lead with the investigative claim, which on an uncorroborated
                  frame is the same generic sentence on every screenshot. */}
              <p className="text-sm text-slate-800 font-medium leading-relaxed pt-1">
                {visualObservation}
              </p>
            </div>

            {/* Section 1: Evidence Details Card */}
            <div className="space-y-3 rounded-[var(--tile-radius)] bg-slate-50 p-4">
              <div className="flex items-center gap-1.5 border-b border-slate-200 pb-2 font-sans text-[13px] font-semibold tracking-[-0.005em] text-slate-700">
                <Info className="h-4 w-4 text-slate-400" />
                <span>Evidence Details</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                {evidenceIds && evidenceIds.length > 0 && (
                  <div>
                    <span className="text-slate-500 block text-[13px] font-medium">Evidence ID</span>
                    <div className="flex flex-wrap gap-1 mt-0.5">
                      {evidenceIds.map((eid) => (
                        <span
                          key={eid}
                          className="font-mono text-[13px] font-semibold px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200"
                        >
                          {eid}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {timestampText && timestampText !== '-' && (
                  <div>
                    <span className="text-slate-500 block text-[13px] font-medium">Captured Time</span>
                    <span className="text-slate-800 font-mono text-[13px] flex items-center gap-1 mt-0.5">
                      <Clock className="h-3 w-3 text-slate-500" />
                      {timestampText}
                    </span>
                  </div>
                )}

                {captureReason && (
                  <div>
                    <span className="text-slate-500 block text-[13px] font-medium">Capture Reason</span>
                    <span className="font-mono text-[13px] px-2 py-0.5 rounded bg-slate-200/80 text-slate-800 inline-block mt-0.5">
                      {captureReason}
                    </span>
                  </div>
                )}

                {entry.state_id && (
                  <div>
                    <span className="text-slate-500 block text-[13px] font-medium">State ID</span>
                    <span className="font-mono text-[13px] text-slate-800 mt-0.5">{entry.state_id}</span>
                  </div>
                )}

                {entry.action_id && (
                  <div>
                    <span className="text-slate-500 block text-[13px] font-medium">Action ID</span>
                    <span className="font-mono text-[13px] text-slate-800 mt-0.5">{entry.action_id}</span>
                  </div>
                )}

                {entry.evidence_moment_id && (
                  <div>
                    <span className="text-slate-500 block text-[13px] font-medium">Evidence Moment</span>
                    <span className="font-mono text-[13px] text-slate-800 mt-0.5">{entry.evidence_moment_id}</span>
                  </div>
                )}

                {entry.foreground_package && (
                  <div>
                    <span className="text-slate-500 block text-[13px] font-medium">Foreground Package</span>
                    <span className="font-mono text-[13px] text-slate-800 mt-0.5 break-all">{entry.foreground_package}</span>
                  </div>
                )}

                {entry.activity && (
                  <div>
                    <span className="text-slate-500 block text-[13px] font-medium">Activity</span>
                    <span className="font-mono text-[13px] text-slate-800 mt-0.5 break-all">{entry.activity}</span>
                  </div>
                )}

                {workflow && (
                  <div>
                    <span className="text-slate-500 block text-[13px] font-medium">Workflow</span>
                    <span className="font-mono text-[13px] px-2 py-0.5 rounded bg-slate-200/80 text-slate-800 inline-block mt-0.5">
                      {workflow}
                    </span>
                  </div>
                )}

                {confidenceVal && (
                  <div>
                    <span className="text-slate-500 block text-[13px] font-medium">Confidence Level</span>
                    <span className="font-mono text-[13px] font-semibold text-slate-800 inline-block mt-0.5">
                      {confidenceVal}
                    </span>
                  </div>
                )}
              </div>
            </div>

            {/* Section 2: Investigation Context Card */}
            {/*
              The same surface as the panel above it. A blue tint on one of two
              sibling panels says they are different kinds of thing; they are
              not - both are read-only detail about this frame. Blue is also
              this product's action colour, so a blue panel reads as something
              to press.
            */}
            <div className="space-y-3 rounded-[var(--tile-radius)] bg-slate-50 p-4">
              <div className="flex items-center gap-1.5 border-b border-slate-200 pb-2 font-sans text-[13px] font-semibold tracking-[-0.005em] text-slate-700">
                <ShieldAlert className="h-4 w-4 text-slate-400" />
                <span>Investigation Context</span>
              </div>

              <div className="space-y-2.5 text-xs">
                <div>
                  <span className="block font-sans text-[13px] font-medium tracking-[0.01em] text-slate-500">Visual observation</span>
                  <p className="text-slate-800 leading-relaxed mt-0.5">
                    {visualObservation}
                  </p>
                </div>

                {investigativeClaim && investigativeClaim !== visualObservation && (
                  <div>
                    <span className="block font-sans text-[13px] font-medium tracking-[0.01em] text-slate-500">Investigative claim</span>
                    <p className="text-slate-800 leading-relaxed mt-0.5">
                      {investigativeClaim}
                    </p>
                  </div>
                )}

                {runtimeObservation && (
                  <div>
                    <span className="block font-sans text-[13px] font-medium tracking-[0.01em] text-slate-500">Runtime observation</span>
                    <p className="text-slate-800 leading-relaxed mt-0.5 font-mono text-[13px]">
                      {runtimeObservation}
                    </p>
                  </div>
                )}

                <div>
                  <span className="block font-sans text-[13px] font-medium tracking-[0.01em] text-slate-500">Why it matters</span>
                  <p className="text-slate-800 leading-relaxed mt-0.5">
                    {corroboration || NO_CORROBORATION_NOTE}
                  </p>
                </div>

                {findingKeys && findingKeys.length > 0 && (
                  <div>
                    <span className="block font-sans text-[13px] font-medium tracking-[0.01em] text-slate-500">Associated Finding(s)</span>
                    <div className="flex flex-wrap gap-1.5 mt-1">
                      {findingKeys.map((fk) => (
                        <span
                          key={fk}
                          className="font-mono text-[13px] font-semibold px-2 py-0.5 rounded bg-amber-100 text-amber-900 border border-amber-200"
                        >
                          {fk}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {trigger && (
                  <div>
                    <span className="block font-sans text-[13px] font-medium tracking-[0.01em] text-slate-500">Supporting Runtime Event</span>
                    <p className="font-mono text-[13px] text-slate-800 bg-white/80 p-2 rounded border border-blue-100 mt-0.5">
                      {trigger}
                    </p>
                  </div>
                )}

                {mitreTech && (
                  <div>
                    <span className="block font-sans text-[13px] font-medium tracking-[0.01em] text-slate-500">MITRE ATT&CK Technique</span>
                    <span className="font-mono text-[13px] font-semibold px-2 py-0.5 rounded bg-slate-900 text-white inline-block mt-0.5">
                      {mitreTech}
                    </span>
                  </div>
                )}

                {analystNote && (
                  <div>
                    <span className="block font-sans text-[13px] font-medium tracking-[0.01em] text-slate-500">Analyst Interpretation</span>
                    <p className="text-slate-800 italic bg-white p-2.5 rounded border border-blue-200/60 mt-0.5 leading-relaxed">
                      "{analystNote}"
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Footer Bar */}
          <div className="flex items-center justify-between border-t border-slate-200 pt-3 font-sans text-[13px] tracking-[0.01em] text-slate-500">
            <span>SOC Evidence Locker</span>
            <span>Use Left/Right arrows or buttons to navigate</span>
          </div>
        </div>
      </div>
    </div>
  );
}

