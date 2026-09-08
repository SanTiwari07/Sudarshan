import { API_BASE, authHeaders } from '../config';
import { screenshotBasename } from './screenshots';
import type { FraudCardData } from '../App';

export type ScreenshotManifestEntry = {
  screenshot_id: string;
  filename: string;
  label: string;
  trigger_event?: string;
  timestamp_ms?: number;
  category?: string;
  source?: string;
  stage?: string;
  reason?: string;
  activity?: string;
  id?: string;
  path?: string;
  thumbnail?: string;
  timestamp?: string | null;
  captured?: boolean;
  png_url?: string;
  capture_trigger?: string;
  claim_type?: string;
  investigative_claim?: string;
  quality?: string;
  priority?: string;
  correlation_status?: string;
  linked_evidence_ids?: string[];
  linked_finding_keys?: string[];
  workflow_stage_label?: string;
  report_tier?: string;
  timeline_eligible?: boolean;
  visual_evidence?: import('./visualEvidence').VisualEvidencePayload | null;
  state_id?: string;
  action_id?: string;
  evidence_moment_id?: string;
  foreground_package?: string;
  screen_hash?: string;
  layout_hash?: string;
  deduplication_status?: string;
  visual_observation?: string;
  runtime_observation?: string;
  screen_summary?: string;
  corroboration_summary?: string;
  semantic_type?: string;
  observation_source?: string;
};

export type VisualEvidenceIndex = {
  by_finding_key?: Record<string, string[]>;
  by_evidence_id?: Record<string, string[]>;
};

export type RuntimeScreenshotMeta = {
  captureEnabled: boolean;
  expected: number;
  captured: number;
  reportedCaptured?: number;
  captureIntervalSeconds?: number;
  dynamicDurationSeconds?: number | null;
  lastCaptureTimestampMs?: number | null;
  lastCaptureIso?: string | null;
  failureReason?: string | null;
  analysisRunning?: boolean;
  warnings?: string[];
  artifactDirResolved?: string | null;
};

export type ScreenshotManifestResponse = {
  sha256: string;
  total: number;
  entries: ScreenshotManifestEntry[];
  screenshots?: ScreenshotManifestEntry[];
  runtime?: RuntimeScreenshotMeta;
  visual_evidence_index?: VisualEvidenceIndex;
  has_visual_evidence?: boolean;
};

export type ScreenshotSortOrder = 'newest' | 'timeline';

export async function fetchScreenshotManifest(
  sha256: string,
  order: ScreenshotSortOrder = 'newest',
): Promise<ScreenshotManifestResponse | null> {
  try {
    const res = await fetch(
      `${API_BASE}/screenshots/${sha256}/manifest?order=${encodeURIComponent(order)}`,
      { headers: authHeaders() },
    );
    if (!res.ok) return null;
    return (await res.json()) as ScreenshotManifestResponse;
  } catch {
    return null;
  }
}

export function formatScreenshotTime(timestampMs?: number): string {
  if (timestampMs == null || Number.isNaN(timestampMs)) return '-';
  if (timestampMs < 86_400_000) {
    const sec = Math.floor(timestampMs / 1000);
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    return m > 0 ? `T+${m}m ${s}s` : `T+${s}s`;
  }
  try {
    return new Date(timestampMs).toLocaleTimeString(undefined, {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  } catch {
    return '-';
  }
}

export function screenshotStageLabel(entry: ScreenshotManifestEntry): string {
  return entry.stage || entry.category || entry.source || 'Runtime capture';
}

/**
 * Short human label for a frame, for tiles and headings.
 *
 * `screen_summary` leads: it names the KIND of screen and its Activity
 * ("Bank login screen (LoginActivity)"), which is what a gallery caption is
 * for. The remaining fallbacks describe the capture rather than the picture
 * and are kept only for manifests written before that field existed.
 *
 * Use `visual_observation` where a full sentence fits - it lists the fields
 * and controls too, which is too much for a tile.
 */
export function screenshotDescription(entry: ScreenshotManifestEntry): string {
  return (
    entry.screen_summary ||
    entry.label ||
    entry.trigger_event ||
    entry.reason ||
    entry.activity ||
    screenshotBasename(entry.filename).replace(/[-_]/g, ' ')
  );
}

export function entryFilename(entry: ScreenshotManifestEntry): string {
  return entry.filename || entry.path || '';
}

/** Client-side fallback when API runtime block is missing. */
export function inferFailureReasonFromCase(data: FraudCardData, captured: number): string | null {
  if (captured > 0) return null;
  const dyn = data.dynamic_analysis as Record<string, unknown> | undefined;
  if (!dyn) return 'Dynamic analysis was not executed for this case.';

  const dae = (dyn.dae_pipeline || {}) as Record<string, unknown>;
  const metrics = (dae.metrics || {}) as Record<string, unknown>;
  const err = String(dyn.error || dae.failure_reason || '');
  const errLower = err.toLowerCase();
  const status = String(dyn.dynamic_status || dae.current_stage || '');

  if (status.toUpperCase() === 'RUNNING' || status === 'INSTALLING' || status === 'EXPLORING') {
    return 'Analysis still running';
  }
  if (errLower.includes('timeout') || errLower.includes('timed out')) {
    return 'Dynamic analysis timed out';
  }
  if (errLower.includes('install failed') || (status === 'FAILED' && errLower.includes('install'))) {
    return 'App terminated immediately';
  }
  if (errLower.includes('disconnect') || errLower.includes('device offline')) {
    return 'Emulator disconnected';
  }
  if (Number(metrics.explorer_actions || 0) === 0 && dyn.available) {
    return 'Agentic Explorer performed no UI interaction';
  }
  if (String(dyn.dynamic_status || '').includes('INSTRUMENTATION')) {
    return 'App terminated immediately';
  }
  return 'No runtime screenshots were captured during sandbox execution';
}
