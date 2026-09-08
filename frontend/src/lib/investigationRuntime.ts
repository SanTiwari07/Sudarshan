import type { FraudCardData } from '../App';
import type { RuntimeScreenshotMeta } from './screenshotManifest';

export type RuntimeDynamicStatus =
  | 'NOT_STARTED'
  | 'NOT_REQUESTED'
  | 'QUEUED'
  | 'RUNNING'
  | 'COMPLETED'
  // A run that produced real runtime evidence from part of its planned
  // investigation. Previously such a run had nowhere to go but INCONCLUSIVE,
  // which reads to an analyst exactly like a run that observed nothing - so 47
  // captured events across 9 confirmed goals and a sandbox that never attached
  // rendered with the same word.
  | 'PARTIAL'
  // The 30-minute wall clock arrived. Distinct from PARTIAL because the reason
  // the investigation stopped short is itself worth reporting.
  | 'TIME_BUDGET_EXHAUSTED'
  | 'INCONCLUSIVE'
  | 'FAILED'
  | 'UNAVAILABLE'
  | 'EMULATOR_UNAVAILABLE'
  | 'INSTALL_FAILED'
  | 'FRIDA_ATTACH_FAILED'
  | 'PERSISTENCE_FAILED'
  | 'ARTIFACT_MISSING';

export type ScreenshotUxState =
  | 'LOADING'
  | 'AVAILABLE'
  | 'NO_UI_REACHED'
  | 'RUNTIME_INCONCLUSIVE'
  | 'CAPTURE_FAILED'
  | 'ARTIFACT_MISSING'
  | 'API_ERROR';

export type DynamicCoverage = {
  dynamic_status?: string;
  dynamic_valid?: boolean;
  dynamic_complete?: boolean;
  coverage_ratio?: number;
  coverage_percent?: number;
  goals_total?: number;
  goals_successful?: number;
  goals_partial?: number;
  goals_failed?: number;
  goals_skipped?: number;
  goals_not_reached?: number;
  evidence_event_count?: number;
  meaningful_transition_count?: number;
  analysis_budget_seconds?: number;
  analysis_elapsed_seconds?: number;
  timeout_reason?: string | null;
  limitations?: string[];
  narrative?: string;
};

type DynPayload = {
  dynamic_status?: string;
  dae_pipeline?: { current_stage?: string };
  error?: string;
  available?: boolean;
  runtime_requested?: boolean;
  runtime_attempted?: boolean;
  dynamic_coverage?: DynamicCoverage;
};

function dynPayload(data: FraudCardData): DynPayload {
  const raw =
    (data.dynamic_result && typeof data.dynamic_result === 'object' && !Array.isArray(data.dynamic_result)
      ? data.dynamic_result
      : data.dynamic_analysis) || {};
  return raw as DynPayload;
}

/**
 * The dynamic coverage block, from wherever this case carries it.
 *
 * Read from the dynamic result first and the FRS breakdown second, because a
 * stored case may have only the latter. Returns null when neither has it - an
 * older record, where the honest thing is to show no coverage panel rather than
 * a row of zeros that reads as "nothing was covered".
 */
export function resolveDynamicCoverage(data: FraudCardData): DynamicCoverage | null {
  const dyn = dynPayload(data);
  if (dyn.dynamic_coverage && typeof dyn.dynamic_coverage === 'object') {
    return dyn.dynamic_coverage;
  }
  const fromFrs = (data.frs_breakdown as { dynamic_coverage?: DynamicCoverage } | undefined)
    ?.dynamic_coverage;
  if (fromFrs && typeof fromFrs === 'object' && Object.keys(fromFrs).length > 0) {
    return fromFrs;
  }
  return null;
}

/** "14m 02s" from a raw second count. Empty when there is nothing to show. */
export function formatRuntimeDuration(seconds: number | undefined | null): string {
  if (seconds === undefined || seconds === null || !Number.isFinite(seconds) || seconds < 0) {
    return '';
  }
  const total = Math.round(seconds);
  const mins = Math.floor(total / 60);
  const secs = total % 60;
  return `${mins}m ${String(secs).padStart(2, '0')}s`;
}

export function resolveRuntimeDynamicStatus(data: FraudCardData): RuntimeDynamicStatus {
  const frs = data.frs_breakdown;
  const dyn = dynPayload(data);

  const raw = String(
    dyn.dynamic_status || dyn.dae_pipeline?.current_stage || '',
  ).toUpperCase();

  const runtimeRequested = Boolean(dyn.runtime_requested);
  const runtimeAttempted = Boolean(
    dyn.runtime_attempted || frs?.dynamic_ran || data.dynamic_available,
  );

  if (!runtimeRequested && !runtimeAttempted && !dyn.available && raw !== 'RUNNING' && raw !== 'QUEUED') {
    return 'NOT_REQUESTED';
  }

  if (raw === 'EMULATOR_UNAVAILABLE') return 'EMULATOR_UNAVAILABLE';
  if (raw === 'INSTALL_FAILED') return 'INSTALL_FAILED';
  if (raw === 'FRIDA_ATTACH_FAILED' || raw === 'INSTRUMENTATION_FAILED') return 'FRIDA_ATTACH_FAILED';
  if (raw === 'PERSISTENCE_FAILED') return 'PERSISTENCE_FAILED';
  if (raw === 'ARTIFACT_MISSING') return 'ARTIFACT_MISSING';

  if (runtimeRequested && !runtimeAttempted && !dyn.available) {
    return 'EMULATOR_UNAVAILABLE';
  }

  if (raw === 'QUEUED' || raw === 'PENDING') return 'QUEUED';
  if (
    raw === 'RUNNING' ||
    raw === 'INSTALLING' ||
    raw === 'EXPLORING' ||
    raw === 'INITIALIZING' ||
    raw === 'STARTING'
  ) {
    return 'RUNNING';
  }

  // ── Coverage decides between COMPLETED, PARTIAL and INCONCLUSIVE ────────
  //
  // Consulted BEFORE the dynamic_conclusive fallback below, because that
  // boolean cannot tell a run that observed part of its plan from one that
  // observed nothing at all - and rendering those identically is the defect
  // this whole path exists to fix. A run is only INCONCLUSIVE here when its own
  // coverage block says it obtained no trustworthy evidence.
  const coverage = resolveDynamicCoverage(data);
  if (coverage?.dynamic_status) {
    const cov = String(coverage.dynamic_status).toUpperCase();
    if (cov === 'COMPLETE') return 'COMPLETED';
    if (cov === 'PARTIAL') return 'PARTIAL';
    if (cov === 'TIME_BUDGET_EXHAUSTED') {
      // A timeout that still collected evidence is a usable partial result.
      // One that collected nothing is not, and says so.
      return coverage.dynamic_valid ? 'TIME_BUDGET_EXHAUSTED' : 'INCONCLUSIVE';
    }
    if (cov === 'INSTRUMENTATION_FAILED') return 'FRIDA_ATTACH_FAILED';
    if (cov === 'SKIPPED') return 'NOT_REQUESTED';
    if (cov === 'NO_BEHAVIOR_OBSERVED') return 'INCONCLUSIVE';
  }

  if (frs?.dynamic_ran && frs.dynamic_conclusive) return 'COMPLETED';
  if (frs?.dynamic_ran && !frs.dynamic_conclusive) return 'INCONCLUSIVE';
  if (raw === 'FAILED' || dyn.error) return 'FAILED';
  if (dyn.available === false && runtimeAttempted) return 'FAILED';
  if (dyn.available === false) return 'UNAVAILABLE';
  if (frs?.dynamic_ran) return 'INCONCLUSIVE';
  return 'UNAVAILABLE';
}

export function runtimeStatusHeadline(status: RuntimeDynamicStatus): string {
  switch (status) {
    case 'NOT_STARTED':
      return 'Not started';
    case 'NOT_REQUESTED':
      return 'Not requested';
    case 'QUEUED':
      return 'Queued';
    case 'RUNNING':
      return 'Running';
    case 'COMPLETED':
      return 'Completed';
    // Never "Failed". A run with meaningful evidence in it has not failed, and
    // labelling it so tells the analyst to ignore evidence that is there.
    case 'PARTIAL':
      return 'Partial evidence';
    case 'TIME_BUDGET_EXHAUSTED':
      return 'Partial evidence (time limit reached)';
    case 'INCONCLUSIVE':
      return 'Inconclusive';
    case 'FAILED':
      return 'Failed';
    case 'EMULATOR_UNAVAILABLE':
      return 'Emulator unavailable';
    case 'INSTALL_FAILED':
      return 'Install failed';
    case 'FRIDA_ATTACH_FAILED':
      return 'Frida attach failed';
    case 'PERSISTENCE_FAILED':
      return 'Persistence failed';
    case 'ARTIFACT_MISSING':
      return 'Artifact missing';
    default:
      return 'Unavailable';
  }
}

export function runtimeStatusExplanation(status: RuntimeDynamicStatus): string {
  switch (status) {
    case 'NOT_STARTED':
      return 'Dynamic sandbox execution has not started for this investigation.';
    case 'NOT_REQUESTED':
      return 'Dynamic sandbox execution was not requested for this investigation.';
    case 'QUEUED':
      return 'The sample is queued for sandbox execution.';
    case 'RUNNING':
      return 'The sandbox is executing the application and collecting telemetry.';
    case 'COMPLETED':
      return 'Runtime behaviour was captured and used in scoring where applicable.';
    case 'PARTIAL':
      return 'The sandbox produced usable runtime evidence from part of its planned investigation. Scoring uses only what was actually observed; the goals that were not exercised contribute nothing.';
    case 'TIME_BUDGET_EXHAUSTED':
      return 'The analysis reached its wall-clock budget. Everything collected up to that point was flushed and scored; the remaining investigation goals were not exercised.';
    case 'INCONCLUSIVE':
      return 'The sandbox executed, but insufficient reliable runtime behaviour was captured for scoring.';
    case 'FAILED':
      return 'Sandbox execution failed before reliable evidence could be collected.';
    case 'EMULATOR_UNAVAILABLE':
      return 'No sandbox emulator was available when dynamic analysis was requested.';
    case 'INSTALL_FAILED':
      return 'The APK could not be installed on the sandbox emulator.';
    case 'FRIDA_ATTACH_FAILED':
      return 'Runtime instrumentation could not attach to the application process.';
    case 'PERSISTENCE_FAILED':
      return 'Runtime analysis ran but results could not be persisted to the case record.';
    case 'ARTIFACT_MISSING':
      return 'Runtime artifacts referenced by this case could not be loaded.';
    default:
      return 'Runtime analysis is not available for this case.';
  }
}

export function classifyScreenshotUxState(args: {
  loading: boolean;
  apiError: string | null;
  entryCount: number;
  runtime: RuntimeScreenshotMeta | null;
  data: FraudCardData;
}): ScreenshotUxState {
  const { loading, apiError, entryCount, runtime, data } = args;
  if (loading) return 'LOADING';
  if (apiError) return 'API_ERROR';
  if (entryCount > 0) return 'AVAILABLE';

  const dynStatus = resolveRuntimeDynamicStatus(data);
  const failure = (runtime?.failureReason || '').toLowerCase();
  const warnings = runtime?.warnings || [];

  if (
    warnings.some((w) => w.toLowerCase().includes('no artifact directory')) ||
    failure.includes('artifact directory not found')
  ) {
    return 'ARTIFACT_MISSING';
  }

  if (failure.includes('screenshot') && failure.includes('fail')) {
    return 'CAPTURE_FAILED';
  }
  if (failure.includes('screenshot pipeline failed') || failure.includes('capture disabled')) {
    return 'CAPTURE_FAILED';
  }

  if (
    dynStatus === 'INCONCLUSIVE' ||
    dynStatus === 'UNAVAILABLE' ||
    failure.includes('no runtime screenshots') ||
    failure.includes('dynamic analysis was not executed')
  ) {
    // A PARTIAL run is deliberately excluded from this branch. It HAS runtime
    // evidence; the absence of screenshots in it is a capture question, not a
    // "no reliable runtime evidence" one, and conflating the two hides the
    // evidence the run did collect.
    if (
      dynStatus === 'INCONCLUSIVE' ||
      (data.frs_breakdown?.dynamic_ran &&
        !data.frs_breakdown?.dynamic_conclusive &&
        dynStatus !== 'PARTIAL' &&
        dynStatus !== 'TIME_BUDGET_EXHAUSTED')
    ) {
      return 'RUNTIME_INCONCLUSIVE';
    }
  }

  if (
    failure.includes('no ui') ||
    failure.includes('no interaction') ||
    failure.includes('terminated immediately') ||
    failure.includes('app terminated')
  ) {
    return 'NO_UI_REACHED';
  }

  if (dynStatus === 'NOT_STARTED' || dynStatus === 'NOT_REQUESTED') return 'RUNTIME_INCONCLUSIVE';

  return 'NO_UI_REACHED';
}

export const SCREENSHOT_STATE_COPY: Record<
  Exclude<ScreenshotUxState, 'LOADING' | 'AVAILABLE'>,
  { title: string; body: string }
> = {
  NO_UI_REACHED: {
    title: 'No application screens were reached',
    body: 'The application launched, but the sandbox did not reach a capturable UI state.',
  },
  RUNTIME_INCONCLUSIVE: {
    title: 'Runtime evidence unavailable',
    body: 'The sandbox did not produce reliable runtime evidence for this investigation.',
  },
  CAPTURE_FAILED: {
    title: 'Capture failed',
    body: 'The application execution started, but screenshot capture failed.',
  },
  ARTIFACT_MISSING: {
    title: 'Evidence artifact unavailable',
    body: 'The analysis record references runtime evidence, but the associated artifact could not be loaded.',
  },
  API_ERROR: {
    title: 'Could not load screenshot manifest',
    body: 'The screenshot service did not respond. Check authentication and try refreshing the case.',
  },
};
