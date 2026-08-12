import type { FraudCardData } from '../App';
import type { RuntimeScreenshotMeta } from './screenshotManifest';

export type RuntimeDynamicStatus =
  | 'NOT_STARTED'
  | 'QUEUED'
  | 'RUNNING'
  | 'COMPLETED'
  | 'INCONCLUSIVE'
  | 'FAILED'
  | 'UNAVAILABLE';

export type ScreenshotUxState =
  | 'LOADING'
  | 'AVAILABLE'
  | 'NO_UI_REACHED'
  | 'RUNTIME_INCONCLUSIVE'
  | 'CAPTURE_FAILED'
  | 'ARTIFACT_MISSING'
  | 'API_ERROR';

export function resolveRuntimeDynamicStatus(data: FraudCardData): RuntimeDynamicStatus {
  const frs = data.frs_breakdown;
  const dyn =
    (data.dynamic_result && typeof data.dynamic_result === 'object' && !Array.isArray(data.dynamic_result)
      ? data.dynamic_result
      : data.dynamic_analysis) || {};

  const raw = String(
    (dyn as { dynamic_status?: string }).dynamic_status ||
      (dyn as { dae_pipeline?: { current_stage?: string } }).dae_pipeline?.current_stage ||
      '',
  ).toUpperCase();

  if (!frs?.dynamic_ran && !dyn.available && raw !== 'RUNNING' && raw !== 'QUEUED') {
    return 'NOT_STARTED';
  }
  if (raw === 'QUEUED' || raw === 'PENDING') return 'QUEUED';
  if (raw === 'RUNNING' || raw === 'INSTALLING' || raw === 'EXPLORING' || raw === 'INITIALIZING') {
    return 'RUNNING';
  }
  if (frs?.dynamic_ran && frs.dynamic_conclusive) return 'COMPLETED';
  if (frs?.dynamic_ran && !frs.dynamic_conclusive) return 'INCONCLUSIVE';
  if (raw === 'FAILED' || (dyn as { error?: string }).error) return 'FAILED';
  if (dyn.available === false) return 'UNAVAILABLE';
  if (frs?.dynamic_ran) return 'INCONCLUSIVE';
  return 'UNAVAILABLE';
}

export function runtimeStatusHeadline(status: RuntimeDynamicStatus): string {
  switch (status) {
    case 'NOT_STARTED':
      return 'Not started';
    case 'QUEUED':
      return 'Queued';
    case 'RUNNING':
      return 'Running';
    case 'COMPLETED':
      return 'Completed';
    case 'INCONCLUSIVE':
      return 'Inconclusive';
    case 'FAILED':
      return 'Failed';
    default:
      return 'Unavailable';
  }
}

export function runtimeStatusExplanation(status: RuntimeDynamicStatus): string {
  switch (status) {
    case 'NOT_STARTED':
      return 'Dynamic sandbox execution was not run for this investigation.';
    case 'QUEUED':
      return 'The sample is queued for sandbox execution.';
    case 'RUNNING':
      return 'The sandbox is executing the application and collecting telemetry.';
    case 'COMPLETED':
      return 'Runtime behaviour was captured and used in scoring where applicable.';
    case 'INCONCLUSIVE':
      return 'The sandbox executed, but insufficient reliable runtime behaviour was captured for scoring.';
    case 'FAILED':
      return 'Sandbox execution failed before reliable evidence could be collected.';
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
    if (dynStatus === 'INCONCLUSIVE' || (data.frs_breakdown?.dynamic_ran && !data.frs_breakdown?.dynamic_conclusive)) {
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

  if (dynStatus === 'NOT_STARTED') return 'RUNTIME_INCONCLUSIVE';

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
