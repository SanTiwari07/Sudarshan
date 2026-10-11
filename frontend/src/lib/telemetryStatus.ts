import type { DynamicAnalysis } from '../types/case';

/**
 * Plain-language reading of the backend's recorded telemetry diagnostics.
 *
 * Every string here restates a value the backend RECORDED. Nothing is
 * inferred: a run with zero events is never described as benign, and a field
 * the backend did not send is reported as unknown rather than defaulted.
 */

export type TelemetryTone = 'ok' | 'warn' | 'fail' | 'unknown';

export type TelemetryView = {
  classification: string | null;
  label: string;
  tone: TelemetryTone;
  explanation: string;
  hooksInstalled: number | null;
  eventsReceived: number | null;
  detachReason: string | null;
  error: string | null;
  encryptedTrafficInspected: boolean | null;
  limitations: string[];
};

const LABELS: Record<string, { label: string; tone: TelemetryTone }> = {
  FRIDA_ATTACH_FAILED: { label: 'Attach failed', tone: 'fail' },
  AGENT_INIT_FAILED: { label: 'Agent failed', tone: 'fail' },
  HOOK_INSTALL_FAILED: { label: 'No hooks installed', tone: 'fail' },
  NO_TELEMETRY_OBSERVED: { label: 'Instrumentation lost', tone: 'warn' },
  HOOKS_INSTALLED_NOT_EXERCISED: { label: 'Hooks not exercised', tone: 'warn' },
  EVENT_PROCESSING_FAILED: { label: 'Events lost in processing', tone: 'warn' },
  RUNTIME_EVENTS_RECEIVED: { label: 'Events received', tone: 'ok' },
};

/** Shown whenever no runtime event was observed, whatever the reason. */
export const ABSENCE_IS_NOT_BENIGN =
  'No runtime events were observed. Missing telemetry is not evidence of benign behaviour.';

function num(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

export function describeTelemetry(dynamic: DynamicAnalysis | null | undefined): TelemetryView {
  const t = (dynamic?.telemetry_diagnostics ?? {}) as Record<string, any>;
  const net = (dynamic?.network_collection ?? {}) as Record<string, any>;
  const classification = typeof t.classification === 'string' ? t.classification : null;
  const meta = classification ? LABELS[classification] : undefined;
  const limitations: string[] = Array.isArray(net.limitations)
    ? net.limitations.filter((l: unknown): l is string => typeof l === 'string')
    : [];

  return {
    classification,
    label: meta?.label ?? (classification ? classification : 'Not recorded'),
    tone: meta?.tone ?? 'unknown',
    explanation:
      typeof t.explanation === 'string' && t.explanation
        ? t.explanation
        : 'Telemetry diagnostics were not recorded for this run.',
    hooksInstalled: num(t.hooks?.installed),
    eventsReceived: num(t.events?.received),
    detachReason:
      t.session?.attached_at_window_end === false && t.session?.detach_reason
        ? String(t.session.detach_reason)
        : null,
    error: typeof dynamic?.error === 'string' && dynamic.error ? dynamic.error : null,
    encryptedTrafficInspected:
      typeof net.encrypted_traffic_inspected === 'boolean' ? net.encrypted_traffic_inspected : null,
    limitations,
  };
}
