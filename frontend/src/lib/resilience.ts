/**
 * Investigation resilience API client.
 *
 * Every URL is built from `API_BASE`, which resolves from
 * `import.meta.env.VITE_API_URL` - so the same bundle works on localhost, a
 * custom IP and a dockerised deployment without a code change.
 */

import { API_BASE, authHeaders } from '../config';

export interface Assertion {
  key: string;
  label: string;
  fired: boolean;
  evidence: string;
  remediation: string;
}

export interface ExecutionAssertions {
  verdict: string;
  incomplete_exercise: boolean;
  dynamic_ran: boolean;
  threat_events_observed: number;
  coverage_ratio: number;
  fired_count: number;
  total_count: number;
  assertions: Assertion[];
  unfired_keys: string[];
}

export interface RemedialAction {
  type: string;
  [key: string]: unknown;
}

export interface Suggestion {
  suggestion_id: string;
  title: string;
  rationale: string;
  priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | string;
  addresses: string;
  action: RemedialAction;
  actionable: boolean;
  threat_context: string;
}

export interface CheckpointInfo {
  session_id: string;
  exists: boolean;
  saved_at?: number;
  state?: string;
  snapshot_id?: string;
  iteration?: number;
  satisfied_goals?: string[];
  screens_visited?: number;
  evidence_count?: number;
}

export interface PersonaSummary {
  persona_id: string;
  display_name: string;
  description: string;
  contacts: number;
  messages: number;
  calls: number;
  photos: number;
}

export interface TimeWarpResult {
  ok: boolean;
  requested_hours: number;
  observed_shift_hours: number;
  method: string;
  jobs_forced: string[];
  idle_cycled: boolean;
  warnings: string[];
  errors: string[];
}

export interface SeedResult {
  ok: boolean;
  persona_id: string;
  display_name: string;
  rooted: boolean;
  api_level: number;
  seeded: { contacts: number; messages: number; calls: number; photos: number };
  warnings: string[];
  errors: string[];
}

export interface AntiEvasionStep {
  key: string;
  label: string;
  ok: boolean;
  detail: string;
  duration_ms: number;
  warnings: string[];
  errors: string[];
  data: Record<string, unknown>;
}

/**
 * One before/after row.
 *
 * `before`, `after` and `delta` are null when the device would not surface the
 * metric. That is not the same as zero and must never be rendered as zero -
 * "0 SMS reads" is a claim about the sample, "unavailable" is a claim about
 * the sandbox.
 */
export interface AntiEvasionDelta {
  key: string;
  label: string;
  before: number | null;
  after: number | null;
  delta: number | null;
  observable: boolean;
  threat_class: boolean;
  source: 'frida' | 'device' | string;
  meaning: string;
}

export interface AntiEvasionSnapshot {
  captured_at: number;
  hooks_attached: boolean;
  telemetry_source: string;
  metrics: Record<string, number | null>;
  notes: string[];
}

/**
 * What the sequence physically did to the device.
 *
 * Reported separately from the verdict: the clock ends and the rows written
 * are true whether or not the sample reacted, and they are how an analyst
 * tells a working control from a silent no-op.
 */
export interface AntiEvasionApplied {
  clock_before_ms: number;
  clock_after_ms: number;
  clock_shift_hours: number;
  jobs_forced: number;
  doze_cycled: boolean;
  battery_level: number | null;
  seeded: Record<string, number>;
  already_present: Record<string, number>;
}

export type AntiEvasionVerdict =
  | 'MALWARE_DETONATED'
  | 'NO_CHANGES_OBSERVED'
  | 'NO_RUNTIME_TELEMETRY';

export interface AntiEvasionResult {
  session_id: string;
  device_serial: string;
  package_name: string;
  persona_id: string;
  verdict: AntiEvasionVerdict | string;
  summary: string;
  ok: boolean;
  steps: AntiEvasionStep[];
  deltas: AntiEvasionDelta[];
  before: AntiEvasionSnapshot | null;
  after: AntiEvasionSnapshot | null;
  applied_changes: AntiEvasionApplied | null;
  triggered_keys: string[];
  warnings: string[];
  errors: string[];
  started_at: number;
  duration_seconds: number;
}

/** Progress frame pushed on the live stream while the sequence runs. */
export interface AntiEvasionProgress {
  phase: 'started' | 'running' | 'finished' | string;
  index?: number;
  total_steps?: number;
  key?: string;
  label?: string;
  description?: string;
  ok?: boolean;
  detail?: string;
  steps?: { key: string; label: string; description: string }[];
}

export interface ResilienceEvent {
  event: string;
  session_id: string;
  timestamp: number;
  payload: Record<string, unknown>;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...authHeaders(),
      ...(init?.headers || {}),
    },
  });
  if (!res.ok) {
    // The seeding endpoint returns a structured 422 describing which providers
    // refused; surface that rather than a bare status code.
    let detail = `Request failed (${res.status})`;
    try {
      const body = await res.json();
      if (typeof body?.detail === 'string') detail = body.detail;
      else if (body?.detail) detail = JSON.stringify(body.detail);
    } catch {
      /* non-JSON error body */
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export function fetchSuggestions(sessionId: string) {
  return request<{
    session_id: string;
    execution_assertions: ExecutionAssertions;
    suggestions: Suggestion[];
  }>(`/analysis/${encodeURIComponent(sessionId)}/suggestions`);
}

export function fetchCheckpoint(sessionId: string) {
  return request<CheckpointInfo>(
    `/analysis/${encodeURIComponent(sessionId)}/checkpoint`,
  );
}

export function restoreCheckpoint(sessionId: string, packageName = '') {
  return request<Record<string, unknown>>(
    `/analysis/${encodeURIComponent(sessionId)}/checkpoint/restore`,
    { method: 'POST', body: JSON.stringify({ package_name: packageName }) },
  );
}

export function applyTimeWarp(
  sessionId: string,
  hours: number,
  forceJobs: boolean,
  packageName = '',
) {
  return request<TimeWarpResult>(
    `/analysis/${encodeURIComponent(sessionId)}/time-warp`,
    {
      method: 'POST',
      body: JSON.stringify({
        hours,
        force_jobs: forceJobs,
        package_name: packageName,
      }),
    },
  );
}

export function listPersonas() {
  return request<{ count: number; personas: PersonaSummary[] }>(
    '/analysis/personas',
  );
}

export function seedPersona(sessionId: string, personaId: string) {
  return request<SeedResult>(
    `/analysis/${encodeURIComponent(sessionId)}/seed-persona`,
    { method: 'POST', body: JSON.stringify({ persona_id: personaId }) },
  );
}

/**
 * Run the full time-warp + persona sequence.
 *
 * Long-running by design - the device work is ~10-15s and the response is only
 * returned once the closing behaviour snapshot has been taken. Progress
 * arrives on the event stream meanwhile, so the caller does not have to wait
 * blind on this promise.
 */
export function runAntiEvasion(
  sessionId: string,
  packageName = '',
  personaId = 'default_retail_user',
) {
  return request<AntiEvasionResult>(
    `/analysis/${encodeURIComponent(sessionId)}/autonomous-anti-evasion`,
    {
      method: 'POST',
      body: JSON.stringify({
        package_name: packageName,
        persona_id: personaId,
      }),
    },
  );
}

export function fetchRecentEvents(sessionId: string) {
  return request<{ session_id: string; events: ResilienceEvent[] }>(
    `/analysis/${encodeURIComponent(sessionId)}/events`,
  );
}

/**
 * Open the live event stream.
 *
 * The URL is derived from `API_BASE` rather than from `window.location`, so a
 * frontend served from a different origin than the API still connects. The
 * bearer token travels as a query parameter because the browser WebSocket API
 * cannot set an Authorization header on the handshake.
 */
export function openEventStream(sessionId: string): WebSocket | null {
  const token = localStorage.getItem('sudarshan_token');
  if (!token) return null;
  try {
    const base = new URL(API_BASE, window.location.origin);
    base.protocol = base.protocol === 'https:' ? 'wss:' : 'ws:';
    base.pathname =
      `${base.pathname.replace(/\/$/, '')}` +
      `/analysis/${encodeURIComponent(sessionId)}/events/ws`;
    base.search = `?token=${encodeURIComponent(token)}`;
    return new WebSocket(base.toString());
  } catch {
    return null;
  }
}
