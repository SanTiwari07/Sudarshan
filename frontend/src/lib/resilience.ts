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
