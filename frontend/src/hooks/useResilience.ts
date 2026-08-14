import { useCallback, useEffect, useRef, useState } from 'react';
import {
  applyTimeWarp,
  fetchCheckpoint,
  fetchRecentEvents,
  fetchSuggestions,
  listPersonas,
  openEventStream,
  restoreCheckpoint,
  seedPersona,
  type CheckpointInfo,
  type ExecutionAssertions,
  type PersonaSummary,
  type ResilienceEvent,
  type Suggestion,
} from '../lib/resilience';

/** Polling cadence when the WebSocket cannot be established. */
const FALLBACK_POLL_MS = 8000;

export interface ResilienceState {
  assertions: ExecutionAssertions | null;
  suggestions: Suggestion[];
  checkpoint: CheckpointInfo | null;
  personas: PersonaSummary[];
  events: ResilienceEvent[];
  loading: boolean;
  busy: string | null;
  error: string | null;
  live: boolean;
}

/**
 * Backs the resilience panels.
 *
 * Prefers the live WebSocket stream and falls back to polling when the socket
 * cannot be opened - a reverse proxy that does not upgrade connections is
 * common, and the panels have to stay correct there, just less immediate.
 */
export function useResilience(sessionId: string | undefined, packageName = '') {
  const [state, setState] = useState<ResilienceState>({
    assertions: null,
    suggestions: [],
    checkpoint: null,
    personas: [],
    events: [],
    loading: true,
    busy: null,
    error: null,
    live: false,
  });
  const mounted = useRef(true);
  const socket = useRef<WebSocket | null>(null);

  const patch = useCallback((next: Partial<ResilienceState>) => {
    if (mounted.current) setState((prev) => ({ ...prev, ...next }));
  }, []);

  const refresh = useCallback(async () => {
    if (!sessionId) {
      patch({ loading: false });
      return;
    }
    try {
      const [sug, ckpt, pers] = await Promise.all([
        fetchSuggestions(sessionId).catch(() => null),
        fetchCheckpoint(sessionId).catch(() => null),
        listPersonas().catch(() => null),
      ]);
      patch({
        assertions: sug?.execution_assertions ?? null,
        suggestions: sug?.suggestions ?? [],
        checkpoint: ckpt,
        personas: pers?.personas ?? [],
        loading: false,
        error: null,
      });
    } catch (err) {
      patch({ loading: false, error: (err as Error).message });
    }
  }, [sessionId, patch]);

  useEffect(() => {
    mounted.current = true;
    void refresh();
    return () => {
      mounted.current = false;
    };
  }, [refresh]);

  // Live stream, with a polling fallback.
  useEffect(() => {
    if (!sessionId) return;
    let poller: ReturnType<typeof setInterval> | null = null;

    const startPolling = () => {
      if (poller) return;
      poller = setInterval(() => {
        void fetchRecentEvents(sessionId)
          .then((r) => patch({ events: r.events }))
          .catch(() => undefined);
      }, FALLBACK_POLL_MS);
    };

    const ws = openEventStream(sessionId);
    socket.current = ws;
    if (!ws) {
      startPolling();
      return () => {
        if (poller) clearInterval(poller);
      };
    }

    ws.onopen = () => patch({ live: true });
    ws.onmessage = (msg) => {
      try {
        const event = JSON.parse(msg.data) as ResilienceEvent;
        setState((prev) => ({
          ...prev,
          // Newest first, bounded - this panel is a live tail, not a log store.
          events: [event, ...prev.events].slice(0, 50),
          assertions:
            event.event === 'EXECUTION_ASSERTION_UPDATED'
              ? (event.payload as unknown as ExecutionAssertions)
              : prev.assertions,
        }));
      } catch {
        /* ignore malformed frames */
      }
    };
    ws.onerror = () => {
      patch({ live: false });
      startPolling();
    };
    ws.onclose = () => {
      patch({ live: false });
      startPolling();
    };

    return () => {
      if (poller) clearInterval(poller);
      ws.close();
      socket.current = null;
    };
  }, [sessionId, patch]);

  const run = useCallback(
    async <T,>(label: string, fn: () => Promise<T>): Promise<T | null> => {
      patch({ busy: label, error: null });
      try {
        const result = await fn();
        await refresh();
        return result;
      } catch (err) {
        patch({ error: (err as Error).message });
        return null;
      } finally {
        patch({ busy: null });
      }
    },
    [patch, refresh],
  );

  return {
    ...state,
    refresh,
    restore: () =>
      run('restore', () => restoreCheckpoint(sessionId ?? '', packageName)),
    warp: (hours: number, forceJobs = true) =>
      run('warp', () => applyTimeWarp(sessionId ?? '', hours, forceJobs, packageName)),
    seed: (personaId: string) =>
      run('seed', () => seedPersona(sessionId ?? '', personaId)),
  };
}
