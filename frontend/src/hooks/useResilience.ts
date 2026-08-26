import { useCallback, useEffect, useRef, useState } from 'react';
import {
  applyTimeWarp,
  fetchCheckpoint,
  fetchRecentEvents,
  fetchSuggestions,
  listPersonas,
  openEventStream,
  restoreCheckpoint,
  runAntiEvasion,
  seedPersona,
  type AntiEvasionProgress,
  type AntiEvasionResult,
  type CheckpointInfo,
  type ExecutionAssertions,
  type PersonaSummary,
  type ResilienceEvent,
  type Suggestion,
} from '../lib/resilience';

/** Polling cadence when the WebSocket cannot be established. */
const FALLBACK_POLL_MS = 8000;

/** A step of the anti-evasion sequence, as the live stream describes it. */
export interface AntiEvasionStepState {
  key: string;
  label: string;
  description: string;
  status: 'pending' | 'running' | 'done' | 'failed';
  detail: string;
}

export interface ResilienceState {
  assertions: ExecutionAssertions | null;
  suggestions: Suggestion[];
  checkpoint: CheckpointInfo | null;
  personas: PersonaSummary[];
  events: ResilienceEvent[];
  antiEvasion: AntiEvasionResult | null;
  antiEvasionSteps: AntiEvasionStepState[];
  loading: boolean;
  busy: string | null;
  error: string | null;
  live: boolean;
}

/**
 * Fold one progress frame into the step list.
 *
 * The backend announces the whole plan up front and then reports each step, so
 * the panel can show the remaining work as pending instead of revealing steps
 * one at a time - an analyst watching a live sandbox should know how much of
 * the sequence is left.
 */
function applyProgress(
  steps: AntiEvasionStepState[],
  progress: AntiEvasionProgress,
): AntiEvasionStepState[] {
  if (progress.phase === 'started') {
    return (progress.steps ?? []).map((s) => ({
      key: s.key,
      label: s.label,
      description: s.description,
      status: 'pending' as const,
      detail: '',
    }));
  }
  if (!progress.key) return steps;

  const known = steps.some((s) => s.key === progress.key);
  const next = known
    ? steps
    : [
        ...steps,
        {
          key: progress.key,
          label: progress.label ?? progress.key,
          description: progress.description ?? '',
          status: 'pending' as const,
          detail: '',
        },
      ];

  return next.map((s) =>
    s.key === progress.key
      ? {
          ...s,
          label: progress.label ?? s.label,
          description: progress.description ?? s.description,
          status:
            progress.phase === 'running'
              ? ('running' as const)
              : progress.ok
                ? ('done' as const)
                : ('failed' as const),
          detail: progress.detail ?? s.detail,
        }
      : s,
  );
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
    antiEvasion: null,
    antiEvasionSteps: [],
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
          .then((r) => {
            // The replay buffer is chronological, so the progress frames are
            // replayed in order: without a socket the step list updates once
            // per poll instead of live, rather than not at all.
            const steps = r.events
              .filter((e) => e.event === 'ANTI_EVASION_STEP')
              .reduce<AntiEvasionStepState[]>(
                (acc, e) => applyProgress(acc, e.payload as unknown as AntiEvasionProgress),
                [],
              );
            patch({ events: r.events, antiEvasionSteps: steps });
          })
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
          antiEvasionSteps:
            event.event === 'ANTI_EVASION_STEP'
              ? applyProgress(
                  prev.antiEvasionSteps,
                  event.payload as unknown as AntiEvasionProgress,
                )
              : prev.antiEvasionSteps,
          antiEvasion:
            event.event === 'ANTI_EVASION_COMPLETE'
              ? (event.payload as unknown as AntiEvasionResult)
              : prev.antiEvasion,
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
    // Still exported: the single-control endpoints remain part of the analyst
    // API, and a caller that wants only half the sequence can reach them.
    warp: (hours: number, forceJobs = true) =>
      run('warp', () => applyTimeWarp(sessionId ?? '', hours, forceJobs, packageName)),
    seed: (personaId: string) =>
      run('seed', () => seedPersona(sessionId ?? '', personaId)),
    antiEvade: (personaId = 'default_retail_user') => {
      // The previous verdict is cleared before the sequence starts: leaving a
      // stale delta card on screen while a new sequence runs would show an
      // analyst a result that does not belong to what they are watching.
      patch({ antiEvasion: null, antiEvasionSteps: [] });
      return run('anti-evasion', async () => {
        const result = await runAntiEvasion(sessionId ?? '', packageName, personaId);
        patch({ antiEvasion: result });
        return result;
      });
    },
  };
}
