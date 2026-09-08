import { describe, it, expect, vi, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useReducedMotion } from './useReducedMotion';

/**
 * The CSS guard in index.css covers declarative animation. JavaScript-driven
 * motion does not consult a media query, so anything animating in JS reads this
 * instead. A security console is left open for hours, so the preference has to
 * be observed, not just sampled once at mount.
 */

type Listener = (e: MediaQueryListEvent) => void;

function stubMatchMedia(initial: boolean) {
  const listeners: Listener[] = [];
  const mql = {
    matches: initial,
    addEventListener: (_: string, cb: Listener) => listeners.push(cb),
    removeEventListener: (_: string, cb: Listener) => {
      const i = listeners.indexOf(cb);
      if (i >= 0) listeners.splice(i, 1);
    },
  };
  vi.stubGlobal(
    'matchMedia',
    vi.fn(() => mql),
  );
  return {
    listenerCount: () => listeners.length,
    emit: (matches: boolean) => {
      mql.matches = matches;
      listeners.forEach((cb) => cb({ matches } as MediaQueryListEvent));
    },
  };
}

afterEach(() => vi.unstubAllGlobals());

describe('useReducedMotion', () => {
  it('reports the preference at mount', () => {
    stubMatchMedia(true);
    const { result } = renderHook(() => useReducedMotion());
    expect(result.current).toBe(true);
  });

  it('reports false when the reader has expressed no preference', () => {
    stubMatchMedia(false);
    const { result } = renderHook(() => useReducedMotion());
    expect(result.current).toBe(false);
  });

  it('follows a change made while the app is open', () => {
    const mq = stubMatchMedia(false);
    const { result } = renderHook(() => useReducedMotion());
    expect(result.current).toBe(false);

    act(() => mq.emit(true));
    expect(result.current).toBe(true);
  });

  it('unsubscribes on unmount', () => {
    const mq = stubMatchMedia(false);
    const { unmount } = renderHook(() => useReducedMotion());
    expect(mq.listenerCount()).toBe(1);
    unmount();
    expect(mq.listenerCount()).toBe(0);
  });

  it('defaults to allowing motion when matchMedia is unavailable', () => {
    // Failing closed here would silently disable motion for everyone on an
    // older engine, which is a worse default than the honest one.
    vi.stubGlobal('matchMedia', undefined);
    const { result } = renderHook(() => useReducedMotion());
    expect(result.current).toBe(false);
  });
});
