import { useCallback, useEffect, useRef, useState } from 'react';
import {
  fetchScreenshotManifest,
  type RuntimeScreenshotMeta,
  type ScreenshotManifestEntry,
  type ScreenshotSortOrder,
} from '../lib/screenshotManifest';

const POLL_MS = 3000;

export function useRuntimeScreenshots(
  sha256: string | undefined,
  options?: { poll?: boolean; sortOrder?: ScreenshotSortOrder },
) {
  const poll = options?.poll ?? false;
  const sortOrder = options?.sortOrder ?? 'newest';
  const [entries, setEntries] = useState<ScreenshotManifestEntry[]>([]);
  const [runtime, setRuntime] = useState<RuntimeScreenshotMeta | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const mounted = useRef(true);

  const refresh = useCallback(async () => {
    if (!sha256) {
      setEntries([]);
      setRuntime(null);
      setLoading(false);
      return;
    }
    const data = await fetchScreenshotManifest(sha256, sortOrder);
    if (!mounted.current) return;
    if (!data) {
      setError('Could not load screenshot manifest');
      setEntries([]);
      setRuntime(null);
      setLoading(false);
      return;
    }
    setError(null);
    const list = data.entries?.length ? data.entries : data.screenshots || [];
    setEntries(list);
    setRuntime(data.runtime || null);
    setLoading(false);
  }, [sha256, sortOrder]);

  useEffect(() => {
    mounted.current = true;
    setLoading(true);
    void refresh();
    return () => {
      mounted.current = false;
    };
  }, [refresh]);

  useEffect(() => {
    if (!poll || !sha256) return;
    const id = window.setInterval(() => {
      void refresh();
    }, POLL_MS);
    return () => window.clearInterval(id);
  }, [poll, sha256, refresh]);

  const capturing =
    poll ||
    runtime?.analysisRunning ||
    (runtime?.failureReason === 'Analysis still running') ||
    false;

  return {
    entries,
    runtime,
    loading,
    error,
    refresh,
    capturing,
    expected: runtime?.expected ?? 0,
    capturedCount: runtime?.captured ?? entries.length,
  };
}
