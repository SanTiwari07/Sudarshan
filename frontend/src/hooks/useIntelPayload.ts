import { useCallback, useEffect, useMemo, useState } from 'react';
import type { FraudCardData } from '../types/case';
import { API_BASE, authHeaders } from '../config';
import type { IntelApiPayload } from '../lib/threatIntelModel';
import {
  intelApiNeededForCase,
  mergeIntelWithCase,
  type MergedThreatIntel,
} from '../lib/intelPayloadMerge';

type CacheEntry = {
  api: IntelApiPayload | null;
  error: string | null;
  fetchedAt: number;
};

const sessionCache = new Map<string, CacheEntry>();

export async function fetchIntelligencePayload(sha256: string): Promise<IntelApiPayload> {
  const res = await fetch(`${API_BASE}/intelligence/${sha256}`, {
    headers: authHeaders(),
  });
  if (!res.ok) {
    throw new Error(
      res.status === 404 ? 'No intelligence analysis found for this hash.' : `Fetch failed (${res.status})`,
    );
  }
  return res.json() as Promise<IntelApiPayload>;
}

export function getCachedIntelApi(sha256: string): CacheEntry | undefined {
  return sessionCache.get(sha256);
}

export function primeIntelCache(sha256: string, api: IntelApiPayload): void {
  sessionCache.set(sha256, { api, error: null, fetchedAt: Date.now() });
}

type UseIntelPayloadOptions = {
  enabled: boolean;
  data: FraudCardData | null;
  /** enrich: fetch only when per-provider case fields are incomplete; always: fetch for full intel page */
  fetchPolicy?: 'enrich' | 'always';
};

export function useIntelPayload({ enabled, data, fetchPolicy = 'enrich' }: UseIntelPayloadOptions) {
  const sha256 = data?.sha256 ?? '';
  const [api, setApi] = useState<IntelApiPayload | null>(() => sessionCache.get(sha256)?.api ?? null);
  const [error, setError] = useState<string | null>(() => sessionCache.get(sha256)?.error ?? null);
  const [loading, setLoading] = useState(false);

  const needsFetch = useMemo(() => {
    if (!data) return false;
    if (sessionCache.get(sha256)?.api) return false;
    if (fetchPolicy === 'always') return true;
    return intelApiNeededForCase(data);
  }, [data, sha256, fetchPolicy]);

  const load = useCallback(
    async (options?: { force?: boolean }) => {
      if (!sha256) return;
      if (options?.force) {
        sessionCache.delete(sha256);
      }
      const cached = sessionCache.get(sha256);
      if (cached?.api && !options?.force) {
        setApi(cached.api);
        setError(cached.error);
        return;
      }
      try {
        setLoading(true);
        setError(null);
        const json = await fetchIntelligencePayload(sha256);
        sessionCache.set(sha256, { api: json, error: null, fetchedAt: Date.now() });
        setApi(json);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : 'Failed to fetch threat intelligence';
        sessionCache.set(sha256, { api: null, error: msg, fetchedAt: Date.now() });
        setError(msg);
        setApi(null);
      } finally {
        setLoading(false);
      }
    },
    [sha256],
  );

  const reload = useCallback(() => load({ force: true }), [load]);

  useEffect(() => {
    if (!enabled || !data) return;
    const cached = sessionCache.get(sha256);
    if (cached?.api) {
      setApi(cached.api);
      setError(cached.error);
      return;
    }
    if (!needsFetch) return;
    load();
  }, [enabled, data, needsFetch, load, sha256]);

  const merged: MergedThreatIntel | null = useMemo(() => {
    if (!data) return null;
    return mergeIntelWithCase(data, api);
  }, [data, api]);

  const fetchState = loading ? 'loading' : error ? 'error' : 'idle';

  return {
    merged,
    api,
    loading,
    error,
    fetchState,
    reload,
    needsFetch,
  };
}
