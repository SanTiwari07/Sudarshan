import { useEffect, useState } from 'react';
import { API_BASE, authHeaders } from '../../config';
import type { BatchListResponse, BatchSummary } from '../../types/batch';
import { TYPOGRAPHY } from '../../theme/typography';

/**
 * Fleet totals across every batch this account has run.
 *
 * The batch page opened straight onto a queue of filenames, which shows that
 * the feature works but not what it is for. These four numbers are the whole
 * argument for batch mode - "we processed this many, and this many came back
 * dangerous" - and they are the one thing on the page a reader can take in
 * without reading a single row.
 */
type Totals = {
  batches: number;
  apks: number;
  critical: number;
  high: number;
  suspicious: number;
  safe: number;
  failed: number;
};

function aggregate(batches: BatchSummary[]): Totals {
  return batches.reduce<Totals>(
    (acc, b) => ({
      batches: acc.batches + 1,
      apks: acc.apks + (b.total_jobs || 0),
      critical: acc.critical + (b.critical_count ?? 0),
      high: acc.high + (b.high_risk_count ?? 0),
      suspicious: acc.suspicious + (b.suspicious_count ?? 0),
      safe: acc.safe + (b.safe_count ?? 0),
      failed: acc.failed + (b.failed_jobs || 0),
    }),
    { batches: 0, apks: 0, critical: 0, high: 0, suspicious: 0, safe: 0, failed: 0 },
  );
}

const TILES: Array<{ key: keyof Totals; label: string; tone: string }> = [
  { key: 'apks', label: 'APKs scanned', tone: 'text-slate-900' },
  { key: 'critical', label: 'Critical', tone: 'text-red-600' },
  { key: 'high', label: 'High risk', tone: 'text-orange-600' },
  { key: 'suspicious', label: 'Suspicious', tone: 'text-amber-600' },
  { key: 'safe', label: 'Safe', tone: 'text-emerald-600' },
];

export default function BatchFleetSummary() {
  const [totals, setTotals] = useState<Totals | null>(null);

  useEffect(() => {
    let cancelled = false;

    (async () => {
      try {
        const res = await fetch(`${API_BASE}/batches?limit=100&offset=0`, {
          headers: authHeaders(),
        });
        if (!res.ok) return;
        const data: BatchListResponse = await res.json();
        if (!cancelled) setTotals(aggregate(data.batches));
      } catch {
        /* The summary is additive - a failure just leaves it off the page. */
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  if (!totals || totals.apks === 0) return null;

  return (
    <section
      aria-label="Batch totals"
      className="bg-white border border-slate-200 rounded-lg divide-y sm:divide-y-0 sm:divide-x divide-slate-100 flex flex-col sm:flex-row"
    >
      {TILES.map((tile) => (
        <div key={tile.key} className="flex-1 px-5 py-4">
          <p className={`font-sans text-3xl font-semibold tabular-nums tracking-[-0.03em] leading-none ${tile.tone}`}>
            {totals[tile.key]}
          </p>
          <p className={`${TYPOGRAPHY.label} mt-1.5`}>{tile.label}</p>
        </div>
      ))}
      <div className="flex-1 px-5 py-4">
        <p className="font-sans text-3xl font-semibold tabular-nums tracking-[-0.03em] leading-none text-slate-400">
          {totals.batches}
        </p>
        <p className={`${TYPOGRAPHY.label} mt-1.5`}>
          {totals.batches === 1 ? 'Batch run' : 'Batches run'}
          {totals.failed > 0 && (
            <span className="text-slate-400"> · {totals.failed} failed</span>
          )}
        </p>
      </div>
    </section>
  );
}
