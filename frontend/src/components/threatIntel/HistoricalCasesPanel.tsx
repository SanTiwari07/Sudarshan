import { useEffect, useState } from 'react';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import { History } from 'lucide-react';
import { API_BASE, authHeaders } from '../../config';
import type { FraudCardData } from '../../types/case';
import { scoreCaseSimilarity, type HistoricalCaseRow } from '../../lib/threatIntelModel';
import Badge from '../ui/Badge';

export default function HistoricalCasesPanel({ data }: { data: FraudCardData }) {
  const [rows, setRows] = useState<HistoricalCaseRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await fetch(`${API_BASE}/cases?limit=50&offset=0`, { headers: authHeaders() });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const body = await res.json();
        const cases = (body.cases || []) as {
          sha256: string;
          family_classification: string | null;
          final_risk_score: number | null;
          risk_band: string | null;
          confidence: number | null;
          package_name: string | null;
        }[];
        const mapped: HistoricalCaseRow[] = cases
          .filter((c) => c.sha256 !== data.sha256)
          .map((c) => ({
            sha256: c.sha256,
            similarity: scoreCaseSimilarity(data, c),
            verdict: c.risk_band || '-',
            family: c.family_classification || 'Unknown',
            risk: c.final_risk_score ?? 0,
            confidence: c.confidence ?? 0,
            analyst: '-',
          }))
          .filter((r) => r.similarity >= 15)
          .sort((a, b) => b.similarity - a.similarity)
          .slice(0, 8);
        if (!cancelled) setRows(mapped);
      } catch (e: unknown) {
        if (!cancelled) setError(e instanceof Error ? e.message : 'Failed to load cases');
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [data.sha256, data.family_classification, data.final_risk_score, data.risk_band, data.package_name]);

  return (
    <SocCard>
      <SectionHeader icon={<History className="h-4 w-4" />} title="Historical cases" subtitle="Similar investigations in corpus" />
      {loading ? (
        <div className="p-6 space-y-2 animate-pulse">
          <div className="h-8 bg-slate-100 rounded" />
          <div className="h-8 bg-slate-100 rounded" />
        </div>
      ) : error ? (
        <p className="p-6 text-xs text-amber-700">{error}</p>
      ) : rows.length === 0 ? (
        <p className="p-6 text-xs text-slate-500 text-center">No similar historical cases in local database.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="bg-slate-50 text-[13px] font-medium tracking-[0.01em] text-slate-500">
              <tr>
                <th className="text-left px-4 py-2">Case</th>
                <th className="text-right px-4 py-2">Similarity</th>
                <th className="text-left px-4 py-2">Verdict</th>
                <th className="text-left px-4 py-2">Family</th>
                <th className="text-right px-4 py-2">Risk</th>
                <th className="text-right px-4 py-2">Confidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rows.map((r) => (
                <tr key={r.sha256} className="hover:bg-slate-50">
                  <td className="px-4 py-2 font-mono text-[13px]">{r.sha256.slice(0, 16)}…</td>
                  <td className="px-4 py-2 text-right font-mono">{r.similarity}%</td>
                  <td className="px-4 py-2">
                    <Badge label={r.verdict} variant="risk" />
                  </td>
                  <td className="px-4 py-2">{r.family}</td>
                  <td className="px-4 py-2 text-right font-mono">{r.risk.toFixed(0)}</td>
                  <td className="px-4 py-2 text-right font-mono">{r.confidence}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </SocCard>
  );
}
