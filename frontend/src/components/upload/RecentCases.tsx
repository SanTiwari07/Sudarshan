import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowRight, Clock, Smartphone } from 'lucide-react';
import { API_BASE } from '../../config';
import { getToken } from '../../pages/Login';
import { useAnalysis } from '../../context/AnalysisContext';
import { formatScore } from '../../lib/verdictCopy';

type RecentCase = {
  sha256: string;
  package_name: string | null;
  app_name: string | null;
  final_risk_score: number | null;
  risk_band: string | null;
  created_at: string;
};

function tone(band: string | null) {
  const b = (band || '').toLowerCase();
  if (b.includes('critical')) return { pill: 'bg-red-50 text-red-700 ring-red-200', bar: 'bg-red-500', tile: 'bg-red-50 text-red-600' };
  if (b.includes('high')) return { pill: 'bg-orange-50 text-orange-700 ring-orange-200', bar: 'bg-orange-500', tile: 'bg-orange-50 text-orange-600' };
  if (b.includes('suspicious')) return { pill: 'bg-amber-50 text-amber-800 ring-amber-200', bar: 'bg-amber-400', tile: 'bg-amber-50 text-amber-600' };
  if (b.includes('safe')) return { pill: 'bg-emerald-50 text-emerald-700 ring-emerald-200', bar: 'bg-emerald-500', tile: 'bg-emerald-50 text-emerald-600' };
  return { pill: 'bg-slate-100 text-slate-600 ring-slate-200', bar: 'bg-slate-400', tile: 'bg-slate-100 text-slate-500' };
}

function timeAgo(iso: string) {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

/** The last few cases, so the landing page doubles as a way back into work. */
export default function RecentCases() {
  const navigate = useNavigate();
  const { loadCaseByHash } = useAnalysis();
  const [cases, setCases] = useState<RecentCase[] | null>(null);

  useEffect(() => {
    let cancelled = false;
    const token = getToken();
    if (!token) return;
    fetch(`${API_BASE}/cases?limit=4&offset=0`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => (r.ok ? r.json() : Promise.reject(r.status)))
      .then((d) => { if (!cancelled) setCases(d.cases ?? []); })
      .catch(() => { if (!cancelled) setCases([]); });
    return () => { cancelled = true; };
  }, []);

  if (cases !== null && cases.length === 0) return null;

  return (
    <section aria-labelledby="recent-cases-heading">
      <div className="flex items-center justify-between mb-4">
        <h2 id="recent-cases-heading" className="text-lg font-semibold tracking-[-0.015em] text-slate-900">
          Recent cases
        </h2>
        <button
          type="button"
          onClick={() => navigate('/history')}
          className="inline-flex items-center gap-1.5 text-sm font-semibold text-blue-600 hover:text-blue-700 group"
        >
          View all
          <ArrowRight className="h-4 w-4 group-hover:translate-x-0.5 transition-transform" aria-hidden />
        </button>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {(cases ?? Array.from({ length: 4 }, () => null)).map((c, i) =>
          c ? (
            <button
              key={c.sha256}
              type="button"
              onClick={async () => {
                await loadCaseByHash(c.sha256);
                navigate(`/history/${c.sha256}`);
              }}
              className="group text-left rounded-2xl border border-slate-200/80 bg-white p-5 transition-all hover:-translate-y-0.5 hover:border-slate-300 hover:shadow-lg hover:shadow-slate-200/60"
            >
              <div className="flex items-start justify-between gap-3">
                <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl ${tone(c.risk_band).tile}`}>
                  <Smartphone className="h-5 w-5" aria-hidden />
                </span>
                <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ring-1 ring-inset ${tone(c.risk_band).pill}`}>
                  {c.risk_band || 'Unscored'}
                </span>
              </div>
              <p className="mt-4 text-[15px] font-semibold text-slate-900 truncate" title={c.app_name || c.package_name || ''}>
                {c.app_name || c.package_name || 'Unnamed app'}
              </p>
              <p className="mt-0.5 flex items-center gap-1.5 text-xs text-slate-500">
                <Clock className="h-3.5 w-3.5" aria-hidden />
                {timeAgo(c.created_at)}
              </p>
              <div className="mt-4 flex items-center gap-3">
                <span className="text-2xl font-semibold tracking-[-0.03em] text-slate-900 tabular-nums">
                  {formatScore(c.final_risk_score)}
                </span>
                <span className="text-xs text-slate-400 -ml-1.5 mt-1.5">/100</span>
                <span className="h-1.5 flex-1 rounded-full bg-slate-100 overflow-hidden">
                  <span
                    className={`block h-full rounded-full ${tone(c.risk_band).bar}`}
                    style={{ width: `${Math.min(100, Math.max(0, c.final_risk_score ?? 0))}%` }}
                  />
                </span>
              </div>
            </button>
          ) : (
            <div key={i} className="h-[158px] rounded-2xl border border-slate-200/80 bg-white animate-pulse" />
          ),
        )}
      </div>
    </section>
  );
}
