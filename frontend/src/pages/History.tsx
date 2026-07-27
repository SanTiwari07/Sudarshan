import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Database, Search, Shield, Clock,
  Filter, RefreshCw, XCircle, Eye
} from 'lucide-react';
import { getToken, getUser } from './Login';
import { API_BASE } from '../config';
import { useAnalysis } from '../context/AnalysisContext';
import Badge from '../components/ui/Badge';
import CopyButton from '../components/ui/CopyButton';
import { fmtDate, fmtScore } from '../utils/derive';

interface CaseSummary {
  sha256: string;
  package_name: string | null;
  app_name: string | null;
  analysis_mode: string | null;
  family_classification: string | null;
  final_risk_score: number | null;
  risk_band: string | null;
  confidence: number | null;
  dynamic_available: boolean;
  obfuscation_score: number;
  has_reflection: boolean;
  created_at: string;
}

interface CaseListResponse {
  total: number;
  limit: number;
  offset: number;
  cases: CaseSummary[];
}

export default function History() {
  const navigate = useNavigate();
  const user = getUser();
  const { loadCaseByHash } = useAnalysis();

  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<string>('all');
  const LIMIT = 15;

  const fetchCases = async (p: number = 0) => {
    const token = getToken();
    if (!token) { navigate('/login'); return; }

    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/cases?limit=${LIMIT}&offset=${p * LIMIT}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.status === 401) { navigate('/login'); return; }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: CaseListResponse = await res.json();
      setCases(data.cases);
      setTotal(data.total);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load cases');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchCases(page); }, [page]);

  const handleCaseClick = async (sha256: string) => {
    await loadCaseByHash(sha256);
    navigate(`/history/${sha256}`);
  };

  const visible = cases.filter(c => {
    const matchSearch = !search ||
      c.sha256.includes(search.toLowerCase()) ||
      (c.package_name || '').toLowerCase().includes(search.toLowerCase()) ||
      (c.family_classification || '').toLowerCase().includes(search.toLowerCase());

    const matchFilter = filter === 'all' || (c.risk_band || '').toLowerCase() === filter;
    return matchSearch && matchFilter;
  });

  const totalPages = Math.ceil(total / LIMIT);

  return (
    <div className="min-h-screen bg-slate-50">
      {/* Header */}
      <div className="bg-blue-900 text-white px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="h-6 w-6 text-blue-300" />
            <span className="font-bold text-lg tracking-wide">SUDARSHAN</span>
            <span className="text-xs text-blue-400 font-mono hidden sm:inline">ENTERPRISE SOC</span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs text-blue-300 hidden sm:block">
              {user?.username} · <span className="uppercase">{user?.role}</span>
            </span>
            <button
              onClick={() => navigate('/')}
              className="text-xs px-3 py-1.5 rounded bg-blue-700 hover:bg-blue-600 transition-colors"
            >
              ← Upload New APK
            </button>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 py-6 space-y-5">
        <div className="flex items-center gap-2">
          <Database className="h-5 w-5 text-blue-700" />
          <h1 className="text-xl font-bold text-slate-900">Case History Registry</h1>
          <span className="ml-2 px-2.5 py-0.5 rounded-full bg-blue-100 text-blue-700 text-xs font-semibold">
            {total} Total Persisted Cases
          </span>
        </div>

        {/* Controls */}
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search SHA256, package name, or family…"
              className="w-full pl-9 pr-3 py-2 rounded-lg border border-slate-300 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-slate-400" />
            <select
              value={filter}
              onChange={e => setFilter(e.target.value)}
              className="rounded-lg border border-slate-300 text-sm py-2 px-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="all">All Risk Bands</option>
              <option value="critical">Critical</option>
              <option value="high risk">High Risk</option>
              <option value="suspicious">Suspicious</option>
              <option value="safe">Safe</option>
            </select>
            <button
              onClick={() => fetchCases(page)}
              disabled={loading}
              className="p-2 rounded-lg border border-slate-300 hover:bg-slate-50 transition-colors disabled:opacity-50"
              title="Refresh"
            >
              <RefreshCw className={`h-4 w-4 text-slate-500 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {error && (
          <div className="flex items-center gap-2 px-4 py-3 rounded-lg bg-red-50 border border-red-200 text-red-700 text-sm">
            <XCircle className="h-4 w-4 flex-shrink-0" />
            {error}
          </div>
        )}

        {/* Table */}
        <div className="bg-white border border-slate-200 rounded-xl shadow-sm overflow-hidden">
          {loading && cases.length === 0 ? (
            <div className="flex items-center justify-center py-16 text-slate-400 gap-3">
              <RefreshCw className="h-5 w-5 animate-spin" />
              Loading persistent cases…
            </div>
          ) : visible.length === 0 ? (
            <div className="py-16 text-center text-slate-400">
              <Database className="h-8 w-8 mx-auto mb-2 opacity-40" />
              <p className="text-sm">No cases found{search ? ' matching your search' : ''}.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
                    <th className="px-4 py-3 text-left">Risk</th>
                    <th className="px-4 py-3 text-left">Package</th>
                    <th className="px-4 py-3 text-left">Family</th>
                    <th className="px-4 py-3 text-right">Score</th>
                    <th className="px-4 py-3 text-center">Dynamic</th>
                    <th className="px-4 py-3 text-left hidden lg:table-cell">SHA256</th>
                    <th className="px-4 py-3 text-left hidden md:table-cell">
                      <Clock className="h-3.5 w-3.5 inline mr-1" />Scanned
                    </th>
                    <th className="px-4 py-3" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {visible.map(c => (
                    <tr
                      key={c.sha256}
                      className="hover:bg-blue-50/40 transition-colors cursor-pointer group"
                      onClick={() => handleCaseClick(c.sha256)}
                    >
                      <td className="px-4 py-3">
                        <Badge label={c.risk_band || 'Safe'} variant="risk" />
                      </td>
                      <td className="px-4 py-3">
                        <div className="font-medium text-slate-800 truncate max-w-[180px]">
                          {c.app_name || c.package_name || '—'}
                        </div>
                        {c.app_name && c.package_name && (
                          <div className="text-xs text-slate-400 truncate max-w-[180px] font-mono">{c.package_name}</div>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span className="inline-flex items-center px-2 py-0.5 rounded bg-slate-100 text-slate-700 text-xs font-mono">
                          {c.family_classification || 'Unknown'}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right font-mono font-bold">
                        {fmtScore(c.final_risk_score)}
                      </td>
                      <td className="px-4 py-3 text-center">
                        {c.dynamic_available ? (
                          <Badge label="Frida" className="bg-emerald-50 text-emerald-700 border border-emerald-200" />
                        ) : (
                          <Badge label="Static" className="bg-slate-50 text-slate-500 border border-slate-200" />
                        )}
                      </td>
                      <td className="px-4 py-3 hidden lg:table-cell">
                        <div className="flex items-center gap-1 font-mono text-xs text-slate-400">
                          <span>{c.sha256.slice(0, 16)}…</span>
                          <CopyButton value={c.sha256} />
                        </div>
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400 hidden md:table-cell whitespace-nowrap">
                        {fmtDate(c.created_at)}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Eye className="h-4 w-4 text-slate-300 group-hover:text-blue-600 transition-colors inline" />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-slate-200 bg-slate-50">
              <span className="text-xs text-slate-500">
                Showing {page * LIMIT + 1}–{Math.min((page + 1) * LIMIT, total)} of {total}
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => setPage(p => Math.max(0, p - 1))}
                  disabled={page === 0}
                  className="px-3 py-1 text-xs rounded border border-slate-300 disabled:opacity-40 hover:bg-slate-100 transition-colors"
                >
                  ← Prev
                </button>
                <span className="px-3 py-1 text-xs text-slate-600">
                  Page {page + 1} / {totalPages}
                </span>
                <button
                  onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                  disabled={page >= totalPages - 1}
                  className="px-3 py-1 text-xs rounded border border-slate-300 disabled:opacity-40 hover:bg-slate-100 transition-colors"
                >
                  Next →
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
