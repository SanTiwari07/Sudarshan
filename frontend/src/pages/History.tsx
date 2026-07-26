import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Database, Search, Shield, Clock,
  TrendingUp, Filter, RefreshCw, AlertTriangle,
  CheckCircle2, XCircle, AlertOctagon, Eye
} from 'lucide-react';
import { getToken, getUser } from './Login';
import { API_BASE } from '../config';



// ─── Types ─────────────────────────────────────────────────────────────────────

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

// ─── Helpers ───────────────────────────────────────────────────────────────────

function riskBandStyle(band: string | null): string {
  switch ((band || '').toLowerCase()) {
    case 'critical':  return 'bg-red-100 text-red-700 border border-red-200';
    case 'high risk': return 'bg-orange-100 text-orange-700 border border-orange-200';
    case 'suspicious': return 'bg-yellow-100 text-yellow-700 border border-yellow-200';
    default:          return 'bg-green-100 text-green-700 border border-green-200';
  }
}

function riskIcon(band: string | null) {
  switch ((band || '').toLowerCase()) {
    case 'critical':   return <XCircle className="h-4 w-4 text-red-500" />;
    case 'high risk':  return <AlertOctagon className="h-4 w-4 text-orange-500" />;
    case 'suspicious': return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
    default:           return <CheckCircle2 className="h-4 w-4 text-green-500" />;
  }
}

function fmtScore(score: number | null): string {
  if (score === null) return '—';
  return score.toFixed(1);
}

function fmtDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString('en-IN', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

// ─── History Page ──────────────────────────────────────────────────────────────

export default function History() {
  const navigate = useNavigate();
  const user = getUser();

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

  // Client-side filter + search
  const visible = cases.filter(c => {
    const matchSearch = !search ||
      c.sha256.includes(search.toLowerCase()) ||
      (c.package_name || '').toLowerCase().includes(search.toLowerCase()) ||
      (c.family_classification || '').toLowerCase().includes(search.toLowerCase());

    const matchFilter = filter === 'all' || (c.risk_band || '').toLowerCase() === filter;
    return matchSearch && matchFilter;
  });

  const totalPages = Math.ceil(total / LIMIT);

  // Stats for the summary bar
  const critical  = cases.filter(c => c.risk_band === 'Critical').length;
  const highRisk  = cases.filter(c => c.risk_band === 'High Risk').length;
  const withDynamic = cases.filter(c => c.dynamic_available).length;
  const avgScore  = cases.length
    ? (cases.reduce((s, c) => s + (c.final_risk_score || 0), 0) / cases.length).toFixed(1)
    : '—';

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-blue-900 text-white px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="h-6 w-6 text-blue-300" />
            <span className="font-bold text-lg tracking-wide">SUDARSHAN</span>
            <span className="text-xs text-blue-400 font-mono hidden sm:inline">v2.1 ENTERPRISE</span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs text-blue-300 hidden sm:block">
              {user?.username} · <span className="uppercase">{user?.role}</span>
            </span>
            <button
              onClick={() => navigate('/')}
              className="text-xs px-3 py-1.5 rounded bg-blue-700 hover:bg-blue-600 transition-colors"
            >
              ← New Analysis
            </button>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 py-6 space-y-5">
        {/* Page title */}
        <div className="flex items-center gap-2">
          <Database className="h-5 w-5 text-blue-700" />
          <h1 className="text-xl font-bold text-gray-900">Case History</h1>
          <span className="ml-2 px-2 py-0.5 rounded-full bg-blue-100 text-blue-700 text-xs font-semibold">
            {total} total
          </span>
        </div>

        {/* Summary stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: 'Critical', value: critical, color: 'text-red-600', bg: 'bg-red-50' },
            { label: 'High Risk', value: highRisk, color: 'text-orange-600', bg: 'bg-orange-50' },
            { label: 'Avg Score', value: avgScore, color: 'text-blue-600', bg: 'bg-blue-50' },
            { label: 'Dynamic', value: withDynamic, color: 'text-purple-600', bg: 'bg-purple-50' },
          ].map(stat => (
            <div key={stat.label} className={`${stat.bg} rounded-xl p-4 border border-gray-200`}>
              <div className={`text-2xl font-black ${stat.color}`}>{stat.value}</div>
              <div className="text-xs text-gray-500 mt-0.5">{stat.label}</div>
            </div>
          ))}
        </div>

        {/* Controls */}
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search SHA256, package name, or family…"
              className="w-full pl-9 pr-3 py-2 rounded-lg border border-gray-300 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-gray-400" />
            <select
              value={filter}
              onChange={e => setFilter(e.target.value)}
              className="rounded-lg border border-gray-300 text-sm py-2 px-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
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
              className="p-2 rounded-lg border border-gray-300 hover:bg-gray-50 transition-colors disabled:opacity-50"
              title="Refresh"
            >
              <RefreshCw className={`h-4 w-4 text-gray-500 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {/* Error state */}
        {error && (
          <div className="flex items-center gap-2 px-4 py-3 rounded-lg bg-red-50 border border-red-200 text-red-700 text-sm">
            <XCircle className="h-4 w-4 flex-shrink-0" />
            {error}
          </div>
        )}

        {/* Table */}
        <div className="bg-white border border-gray-200 rounded-xl shadow-sm overflow-hidden">
          {loading && cases.length === 0 ? (
            <div className="flex items-center justify-center py-16 text-gray-400 gap-3">
              <RefreshCw className="h-5 w-5 animate-spin" />
              Loading cases…
            </div>
          ) : visible.length === 0 ? (
            <div className="py-16 text-center text-gray-400">
              <Database className="h-8 w-8 mx-auto mb-2 opacity-40" />
              <p className="text-sm">No cases found{search ? ' matching your search' : ''}.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-gray-50 border-b border-gray-200 text-xs uppercase tracking-wide text-gray-500">
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
                <tbody className="divide-y divide-gray-100">
                  {visible.map(c => (
                    <tr
                      key={c.sha256}
                      className="hover:bg-blue-50/40 transition-colors cursor-pointer"
                      onClick={() => navigate(`/history/${c.sha256}`)}
                    >
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5">
                          {riskIcon(c.risk_band)}
                          <span className={`text-xs px-2 py-0.5 rounded font-semibold ${riskBandStyle(c.risk_band)}`}>
                            {c.risk_band || '—'}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="font-medium text-gray-800 truncate max-w-[160px]">
                          {c.app_name || c.package_name || '—'}
                        </div>
                        {c.app_name && c.package_name && (
                          <div className="text-xs text-gray-400 truncate max-w-[160px]">{c.package_name}</div>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span className="inline-flex items-center px-2 py-0.5 rounded bg-gray-100 text-gray-700 text-xs font-mono">
                          {c.family_classification || 'Unknown'}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <span className={`text-lg font-black ${
                          (c.final_risk_score || 0) >= 90 ? 'text-red-600' :
                          (c.final_risk_score || 0) >= 61 ? 'text-orange-500' :
                          (c.final_risk_score || 0) >= 31 ? 'text-yellow-600' : 'text-green-600'
                        }`}>
                          {fmtScore(c.final_risk_score)}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-center">
                        {c.dynamic_available ? (
                          <span className="inline-flex items-center gap-1 text-xs text-green-700 bg-green-50 px-2 py-0.5 rounded">
                            <TrendingUp className="h-3 w-3" /> Frida
                          </span>
                        ) : (
                          <span className="text-xs text-gray-400">Static</span>
                        )}
                      </td>
                      <td className="px-4 py-3 hidden lg:table-cell">
                        <span className="font-mono text-xs text-gray-400">{c.sha256.slice(0, 16)}…</span>
                      </td>
                      <td className="px-4 py-3 text-xs text-gray-400 hidden md:table-cell whitespace-nowrap">
                        {fmtDate(c.created_at)}
                      </td>
                      <td className="px-4 py-3">
                        <Eye className="h-4 w-4 text-gray-300 group-hover:text-blue-500" />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200 bg-gray-50">
              <span className="text-xs text-gray-500">
                Showing {page * LIMIT + 1}–{Math.min((page + 1) * LIMIT, total)} of {total}
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => setPage(p => Math.max(0, p - 1))}
                  disabled={page === 0}
                  className="px-3 py-1 text-xs rounded border border-gray-300 disabled:opacity-40 hover:bg-gray-100 transition-colors"
                >
                  ← Prev
                </button>
                <span className="px-3 py-1 text-xs text-gray-600">
                  Page {page + 1} / {totalPages}
                </span>
                <button
                  onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                  disabled={page >= totalPages - 1}
                  className="px-3 py-1 text-xs rounded border border-gray-300 disabled:opacity-40 hover:bg-gray-100 transition-colors"
                >
                  Next →
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Footer note */}
        <p className="text-xs text-gray-400 text-center">
          All cases are persisted in SQLite — data survives server restarts.
        </p>
      </div>
    </div>
  );
}
