import { useState, useEffect, useMemo } from 'react';
import { Navigate } from 'react-router-dom';
import {
  Globe, CheckCircle2, FileText, Database, ExternalLink, Download,
  ShieldAlert, Activity, Search, Filter, RefreshCw,
  Cpu, AlertTriangle, ChevronLeft, ChevronRight, Code, Layers
} from 'lucide-react';
import type { FraudCardData } from '../App';
import { API_BASE, authHeaders, downloadAuthed } from '../config';
import SocCard from '../components/ui/Card';
import SectionHeader from '../components/ui/SectionHeader';
import Badge from '../components/ui/Badge';
import CopyButton from '../components/ui/CopyButton';

// ─── Interfaces ──────────────────────────────────────────────────────────────

interface SourceStatus {
  name: string;
  status: 'active' | 'missing_key' | 'error' | 'no_match';
  message: string;
}

interface VirusTotalDetail {
  available: boolean;
  malicious: number;
  total: number;
  ratio: number;
  permalink: string;
  vendors: string[];
  reputation: number;
  suggested_label?: string;
}

interface AlienVaultDetail {
  available: boolean;
  pulse_count: number;
  campaign: string;
  pulses: any[];
}

interface AbuseIPDBDetail {
  available: boolean;
  confidence: number;
  reports: number;
}

interface IOCItem {
  type: string;
  value: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  source: string;
  reputation: 'malicious' | 'suspicious' | 'clean' | 'unknown';
}

interface TimelineStep {
  step: string;
  status: 'completed' | 'skipped' | 'in_progress' | 'failed';
  timestamp: string;
  detail: string;
}

interface IntelligenceData {
  available: boolean;
  mode: 'dynamic' | 'static';
  sha256: string;
  package_name: string;
  app_name: string;
  threat_score: number;
  malware_family: string;
  family_rule_matched: string;
  campaign: string;
  confidence: number;
  risk_band: string;
  sources: string[];
  sources_status: SourceStatus[];
  virus_total: VirusTotalDetail;
  alienvault: AlienVaultDetail;
  abuseipdb: AbuseIPDBDetail;
  iocs: IOCItem[];
  timeline: TimelineStep[];
  ai_summary: string;
}

// ─── Skeleton Loader Component ────────────────────────────────────────────────

function IntelligenceSkeleton() {
  return (
    <div className="space-y-4 animate-pulse">
      <div className="h-16 bg-slate-200 rounded-xl"></div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="h-28 bg-slate-200 rounded-xl"></div>
        <div className="h-28 bg-slate-200 rounded-xl"></div>
        <div className="h-28 bg-slate-200 rounded-xl"></div>
        <div className="h-28 bg-slate-200 rounded-xl"></div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="h-40 bg-slate-200 rounded-xl"></div>
        <div className="h-40 bg-slate-200 rounded-xl"></div>
        <div className="h-40 bg-slate-200 rounded-xl"></div>
      </div>
      <div className="h-64 bg-slate-200 rounded-xl"></div>
    </div>
  );
}

// ─── Threat Score Gauge Card ──────────────────────────────────────────────────

function ThreatScoreGauge({ score, riskBand }: { score: number; riskBand: string }) {
  const color = score >= 75 ? 'text-red-600' : score >= 50 ? 'text-orange-500' : score >= 25 ? 'text-yellow-600' : 'text-emerald-600';
  const bgColor = score >= 75 ? 'bg-red-50' : score >= 50 ? 'bg-orange-50' : score >= 25 ? 'bg-yellow-50' : 'bg-emerald-50';
  const borderColor = score >= 75 ? 'border-red-200' : score >= 50 ? 'border-orange-200' : score >= 25 ? 'border-yellow-200' : 'border-emerald-200';

  return (
    <div className={`p-4 rounded-xl border ${borderColor} ${bgColor} flex flex-col justify-between`}>
      <div className="flex items-center justify-between">
        <span className="text-xs font-bold text-slate-700 uppercase tracking-wider">Threat Score</span>
        <Activity className={`h-4 w-4 ${color}`} />
      </div>
      <div className="my-2 text-center">
        <div className={`text-3xl font-black ${color}`}>{score.toFixed(0)}</div>
        <div className="text-[11px] font-mono text-slate-500">out of 100</div>
      </div>
      <div className="flex items-center justify-center">
        <span className={`px-2 py-0.5 text-[10px] font-bold rounded uppercase tracking-wide ${
          score >= 75 ? 'bg-red-200 text-red-800' : score >= 50 ? 'bg-orange-200 text-orange-800' : 'bg-emerald-200 text-emerald-800'
        }`}>
          {riskBand}
        </span>
      </div>
    </div>
  );
}

// ─── Threat Sources Cards ──────────────────────────────────────────────────────

function ThreatSourcesGrid({ intel }: { intel: IntelligenceData }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {/* VirusTotal Card */}
      <SocCard className="p-4 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="font-bold text-xs text-slate-800 flex items-center gap-1.5">
              <Globe className="h-4 w-4 text-blue-600" /> VirusTotal
            </span>
            <span className={`px-2 py-0.5 text-[10px] font-semibold rounded ${
              intel.virus_total.available ? 'bg-emerald-100 text-emerald-700 border border-emerald-200' : 'bg-slate-100 text-slate-600 border border-slate-200'
            }`}>
              {intel.virus_total.available ? 'ACTIVE' : 'UNCONFIGURED'}
            </span>
          </div>

          <div className="mt-3 space-y-1.5">
            <div className="flex items-center justify-between text-xs text-slate-600">
              <span>Vendor Detections:</span>
              <span className="font-mono font-bold text-slate-900">
                {intel.virus_total.malicious} / {intel.virus_total.total}
              </span>
            </div>
            {intel.virus_total.total > 0 && (
              <div className="w-full h-2 bg-slate-100 rounded-full overflow-hidden">
                <div
                  className="h-full bg-red-500 rounded-full transition-all"
                  style={{ width: `${Math.min(intel.virus_total.ratio * 100, 100)}%` }}
                />
              </div>
            )}
            {intel.virus_total.suggested_label && (
              <div className="text-[11px] text-slate-500 pt-1">
                VT Classification: <code className="text-blue-700">{intel.virus_total.suggested_label}</code>
              </div>
            )}
          </div>
        </div>

        <div className="mt-4 pt-3 border-t border-slate-100 flex items-center justify-between text-[11px]">
          <span className="text-slate-400">
            {intel.sources_status.find(s => s.name === 'VirusTotal')?.message || 'Status verified'}
          </span>
          {intel.virus_total.permalink && (
            <a
              href={intel.virus_total.permalink}
              target="_blank"
              rel="noreferrer"
              className="text-blue-600 hover:text-blue-800 font-medium flex items-center gap-1"
            >
              VT Link <ExternalLink className="h-3 w-3" />
            </a>
          )}
        </div>
      </SocCard>

      {/* AlienVault OTX Card */}
      <SocCard className="p-4 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="font-bold text-xs text-slate-800 flex items-center gap-1.5">
              <ShieldAlert className="h-4 w-4 text-purple-600" /> AlienVault OTX
            </span>
            <span className={`px-2 py-0.5 text-[10px] font-semibold rounded ${
              intel.alienvault.available ? 'bg-purple-100 text-purple-700 border border-purple-200' : 'bg-slate-100 text-slate-600 border border-slate-200'
            }`}>
              {intel.alienvault.available ? 'ACTIVE' : 'UNCONFIGURED'}
            </span>
          </div>

          <div className="mt-3 space-y-1">
            <div className="flex items-center justify-between text-xs text-slate-600">
              <span>Correlated Pulses:</span>
              <span className="font-mono font-bold text-slate-900">{intel.alienvault.pulse_count}</span>
            </div>
            <div className="flex items-center justify-between text-xs text-slate-600">
              <span>Campaign Attribution:</span>
              <span className="font-mono text-slate-700 truncate max-w-[140px]" title={intel.alienvault.campaign}>
                {intel.alienvault.campaign}
              </span>
            </div>
          </div>
        </div>

        <div className="mt-4 pt-3 border-t border-slate-100 text-[11px] text-slate-400">
          {intel.sources_status.find(s => s.name === 'AlienVault OTX')?.message || 'No API key set'}
        </div>
      </SocCard>

      {/* AbuseIPDB Card */}
      <SocCard className="p-4 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="font-bold text-xs text-slate-800 flex items-center gap-1.5">
              <Database className="h-4 w-4 text-emerald-600" /> AbuseIPDB
            </span>
            <span className={`px-2 py-0.5 text-[10px] font-semibold rounded ${
              intel.abuseipdb.available ? 'bg-emerald-100 text-emerald-700 border border-emerald-200' : 'bg-slate-100 text-slate-600 border border-slate-200'
            }`}>
              {intel.abuseipdb.available ? 'ACTIVE' : 'UNCONFIGURED'}
            </span>
          </div>

          <div className="mt-3 space-y-1">
            <div className="flex items-center justify-between text-xs text-slate-600">
              <span>Confidence Score:</span>
              <span className="font-mono font-bold text-slate-900">{intel.abuseipdb.confidence}%</span>
            </div>
            <div className="flex items-center justify-between text-xs text-slate-600">
              <span>Malicious IP Reports:</span>
              <span className="font-mono font-bold text-slate-900">{intel.abuseipdb.reports}</span>
            </div>
          </div>
        </div>

        <div className="mt-4 pt-3 border-t border-slate-100 text-[11px] text-slate-400">
          {intel.sources_status.find(s => s.name === 'AbuseIPDB')?.message || 'No API key set'}
        </div>
      </SocCard>
    </div>
  );
}

// ─── Filterable IOC Registry Table ────────────────────────────────────────────

function IOCRegistryTable({ iocs }: { iocs: IOCItem[] }) {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [typeFilter, setTypeFilter] = useState('All');
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 10;

  const filteredIocs = useMemo(() => {
    return iocs.filter(ioc => {
      const matchSearch = ioc.value.toLowerCase().includes(search.toLowerCase()) ||
                          ioc.type.toLowerCase().includes(search.toLowerCase()) ||
                          ioc.source.toLowerCase().includes(search.toLowerCase());
      const matchSeverity = severityFilter === 'All' || ioc.severity === severityFilter;
      const matchType = typeFilter === 'All' || ioc.type === typeFilter;
      return matchSearch && matchSeverity && matchType;
    });
  }, [iocs, search, severityFilter, typeFilter]);

  const totalPages = Math.ceil(filteredIocs.length / pageSize) || 1;
  const paginatedIocs = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredIocs.slice(start, start + pageSize);
  }, [filteredIocs, currentPage]);

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-red-100 text-red-800 border border-red-200">CRITICAL</span>;
      case 'High':
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-orange-100 text-orange-800 border border-orange-200">HIGH</span>;
      case 'Medium':
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-yellow-100 text-yellow-800 border border-yellow-200">MEDIUM</span>;
      case 'Low':
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-blue-100 text-blue-800 border border-blue-200">LOW</span>;
      default:
        return <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-slate-100 text-slate-700 border border-slate-200">INFO</span>;
    }
  };

  const types = Array.from(new Set(iocs.map(i => i.type)));

  return (
    <SocCard>
      <SectionHeader icon={<Database className="h-4 w-4" />} title="Correlated IOC Registry" />

      {/* Controls Bar */}
      <div className="p-4 bg-slate-50 border-b border-slate-200 grid grid-cols-1 sm:grid-cols-3 gap-3">
        {/* Search */}
        <div className="relative">
          <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
          <input
            type="text"
            value={search}
            onChange={e => { setSearch(e.target.value); setCurrentPage(1); }}
            placeholder="Search indicator, type, or source..."
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-white border border-slate-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>

        {/* Severity Filter */}
        <div className="flex items-center gap-2">
          <Filter className="h-3.5 w-3.5 text-slate-400 flex-shrink-0" />
          <select
            value={severityFilter}
            onChange={e => { setSeverityFilter(e.target.value); setCurrentPage(1); }}
            className="w-full py-1.5 px-2 text-xs bg-white border border-slate-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-blue-500"
          >
            <option value="All">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Info">Info</option>
          </select>
        </div>

        {/* Type Filter */}
        <div className="flex items-center gap-2">
          <select
            value={typeFilter}
            onChange={e => { setTypeFilter(e.target.value); setCurrentPage(1); }}
            className="w-full py-1.5 px-2 text-xs bg-white border border-slate-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-blue-500"
          >
            <option value="All">All Types ({types.length})</option>
            {types.map(t => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Table */}
      {paginatedIocs.length === 0 ? (
        <div className="p-8 text-center text-slate-400 text-xs">
          <CheckCircle2 className="h-8 w-8 text-emerald-500 mx-auto mb-2 opacity-80" />
          No indicators matched your filters.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left text-slate-600">
            <thead className="bg-slate-100 text-slate-700 uppercase font-semibold text-[10px] tracking-wider border-b border-slate-200">
              <tr>
                <th className="px-4 py-2.5">Indicator / Value</th>
                <th className="px-4 py-2.5">Type</th>
                <th className="px-4 py-2.5">Severity</th>
                <th className="px-4 py-2.5">Source Engine</th>
                <th className="px-4 py-2.5">Reputation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {paginatedIocs.map((ioc, idx) => (
                <tr key={idx} className="hover:bg-slate-50 transition-colors">
                  <td className="px-4 py-2.5 font-mono text-slate-900 flex items-center justify-between gap-2 max-w-md">
                    <span className="truncate" title={ioc.value}>{ioc.value}</span>
                    <CopyButton value={ioc.value} />
                  </td>
                  <td className="px-4 py-2.5 font-mono">
                    <span className="px-2 py-0.5 text-[10px] bg-slate-100 border border-slate-200 rounded text-slate-700">
                      {ioc.type}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">{getSeverityBadge(ioc.severity)}</td>
                  <td className="px-4 py-2.5 text-slate-500">{ioc.source}</td>
                  <td className="px-4 py-2.5">
                    <Badge label={ioc.reputation} variant="risk" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination Footer */}
      <div className="px-4 py-3 border-t border-slate-200 flex items-center justify-between text-xs text-slate-500">
        <div>
          Showing {paginatedIocs.length} of {filteredIocs.length} correlated indicators
        </div>
        <div className="flex items-center gap-2">
          <button
            disabled={currentPage === 1}
            onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
            className="p-1 border border-slate-200 rounded hover:bg-slate-100 disabled:opacity-40"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
          <span>Page {currentPage} of {totalPages}</span>
          <button
            disabled={currentPage >= totalPages}
            onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
            className="p-1 border border-slate-200 rounded hover:bg-slate-100 disabled:opacity-40"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      </div>
    </SocCard>
  );
}

// ─── Threat Intelligence Timeline ─────────────────────────────────────────────

function ThreatTimeline({ steps }: { steps: TimelineStep[] }) {
  return (
    <SocCard>
      <SectionHeader icon={<Activity className="h-4 w-4" />} title="Threat Intelligence Timeline" />
      <div className="p-4">
        <div className="relative border-l-2 border-slate-200 ml-3 space-y-4">
          {steps.map((s, idx) => (
            <div key={idx} className="mb-4 ml-6 relative">
              <span className={`absolute -left-[31px] top-0.5 w-3.5 h-3.5 rounded-full border-2 border-white ${
                s.status === 'completed' ? 'bg-emerald-500' : s.status === 'skipped' ? 'bg-slate-300' : 'bg-blue-500'
              }`} />
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-bold text-slate-800">{s.step}</h4>
                <span className="text-[10px] font-mono text-slate-400">{s.timestamp}</span>
              </div>
              <p className="text-xs text-slate-600 mt-0.5">{s.detail}</p>
            </div>
          ))}
        </div>
      </div>
    </SocCard>
  );
}

// ─── Export Suite Panel ───────────────────────────────────────────────────────

function FullExportSuite({ sha256 }: { sha256: string }) {
  const [activeExport, setActiveExport] = useState<string | null>(null);

  const runExport = async (name: string, path: string, filename: string, isWindowOpen: boolean = false) => {
    try {
      setActiveExport(name);
      if (isWindowOpen) {
        const res = await fetch(`${API_BASE}${path}`, { headers: authHeaders() });
        if (!res.ok) throw new Error(`Export failed (${res.status})`);
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const win = window.open(url, '_blank');
        if (!win) await downloadAuthed(`${API_BASE}${path}`, filename);
      } else {
        await downloadAuthed(`${API_BASE}${path}`, filename);
      }
    } catch (err: any) {
      alert(err.message || 'Export error');
    } finally {
      setTimeout(() => setActiveExport(null), 1500);
    }
  };

  return (
    <SocCard>
      <SectionHeader icon={<FileText className="h-4 w-4" />} title="Threat Intel Export Suite" />
      <div className="p-4 grid grid-cols-2 sm:grid-cols-4 gap-2">
        <button
          disabled={!!activeExport}
          onClick={() => runExport('stix', `/report/stix/${sha256}`, `sudarshan_stix_${sha256.slice(0, 8)}.json`)}
          className="flex items-center justify-between px-3 py-2 text-xs font-medium bg-slate-50 border border-slate-200 rounded-lg hover:bg-blue-50 hover:text-blue-700 transition-colors disabled:opacity-50"
        >
          <span className="flex items-center gap-1.5"><Globe className="h-3.5 w-3.5" /> STIX 2.1 JSON</span>
          {activeExport === 'stix' ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3" />}
        </button>

        <button
          disabled={!!activeExport}
          onClick={() => runExport('csv', `/report/iocs/${sha256}`, `sudarshan_iocs_${sha256.slice(0, 8)}.csv`)}
          className="flex items-center justify-between px-3 py-2 text-xs font-medium bg-slate-50 border border-slate-200 rounded-lg hover:bg-blue-50 hover:text-blue-700 transition-colors disabled:opacity-50"
        >
          <span className="flex items-center gap-1.5"><Database className="h-3.5 w-3.5" /> IOC CSV</span>
          {activeExport === 'csv' ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3" />}
        </button>

        <button
          disabled={!!activeExport}
          onClick={() => runExport('txt', `/report/iocs-txt/${sha256}`, `sudarshan_iocs_${sha256.slice(0, 8)}.txt`)}
          className="flex items-center justify-between px-3 py-2 text-xs font-medium bg-slate-50 border border-slate-200 rounded-lg hover:bg-blue-50 hover:text-blue-700 transition-colors disabled:opacity-50"
        >
          <span className="flex items-center gap-1.5"><FileText className="h-3.5 w-3.5" /> Raw IOC TXT</span>
          {activeExport === 'txt' ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3" />}
        </button>

        <button
          disabled={!!activeExport}
          onClick={() => runExport('yara', `/report/yara/${sha256}`, `sudarshan_rule_${sha256.slice(0, 8)}.yar`)}
          className="flex items-center justify-between px-3 py-2 text-xs font-medium bg-slate-50 border border-slate-200 rounded-lg hover:bg-blue-50 hover:text-blue-700 transition-colors disabled:opacity-50"
        >
          <span className="flex items-center gap-1.5"><Code className="h-3.5 w-3.5" /> YARA Rules</span>
          {activeExport === 'yara' ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3" />}
        </button>

        <button
          disabled={!!activeExport}
          onClick={() => runExport('mitre', `/report/mitre/${sha256}`, `sudarshan_mitre_${sha256.slice(0, 8)}.json`)}
          className="flex items-center justify-between px-3 py-2 text-xs font-medium bg-slate-50 border border-slate-200 rounded-lg hover:bg-blue-50 hover:text-blue-700 transition-colors disabled:opacity-50"
        >
          <span className="flex items-center gap-1.5"><Layers className="h-3.5 w-3.5" /> MITRE Matrix</span>
          {activeExport === 'mitre' ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3" />}
        </button>

        <button
          disabled={!!activeExport}
          onClick={() => runExport('pdf', `/report/pdf/${sha256}`, `sudarshan_report_${sha256.slice(0, 8)}.html`, true)}
          className="col-span-3 flex items-center justify-center gap-2 px-3 py-2 text-xs font-semibold text-white bg-blue-700 rounded-lg hover:bg-blue-800 transition-colors shadow-sm disabled:opacity-50"
        >
          <FileText className="h-4 w-4" />
          {activeExport === 'pdf' ? 'Generating Executive PDF...' : 'Export Executive PDF Report'}
        </button>
      </div>
    </SocCard>
  );
}

// ─── Main Page Component ──────────────────────────────────────────────────────

export default function ThreatIntelView({ data }: { data: FraudCardData | null }) {
  if (!data) return <Navigate to="/" />;

  const [intel, setIntel] = useState<IntelligenceData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchIntelligence = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await fetch(`${API_BASE}/intelligence/${data.sha256}`, {
        headers: authHeaders(),
      });
      if (!res.ok) {
        throw new Error(res.status === 404 ? 'No intelligence analysis found for this hash.' : `Fetch failed (${res.status})`);
      }
      const json: IntelligenceData = await res.json();
      setIntel(json);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch threat intelligence');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIntelligence();
  }, [data.sha256]);

  return (
    <div className="space-y-4">
      {/* Top Bar Header */}
      <div className="bg-white border border-slate-200 rounded-xl shadow-sm px-5 py-3.5 flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-base font-bold text-slate-900 flex items-center gap-2">
            <Globe className="h-5 w-5 text-blue-700" />
            Threat Intelligence Correlation Dashboard
          </h1>
          <p className="text-xs text-slate-500 mt-0.5 font-mono flex items-center gap-2">
            <span>{data.sha256}</span>
            <CopyButton value={data.sha256} />
            <span>·</span>
            <span>{data.package_name}</span>
          </p>
        </div>

        <div className="flex items-center gap-2">
          {intel && (
            <span className={`px-2.5 py-1 text-xs font-mono font-bold rounded-lg border ${
              intel.mode === 'dynamic' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-amber-50 text-amber-700 border-amber-200'
            }`}>
              {intel.mode === 'dynamic' ? 'DYNAMIC CORRELATION' : 'STATIC ONLY'}
            </span>
          )}
          <Badge label={data.risk_band} variant="risk" />
          <button
            onClick={fetchIntelligence}
            className="p-1.5 text-slate-400 hover:text-slate-700 rounded-lg hover:bg-slate-100 transition-colors"
            title="Refresh Intelligence"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {loading ? (
        <IntelligenceSkeleton />
      ) : error ? (
        <SocCard className="p-8 text-center text-slate-500">
          <AlertTriangle className="h-10 w-10 text-amber-500 mx-auto mb-2" />
          <p className="font-semibold text-slate-800">{error}</p>
          <button
            onClick={fetchIntelligence}
            className="mt-3 px-3 py-1.5 text-xs font-semibold text-white bg-blue-600 rounded-lg hover:bg-blue-700"
          >
            Retry
          </button>
        </SocCard>
      ) : intel ? (
        <>
          {/* Top Metrics Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <ThreatScoreGauge score={intel.threat_score} riskBand={intel.risk_band} />

            <div className="p-4 bg-white border border-slate-200 rounded-xl flex flex-col justify-between">
              <span className="text-xs font-bold text-slate-600 uppercase">VT Consensus</span>
              <div className="my-2 text-center">
                <div className="text-2xl font-black text-slate-900">
                  {intel.virus_total.malicious} / {intel.virus_total.total}
                </div>
                <div className="text-[10px] text-slate-400 font-mono mt-0.5">
                  {(intel.virus_total.ratio * 100).toFixed(0)}% engine detection
                </div>
              </div>
              <div className="text-[10px] text-center text-slate-500 font-medium truncate" title={intel.virus_total.suggested_label}>
                {intel.virus_total.suggested_label || 'No VT label'}
              </div>
            </div>

            <div className="p-4 bg-white border border-slate-200 rounded-xl flex flex-col justify-between">
              <span className="text-xs font-bold text-slate-600 uppercase">Malware Family</span>
              <div className="my-2 text-center">
                <div className="text-xl font-bold text-red-700 truncate" title={intel.malware_family}>
                  {intel.malware_family}
                </div>
                <div className="text-[10px] text-slate-500 mt-0.5">{intel.campaign}</div>
              </div>
              <div className="text-[9px] text-center text-slate-400 truncate" title={intel.family_rule_matched}>
                {intel.family_rule_matched}
              </div>
            </div>

            <div className="p-4 bg-white border border-slate-200 rounded-xl flex flex-col justify-between">
              <span className="text-xs font-bold text-slate-600 uppercase">Correlated IOCs</span>
              <div className="my-2 text-center">
                <div className="text-3xl font-black text-blue-700">{intel.iocs.length}</div>
                <div className="text-[10px] text-slate-400 font-mono">Indicators collected</div>
              </div>
              <div className="text-[10px] text-center text-slate-500 font-medium">
                {intel.iocs.filter(i => i.severity === 'Critical' || i.severity === 'High').length} Critical/High
              </div>
            </div>
          </div>

          {/* Sources Grid */}
          <ThreatSourcesGrid intel={intel} />

          {/* AI Narrative Summary Card */}
          <SocCard className="p-4 bg-gradient-to-r from-slate-900 to-slate-800 text-white">
            <div className="flex items-center gap-2 mb-2">
              <Cpu className="h-4 w-4 text-blue-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-blue-400">RAG Intelligence Narrative Summary</h3>
            </div>
            <p className="text-xs text-slate-200 leading-relaxed font-sans">{intel.ai_summary}</p>
          </SocCard>

          {/* IOC Registry Table */}
          <IOCRegistryTable iocs={intel.iocs} />

          {/* Timeline & Export Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2">
              <ThreatTimeline steps={intel.timeline} />
            </div>
            <FullExportSuite sha256={data.sha256} />
          </div>
        </>
      ) : null}
    </div>
  );
}
