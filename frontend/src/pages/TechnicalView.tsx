import React, { useState } from 'react';
import { Navigate } from 'react-router-dom';
import {
  Terminal, Cpu, Shield, AlertTriangle, CheckCircle2,
  Copy, Search, Download, Hash, Globe, Lock, Info,
  BarChart2, Database, Code, Package
} from 'lucide-react';
import type { FraudCardData } from '../App';
import {
  getPermissionTable, getApiTable, getThreatIndicators, getNetworkIntel,
  getTopEvidence, getRiskBreakdown, severityBg, riskBandText, statusChip,
  expectedChip, exportJSON, exportCSV,
} from '../utils/derive';
import WorkflowDiagram from '../components/WorkflowDiagram';

// ─── Shared UI Primitives ────────────────────────────────────────────────────────

function SocCard({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`bg-white border border-gray-200 rounded-xl shadow-sm overflow-hidden ${className}`}>
      {children}
    </div>
  );
}

function SectionHeader({ icon, title, subtitle }: { icon: React.ReactNode; title: string; subtitle?: string }) {
  return (
    <div className="flex items-center gap-2 px-5 py-3 bg-gray-50 border-b border-gray-200">
      <span className="text-blue-700">{icon}</span>
      <div>
        <h2 className="text-sm font-semibold text-gray-800 tracking-tight">{title}</h2>
        {subtitle && <p className="text-xs text-gray-500">{subtitle}</p>}
      </div>
    </div>
  );
}

function Badge({ label, className = '' }: { label: string; className?: string }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wide ${className}`}>
      {label}
    </span>
  );
}

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
      className="p-1 rounded hover:bg-gray-100 text-gray-400 hover:text-gray-600 transition-colors"
      title="Copy"
    >
      {copied ? <CheckCircle2 className="h-3.5 w-3.5 text-green-500" /> : <Copy className="h-3.5 w-3.5" />}
    </button>
  );
}

function EmptyState({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-2 px-4 py-3 text-sm text-green-700 bg-green-50">
      <CheckCircle2 className="h-4 w-4 flex-shrink-0" />
      <span>{label}</span>
    </div>
  );
}

// ─── Explainability Engine ────────────────────────────────────────────────────────

function ExplainabilityEngine({ data }: { data: FraudCardData }) {
  return (
    <SocCard>
      <div className="bg-gray-900 px-5 py-3 flex items-center gap-2">
        <Cpu className="h-4 w-4 text-blue-400" />
        <h2 className="text-sm font-semibold text-blue-400 font-mono tracking-wide">Explainability Engine</h2>
      </div>
      <div className="bg-gray-900 p-4 space-y-3">
        <div className="bg-gray-800 p-3 rounded-lg">
          <p className="text-xs text-gray-400 font-mono mb-1 uppercase tracking-wider">Deterministic Classification</p>
          <p className={`text-lg font-bold ${data.family_classification !== 'Unknown' ? 'text-red-400' : 'text-gray-200'}`}>
            {data.family_classification}
          </p>
        </div>
        <div className="bg-gray-800 p-3 rounded-lg border border-gray-700">
          <p className="text-xs text-gray-400 font-mono mb-2 uppercase tracking-wider">Rule Matched</p>
          <p className="font-mono text-xs text-gray-200 bg-black p-2.5 rounded leading-relaxed">
            {data.technical_view.matched_rule}
          </p>
        </div>
        <div className="flex items-start gap-2 text-xs text-gray-400 bg-gray-800 p-2.5 rounded">
          <AlertTriangle className="h-3.5 w-3.5 text-yellow-500 flex-shrink-0 mt-0.5" />
          <p>Classification uses deterministic behavioral pattern matching — not LLM inference. Results are auditable and reproducible.</p>
        </div>
      </div>
    </SocCard>
  );
}

// ─── APK Metadata ────────────────────────────────────────────────────────────────

function APKMetadata({ data }: { data: FraudCardData }) {
  const rows = [
    { label: 'Package Name', value: data.package_name || 'Unknown', mono: true },
    { label: 'SHA-256 Hash', value: data.sha256, mono: true, truncate: true, copy: data.sha256 },
    { label: 'Total Permissions', value: `${data.all_permissions.length}`, mono: false },
    { label: 'Critical Permissions', value: `${data.technical_view.permissions_fired.length}`, mono: false, highlight: data.technical_view.permissions_fired.length > 0 },
    { label: 'Dangerous APIs', value: data.technical_view.apis_fired.length > 0 ? data.technical_view.apis_fired.join(', ') : 'None detected', mono: true },
    { label: 'Network IOCs', value: `${data.hardcoded_urls_ips.length} hardcoded URL(s)/IP(s)`, mono: false },
    { label: 'Banking Targeting', value: data.targets_indian_banks ? 'YES — Indian bank packages detected' : 'No', mono: false, highlight: data.targets_indian_banks },
    { label: 'Base Risk Score', value: `${data.base_score.toFixed(2)} / 100`, mono: true },
    { label: 'AI Multiplier', value: `×${data.ai_confidence_multiplier.toFixed(2)}`, mono: true },
    { label: 'Final Score', value: `${data.final_risk_score.toFixed(2)} / 100`, mono: true, highlight: data.final_risk_score > 30 },
  ];

  return (
    <SocCard>
      <SectionHeader icon={<Package className="h-4 w-4" />} title="APK Metadata" subtitle="Static identification data" />
      <div className="divide-y divide-gray-100">
        {rows.map(r => (
          <div key={r.label} className="flex items-start justify-between gap-3 px-4 py-2.5 hover:bg-gray-50 transition-colors">
            <span className="text-xs text-gray-500 flex-shrink-0 w-36">{r.label}</span>
            <div className="flex items-center gap-1 min-w-0 flex-1 justify-end">
              <span className={`text-xs text-right ${r.mono ? 'font-mono' : ''} ${r.highlight ? 'text-red-600 font-semibold' : 'text-gray-800'} ${r.truncate ? 'truncate max-w-xs' : ''}`}
                    title={r.truncate ? r.value : undefined}>
                {r.truncate ? `${r.value.slice(0, 20)}…${r.value.slice(-8)}` : r.value}
              </span>
              {r.copy && <CopyButton value={r.copy} />}
            </div>
          </div>
        ))}
      </div>
    </SocCard>
  );
}

// ─── Threat Indicators Checklist ──────────────────────────────────────────────────

function ThreatIndicatorsPanel({ data }: { data: FraudCardData }) {
  const indicators = getThreatIndicators(data);
  const detectedCount = indicators.filter(i => i.status === 'Detected').length;

  return (
    <SocCard>
      <SectionHeader
        icon={<Shield className="h-4 w-4" />}
        title="Threat Indicators"
        subtitle={`${detectedCount} / ${indicators.length} detected`}
      />
      <div className="divide-y divide-gray-100">
        {indicators.map((ind, i) => (
          <div key={i} className={`flex items-start gap-3 px-4 py-2.5 transition-colors ${ind.status === 'Detected' ? 'bg-red-50/40 hover:bg-red-50' : 'hover:bg-gray-50'}`}>
            <div className="text-base flex-shrink-0 mt-0.5">{ind.icon}</div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-0.5">
                <span className="text-xs font-semibold text-gray-800">{ind.label}</span>
              </div>
              <p className="text-xs text-gray-500 leading-snug">{ind.description}</p>
            </div>
            <Badge
              label={ind.status === 'Detected' ? 'Detected' : ind.status === 'Unknown' ? 'Unknown' : 'Clear'}
              className={`flex-shrink-0 text-xs ${statusChip(ind.status)}`}
            />
          </div>
        ))}
      </div>
    </SocCard>
  );
}

// ─── Permission Analysis Table ────────────────────────────────────────────────────

function PermissionTable({ data }: { data: FraudCardData }) {
  const [search, setSearch] = useState('');
  const perms = getPermissionTable(data);
  const filtered = perms.filter(p =>
    p.shortName.toLowerCase().includes(search.toLowerCase()) ||
    p.reason.toLowerCase().includes(search.toLowerCase())
  );

  const rowBg = (sev: string, fired: boolean): string => {
    if (!fired && sev !== 'Critical' && sev !== 'High') return '';
    switch (sev) {
      case 'Critical': return 'bg-red-50/60';
      case 'High': return 'bg-orange-50/60';
      case 'Medium': return 'bg-yellow-50/30';
      default: return '';
    }
  };

  return (
    <SocCard>
      <SectionHeader
        icon={<Lock className="h-4 w-4" />}
        title="Permission Analysis"
        subtitle={`${perms.length} permissions — ${perms.filter(p => ['Critical', 'High'].includes(p.severity)).length} high-severity`}
      />
      {/* Search */}
      <div className="px-4 py-2.5 border-b border-gray-200">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-400" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Filter permissions…"
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
      </div>
      {filtered.length === 0 ? (
        <EmptyState label="No permissions detected or all filtered out" />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="px-4 py-2.5 text-left font-semibold text-gray-600 uppercase tracking-wide">Permission</th>
                <th className="px-4 py-2.5 text-left font-semibold text-gray-600 uppercase tracking-wide">Severity</th>
                <th className="px-4 py-2.5 text-left font-semibold text-gray-600 uppercase tracking-wide">Reason</th>
                <th className="px-4 py-2.5 text-left font-semibold text-gray-600 uppercase tracking-wide">Assessment</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {filtered.map((p, i) => (
                <tr key={i} className={`hover:brightness-95 transition-all ${rowBg(p.severity, p.fired)}`}>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-1.5">
                      {p.fired && <AlertTriangle className="h-3 w-3 text-red-500 flex-shrink-0" />}
                      <span className="font-mono text-gray-800 break-all">{p.shortName}</span>
                    </div>
                  </td>
                  <td className="px-4 py-2.5">
                    <Badge label={p.severity} className={severityBg(p.severity)} />
                  </td>
                  <td className="px-4 py-2.5 text-gray-600 max-w-xs">{p.reason}</td>
                  <td className="px-4 py-2.5">
                    <Badge label={p.expected} className={expectedChip(p.expected)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </SocCard>
  );
}

// ─── Dangerous API Table ──────────────────────────────────────────────────────────

function DangerousAPITable({ data }: { data: FraudCardData }) {
  const apis = getApiTable(data);
  const foundApis = apis.filter(a => a.found);

  return (
    <SocCard>
      <SectionHeader
        icon={<Code className="h-4 w-4" />}
        title="Dangerous API Analysis"
        subtitle={`${foundApis.length} of ${apis.length} tracked APIs detected`}
      />
      {foundApis.length === 0 ? (
        <EmptyState label="No dangerous APIs detected — no dynamic loading, shell execution, or WebView injection found" />
      ) : null}
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead className="bg-gray-50 border-b border-gray-200">
            <tr>
              <th className="px-4 py-2.5 text-left font-semibold text-gray-600 uppercase tracking-wide">API</th>
              <th className="px-4 py-2.5 text-left font-semibold text-gray-600 uppercase tracking-wide">Purpose</th>
              <th className="px-4 py-2.5 text-left font-semibold text-gray-600 uppercase tracking-wide">Risk</th>
              <th className="px-4 py-2.5 text-left font-semibold text-gray-600 uppercase tracking-wide">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {apis.map((a, i) => (
              <tr key={i} className={`transition-colors ${a.found ? 'bg-red-50/40 hover:bg-red-50' : 'opacity-50 hover:opacity-100 hover:bg-gray-50'}`}>
                <td className="px-4 py-2.5 font-mono text-gray-800">{a.api}</td>
                <td className="px-4 py-2.5 text-gray-600 max-w-sm">{a.purpose}</td>
                <td className="px-4 py-2.5">
                  <Badge label={a.risk} className={severityBg(a.risk)} />
                </td>
                <td className="px-4 py-2.5">
                  {a.found ? (
                    <div className="flex items-center gap-1 text-red-600 font-semibold">
                      <AlertTriangle className="h-3.5 w-3.5" />
                      Found
                    </div>
                  ) : (
                    <div className="flex items-center gap-1 text-gray-400">
                      <CheckCircle2 className="h-3.5 w-3.5 text-green-400" />
                      Not Found
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </SocCard>
  );
}

// ─── Network Intelligence ─────────────────────────────────────────────────────────

function NetworkIntelligence({ data }: { data: FraudCardData }) {
  const entries = getNetworkIntel(data);

  const repColor = (rep: string) => {
    switch (rep) {
      case 'Malicious':  return 'bg-red-100 text-red-700 border-red-200';
      case 'Suspicious': return 'bg-orange-100 text-orange-700 border-orange-200';
      case 'Safe':       return 'bg-green-100 text-green-700 border-green-200';
      default:           return 'bg-gray-100 text-gray-600 border-gray-200';
    }
  };

  return (
    <SocCard>
      <SectionHeader
        icon={<Globe className="h-4 w-4" />}
        title="Network Intelligence"
        subtitle={`${entries.length} hardcoded network indicator(s) extracted from DEX bytecode`}
      />
      {entries.length === 0 ? (
        <EmptyState label="No hardcoded URLs or IP addresses found in DEX strings" />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="px-4 py-2.5 text-left font-semibold text-gray-600 uppercase tracking-wide">Host / URL</th>
                <th className="px-4 py-2.5 text-left font-semibold text-gray-600 uppercase tracking-wide">Type</th>
                <th className="px-4 py-2.5 text-left font-semibold text-gray-600 uppercase tracking-wide">Protocol</th>
                <th className="px-4 py-2.5 text-left font-semibold text-gray-600 uppercase tracking-wide">TLS</th>
                <th className="px-4 py-2.5 text-left font-semibold text-gray-600 uppercase tracking-wide">Reputation</th>
                <th className="px-4 py-2.5 text-left font-semibold text-gray-600 uppercase tracking-wide"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {entries.map((e, i) => (
                <tr key={i} className={`hover:bg-gray-50 transition-colors ${e.reputation === 'Suspicious' ? 'bg-orange-50/30' : e.reputation === 'Malicious' ? 'bg-red-50/30' : ''}`}>
                  <td className="px-4 py-2.5 font-mono text-gray-800 max-w-xs truncate" title={e.fullUrl}>
                    {e.host}
                  </td>
                  <td className="px-4 py-2.5">
                    <Badge label={e.type} className="bg-blue-50 text-blue-700 border border-blue-200" />
                  </td>
                  <td className="px-4 py-2.5 font-mono text-gray-700">{e.protocol}</td>
                  <td className="px-4 py-2.5">
                    {e.certValid === true && <Badge label="TLS ✓" className="bg-green-50 text-green-700 border-green-200" />}
                    {e.certValid === false && <Badge label="No TLS" className="bg-red-50 text-red-700 border-red-200" />}
                    {e.certValid === null && <Badge label="Unknown" className="bg-gray-50 text-gray-500 border-gray-200" />}
                  </td>
                  <td className="px-4 py-2.5">
                    <Badge label={e.reputation} className={`border ${repColor(e.reputation)}`} />
                  </td>
                  <td className="px-4 py-2.5">
                    <CopyButton value={e.fullUrl} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </SocCard>
  );
}

// ─── Top Evidence ────────────────────────────────────────────────────────────────

function TopEvidencePanel({ data }: { data: FraudCardData }) {
  const evidence = getTopEvidence(data);
  const categoryColor: Record<string, string> = {
    permission: 'bg-red-100 text-red-700',
    api:        'bg-orange-100 text-orange-700',
    url:        'bg-blue-100 text-blue-700',
    behavior:   'bg-purple-100 text-purple-700',
    string:     'bg-gray-100 text-gray-600',
  };

  return (
    <SocCard>
      <SectionHeader icon={<BarChart2 className="h-4 w-4" />} title="Top Evidence" subtitle="Ranked by confidence" />
      <div className="divide-y divide-gray-100">
        {evidence.length === 0 ? (
          <div className="p-4 text-center text-sm text-gray-400">No significant evidence detected</div>
        ) : evidence.map(e => (
          <div key={e.rank} className="flex items-start gap-3 px-4 py-3 hover:bg-gray-50 transition-colors group">
            <div className="flex-shrink-0 w-5 h-5 rounded-full bg-blue-100 text-blue-700 flex items-center justify-center text-xs font-bold mt-0.5">
              {e.rank}
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className={`text-xs px-1.5 py-0.5 rounded font-medium ${categoryColor[e.category] || 'bg-gray-100 text-gray-600'}`}>
                  {e.type}
                </span>
                <div className="flex-1 h-1 bg-gray-100 rounded-full overflow-hidden">
                  <div className="h-full bg-blue-500 rounded-full" style={{ width: `${e.confidence}%` }} />
                </div>
                <span className="text-xs text-gray-500 flex-shrink-0">{e.confidence}%</span>
              </div>
              <p className="text-xs font-mono text-gray-700 break-all">{e.value}</p>
            </div>
            <CopyButton value={e.value} />
          </div>
        ))}
      </div>
    </SocCard>
  );
}

// ─── Raw Evidence Tabs ────────────────────────────────────────────────────────────

function RawEvidenceTabs({ data }: { data: FraudCardData }) {
  type TabKey = 'permissions' | 'strings' | 'urls' | 'apis' | 'manifest' | 'dynamic_apis';
  const [activeTab, setActiveTab] = useState<TabKey>('permissions');
  const [search, setSearch] = useState('');

  const tabs: Array<{ key: TabKey; label: string; count: number }> = [
    { key: 'permissions', label: 'Permissions', count: data.all_permissions.length },
    { key: 'strings', label: 'Strings', count: data.technical_view.strings_fired.length },
    { key: 'urls', label: 'URLs / IPs', count: data.hardcoded_urls_ips.length },
    { key: 'apis', label: 'Static APIs', count: data.technical_view.apis_fired.length },
    { key: 'manifest', label: 'Manifest', count: data.technical_view.decoded_manifest_excerpts.length },
    ...(data.dynamic_available && data.dynamic_analysis ? [{ key: 'dynamic_apis' as TabKey, label: 'Runtime Calls (Frida)', count: data.dynamic_analysis.api_calls?.length || 0 }] : []),
  ];

  const rawContent: Record<TabKey, string[]> = {
    permissions: data.all_permissions,
    strings: data.technical_view.strings_fired,
    urls: data.hardcoded_urls_ips,
    apis: data.technical_view.apis_fired,
    manifest: data.technical_view.decoded_manifest_excerpts,
    dynamic_apis: data.dynamic_analysis?.api_calls?.map(c => typeof c === 'string' ? c : JSON.stringify(c)) || [],
  };

  const items = rawContent[activeTab].filter(s =>
    s.toLowerCase().includes(search.toLowerCase())
  );

  const copyAll = () => navigator.clipboard.writeText(rawContent[activeTab].join('\n'));

  return (
    <SocCard>
      <SectionHeader icon={<Database className="h-4 w-4" />} title="Raw Evidence" subtitle="Extracted from DEX bytecode and AndroidManifest.xml" />
      {/* Tabs */}
      <div className="flex border-b border-gray-200 overflow-x-auto">
        {tabs.map(t => (
          <button
            key={t.key}
            onClick={() => { setActiveTab(t.key); setSearch(''); }}
            className={`px-3.5 py-2 text-xs font-medium whitespace-nowrap border-b-2 transition-colors flex items-center gap-1.5 ${
              activeTab === t.key
                ? 'border-blue-600 text-blue-700 bg-blue-50'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:bg-gray-50'
            }`}
          >
            {t.label}
            <span className={`text-xs px-1.5 py-0.5 rounded-full ${activeTab === t.key ? 'bg-blue-200 text-blue-800' : 'bg-gray-200 text-gray-600'}`}>
              {t.count}
            </span>
          </button>
        ))}
      </div>
      {/* Search + copy toolbar */}
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-gray-200">
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-400" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder={`Search ${tabs.find(t => t.key === activeTab)?.label.toLowerCase()}…`}
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <button
          onClick={copyAll}
          className="flex items-center gap-1.5 text-xs px-2.5 py-1.5 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors text-gray-600"
        >
          <Copy className="h-3.5 w-3.5" />
          Copy All
        </button>
      </div>
      {/* Content */}
      <div className="max-h-64 overflow-y-auto">
        {items.length === 0 ? (
          <div className="p-6 text-center text-sm text-gray-400">
            {rawContent[activeTab].length === 0 ? 'No data available for this category' : 'No results match your filter'}
          </div>
        ) : (
          <div className="divide-y divide-gray-100">
            {items.map((item, i) => (
              <div key={i} className="flex items-center justify-between gap-3 px-4 py-2 hover:bg-gray-50 group">
                <span className="text-xs font-mono text-gray-700 break-all flex-1">{item}</span>
                <div className="opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0">
                  <CopyButton value={item} />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
      {items.length > 0 && (
        <div className="px-4 py-2 bg-gray-50 border-t border-gray-200 text-xs text-gray-400">
          Showing {items.length} of {rawContent[activeTab].length} items
        </div>
      )}
    </SocCard>
  );
}

// ─── IOC Panel ───────────────────────────────────────────────────────────────────

function IOCPanel({ data }: { data: FraudCardData }) {
  const [toast, setToast] = useState<string | null>(null);
  const showToast = (msg: string) => { setToast(msg); setTimeout(() => setToast(null), 2500); };

  const iocGroups = [
    { label: 'SHA-256', items: [data.sha256], type: 'hash' },
    { label: 'URLs', items: data.hardcoded_urls_ips.filter(u => u.startsWith('http')), type: 'url' },
    { label: 'IPs', items: data.hardcoded_urls_ips.filter(u => /^\d{1,3}(\.\d{1,3}){3}/.test(u)), type: 'ip' },
    { label: 'Package Names', items: [data.package_name].filter(Boolean), type: 'package' },
    { label: 'APIs', items: data.technical_view.apis_fired, type: 'api' },
    { label: 'Permissions', items: data.technical_view.permissions_fired, type: 'permission' },
  ].filter(g => g.items.length > 0);

  return (
    <SocCard className="relative">
      <SectionHeader
        icon={<Hash className="h-4 w-4" />}
        title="IOC Panel"
        subtitle="Extracted indicators of compromise"
      />
      <div className="p-4 space-y-4">
        {/* IOC groups */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {iocGroups.map(g => (
            <div key={g.label} className="p-3 bg-gray-50 border border-gray-200 rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-gray-600 uppercase tracking-wide">{g.label}</span>
                <span className="text-xs text-gray-400">{g.items.length}</span>
              </div>
              <div className="space-y-1 max-h-24 overflow-y-auto">
                {g.items.map((item, i) => (
                  <div key={i} className="flex items-center justify-between gap-2 group">
                    <span className="text-xs font-mono text-gray-700 truncate flex-1" title={item}>{item.length > 35 ? item.slice(0, 35) + '…' : item}</span>
                    <div className="opacity-0 group-hover:opacity-100 transition-opacity">
                      <CopyButton value={item} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
        {/* Export buttons */}
        <div className="flex flex-wrap gap-2 pt-1">
          <button onClick={() => exportJSON(data)} className="flex items-center gap-1.5 text-xs px-3 py-1.5 bg-blue-700 text-white rounded-lg hover:bg-blue-800 transition-colors">
            <Download className="h-3 w-3" /> Export JSON
          </button>
          <button onClick={() => exportCSV(data)} className="flex items-center gap-1.5 text-xs px-3 py-1.5 bg-gray-700 text-white rounded-lg hover:bg-gray-800 transition-colors">
            <Download className="h-3 w-3" /> Export CSV
          </button>
          <button onClick={() => showToast('STIX 2.1 export — connect to a threat intelligence platform to enable')} className="flex items-center gap-1.5 text-xs px-3 py-1.5 border border-gray-300 text-gray-600 rounded-lg hover:bg-gray-50 transition-colors">
            <Globe className="h-3 w-3" /> STIX Package
          </button>
          <button onClick={() => navigator.clipboard.writeText([...data.hardcoded_urls_ips, data.sha256].join('\n'))} className="flex items-center gap-1.5 text-xs px-3 py-1.5 border border-gray-300 text-gray-600 rounded-lg hover:bg-gray-50 transition-colors">
            <Copy className="h-3 w-3" /> Copy All IOCs
          </button>
        </div>
      </div>
      {toast && (
        <div className="absolute bottom-3 left-3 right-3 bg-blue-800 text-white text-xs p-2.5 rounded-lg shadow-lg z-10">
          <Info className="h-3.5 w-3.5 inline mr-1.5" />{toast}
        </div>
      )}
    </SocCard>
  );
}

// ─── Risk Scoring Breakdown (Technical Detail) ────────────────────────────────────

function RiskScoringBreakdown({ data }: { data: FraudCardData }) {
  const breakdown = getRiskBreakdown(data);

  return (
    <SocCard>
      <SectionHeader icon={<BarChart2 className="h-4 w-4" />} title="Risk Scoring Formula" subtitle="Transparent score computation" />
      <div className="p-5">
        <div className="mb-4 p-3 bg-gray-900 rounded-lg font-mono text-xs text-gray-200">
          <div className="text-gray-400 mb-1">{'// Sudarshan Risk Engine v1.0'}</div>
          <div><span className="text-blue-400">base_score</span> = <span className="text-yellow-300">(25×perm_risk)</span> + <span className="text-orange-300">(15×api_risk)</span> + <span className="text-green-300">(10×net_risk)</span></div>
          <div><span className="text-blue-400">final_score</span> = <span className="text-blue-400">base_score</span> × <span className="text-purple-400">ai_multiplier</span></div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {breakdown.map(b => (
            <div key={b.label}>
              <div className="flex justify-between items-center mb-1.5">
                <span className="text-xs font-medium text-gray-700">{b.label}</span>
                <span className={`text-xs font-bold font-mono ${b.score > 0 ? 'text-gray-800' : 'text-gray-400'}`}>
                  +{b.score.toFixed(1)} pts
                </span>
              </div>
              <div className="w-full h-2 bg-gray-100 rounded-full overflow-hidden">
                <div
                  className={`h-full ${b.color} rounded-full transition-all`}
                  style={{ width: b.maxScore > 0 ? `${Math.min((b.score / b.maxScore) * 100, 100)}%` : '0%' }}
                />
              </div>
              <div className="text-xs text-gray-400 mt-0.5 text-right">max {b.maxScore}</div>
            </div>
          ))}
        </div>
        <div className="mt-4 pt-4 border-t border-gray-200 grid grid-cols-3 gap-4 text-center">
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wide">Base Score</div>
            <div className="text-xl font-black text-gray-800 font-mono">{data.base_score.toFixed(2)}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wide">AI Multiplier</div>
            <div className="text-xl font-black text-purple-700 font-mono">×{data.ai_confidence_multiplier.toFixed(2)}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wide">Final Score</div>
            <div className={`text-xl font-black font-mono ${riskBandText(data.risk_band)}`}>
              {data.final_risk_score.toFixed(2)}
            </div>
          </div>
        </div>
      </div>
    </SocCard>
  );
}

// ─── Dynamic Analysis Panel ────────────────────────────────────────────────────────

function DynamicAnalysisPanel({ data }: { data: FraudCardData }) {
  if (!data.dynamic_available || !data.dynamic_analysis) {
    return (
      <SocCard>
        <SectionHeader icon={<Terminal className="h-4 w-4" />} title="Dynamic Sandbox Execution" subtitle="Frida & ADB UI Explorer" />
        <div className="p-6 text-center text-sm text-gray-400">Dynamic analysis data unavailable or disabled</div>
      </SocCard>
    );
  }

  const dyn = data.dynamic_analysis;
  
  // Format coverage
  const cov = dyn.coverage_metrics || {};
  const coverageHtml = cov.total_activities ? (
    <div className="text-sm">
      <div className="flex justify-between text-gray-600 mb-1">
        <span>Activity Coverage</span>
        <span>{((cov.covered_activities / cov.total_activities) * 100).toFixed(1)}%</span>
      </div>
      <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
        <div className="bg-blue-600 h-2 rounded-full" style={{ width: `${(cov.covered_activities / cov.total_activities) * 100}%` }}></div>
      </div>
      <div className="text-xs text-gray-500 mt-2 text-right">{cov.covered_activities} of {cov.total_activities} activities reached</div>
    </div>
  ) : <span className="text-gray-400 text-sm">No coverage data</span>;

  return (
    <SocCard>
      <SectionHeader icon={<Terminal className="h-4 w-4" />} title="Dynamic Sandbox Execution" subtitle="Multi-Stage Frida & UI Explorer Results" />
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-0 divide-x divide-y divide-gray-100">
        
        {/* Execution Summary */}
        <div className="p-4">
          <h3 className="text-xs font-semibold uppercase text-gray-500 mb-3">Multi-Stage Summary</h3>
          {Object.keys(dyn.multi_stage_summary || {}).length > 0 ? (
            <div className="space-y-2">
              {Object.entries(dyn.multi_stage_summary).map(([stage, res]: [string, any]) => (
                <div key={stage} className="flex justify-between items-center bg-gray-50 p-2 rounded text-sm">
                  <span className="font-mono text-xs truncate mr-2" title={stage}>{stage}</span>
                  <span className={`px-2 py-0.5 rounded text-xs font-medium flex-shrink-0 ${res.success ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
                    {res.success ? 'Success' : 'Failed'}
                  </span>
                </div>
              ))}
            </div>
          ) : <div className="text-sm text-gray-400">No multi-stage summary available</div>}
        </div>

        {/* Coverage Metrics */}
        <div className="p-4">
          <h3 className="text-xs font-semibold uppercase text-gray-500 mb-3">UI Coverage</h3>
          {coverageHtml}
        </div>

        {/* Timeline */}
        <div className="p-4 lg:row-span-2 overflow-y-auto max-h-96">
          <h3 className="text-xs font-semibold uppercase text-gray-500 mb-3">Attack Timeline</h3>
          {(dyn.attack_timeline || []).length > 0 ? (
            <div className="space-y-4 border-l-2 border-gray-100 ml-2 pl-3 pb-2 mt-2">
              {dyn.attack_timeline.map((evt: any, i: number) => (
                <div key={i} className="relative">
                  <div className="absolute -left-[21px] top-1 h-3 w-3 rounded-full bg-blue-100 border-2 border-blue-500"></div>
                  <div className="text-xs text-gray-400 font-mono mb-0.5">Stage {evt.stage_index + 1}</div>
                  <div className="text-sm font-medium text-gray-800">{evt.action_type === 'INPUT' ? `Typed "${evt.text}"` : `Clicked node`}</div>
                  {evt.target_node && <div className="text-xs font-mono text-gray-500 truncate" title={evt.target_node}>{evt.target_node}</div>}
                </div>
              ))}
            </div>
          ) : <div className="text-sm text-gray-400">No timeline data</div>}
        </div>

        {/* Screenshots */}
        <div className="p-4 lg:col-span-2">
          <h3 className="text-xs font-semibold uppercase text-gray-500 mb-3">Screenshots (Simulated)</h3>
          {(dyn.screenshots || []).length > 0 ? (
             <div className="flex gap-4 overflow-x-auto pb-2">
               {dyn.screenshots.map((s: string, i: number) => (
                 <div key={i} className="flex-shrink-0 w-32 border border-gray-200 rounded overflow-hidden shadow-sm">
                   <div className="h-48 bg-gray-100 flex items-center justify-center relative">
                     <span className="text-gray-500 text-[10px] text-center p-2 break-all z-10">{s.split('/').pop()}</span>
                     <div className="absolute inset-0 opacity-10 flex flex-col justify-between p-2">
                        <div className="h-4 bg-gray-400 rounded w-3/4"></div>
                        <div className="h-20 bg-gray-400 rounded w-full"></div>
                        <div className="h-6 bg-gray-400 rounded w-1/2 mx-auto"></div>
                     </div>
                   </div>
                 </div>
               ))}
             </div>
          ) : <div className="text-sm text-gray-400 flex h-24 items-center justify-center border-2 border-dashed border-gray-100 rounded">No screenshots captured</div>}
        </div>
      </div>

      {/* Fraud Workflow Reconstruction */}
      <div className="border-t border-gray-100 p-5">
        <div className="flex items-center gap-2 mb-4">
          <span className="text-xs font-semibold uppercase text-gray-500 tracking-wide">Fraud Workflow Reconstruction</span>
          <span className="px-2 py-0.5 text-xs bg-blue-100 text-blue-700 rounded font-medium">Causal Chain Analysis</span>
        </div>
        <WorkflowDiagram workflow={(data as any).fraud_workflow ?? null} />
      </div>
    </SocCard>
  );
}

// ─── Main TechnicalView Page ──────────────────────────────────────────────────────

export default function TechnicalView({ data }: { data: FraudCardData | null }) {
  if (!data) return <Navigate to="/" />;

  return (
    <div className="space-y-5 max-w-7xl mx-auto">
      {/* Page header */}
      <div className="flex items-center gap-3 pb-4 border-b border-gray-200">
        <Terminal className="h-7 w-7 text-gray-700" />
        <div>
          <h1 className="text-2xl font-bold text-gray-900">SOC / Technical View</h1>
          <p className="text-sm text-gray-500 mt-0.5">Static analysis — {data.package_name || data.sha256.slice(0, 20) + '…'}</p>
        </div>
      </div>

      {/* Row 1: Explainability + APK Metadata */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <ExplainabilityEngine data={data} />
        <div className="lg:col-span-2">
          <APKMetadata data={data} />
        </div>
      </div>

      {/* Row 2: Threat Indicators + Permission Analysis */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <ThreatIndicatorsPanel data={data} />
        <div className="lg:col-span-2">
          <PermissionTable data={data} />
        </div>
      </div>

      {/* Row 3: Dangerous API Table */}
      <DangerousAPITable data={data} />

      {/* Row 4: Network Intelligence */}
      <NetworkIntelligence data={data} />

      {/* Row 5: Top Evidence + Raw Evidence Tabs */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <TopEvidencePanel data={data} />
        <div className="lg:col-span-2">
          <RawEvidenceTabs data={data} />
        </div>
      </div>

      {/* Row 6: IOC Panel */}
      <IOCPanel data={data} />

      {/* Row 7: Dynamic Analysis */}
      <DynamicAnalysisPanel data={data} />

      {/* Row 8: Risk Scoring Breakdown */}
      <RiskScoringBreakdown data={data} />
    </div>
  );
}
