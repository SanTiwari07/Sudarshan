import { useState } from 'react';
import { Navigate } from 'react-router-dom';
import {
  Terminal, Cpu, AlertTriangle,
  Search, Lock, Code, Package
} from 'lucide-react';
import type { FraudCardData } from '../App';
import { exportJSON, exportCSV } from '../utils/derive';
import { API_BASE } from '../config';
import SocCard from '../components/ui/Card';
import SectionHeader from '../components/ui/SectionHeader';
import Badge from '../components/ui/Badge';
import CopyButton from '../components/ui/CopyButton';
import WorkflowDiagram from '../components/WorkflowDiagram';

// ─── Explainability Engine ────────────────────────────────────────────────────────

function ExplainabilityEngine({ data }: { data: FraudCardData }) {
  return (
    <SocCard>
      <div className="bg-slate-900 px-5 py-3 flex items-center gap-2">
        <Cpu className="h-4 w-4 text-blue-400" />
        <h2 className="text-sm font-semibold text-blue-400 font-mono tracking-wide">Explainability Engine</h2>
      </div>
      <div className="bg-slate-900 p-4 space-y-3">
        <div className="bg-slate-800 p-3 rounded-lg">
          <p className="text-xs text-slate-400 font-mono mb-1 uppercase tracking-wider">Classification Result</p>
          <p className={`text-lg font-bold ${data.family_classification !== 'Unknown' ? 'text-red-400' : 'text-slate-200'}`}>
            {data.family_classification}
          </p>
        </div>
        <div className="bg-slate-800 p-3 rounded-lg border border-slate-700">
          <p className="text-xs text-slate-400 font-mono mb-2 uppercase tracking-wider">Matched Rule</p>
          <p className="font-mono text-xs text-slate-200 bg-black p-2.5 rounded leading-relaxed">
            {data.technical_view.matched_rule}
          </p>
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
    { label: 'Network Indicators', value: `${data.hardcoded_urls_ips.length} hardcoded URL(s)/IP(s)`, mono: false },
    { label: 'Banking Targeting', value: data.targets_indian_banks ? 'YES — Target Package Found' : 'No', mono: false, highlight: data.targets_indian_banks },
    { label: 'Final Score', value: `${data.final_risk_score.toFixed(2)} / 100`, mono: true, highlight: data.final_risk_score > 30 },
  ];

  return (
    <SocCard>
      <SectionHeader icon={<Package className="h-4 w-4" />} title="APK Technical Identifiers" />
      <div className="divide-y divide-slate-100">
        {rows.map(r => (
          <div key={r.label} className="flex items-start justify-between gap-3 px-4 py-2.5 hover:bg-slate-50 transition-colors">
            <span className="text-xs text-slate-500 flex-shrink-0 w-36">{r.label}</span>
            <div className="flex items-center gap-1 min-w-0 flex-1 justify-end">
              <span className={`text-xs text-right ${r.mono ? 'font-mono' : ''} ${r.highlight ? 'text-red-600 font-semibold' : 'text-slate-800'} ${r.truncate ? 'truncate max-w-xs' : ''}`}>
                {r.value}
              </span>
              {r.copy && <CopyButton value={r.copy} />}
            </div>
          </div>
        ))}
      </div>
    </SocCard>
  );
}

// ─── Permission Analysis Table ────────────────────────────────────────────────────

function PermissionTable({ data }: { data: FraudCardData }) {
  const [search, setSearch] = useState('');
  const permissions = data.all_permissions;
  const firedSet = new Set(data.technical_view.permissions_fired);

  const filtered = permissions.filter(p => p.toLowerCase().includes(search.toLowerCase()));

  return (
    <SocCard>
      <SectionHeader
        icon={<Lock className="h-4 w-4" />}
        title="Permission Analysis"
        subtitle={`${permissions.length} total permissions extracted`}
      />
      <div className="px-4 py-2.5 border-b border-slate-200">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-400" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Filter permissions…"
            className="w-full pl-8 pr-3 py-1.5 text-xs border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
      </div>
      <div className="overflow-x-auto max-h-72">
        <table className="w-full text-xs">
          <thead className="bg-slate-50 border-b border-slate-200">
            <tr>
              <th className="px-4 py-2.5 text-left font-semibold text-slate-600">Permission</th>
              <th className="px-4 py-2.5 text-left font-semibold text-slate-600">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {filtered.map((perm, i) => {
              const fired = firedSet.has(perm);
              return (
                <tr key={i} className={`hover:bg-slate-50 ${fired ? 'bg-red-50/60' : ''}`}>
                  <td className="px-4 py-2.5 font-mono text-slate-800 break-all">{perm}</td>
                  <td className="px-4 py-2.5">
                    {fired ? (
                      <Badge label="Flagged Critical" className="bg-red-100 text-red-700 border border-red-200" />
                    ) : (
                      <Badge label="Granted" className="bg-slate-100 text-slate-600 border border-slate-200" />
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </SocCard>
  );
}

// ─── Dangerous API Table ──────────────────────────────────────────────────────────

function DangerousAPITable({ data }: { data: FraudCardData }) {
  const apis = data.technical_view.apis_fired;

  return (
    <SocCard>
      <SectionHeader
        icon={<Code className="h-4 w-4" />}
        title="Dangerous API Detection"
        subtitle={`${apis.length} dangerous API(s) detected`}
      />
      {apis.length === 0 ? (
        <div className="p-4 text-center text-xs text-slate-400">
          No dangerous Java/Android API invocations detected in DEX bytecode.
        </div>
      ) : (
        <div className="divide-y divide-slate-100">
          {apis.map((api, i) => (
            <div key={i} className="flex items-center justify-between p-3 bg-red-50/40">
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-red-500 flex-shrink-0" />
                <code className="text-xs font-mono font-bold text-slate-800">{api}</code>
              </div>
              <Badge label="Dangerous API" className="bg-red-100 text-red-700 border border-red-200" />
            </div>
          ))}
        </div>
      )}
    </SocCard>
  );
}

// ─── Dynamic Analysis Panel ────────────────────────────────────────────────────────

function DynamicAnalysisPanel({ data }: { data: FraudCardData }) {
  if (!data.dynamic_available || !data.dynamic_analysis) {
    return (
      <SocCard>
        <SectionHeader icon={<Terminal className="h-4 w-4" />} title="Dynamic Sandbox Execution" subtitle="Frida & ADB UI Explorer" />
        <div className="p-6 text-center text-xs text-slate-400">Dynamic analysis data unavailable or disabled</div>
      </SocCard>
    );
  }

  const dyn = data.dynamic_analysis;

  return (
    <SocCard>
      <SectionHeader icon={<Terminal className="h-4 w-4" />} title="Dynamic Sandbox Execution" subtitle="Frida Runtime Instrumentation & UI Explorer" />
      
      {/* Real Screenshots Gallery */}
      <div className="p-4 border-b border-slate-100">
        <h3 className="text-xs font-semibold uppercase text-slate-500 mb-3">Runtime Screen Captures</h3>
        {(dyn.screenshots || []).length > 0 ? (
          <div className="flex gap-4 overflow-x-auto pb-2">
            {dyn.screenshots.map((s: string, i: number) => {
              const filename = s.split('/').pop() || s;
              const imgUrl = `${API_BASE}/screenshots/${filename}`;
              return (
                <div key={i} className="flex-shrink-0 w-36 border border-slate-200 rounded-lg overflow-hidden shadow-sm bg-slate-900">
                  <img
                    src={imgUrl}
                    alt={`Screen capture ${i + 1}`}
                    className="h-52 w-full object-cover"
                    onError={(e) => {
                      // Fallback text if screenshot path fails to load
                      (e.target as HTMLElement).style.display = 'none';
                    }}
                  />
                  <div className="p-1.5 text-[10px] font-mono text-slate-400 truncate bg-slate-900 border-t border-slate-800">
                    {filename}
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="text-xs text-slate-400 p-4 border border-dashed border-slate-200 rounded-lg text-center">
            No runtime screenshots captured during execution.
          </div>
        )}
      </div>

      {/* Fraud Workflow Reconstruction */}
      <div className="p-5">
        <h3 className="text-xs font-semibold uppercase text-slate-500 mb-3">Reconstructed Behavioral Chain</h3>
        <WorkflowDiagram workflow={data.fraud_workflow} />
      </div>
    </SocCard>
  );
}

// ─── Main TechnicalView Page ──────────────────────────────────────────────────────

export default function TechnicalView({ data }: { data: FraudCardData | null }) {
  if (!data) return <Navigate to="/" />;

  return (
    <div className="space-y-5">
      {/* Page header */}
      <div className="flex items-center justify-between pb-4 border-b border-slate-200">
        <div className="flex items-center gap-3">
          <Terminal className="h-7 w-7 text-slate-700" />
          <div>
            <h1 className="text-2xl font-bold text-slate-900">SOC / Technical View</h1>
            <p className="text-sm text-slate-500 mt-0.5">Deep inspection — {data.package_name || data.sha256.slice(0, 16) + '…'}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => exportJSON(data)} className="px-3 py-1.5 text-xs font-semibold bg-slate-800 text-white rounded-lg hover:bg-slate-900 transition-colors">
            Export JSON
          </button>
          <button onClick={() => exportCSV(data)} className="px-3 py-1.5 text-xs font-semibold bg-slate-700 text-white rounded-lg hover:bg-slate-800 transition-colors">
            Export CSV
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <ExplainabilityEngine data={data} />
        <div className="lg:col-span-2">
          <APKMetadata data={data} />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <PermissionTable data={data} />
        <DangerousAPITable data={data} />
      </div>

      <DynamicAnalysisPanel data={data} />
    </div>
  );
}
