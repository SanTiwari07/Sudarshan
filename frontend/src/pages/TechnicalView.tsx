import { useState } from 'react';
import { Navigate } from 'react-router-dom';
import {
  Terminal, Cpu, Search, Lock, Code, Package
} from 'lucide-react';
import type { FraudCardData } from '../App';
import { exportJSON, exportCSV } from '../utils/derive';
import { API_BASE } from '../config';
import SocCard from '../components/ui/Card';
import SectionHeader from '../components/ui/SectionHeader';
import CopyButton from '../components/ui/CopyButton';
import WorkflowDiagram from '../components/WorkflowDiagram';

// ─── Explainability Engine ────────────────────────────────────────────────────────

function ExplainabilityEngine({ data }: { data: FraudCardData }) {
  return (
    <SocCard>
      <SectionHeader icon={<Cpu className="h-4 w-4 text-blue-700" />} title="Explainability Engine" />
      <div className="p-4 space-y-3">
        <div className="bg-slate-50 border border-slate-200 p-3.5 rounded-xl">
          <p className="text-[10px] text-slate-500 font-mono mb-1 uppercase tracking-wider">Classification Result</p>
          <p className={`text-base font-bold ${data.family_classification !== 'Unknown' ? 'text-red-600' : 'text-slate-900'}`}>
            {data.family_classification}
          </p>
        </div>
        <div className="bg-slate-50 border border-slate-200 p-3.5 rounded-xl">
          <p className="text-[10px] text-slate-500 font-mono mb-2 uppercase tracking-wider">Matched Rule</p>
          <p className="font-mono text-xs text-slate-800 bg-white border border-slate-200 p-3 rounded-lg leading-relaxed shadow-xs">
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

// ─── Permission Analysis ──────────────────────────────────────────────────────────

function PermissionTable({ data }: { data: FraudCardData }) {
  const [filter, setFilter] = useState('');
  const perms = data.all_permissions.filter(p => p.toLowerCase().includes(filter.toLowerCase()));
  const fired = new Set(data.technical_view.permissions_fired);

  return (
    <SocCard>
      <SectionHeader icon={<Lock className="h-4 w-4" />} title="Permission Analysis" subtitle={`${data.all_permissions.length} total permissions extracted`} />
      <div className="p-3 border-b border-slate-100">
        <div className="relative">
          <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
          <input
            type="text"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter permissions..."
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>
      </div>
      <div className="overflow-x-auto max-h-64">
        <table className="w-full text-xs">
          <thead className="bg-slate-50 border-b border-slate-200">
            <tr>
              <th className="px-4 py-2 text-left font-semibold text-slate-600">Permission</th>
              <th className="px-4 py-2 text-right font-semibold text-slate-600">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 font-mono">
            {perms.map(p => {
              const isFired = fired.has(p);
              return (
                <tr key={p} className={`hover:bg-slate-50 ${isFired ? 'bg-red-50/50' : ''}`}>
                  <td className="px-4 py-2 text-slate-800">{p}</td>
                  <td className="px-4 py-2 text-right">
                    {isFired ? (
                      <span className="px-2 py-0.5 text-[10px] font-bold bg-red-100 text-red-700 rounded">FLAGGED CRITICAL</span>
                    ) : (
                      <span className="text-slate-400">Normal</span>
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

// ─── Dangerous API Table ─────────────────────────────────────────────────────────

function DangerousAPITable({ data }: { data: FraudCardData }) {
  const apis = data.technical_view.apis_fired;

  return (
    <SocCard>
      <SectionHeader icon={<Code className="h-4 w-4" />} title="Dangerous API Detection" subtitle={`${apis.length} dangerous API(s) detected`} />
      {apis.length === 0 ? (
        <div className="p-6 text-center text-xs text-slate-400">
          No dangerous Java/Android API invocations detected in DEX bytecode.
        </div>
      ) : (
        <div className="divide-y divide-slate-100 font-mono text-xs max-h-64 overflow-y-auto">
          {apis.map((api, i) => (
            <div key={i} className="px-4 py-2.5 flex items-center justify-between hover:bg-slate-50">
              <span className="text-red-700 font-semibold">{api}</span>
              <span className="px-2 py-0.5 text-[10px] bg-red-50 text-red-600 border border-red-200 rounded">DANGEROUS HOOK</span>
            </div>
          ))}
        </div>
      )}
    </SocCard>
  );
}

// ─── Digital Certificate & Signature Panel ─────────────────────────────────────────

function CertificatePanel({ certificate }: { certificate?: Record<string, any> }) {
  if (!certificate || Object.keys(certificate).length === 0) {
    return (
      <SocCard>
        <SectionHeader icon={<Lock className="h-4 w-4" />} title="Digital Certificate & Signature" subtitle="X.509 Cryptographic Identity" />
        <div className="p-4 text-center text-xs text-slate-400">No certificate metadata available</div>
      </SocCard>
    );
  }

  const entries = Object.entries(certificate);

  return (
    <SocCard>
      <SectionHeader icon={<Lock className="h-4 w-4" />} title="Digital Certificate & Signature" subtitle="X.509 Cryptographic Identity & Attribution" />
      <div className="divide-y divide-slate-100 max-h-64 overflow-y-auto text-xs">
        {entries.map(([k, v]) => (
          <div key={k} className="flex justify-between p-2.5 hover:bg-slate-50">
            <span className="text-slate-500 font-mono capitalize">{k.replace(/_/g, ' ')}</span>
            <span className="font-mono text-slate-800 break-all text-right max-w-md">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
          </div>
        ))}
      </div>
    </SocCard>
  );
}

// ─── Decompilation & Static Enrichment Panel ───────────────────────────────────────

function DecompilationPanel({ data }: { data: FraudCardData }) {
  const apktool = (data as any).apktool_enrichment;
  const jadx = (data as any).jadx_enrichment;

  if (!apktool && !jadx) {
    return (
      <SocCard>
        <SectionHeader icon={<Code className="h-4 w-4" />} title="Static Decompilation Intelligence" subtitle="APKTool Resources & JADX Source Pattern Scanner" />
        <div className="p-4 text-center text-xs text-slate-400">Decompilation enrichment data unavailable for this scan</div>
      </SocCard>
    );
  }

  return (
    <SocCard>
      <SectionHeader icon={<Code className="h-4 w-4" />} title="Static Decompilation Intelligence" subtitle="APKTool Resources & JADX Java Source Hits" />
      <div className="p-4 space-y-3 font-mono text-xs">
        {jadx?.fraud_class_hits?.length > 0 && (
          <div className="p-3 bg-red-50 border border-red-200 rounded-lg">
            <span className="font-bold text-red-700 uppercase">JADX Fraud Classes Found:</span>
            <div className="mt-1 text-red-800 text-[11px]">{jadx.fraud_class_hits.join(', ')}</div>
          </div>
        )}
        {apktool?.decoded_manifest_xml && (
          <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-slate-700">
            <span className="font-bold text-slate-800 uppercase">Decoded Manifest Excerpt:</span>
            <pre className="mt-1 text-[11px] text-slate-600 overflow-x-auto whitespace-pre-wrap">
              {apktool.decoded_manifest_xml.slice(0, 300)}...
            </pre>
          </div>
        )}
      </div>
    </SocCard>
  );
}

// ─── Network Capture Panel ─────────────────────────────────────────────────────────

function NetworkCapturePanel({ networkLogs }: { networkLogs?: any[] }) {
  if (!networkLogs || networkLogs.length === 0) {
    return (
      <SocCard>
        <SectionHeader icon={<Terminal className="h-4 w-4" />} title="Network Capture & C2 Telemetry" subtitle="Runtime mitmproxy & PCAP logs" />
        <div className="p-4 text-center text-xs text-slate-400">No dynamic network traffic captured</div>
      </SocCard>
    );
  }

  return (
    <SocCard>
      <SectionHeader icon={<Terminal className="h-4 w-4" />} title="Network Capture & C2 Telemetry" subtitle={`${networkLogs.length} network request(s) captured`} />
      <div className="overflow-x-auto max-h-64">
        <table className="w-full text-xs">
          <thead className="bg-slate-50 border-b border-slate-200">
            <tr>
              <th className="px-3 py-2 text-left font-semibold text-slate-600">Method</th>
              <th className="px-3 py-2 text-left font-semibold text-slate-600">Host / IP</th>
              <th className="px-3 py-2 text-left font-semibold text-slate-600">URL / Endpoint</th>
              <th className="px-3 py-2 text-left font-semibold text-slate-600">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 font-mono">
            {networkLogs.map((req, i) => (
              <tr key={i} className={`hover:bg-slate-50 ${req.is_suspicious ? 'bg-red-50/60' : ''}`}>
                <td className="px-3 py-2 font-bold text-slate-800">{req.method || 'GET'}</td>
                <td className="px-3 py-2 text-slate-700">{req.domain || req.ip || '—'}</td>
                <td className="px-3 py-2 text-slate-600 truncate max-w-xs">{req.url || '—'}</td>
                <td className="px-3 py-2 font-bold text-slate-800">{req.response_status || 200}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </SocCard>
  );
}

// ─── Logcat Inspector Panel ─────────────────────────────────────────────────────────

function LogcatInspectorPanel({ logcat }: { logcat?: string }) {
  if (!logcat || !logcat.trim()) {
    return (
      <SocCard>
        <SectionHeader icon={<Terminal className="h-4 w-4" />} title="Logcat System Diagnostics" subtitle="Android OS Event Stream" />
        <div className="p-4 text-center text-xs text-slate-400">No logcat telemetry collected</div>
      </SocCard>
    );
  }

  return (
    <SocCard>
      <SectionHeader icon={<Terminal className="h-4 w-4" />} title="Logcat System Diagnostics" subtitle="Monospace Android System Log Inspector" />
      <div className="p-3 bg-slate-900 font-mono text-[11px] text-emerald-400 max-h-60 overflow-y-auto rounded-b-lg whitespace-pre-wrap leading-relaxed border-t border-slate-800">
        {logcat}
      </div>
    </SocCard>
  );
}

// ─── Dynamic Sandbox Panel ────────────────────────────────────────────────────────

function DynamicAnalysisPanel({ data }: { data: FraudCardData }) {
  const dyn = data.dynamic_result || {};

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
                <div key={i} className="flex-shrink-0 w-36 border border-slate-200 rounded-lg overflow-hidden shadow-xs bg-white">
                  <img
                    src={imgUrl}
                    alt={`Screen capture ${i + 1}`}
                    className="h-52 w-full object-cover"
                    onError={(e) => {
                      (e.target as HTMLElement).style.display = 'none';
                    }}
                  />
                  <div className="p-1.5 text-[10px] font-mono text-slate-700 truncate bg-slate-50 border-t border-slate-200">
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
          <button onClick={() => exportJSON(data)} className="px-3 py-1.5 text-xs font-semibold bg-white border border-slate-200 text-slate-700 rounded-lg hover:bg-slate-50 transition-colors shadow-xs">
            Export JSON
          </button>
          <button onClick={() => exportCSV(data)} className="px-3 py-1.5 text-xs font-semibold bg-white border border-slate-200 text-slate-700 rounded-lg hover:bg-slate-50 transition-colors shadow-xs">
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

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <CertificatePanel certificate={data.certificate} />
        <DecompilationPanel data={data} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <NetworkCapturePanel networkLogs={data.dynamic_analysis?.network_logs} />
        <LogcatInspectorPanel logcat={data.dynamic_analysis?.logcat} />
      </div>

      <DynamicAnalysisPanel data={data} />
    </div>
  );
}
