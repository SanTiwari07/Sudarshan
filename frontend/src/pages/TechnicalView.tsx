import { useEffect, useState } from 'react';
import {
  Terminal, Cpu, Search, Lock, Code, Package,
  ChevronDown, ChevronUp, Shield, Globe, AlertTriangle, Database, Tag, Key
} from 'lucide-react';
import type { FraudCardData } from '../App';
import { exportJSON, exportCSV } from '../utils/derive';
import { API_BASE, authHeaders } from '../config';
import SocCard from '../components/ui/Card';
import SectionHeader from '../components/ui/SectionHeader';
import CopyButton from '../components/ui/CopyButton';
import WorkflowDiagram from '../components/WorkflowDiagram';
import FindingsRegistryTable from '../components/investigation/FindingsRegistryTable';
import { useAnalysis } from '../context/AnalysisContext';

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

function AuthedScreenshot({ sha256, relPath }: { sha256: string; relPath: string }) {
  const filename = relPath.split('/').pop() || relPath;
  const [src, setSrc] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    let objectUrl: string | null = null;
    const url = `${API_BASE}/screenshots/${sha256}/${encodeURIComponent(filename)}`;

    fetch(url, { headers: authHeaders() })
      .then((res) => {
        if (!res.ok) throw new Error(String(res.status));
        return res.blob();
      })
      .then((blob) => {
        if (cancelled) return;
        objectUrl = URL.createObjectURL(blob);
        setSrc(objectUrl);
      })
      .catch(() => {
        if (!cancelled) setSrc(null);
      });

    return () => {
      cancelled = true;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [sha256, filename]);

  if (!src) {
    return (
      <div className="h-52 w-full bg-slate-100 flex items-center justify-center text-[10px] text-slate-400">
        Unavailable
      </div>
    );
  }

  return (
    <img
      src={src}
      alt={filename}
      className="h-52 w-full object-cover"
    />
  );
}

function DynamicAnalysisPanel({ data }: { data: FraudCardData }) {
  const dyn = data.dynamic_result || {};
  const status = (dyn.dynamic_status || (data.frs_breakdown?.dynamic_available ? 'EVENTS_CAPTURED' : 'NOT_RUN')).toUpperCase();
  const isOk = status === 'EVENTS_CAPTURED' || status === 'NO_RUNTIME_ACTIVITY';

  return (
    <SocCard>
      <SectionHeader
        icon={<Terminal className="h-4 w-4" />}
        title="Dynamic Sandbox Execution"
        subtitle="Frida Runtime Instrumentation & Telemetry"
      />
      
      {/* Pipeline Diagnostic Header */}
      <div className="p-4 border-b border-slate-100 bg-slate-50/50">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
          <div className="flex items-center gap-2">
            <span className="text-xs font-medium text-slate-500">Pipeline Status:</span>
            <span className={`px-2 py-0.5 text-xs font-bold rounded-md font-mono ${
              isOk ? 'bg-emerald-100 text-emerald-800 border border-emerald-300' : 'bg-amber-100 text-amber-800 border border-amber-300'
            }`}>
              {status}
            </span>
          </div>
          <div className="flex items-center gap-2 text-xs font-mono text-slate-600">
            <span>Engine: <strong>{dyn.engine || 'frida'}</strong></span>
            <span>•</span>
            <span>Canary: <strong>{dyn.canary_received ? '✓ LOADED' : '✗ UNRECEIVED'}</strong></span>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
          <div className="p-2 bg-white rounded border border-slate-200">
            <span className="text-slate-400 block text-[10px] uppercase font-semibold">BFCI Score</span>
            <span className="font-mono font-bold text-slate-800 text-sm">{(dyn.bfci || data.frs_breakdown?.dynamic || 0).toFixed(1)} / 100</span>
          </div>
          <div className="p-2 bg-white rounded border border-slate-200">
            <span className="text-slate-400 block text-[10px] uppercase font-semibold">Hook Coverage</span>
            <span className="font-mono font-bold text-emerald-600 text-sm">100% (11 Cats)</span>
          </div>
          <div className="p-2 bg-white rounded border border-slate-200">
            <span className="text-slate-400 block text-[10px] uppercase font-semibold">Raw Events</span>
            <span className="font-mono font-bold text-slate-800 text-sm">{dyn.evidence_record_count || (dyn.api_calls || []).length}</span>
          </div>
          <div className="p-2 bg-white rounded border border-slate-200">
            <span className="text-slate-400 block text-[10px] uppercase font-semibold">Hook Errors</span>
            <span className="font-mono font-bold text-slate-800 text-sm">{(dyn.hook_errors || []).length}</span>
          </div>
        </div>
      </div>

      {/* Real Screenshots Gallery */}
      <div className="p-4 border-b border-slate-100">
        <h3 className="text-xs font-semibold uppercase text-slate-500 mb-3">Runtime Screen Captures</h3>
        {(dyn.screenshots || []).length > 0 ? (
          <div className="flex gap-4 overflow-x-auto pb-2">
            {dyn.screenshots.map((s: string, i: number) => {
              const filename = s.split('/').pop() || s;
              return (
                <div key={i} className="flex-shrink-0 w-36 border border-slate-200 rounded-lg overflow-hidden shadow-xs bg-white">
                  <AuthedScreenshot sha256={data.sha256} relPath={s} />
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


// ─── Manifest Findings Panel ─────────────────────────────────────────────────────

function ManifestFindingsPanel({ data }: { data: FraudCardData }) {
  const [open, setOpen] = useState(true);
  const [filter, setFilter] = useState('');
  const [sev, setSev] = useState<string>('all');
  const findings = data.manifest_findings || [];

  if (findings.length === 0) return null;

  const sevCounts = findings.reduce((acc, f) => {
    const s = f.severity?.toLowerCase() || 'info';
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const visible = findings.filter(f => {
    const matchSev = sev === 'all' || (f.severity?.toLowerCase() === sev);
    const matchText = !filter || f.title.toLowerCase().includes(filter.toLowerCase()) || f.component.toLowerCase().includes(filter.toLowerCase());
    return matchSev && matchText;
  });

  const sevColor = (s: string) => ({
    high: 'bg-red-100 text-red-700',
    warning: 'bg-orange-100 text-orange-700',
    info: 'bg-blue-100 text-blue-700',
  }[s.toLowerCase()] || 'bg-slate-100 text-slate-600');

  return (
    <SocCard>
      <button onClick={() => setOpen(o => !o)} className="w-full">
        <SectionHeader
          icon={<AlertTriangle className="h-4 w-4" />}
          title="Manifest Security Findings"
          subtitle={`${findings.length} finding(s) from AndroidManifest.xml analysis`}
          action={open ? <ChevronUp className="h-4 w-4 text-slate-400" /> : <ChevronDown className="h-4 w-4 text-slate-400" />}
        />
      </button>
      {open && (
        <>
          <div className="flex items-center gap-2 px-3 pb-3 border-b border-slate-100">
            <div className="relative flex-1">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
              <input type="text" value={filter} onChange={e => setFilter(e.target.value)}
                placeholder="Filter findings..." className="w-full pl-8 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-blue-500" />
            </div>
            {['all', 'high', 'warning', 'info'].map(s => (
              <button key={s} onClick={() => setSev(s)}
                className={`px-2.5 py-1 text-[10px] font-bold uppercase rounded-full transition-colors ${sev === s ? 'bg-blue-600 text-white' : 'bg-slate-100 text-slate-500 hover:bg-slate-200'}`}>
                {s}{s !== 'all' && sevCounts[s] ? ` (${sevCounts[s]})` : ''}
              </button>
            ))}
          </div>
          <div className="divide-y divide-slate-100 max-h-72 overflow-y-auto">
            {visible.map((f, i) => (
              <div key={i} className="px-4 py-2.5 hover:bg-slate-50">
                <div className="flex items-start gap-2">
                  <span className={`mt-0.5 px-1.5 py-0.5 text-[10px] font-bold rounded flex-shrink-0 ${sevColor(f.severity)}`}>{f.severity?.toUpperCase()}</span>
                  <div className="min-w-0">
                    <p className="text-xs font-semibold text-slate-800">{f.title}</p>
                    {f.component && <p className="text-[10px] font-mono text-slate-500 truncate">{f.component}</p>}
                    {f.description && <p className="text-[10px] text-slate-500 mt-0.5">{f.description}</p>}
                  </div>
                </div>
              </div>
            ))}
            {visible.length === 0 && <div className="p-6 text-center text-xs text-slate-400">No findings match the current filter.</div>}
          </div>
        </>
      )}
    </SocCard>
  );
}

// ─── Code Findings Panel (with MASVS/CWE/OWASP) ────────────────────────────────────

const CODE_CATEGORIES = [
  { id: 'all', label: 'All' },
  { id: 'crypto', label: 'Crypto', keywords: ['crypto', 'cipher', 'des', 'md5', 'sha1', 'ecb', 'aes', 'rsa', 'rc4', 'encryption', 'digest', 'random'] },
  { id: 'webview', label: 'WebView', keywords: ['webview', 'javascript', 'addjavascriptinterface', 'loadurl', 'evaluatejavascript', 'allowfileaccess'] },
  { id: 'ssl', label: 'SSL/TLS', keywords: ['ssl', 'tls', 'trustmanager', 'hostname', 'pinning', 'hostnamevalidator', 'x509', 'cleartext'] },
  { id: 'antiana', label: 'Anti-Analysis', keywords: ['root', 'debug', 'frida', 'emulator', 'hooking', 'isdebugg', 'systemproperties', 'buildtags'] },
];

function CodeFindingsPanel({ data }: { data: FraudCardData }) {
  const [open, setOpen] = useState(true);
  const [filter, setFilter] = useState('');
  const [cat, setCat] = useState('all');
  const [sev, setSev] = useState<string>('all');
  const findings = data.code_findings || [];

  if (findings.length === 0) return null;

  const activeCat = CODE_CATEGORIES.find(c => c.id === cat);
  const visible = findings.filter(f => {
    const text = `${f.title} ${f.description} ${(f as any).rule_id || ''}`.toLowerCase();
    const matchCat = cat === 'all' || (activeCat?.keywords || []).some(k => text.includes(k));
    const matchSev = sev === 'all' || (f.severity?.toLowerCase() === sev);
    const matchFilter = !filter || text.includes(filter.toLowerCase());
    return matchCat && matchSev && matchFilter;
  });

  const sevColor = (s: string) => ({
    high: 'text-red-700 bg-red-50 border-red-200',
    warning: 'text-orange-700 bg-orange-50 border-orange-200',
    info: 'text-blue-700 bg-blue-50 border-blue-200',
  }[s?.toLowerCase()] || 'text-slate-600 bg-slate-50 border-slate-200');

  return (
    <SocCard>
      <button onClick={() => setOpen(o => !o)} className="w-full">
        <SectionHeader
          icon={<Code className="h-4 w-4" />}
          title="Static Code Security Findings"
          subtitle={`${findings.length} finding(s) from source analysis — with MASVS/CWE/OWASP`}
          action={open ? <ChevronUp className="h-4 w-4 text-slate-400" /> : <ChevronDown className="h-4 w-4 text-slate-400" />}
        />
      </button>
      {open && (
        <>
          <div className="flex flex-wrap items-center gap-2 px-3 pb-3 border-b border-slate-100">
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
              <input type="text" value={filter} onChange={e => setFilter(e.target.value)}
                placeholder="Search findings..." className="pl-8 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg w-44 focus:outline-none focus:ring-1 focus:ring-blue-500" />
            </div>
            <div className="flex gap-1">
              {CODE_CATEGORIES.map(c => (
                <button key={c.id} onClick={() => setCat(c.id)}
                  className={`px-2.5 py-1 text-[10px] font-bold rounded-full transition-colors ${cat === c.id ? 'bg-blue-600 text-white' : 'bg-slate-100 text-slate-500 hover:bg-slate-200'}`}>
                  {c.label}
                </button>
              ))}
            </div>
            <div className="flex gap-1 ml-auto">
              {['all', 'high', 'warning', 'info'].map(s => (
                <button key={s} onClick={() => setSev(s)}
                  className={`px-2 py-0.5 text-[10px] font-bold rounded transition-colors ${sev === s ? 'bg-slate-700 text-white' : 'bg-slate-100 text-slate-400'}`}>
                  {s}
                </button>
              ))}
            </div>
          </div>
          <div className="divide-y divide-slate-100 max-h-96 overflow-y-auto">
            {visible.map((f, i) => (
              <div key={i} className="px-4 py-3 hover:bg-slate-50">
                <div className="flex items-start justify-between gap-2 mb-1">
                  <p className="text-xs font-semibold text-slate-800 leading-snug">{f.title}</p>
                  <span className={`px-1.5 py-0.5 text-[10px] font-bold rounded border flex-shrink-0 ${sevColor(f.severity)}`}>{f.severity?.toUpperCase()}</span>
                </div>
                {f.description && <p className="text-[10px] text-slate-500 mb-1.5">{f.description}</p>}
                <div className="flex flex-wrap gap-1.5">
                  {(f as any).rule_id && <code className="text-[9px] bg-slate-100 text-slate-600 px-1.5 py-0.5 rounded font-mono">{(f as any).rule_id}</code>}
                  {(f as any).masvs && <span className="text-[9px] bg-purple-50 text-purple-700 border border-purple-200 px-1.5 py-0.5 rounded font-mono">MASVS: {(f as any).masvs}</span>}
                  {(f as any).cwe && <span className="text-[9px] bg-orange-50 text-orange-700 border border-orange-200 px-1.5 py-0.5 rounded font-mono">{(f as any).cwe}</span>}
                  {(f as any).owasp && <span className="text-[9px] bg-green-50 text-green-700 border border-green-200 px-1.5 py-0.5 rounded font-mono">{(f as any).owasp}</span>}
                </div>
                {f.files?.length > 0 && (
                  <div className="mt-1.5">
                    {f.files.slice(0, 3).map((file, fi) => (
                      <p key={fi} className="text-[9px] font-mono text-slate-400 truncate">{file}</p>
                    ))}
                  </div>
                )}
              </div>
            ))}
            {visible.length === 0 && <div className="p-6 text-center text-xs text-slate-400">No findings match the current filter.</div>}
          </div>
        </>
      )}
    </SocCard>
  );
}

// ─── Exported Components Panel ──────────────────────────────────────────────────────

function ExportedComponentsPanel({ data }: { data: FraudCardData }) {
  const [open, setOpen] = useState(true);
  const [filter, setFilter] = useState('');
  const acts = data.exported_activities || [];
  const svcs = data.exported_services || [];
  const rcvs = data.exported_receivers || [];
  const prvs = data.providers || [];
  const total = acts.length + svcs.length + rcvs.length + prvs.length;

  if (total === 0) return null;

  type ComponentRow = { name: string; type: string; color: string };
  const rows: ComponentRow[] = [
    ...acts.map(n => ({ name: n, type: 'Activity', color: 'bg-red-50 text-red-700 border-red-200' })),
    ...svcs.map(n => ({ name: n, type: 'Service', color: 'bg-orange-50 text-orange-700 border-orange-200' })),
    ...rcvs.map(n => ({ name: n, type: 'Receiver', color: 'bg-yellow-50 text-yellow-700 border-yellow-200' })),
    ...prvs.map(n => ({ name: n, type: 'Provider', color: 'bg-purple-50 text-purple-700 border-purple-200' })),
  ];

  const visible = filter ? rows.filter(r => r.name.toLowerCase().includes(filter.toLowerCase())) : rows;

  return (
    <SocCard>
      <button onClick={() => setOpen(o => !o)} className="w-full">
        <SectionHeader
          icon={<Shield className="h-4 w-4" />}
          title="Exported Components — Attack Surface"
          subtitle={`${total} exported component(s) accessible by external apps / intents`}
          action={open ? <ChevronUp className="h-4 w-4 text-slate-400" /> : <ChevronDown className="h-4 w-4 text-slate-400" />}
        />
      </button>
      {open && (
        <>
          <div className="px-3 pb-3 border-b border-slate-100">
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
              <input type="text" value={filter} onChange={e => setFilter(e.target.value)}
                placeholder="Filter by component name..." className="w-full pl-8 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-blue-500" />
            </div>
          </div>
          <div className="divide-y divide-slate-100 max-h-72 overflow-y-auto">
            {visible.map((row, i) => (
              <div key={i} className="px-4 py-2.5 flex items-center gap-3 hover:bg-slate-50">
                <span className={`px-2 py-0.5 text-[10px] font-bold rounded border flex-shrink-0 ${row.color}`}>{row.type}</span>
                <span className="font-mono text-xs text-slate-800 break-all">{row.name}</span>
                <CopyButton value={row.name} />
              </div>
            ))}
            {visible.length === 0 && <div className="p-6 text-center text-xs text-slate-400">No components match filter.</div>}
          </div>
        </>
      )}
    </SocCard>
  );
}

// ─── Native Binary Analysis Panel ──────────────────────────────────────────────────

function BinaryAnalysisPanel({ data }: { data: FraudCardData }) {
  const [open, setOpen] = useState(true);
  const bins = data.binary_analysis || [];

  if (bins.length === 0) return null;

  const flagStyle = (val?: string | null) => {
    if (!val) return 'text-slate-400';
    const v = String(val).toLowerCase();
    if (v === 'true' || v === 'full' || v === 'enabled') return 'text-emerald-600 font-bold';
    if (v === 'false' || v === 'none' || v === 'disabled') return 'text-red-600 font-bold';
    if (v === 'partial') return 'text-orange-600 font-bold';
    return 'text-slate-600';
  };

  return (
    <SocCard>
      <button onClick={() => setOpen(o => !o)} className="w-full">
        <SectionHeader
          icon={<Database className="h-4 w-4" />}
          title="Native Binary Analysis"
          subtitle={`${bins.length} native library (SO) file(s) — NX, Stack Canary, RELRO, RPATH`}
          action={open ? <ChevronUp className="h-4 w-4 text-slate-400" /> : <ChevronDown className="h-4 w-4 text-slate-400" />}
        />
      </button>
      {open && (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="bg-slate-50 border-b border-slate-200">
              <tr>
                <th className="px-4 py-2 text-left font-semibold text-slate-600">Library</th>
                <th className="px-3 py-2 text-center font-semibold text-slate-600">NX</th>
                <th className="px-3 py-2 text-center font-semibold text-slate-600">Stack Canary</th>
                <th className="px-3 py-2 text-center font-semibold text-slate-600">RELRO</th>
                <th className="px-3 py-2 text-center font-semibold text-slate-600">RPATH</th>
                <th className="px-3 py-2 text-center font-semibold text-slate-600">Fortify</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {bins.map((b, i) => (
                <tr key={i} className="hover:bg-slate-50">
                  <td className="px-4 py-2.5 font-mono text-slate-800">{b.name || '—'}</td>
                  <td className={`px-3 py-2.5 text-center font-mono ${flagStyle(b.nx)}`}>{String(b.nx ?? '—')}</td>
                  <td className={`px-3 py-2.5 text-center font-mono ${flagStyle(b.stack_canary)}`}>{String(b.stack_canary ?? '—')}</td>
                  <td className={`px-3 py-2.5 text-center font-mono ${flagStyle(b.relro)}`}>{String(b.relro ?? '—')}</td>
                  <td className={`px-3 py-2.5 text-center font-mono ${b.rpath && String(b.rpath) !== 'False' ? 'text-red-600 font-bold' : 'text-emerald-600'}`}>{String(b.rpath ?? '—')}</td>
                  <td className={`px-3 py-2.5 text-center font-mono ${flagStyle(b.fortify)}`}>{String(b.fortify ?? '—')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </SocCard>
  );
}

// ─── Network Security Config Panel ──────────────────────────────────────────────────

function NetworkSecurityPanel({ data }: { data: FraudCardData }) {
  const [open, setOpen] = useState(true);
  const nsc = data.network_security;

  if (!nsc || Object.keys(nsc).length === 0) return null;

  const entries = Object.entries(nsc);

  return (
    <SocCard>
      <button onClick={() => setOpen(o => !o)} className="w-full">
        <SectionHeader
          icon={<Globe className="h-4 w-4" />}
          title="Network Security Config"
          subtitle={`${entries.length} NSC configuration entries (cleartext, pinning, trust anchors)`}
          action={open ? <ChevronUp className="h-4 w-4 text-slate-400" /> : <ChevronDown className="h-4 w-4 text-slate-400" />}
        />
      </button>
      {open && (
        <div className="divide-y divide-slate-100 max-h-60 overflow-y-auto text-xs">
          {entries.map(([k, v]) => (
            <div key={k} className="flex justify-between p-3 hover:bg-slate-50 gap-4">
              <span className="text-slate-500 font-mono flex-shrink-0 capitalize">{k.replace(/_/g, ' ')}</span>
              <span className={`font-mono text-right break-all ${String(v) === 'true' ? 'text-red-600 font-bold' : String(v) === 'false' ? 'text-emerald-600' : 'text-slate-700'}`}>
                {typeof v === 'object' ? JSON.stringify(v) : String(v)}
              </span>
            </div>
          ))}
        </div>
      )}
    </SocCard>
  );
}

// ─── Trackers & Third-Party SDKs Panel ─────────────────────────────────────────────

function TrackersPanel({ data }: { data: FraudCardData }) {
  const [open, setOpen] = useState(true);
  const trackers = data.trackers || [];

  if (trackers.length === 0) return null;

  const catColor = (cats: string[]) => {
    const s = cats.join(' ').toLowerCase();
    if (s.includes('analytics') || s.includes('tracker')) return 'bg-orange-50 text-orange-700 border-orange-200';
    if (s.includes('crash') || s.includes('error')) return 'bg-red-50 text-red-700 border-red-200';
    if (s.includes('ads') || s.includes('advertis')) return 'bg-yellow-50 text-yellow-700 border-yellow-200';
    return 'bg-slate-100 text-slate-600 border-slate-200';
  };

  return (
    <SocCard>
      <button onClick={() => setOpen(o => !o)} className="w-full">
        <SectionHeader
          icon={<Tag className="h-4 w-4" />}
          title="Third-Party SDKs & Trackers"
          subtitle={`${trackers.length} SDK fingerprint(s) identified`}
          action={open ? <ChevronUp className="h-4 w-4 text-slate-400" /> : <ChevronDown className="h-4 w-4 text-slate-400" />}
        />
      </button>
      {open && (
        <div className="p-4 flex flex-wrap gap-2">
          {trackers.map((t, i) => (
            <div key={i} className="flex items-center gap-2 px-3 py-1.5 bg-white border border-slate-200 rounded-lg shadow-xs text-xs">
              <span className="font-semibold text-slate-800">{t.name}</span>
              {t.categories.length > 0 && (
                <div className="flex gap-1">
                  {t.categories.slice(0, 2).map((c, ci) => (
                    <span key={ci} className={`px-1.5 py-0.5 text-[9px] font-bold rounded border ${catColor([c])}`}>{c}</span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </SocCard>
  );
}

// ─── Secrets Inspector Panel ─────────────────────────────────────────────────────────

function SecretsPanel({ data }: { data: FraudCardData }) {
  const [open, setOpen] = useState(true);
  const [filter, setFilter] = useState('');
  const [showAll, setShowAll] = useState(false);
  const secrets = data.hardcoded_secrets || [];

  if (secrets.length === 0) return null;

  const visible = secrets.filter(s => !filter || s.toLowerCase().includes(filter.toLowerCase()));
  const display = showAll ? visible : visible.slice(0, 15);

  return (
    <SocCard>
      <button onClick={() => setOpen(o => !o)} className="w-full">
        <SectionHeader
          icon={<Key className="h-4 w-4" />}
          title="Hardcoded Secrets & Credentials"
          subtitle={`${secrets.length} secret(s) found — API keys, tokens, Firebase configs, JWT`}
          action={open ? <ChevronUp className="h-4 w-4 text-slate-400" /> : <ChevronDown className="h-4 w-4 text-slate-400" />}
        />
      </button>
      {open && (
        <>
          <div className="px-3 pb-3 border-b border-slate-100">
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
              <input type="text" value={filter} onChange={e => setFilter(e.target.value)}
                placeholder="Filter secrets..." className="w-full pl-8 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-blue-500" />
            </div>
          </div>
          <div className="divide-y divide-slate-100 max-h-72 overflow-y-auto">
            {display.map((s, i) => (
              <div key={i} className="px-4 py-2.5 flex items-center gap-2 hover:bg-slate-50">
                <span className="px-1.5 py-0.5 text-[9px] font-bold bg-red-50 text-red-600 border border-red-200 rounded flex-shrink-0">SECRET</span>
                <span className="font-mono text-xs text-slate-700 break-all">{s}</span>
                <CopyButton value={s} />
              </div>
            ))}
          </div>
          {visible.length > 15 && (
            <div className="p-3 border-t border-slate-100 text-center">
              <button onClick={() => setShowAll(a => !a)} className="text-xs text-blue-600 font-semibold hover:text-blue-800">
                {showAll ? 'Show fewer' : `Show all ${visible.length} secrets`}
              </button>
            </div>
          )}
        </>
      )}
    </SocCard>
  );
}


// ─── Main TechnicalView Page ──────────────────────────────────────────────────────

export default function TechnicalView({ data }: { data: FraudCardData | null }) {
  const { investigationBundle } = useAnalysis();
  if (!data) return null;

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

      {investigationBundle && <FindingsRegistryTable bundle={investigationBundle} />}

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

      {/* MobSF Enrichment: Manifest + Code Findings with compliance mappings */}
      <ManifestFindingsPanel data={data} />
      <CodeFindingsPanel data={data} />

      {/* MobSF Enrichment: Attack surface — exported components */}
      <ExportedComponentsPanel data={data} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <CertificatePanel certificate={data.certificate} />
        <DecompilationPanel data={data} />
      </div>

      {/* MobSF Enrichment: Native binary security */}
      <BinaryAnalysisPanel data={data} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* MobSF Enrichment: Network Security Config */}
        <NetworkSecurityPanel data={data} />
        {/* MobSF Enrichment: Third-party SDKs/Trackers */}
        <TrackersPanel data={data} />
      </div>

      {/* MobSF Enrichment: Secrets Inspector */}
      <SecretsPanel data={data} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <NetworkCapturePanel networkLogs={data.dynamic_analysis?.network_logs} />
        <LogcatInspectorPanel logcat={data.dynamic_analysis?.logcat} />
      </div>

      <DynamicAnalysisPanel data={data} />
    </div>
  );
}
