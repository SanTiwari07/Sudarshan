import { useState, type ReactNode } from 'react';
import {
  Terminal, Cpu, Search, Lock, Code, Package,
  ChevronDown, ChevronUp, Shield, Globe, AlertTriangle, Database, Tag, Key
} from 'lucide-react';
import type { FraudCardData } from '../App';
import VisualImpersonationPanel from '../components/investigation/VisualImpersonationPanel';
import VisualDiffViewer from '../components/investigation/VisualDiffViewer';
import OverlayEvidenceViewer from '../components/investigation/OverlayEvidenceViewer';
import SocCard from '../components/ui/Card';
import SectionHeader from '../components/ui/SectionHeader';
import CopyButton from '../components/ui/CopyButton';
import WorkflowDiagram from '../components/WorkflowDiagram';
import EvidenceRegistrySection from '../components/investigation/EvidenceRegistrySection';
import ScreenshotGallery from '../components/investigation/ScreenshotGallery';
import DynamicAnalysisSummary from '../components/investigation/DynamicAnalysisSummary';
import HelpTerm from '../components/investigation/HelpTerm';
import {
  resolveRuntimeDynamicStatus,
  runtimeStatusHeadline,
} from '../lib/investigationRuntime';
import { useAnalysis } from '../context/AnalysisContext';

function EvidenceSection({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children: ReactNode;
}) {
  return (
    <section className="evidence-section">
      <header className="evidence-section__header">
        <h2 className="evidence-section__title">{title}</h2>
        {description && <p className="evidence-section__desc">{description}</p>}
      </header>
      <div className="space-y-4">{children}</div>
    </section>
  );
}

// ─── Explainability Engine ────────────────────────────────────────────────────────

function ExplainabilityEngine({ data }: { data: FraudCardData }) {
  const isMalicious = data.family_classification !== 'Unknown';
  return (
    <SocCard className="h-full flex flex-col">
      <SectionHeader
        icon={<Cpu className="h-4 w-4" />}
        title="Explainability Engine"
        subtitle="Classification output from the rules engine"
      />
      <div className="p-3 space-y-3 flex-1 flex flex-col justify-between">
        <div className="border border-slate-200 bg-slate-50/50 p-2.5 rounded-md">
          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1">Classification result</p>
          <div className="flex items-center gap-2">
            <span className={`inline-block h-2 w-2 rounded-full ${isMalicious ? 'bg-red-500 animate-pulse' : 'bg-slate-400'}`} />
            <p className={`text-base font-bold tracking-tight ${isMalicious ? 'text-red-700' : 'text-slate-800'}`}>
              {data.family_classification}
            </p>
          </div>
        </div>
        <div className="border border-slate-200 bg-slate-50/50 p-2.5 rounded-md min-w-0 flex-1 flex flex-col justify-between">
          <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wider mb-1.5">Matched rule</p>
          <p className="font-mono text-xs text-slate-800 bg-white border border-slate-200 p-2.5 rounded-md leading-normal break-all overflow-y-auto max-h-32 scrollbar-hidden">
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
    { label: 'Banking Targeting', value: data.targets_indian_banks ? 'YES - Target Package Found' : 'No', mono: false, highlight: data.targets_indian_banks },
    { label: 'Final Score', value: `${data.final_risk_score.toFixed(2)} / 100`, mono: true, highlight: data.final_risk_score > 30 },
  ];

  return (
    <SocCard>
      <SectionHeader
        icon={<Package className="h-4 w-4" />}
        title="APK Technical Identifiers"
        subtitle="Package identity, hash, and scoring inputs"
      />
      <div className="px-3 py-1 bg-white">
        {rows.map(r => (
          <div
            key={r.label}
            className="grid grid-cols-1 sm:grid-cols-[minmax(9rem,28%)_1fr] gap-x-4 gap-y-0.5 py-1.5 border-b border-slate-150 last:border-0 hover:bg-slate-50/50 rounded px-1.5 -mx-1.5 transition-colors duration-100 items-center"
          >
            <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">{r.label}</span>
            <div className="flex items-center gap-1.5 min-w-0">
              <span
                className={`text-xs min-w-0 ${r.mono ? 'font-mono' : ''} ${r.highlight ? 'text-red-700 font-semibold' : 'text-slate-800'} ${r.truncate ? 'truncate' : 'break-all'}`}
                title={r.truncate ? String(r.value) : undefined}
              >
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
  const perms = data.all_permissions.filter(
    (p) => typeof p === 'string' && p.toLowerCase().includes(filter.toLowerCase()),
  );
  const fired = new Set(data.technical_view.permissions_fired);

  return (
    <SocCard>
      <SectionHeader icon={<Lock className="h-4 w-4" />} title="Permission Analysis" subtitle={`${data.all_permissions.length} total permissions extracted`} />
      <div className="p-2 border-b border-slate-200 bg-slate-50/30">
        <div className="relative">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-400" />
          <input
            type="text"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter permissions..."
            className="w-full pl-7 pr-3 py-1 text-xs bg-white border border-slate-200 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>
      </div>
      <div className="soc-table-wrap !border-0 rounded-none max-h-72">
        <table className="soc-table text-xs">
          <thead>
            <tr>
              <th className="!bg-slate-50/80">Permission</th>
              <th className="text-right !bg-slate-50/80">Status</th>
            </tr>
          </thead>
          <tbody className="font-mono">
            {perms.map(p => {
              const isFired = fired.has(p);
              return (
                <tr key={p} className={isFired ? '!bg-red-50/40' : ''}>
                  <td className="break-all">{p}</td>
                  <td className="text-right">
                    {isFired ? (
                      <span className="inline-flex px-1.5 py-0.5 text-[9px] font-bold bg-red-100 text-red-800 rounded border border-red-200/50 whitespace-nowrap">
                        CRITICAL
                      </span>
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
        <div className="p-6 text-center text-xs text-slate-400 font-mono">
          No dangerous Java/Android API invocations detected in DEX bytecode.
        </div>
      ) : (
        <div className="soc-table-wrap !border-0 rounded-none max-h-72">
          <table className="soc-table text-xs">
            <thead>
              <tr>
                <th className="!bg-slate-50/80">API Signature</th>
                <th className="text-right !bg-slate-50/80">Category</th>
              </tr>
            </thead>
            <tbody className="font-mono">
              {apis.map((api, i) => (
                <tr key={i} className="!bg-red-50/20">
                  <td className="break-all text-red-700 font-semibold">{api}</td>
                  <td className="text-right">
                    <span className="inline-flex px-1.5 py-0.5 text-[9px] font-bold bg-red-100 text-red-800 rounded border border-red-200/50 whitespace-nowrap">
                      DANGEROUS HOOK
                    </span>
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

// ─── Digital Certificate & Signature Panel ─────────────────────────────────────────

function CertificatePanel({ certificate }: { certificate?: Record<string, any> }) {
  if (!certificate || Object.keys(certificate).length === 0) {
    return (
      <SocCard>
        <SectionHeader icon={<Lock className="h-4 w-4" />} title="Digital Certificate & Signature" subtitle="X.509 Cryptographic Identity" />
        <div className="p-6 text-center text-xs text-slate-400 font-mono">No certificate metadata available</div>
      </SocCard>
    );
  }

  const entries = Object.entries(certificate);

  return (
    <SocCard>
      <SectionHeader icon={<Lock className="h-4 w-4" />} title="Digital Certificate & Signature" subtitle="X.509 Cryptographic Identity & Attribution" />
      <div className="soc-table-wrap !border-0 rounded-none max-h-72">
        <table className="soc-table text-xs">
          <thead>
            <tr>
              <th className="!bg-slate-50/80 w-1/3">Property</th>
              <th className="!bg-slate-50/80 w-2/3">Value</th>
            </tr>
          </thead>
          <tbody className="font-mono">
            {entries.map(([k, v]) => (
              <tr key={k}>
                <td className="text-slate-500 capitalize">{k.replace(/_/g, ' ')}</td>
                <td className="break-all text-slate-800">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</td>
              </tr>
            ))}
          </tbody>
        </table>
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
        <div className="p-4 text-center text-xs text-slate-400 font-mono">Decompilation enrichment data unavailable for this scan</div>
      </SocCard>
    );
  }

  return (
    <SocCard>
      <SectionHeader icon={<Code className="h-4 w-4" />} title="Static Decompilation Intelligence" subtitle="APKTool Resources & JADX Java Source Hits" />
      <div className="p-3 space-y-2.5 font-mono text-xs">
        {jadx?.fraud_class_hits?.length > 0 && (
          <div className="p-2.5 bg-red-50/50 border border-red-200 rounded-md">
            <span className="font-bold text-red-800 uppercase tracking-wider text-[10px]">JADX Fraud Classes Found:</span>
            <div className="mt-1 text-red-900 text-xs break-all leading-relaxed">{jadx.fraud_class_hits.join(', ')}</div>
          </div>
        )}
        {apktool?.decoded_manifest_xml && (
          <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-md text-slate-700">
            <span className="font-bold text-slate-800 uppercase tracking-wider text-[10px]">Decoded Manifest Excerpt:</span>
            <pre className="mt-1 text-[11px] text-slate-600 overflow-x-auto whitespace-pre-wrap font-mono leading-normal bg-white p-2 border border-slate-150 rounded">
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
        <div className="p-6 text-center text-xs text-slate-400 font-mono">No dynamic network traffic captured</div>
      </SocCard>
    );
  }

  return (
    <SocCard>
      <SectionHeader icon={<Terminal className="h-4 w-4" />} title="Network Capture & C2 Telemetry" subtitle={`${networkLogs.length} network request(s) captured`} />
      <div className="soc-table-wrap !border-0 rounded-none max-h-72">
        <table className="soc-table text-xs">
          <thead>
            <tr>
              <th className="!bg-slate-50/80">Method</th>
              <th className="!bg-slate-50/80">Host / IP</th>
              <th className="!bg-slate-50/80">URL / Endpoint</th>
              <th className="text-right !bg-slate-50/80">Status</th>
            </tr>
          </thead>
          <tbody className="font-mono">
            {networkLogs.map((req, i) => (
              <tr key={i} className={req.is_suspicious ? '!bg-red-50/40' : ''}>
                <td className="font-bold text-slate-900">{req.method || 'GET'}</td>
                <td className="break-all text-slate-700">{req.domain || req.ip || '-'}</td>
                <td className="max-w-[14rem] truncate text-slate-600" title={req.url || undefined}>{req.url || '-'}</td>
                <td className="text-right font-semibold tabular-nums text-slate-900">{req.response_status || 200}</td>
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
        <div className="p-6 text-center text-xs text-slate-400 font-mono">No logcat telemetry collected</div>
      </SocCard>
    );
  }

  return (
    <SocCard>
      <SectionHeader icon={<Terminal className="h-4 w-4" />} title="Logcat System Diagnostics" subtitle="Monospace Android System Log Inspector" />
      <div className="p-3 bg-slate-950 font-mono text-[11px] text-emerald-400 max-h-60 overflow-y-auto scrollbar-hidden rounded-b-md whitespace-pre-wrap leading-normal border-t border-slate-800">
        {logcat}
      </div>
    </SocCard>
  );
}

// ─── Dynamic Sandbox Panel ────────────────────────────────────────────────────────

function DynamicAnalysisPanel({ data }: { data: FraudCardData }) {
  const dyn =
    data.dynamic_result && typeof data.dynamic_result === 'object' && !Array.isArray(data.dynamic_result)
      ? data.dynamic_result
      : {};
  const runtimeStatus = resolveRuntimeDynamicStatus(data);
  const headline = runtimeStatusHeadline(runtimeStatus);
  const isOk = runtimeStatus === 'COMPLETED';

  return (
    <SocCard>
      <SectionHeader
        icon={<Terminal className="h-4 w-4" />}
        title="Dynamic Sandbox Execution"
        subtitle="Frida runtime instrumentation and telemetry"
      />

      <div className="p-3 border-b border-slate-200 bg-slate-50/40">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-2.5">
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Runtime status:</span>
            <span
              className={`px-1.5 py-0.5 text-[10px] font-bold rounded border font-mono uppercase ${
                isOk
                  ? 'bg-emerald-50 text-emerald-800 border-emerald-200/50'
                  : 'bg-amber-50 text-amber-800 border-amber-200/50'
              }`}
            >
              {headline}
            </span>
          </div>
          <div className="flex items-center gap-2 text-[11px] font-mono text-slate-600">
            <span>
              Engine: <strong className="text-slate-800">{dyn.engine || 'frida'}</strong>
            </span>
            <span>•</span>
            <span>
              Canary: <strong className="text-slate-800">{dyn.canary_received ? '✓ LOADED' : '✗ UNRECEIVED'}</strong>
            </span>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs">
          {data.frs_breakdown?.dynamic_ran && (
            <div className="p-2 bg-white rounded border border-slate-200">
              <span className="text-slate-400 block text-[9px] uppercase font-bold tracking-wider">
                <HelpTerm term="BFCI">Observed BFCI</HelpTerm>
              </span>
              <span className="font-mono font-bold text-slate-800 text-sm">
                {(dyn.bfci ?? data.frs_breakdown?.dynamic ?? 0).toFixed(1)} / 100
              </span>
            </div>
          )}
          <div className="p-2 bg-white rounded border border-slate-200">
            <span className="text-slate-400 block text-[9px] uppercase font-bold tracking-wider">Raw events</span>
            <span className="font-mono font-bold text-slate-800 text-sm">
              {dyn.evidence_record_count || (dyn.api_calls || []).length}
            </span>
          </div>
          <div className="p-2 bg-white rounded border border-slate-200">
            <span className="text-slate-400 block text-[9px] uppercase font-bold tracking-wider">Hook errors</span>
            <span className="font-mono font-bold text-slate-800 text-sm">{(dyn.hook_errors || []).length}</span>
          </div>
        </div>
      </div>

      <div className="p-3 bg-white">
        <h3 className="text-[11px] font-bold text-slate-500 uppercase tracking-wider mb-2.5">Reconstructed behavioral chain</h3>
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
  const findings = (data.manifest_findings || []).filter(
    (f) => f && typeof f === 'object' && typeof f.title === 'string',
  );

  if (findings.length === 0) return null;

  const sevCounts = findings.reduce((acc, f) => {
    const s = f.severity?.toLowerCase() || 'info';
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const visible = findings.filter(f => {
    const matchSev = sev === 'all' || (f.severity?.toLowerCase() === sev);
    const matchText =
      !filter ||
      f.title.toLowerCase().includes(filter.toLowerCase()) ||
      String(f.component || '').toLowerCase().includes(filter.toLowerCase());
    return matchSev && matchText;
  });

  const sevColor = (s?: string) => ({
    high: 'bg-red-50 text-red-800 border-red-200/50',
    warning: 'bg-orange-50 text-orange-800 border-orange-200/50',
    info: 'bg-blue-50 text-blue-800 border-blue-200/50',
  }[(s || 'info').toLowerCase()] || 'bg-slate-50 text-slate-600 border-slate-200/50');

  return (
    <SocCard>
      <button onClick={() => setOpen(o => !o)} className="w-full text-left">
        <SectionHeader
          icon={<AlertTriangle className="h-4 w-4" />}
          title="Manifest Security Findings"
          subtitle={`${findings.length} finding(s) from AndroidManifest.xml analysis`}
          action={open ? <ChevronUp className="h-4 w-4 text-slate-400" /> : <ChevronDown className="h-4 w-4 text-slate-400" />}
        />
      </button>
      {open && (
        <>
          <div className="flex flex-wrap items-center justify-between gap-2 p-2 border-b border-slate-200 bg-slate-50/40">
            <div className="relative flex-1 min-w-[140px]">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-400" />
              <input type="text" value={filter} onChange={e => setFilter(e.target.value)}
                placeholder="Filter findings..." className="w-full pl-7 pr-3 py-1 text-xs bg-white border border-slate-200 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500" />
            </div>
            <div className="flex items-center gap-1">
              {['all', 'high', 'warning', 'info'].map(s => (
                <button key={s} onClick={() => setSev(s)}
                  className={`px-2 py-0.5 text-[9px] font-bold uppercase rounded border transition-all ${sev === s ? 'bg-slate-700 text-white border-slate-700' : 'bg-white text-slate-500 border-slate-200 hover:bg-slate-50'}`}>
                  {s}{s !== 'all' && sevCounts[s] ? ` (${sevCounts[s]})` : ''}
                </button>
              ))}
            </div>
          </div>
          <div className="divide-y divide-slate-150 max-h-72 overflow-y-auto scrollbar-hidden">
            {visible.map((f, i) => (
              <div key={i} className="p-3 hover:bg-slate-50/50 transition-colors">
                <div className="flex items-start gap-2.5">
                  <span className={`mt-0.5 px-1.5 py-0.5 text-[9px] font-bold rounded border flex-shrink-0 ${sevColor(f.severity)}`}>{f.severity?.toUpperCase()}</span>
                  <div className="min-w-0">
                    <p className="text-xs font-bold text-slate-800 leading-tight">{f.title}</p>
                    {f.component && <p className="text-[10px] font-mono text-slate-500 truncate mt-0.5">{f.component}</p>}
                    {f.description && <p className="text-[10px] text-slate-500 mt-1 leading-normal">{f.description}</p>}
                  </div>
                </div>
              </div>
            ))}
            {visible.length === 0 && <div className="p-6 text-center text-xs text-slate-400 font-mono">No findings match the current filter.</div>}
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
  const findings = (data.code_findings || []).filter(
    (f) => f && typeof f === 'object' && typeof f.title === 'string',
  );

  if (findings.length === 0) return null;

  const activeCat = CODE_CATEGORIES.find(c => c.id === cat);
  const visible = findings.filter(f => {
    const text = `${f.title} ${f.description} ${(f as any).rule_id || ''}`.toLowerCase();
    const matchCat = cat === 'all' || (activeCat?.keywords || []).some(k => text.includes(k));
    const matchSev = sev === 'all' || (f.severity?.toLowerCase() === sev);
    const matchFilter = !filter || text.includes(filter.toLowerCase());
    return matchCat && matchSev && matchFilter;
  });

  const sevColor = (s?: string) => ({
    high: 'text-red-800 bg-red-50 border-red-200/50',
    warning: 'text-orange-800 bg-orange-50 border-orange-200/50',
    info: 'text-blue-800 bg-blue-50 border-blue-200/50',
  }[(s || 'info').toLowerCase()] || 'text-slate-600 bg-slate-50 border-slate-200/50');

  return (
    <SocCard>
      <button onClick={() => setOpen(o => !o)} className="w-full text-left">
        <SectionHeader
          icon={<Code className="h-4 w-4" />}
          title="Static Code Security Findings"
          subtitle={`${findings.length} finding(s) from source analysis - with MASVS/CWE/OWASP`}
          action={open ? <ChevronUp className="h-4 w-4 text-slate-400" /> : <ChevronDown className="h-4 w-4 text-slate-400" />}
        />
      </button>
      {open && (
        <>
          <div className="flex flex-wrap items-center gap-2 p-2.5 border-b border-slate-200 bg-slate-50/40">
            <div className="relative min-w-[130px]">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-400" />
              <input type="text" value={filter} onChange={e => setFilter(e.target.value)}
                placeholder="Search..." className="pl-7 pr-3 py-1 text-xs bg-white border border-slate-200 rounded-md w-36 focus:outline-none focus:ring-1 focus:ring-blue-500" />
            </div>
            <div className="flex gap-1">
              {CODE_CATEGORIES.map(c => (
                <button key={c.id} onClick={() => setCat(c.id)}
                  className={`px-2 py-0.5 text-[9px] font-bold rounded border transition-all ${cat === c.id ? 'bg-blue-600 text-white border-blue-600' : 'bg-white text-slate-500 border-slate-200 hover:bg-slate-50'}`}>
                  {c.label}
                </button>
              ))}
            </div>
            <div className="flex gap-1 ml-auto">
              {['all', 'high', 'warning', 'info'].map(s => (
                <button key={s} onClick={() => setSev(s)}
                  className={`px-1.5 py-0.5 text-[9px] font-bold rounded border transition-all ${sev === s ? 'bg-slate-700 text-white border-slate-700' : 'bg-white text-slate-400 border-slate-200 hover:bg-slate-50'}`}>
                  {s}
                </button>
              ))}
            </div>
          </div>
          <div className="divide-y divide-slate-150 max-h-96 overflow-y-auto scrollbar-hidden">
            {visible.map((f, i) => (
              <div key={i} className="p-3 hover:bg-slate-50/50 transition-colors">
                <div className="flex items-start justify-between gap-2.5 mb-1.5">
                  <p className="text-xs font-bold text-slate-800 leading-tight">{f.title}</p>
                  <span className={`px-1.5 py-0.5 text-[9px] font-bold rounded border flex-shrink-0 ${sevColor(f.severity)}`}>{f.severity?.toUpperCase()}</span>
                </div>
                {f.description && <p className="text-[10px] text-slate-500 mb-2 leading-relaxed">{f.description}</p>}
                <div className="flex flex-wrap gap-1.5">
                  {(f as any).rule_id && <code className="text-[9px] bg-slate-100 text-slate-600 border border-slate-200 px-1.5 py-0.5 rounded font-mono">{(f as any).rule_id}</code>}
                  {(f as any).masvs && <span className="text-[9px] bg-purple-50 text-purple-700 border border-purple-200/50 px-1.5 py-0.5 rounded font-mono">MASVS: {(f as any).masvs}</span>}
                  {(f as any).cwe && <span className="text-[9px] bg-orange-50 text-orange-700 border border-orange-200/50 px-1.5 py-0.5 rounded font-mono">{(f as any).cwe}</span>}
                  {(f as any).owasp && <span className="text-[9px] bg-green-50 text-green-700 border border-green-200/50 px-1.5 py-0.5 rounded font-mono">{(f as any).owasp}</span>}
                </div>
                {f.files?.length > 0 && (
                  <div className="mt-2 space-y-0.5 border-t border-slate-100 pt-1.5">
                    {f.files.slice(0, 3).map((file, fi) => (
                      <p key={fi} className="text-[9px] font-mono text-slate-400 truncate">{file}</p>
                    ))}
                  </div>
                )}
              </div>
            ))}
            {visible.length === 0 && <div className="p-6 text-center text-xs text-slate-400 font-mono">No findings match the current filter.</div>}
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
    ...acts.map(n => ({ name: n, type: 'Activity', color: 'bg-red-50 text-red-700 border-red-200/50' })),
    ...svcs.map(n => ({ name: n, type: 'Service', color: 'bg-orange-50 text-orange-700 border-orange-200/50' })),
    ...rcvs.map(n => ({ name: n, type: 'Receiver', color: 'bg-yellow-50 text-yellow-700 border-yellow-200/50' })),
    ...prvs.map(n => ({ name: n, type: 'Provider', color: 'bg-purple-50 text-purple-700 border-purple-200/50' })),
  ];

  const visible = filter ? rows.filter(r => r.name.toLowerCase().includes(filter.toLowerCase())) : rows;

  return (
    <SocCard>
      <button onClick={() => setOpen(o => !o)} className="w-full text-left">
        <SectionHeader
          icon={<Shield className="h-4 w-4" />}
          title="Exported Components - Attack Surface"
          subtitle={`${total} exported component(s) accessible by external apps / intents`}
          action={open ? <ChevronUp className="h-4 w-4 text-slate-400" /> : <ChevronDown className="h-4 w-4 text-slate-400" />}
        />
      </button>
      {open && (
        <>
          <div className="p-2 border-b border-slate-200 bg-slate-50/40">
            <div className="relative">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-400" />
              <input type="text" value={filter} onChange={e => setFilter(e.target.value)}
                placeholder="Filter by component name..." className="w-full pl-7 pr-3 py-1 text-xs bg-white border border-slate-200 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500" />
            </div>
          </div>
          <div className="soc-table-wrap !border-0 rounded-none max-h-72">
            <table className="soc-table text-xs">
              <thead>
                <tr>
                  <th className="!bg-slate-50/80 w-24">Type</th>
                  <th className="!bg-slate-50/80">Component Name</th>
                  <th className="text-right !bg-slate-50/80 w-16">Actions</th>
                </tr>
              </thead>
              <tbody className="font-mono">
                {visible.map((row, i) => (
                  <tr key={i}>
                    <td>
                      <span className={`px-1.5 py-0.5 text-[9px] font-bold rounded border ${row.color}`}>{row.type}</span>
                    </td>
                    <td className="break-all text-slate-800 text-xs">{row.name}</td>
                    <td className="text-right">
                      <CopyButton value={row.name} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {visible.length === 0 && <div className="p-6 text-center text-xs text-slate-400 font-mono">No components match filter.</div>}
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
    if (v === 'true' || v === 'full' || v === 'enabled') return 'text-emerald-700 font-bold';
    if (v === 'false' || v === 'none' || v === 'disabled') return 'text-red-700 font-bold';
    if (v === 'partial') return 'text-orange-700 font-bold';
    return 'text-slate-600';
  };

  return (
    <SocCard>
      <button onClick={() => setOpen(o => !o)} className="w-full text-left">
        <SectionHeader
          icon={<Database className="h-4 w-4" />}
          title="Native Binary Analysis"
          subtitle={`${bins.length} native library (SO) file(s) - NX, Stack Canary, RELRO, RPATH`}
          action={open ? <ChevronUp className="h-4 w-4 text-slate-400" /> : <ChevronDown className="h-4 w-4 text-slate-400" />}
        />
      </button>
      {open && (
        <div className="soc-table-wrap !border-0 rounded-none max-h-72">
          <table className="soc-table text-xs">
            <thead>
              <tr>
                <th className="!bg-slate-50/80">Library</th>
                <th className="text-center !bg-slate-50/80 w-16">NX</th>
                <th className="text-center !bg-slate-50/80 w-24">Stack Canary</th>
                <th className="text-center !bg-slate-50/80 w-20">RELRO</th>
                <th className="text-center !bg-slate-50/80 w-16">RPATH</th>
                <th className="text-center !bg-slate-50/80 w-16">Fortify</th>
              </tr>
            </thead>
            <tbody>
              {bins.map((b, i) => (
                <tr key={i}>
                  <td className="font-mono break-all text-slate-800">{b.name || '-'}</td>
                  <td className={`text-center font-mono ${flagStyle(b.nx)}`}>{String(b.nx ?? '-')}</td>
                  <td className={`text-center font-mono ${flagStyle(b.stack_canary)}`}>{String(b.stack_canary ?? '-')}</td>
                  <td className={`text-center font-mono ${flagStyle(b.relro)}`}>{String(b.relro ?? '-')}</td>
                  <td className={`text-center font-mono ${b.rpath && String(b.rpath) !== 'False' ? 'text-red-700 font-bold' : 'text-emerald-700'}`}>{String(b.rpath ?? '-')}</td>
                  <td className={`text-center font-mono ${flagStyle(b.fortify)}`}>{String(b.fortify ?? '-')}</td>
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
      <button onClick={() => setOpen(o => !o)} className="w-full text-left">
        <SectionHeader
          icon={<Globe className="h-4 w-4" />}
          title="Network Security Config"
          subtitle={`${entries.length} NSC configuration entries (cleartext, pinning, trust anchors)`}
          action={open ? <ChevronUp className="h-4 w-4 text-slate-400" /> : <ChevronDown className="h-4 w-4 text-slate-400" />}
        />
      </button>
      {open && (
        <div className="soc-table-wrap !border-0 rounded-none max-h-60">
          <table className="soc-table text-xs">
            <thead>
              <tr>
                <th className="!bg-slate-50/80 w-1/2">Property</th>
                <th className="!bg-slate-50/80 w-1/2 text-right">Setting</th>
              </tr>
            </thead>
            <tbody className="font-mono">
              {entries.map(([k, v]) => (
                <tr key={k}>
                  <td className="text-slate-500 capitalize">{k.replace(/_/g, ' ')}</td>
                  <td className={`text-right break-all ${String(v) === 'true' ? 'text-red-700 font-bold' : String(v) === 'false' ? 'text-emerald-700' : 'text-slate-800'}`}>
                    {typeof v === 'object' ? JSON.stringify(v) : String(v)}
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

// ─── Trackers & Third-Party SDKs Panel ─────────────────────────────────────────────

function TrackersPanel({ data }: { data: FraudCardData }) {
  const [open, setOpen] = useState(true);
  const trackers = data.trackers || [];

  if (trackers.length === 0) return null;

  const catColor = (cats: string[]) => {
    const s = cats.join(' ').toLowerCase();
    if (s.includes('analytics') || s.includes('tracker')) return 'bg-orange-50 text-orange-800 border-orange-200/50';
    if (s.includes('crash') || s.includes('error')) return 'bg-red-50 text-red-800 border-red-200/50';
    if (s.includes('ads') || s.includes('advertis')) return 'bg-yellow-50 text-yellow-800 border-yellow-200/50';
    return 'bg-slate-50 text-slate-600 border-slate-200/50';
  };

  return (
    <SocCard>
      <button onClick={() => setOpen(o => !o)} className="w-full text-left">
        <SectionHeader
          icon={<Tag className="h-4 w-4" />}
          title="Third-Party SDKs & Trackers"
          subtitle={`${trackers.length} SDK fingerprint(s) identified`}
          action={open ? <ChevronUp className="h-4 w-4 text-slate-400" /> : <ChevronDown className="h-4 w-4 text-slate-400" />}
        />
      </button>
      {open && (
        <div className="p-3 flex flex-wrap gap-2 bg-white">
          {trackers.map((t, i) => (
            <div key={i} className="flex items-center gap-2 px-2.5 py-1 bg-slate-50 border border-slate-200 rounded-md text-xs">
              <span className="font-bold text-slate-800">{t.name}</span>
              {t.categories.length > 0 && (
                <div className="flex gap-1">
                  {t.categories.slice(0, 2).map((c, ci) => (
                    <span key={ci} className={`px-1.5 py-0.2 text-[9px] font-bold rounded border uppercase ${catColor([c])}`}>{c}</span>
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
      <button onClick={() => setOpen(o => !o)} className="w-full text-left">
        <SectionHeader
          icon={<Key className="h-4 w-4" />}
          title="Hardcoded Secrets & Credentials"
          subtitle={`${secrets.length} secret(s) found - API keys, tokens, Firebase configs, JWT`}
          action={open ? <ChevronUp className="h-4 w-4 text-slate-400" /> : <ChevronDown className="h-4 w-4 text-slate-400" />}
        />
      </button>
      {open && (
        <>
          <div className="p-2 border-b border-slate-200 bg-slate-50/40">
            <div className="relative">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-400" />
              <input type="text" value={filter} onChange={e => setFilter(e.target.value)}
                placeholder="Filter secrets..." className="w-full pl-7 pr-3 py-1 text-xs bg-white border border-slate-200 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500" />
            </div>
          </div>
          <div className="soc-table-wrap !border-0 rounded-none max-h-72">
            <table className="soc-table text-xs">
              <thead>
                <tr>
                  <th className="!bg-slate-50/80 w-20">Type</th>
                  <th className="!bg-slate-50/80">Value</th>
                  <th className="text-right !bg-slate-50/80 w-16">Copy</th>
                </tr>
              </thead>
              <tbody className="font-mono">
                {display.map((s, i) => (
                  <tr key={i}>
                    <td>
                      <span className="px-1 py-0.5 text-[9px] font-bold bg-red-100 text-red-800 border border-red-200/50 rounded uppercase whitespace-nowrap">SECRET</span>
                    </td>
                    <td className="break-all text-xs text-slate-700">{s}</td>
                    <td className="text-right">
                      <CopyButton value={s} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {visible.length > 15 && (
            <div className="p-2.5 border-t border-slate-200 text-center bg-slate-50/50">
              <button onClick={() => setShowAll(a => !a)} className="text-xs text-blue-700 font-bold hover:text-blue-800 transition-colors">
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
  const { investigationBundle, loading } = useAnalysis();
  if (!data) return null;

  return (
    <div className="technical-view">
      <EvidenceRegistrySection data={data} bundle={investigationBundle} loading={loading} />

      <EvidenceSection title="Overview" description="Classification summary and APK identifiers.">
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-4 items-stretch">
          <div className="xl:col-span-4 min-w-0">
            <ExplainabilityEngine data={data} />
          </div>
          <div className="xl:col-span-8 min-w-0">
            <APKMetadata data={data} />
          </div>
        </div>
      </EvidenceSection>

      <EvidenceSection title="Static analysis" description="Permissions, bytecode signals, manifest, and attack surface.">
        <VisualImpersonationPanel data={data} />
        {data.vide && <VisualDiffViewer vide={data.vide} />}
        {data.vide && <OverlayEvidenceViewer vide={data.vide} />}
        <div className="analyst-grid-2">
          <PermissionTable data={data} />
          <DangerousAPITable data={data} />
        </div>
        <ManifestFindingsPanel data={data} />
        <CodeFindingsPanel data={data} />
        <ExportedComponentsPanel data={data} />
        <div className="analyst-grid-2">
          <CertificatePanel certificate={data.certificate} />
          <DecompilationPanel data={data} />
        </div>
        <BinaryAnalysisPanel data={data} />
        <div className="analyst-grid-2">
          <NetworkSecurityPanel data={data} />
          <TrackersPanel data={data} />
        </div>
        <SecretsPanel data={data} />
      </EvidenceSection>

      <EvidenceSection title="Runtime analysis" description="Network capture, sandbox telemetry, and visual evidence.">
        <DynamicAnalysisSummary data={data} />
        <ScreenshotGallery data={data} bundle={investigationBundle} />
        <div className="analyst-grid-2">
          <NetworkCapturePanel networkLogs={data.dynamic_analysis?.network_logs} />
          <LogcatInspectorPanel logcat={data.dynamic_analysis?.logcat} />
        </div>
        <DynamicAnalysisPanel data={data} />
      </EvidenceSection>
    </div>
  );
}
