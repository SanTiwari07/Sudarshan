import { useState, useEffect } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import {
  Shield, Download, MessageSquare, BarChart2,
  FileText, Target, Database, Globe, X, StickyNote
} from 'lucide-react';
import type { FraudCardData } from '../App';
import { exportJSON, exportCSV } from '../utils/derive';
import { API_BASE, authHeaders, downloadAuthed } from '../config';
import SocCard from '../components/ui/Card';
import SectionHeader from '../components/ui/SectionHeader';
import Badge from '../components/ui/Badge';
import CopyButton from '../components/ui/CopyButton';
import { getRiskStyle } from '../theme/colors';

// ─── Executive Risk Panel ────────────────────────────────────────────────────────

function ExecutiveRiskPanel({ data }: { data: FraudCardData }) {
  const riskStyle = getRiskStyle(data.risk_band);

  return (
    <SocCard>
      <div className="bg-blue-900 px-5 py-2.5 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-blue-300" />
          <span className="text-xs font-mono text-blue-200 uppercase tracking-widest">Executive Assessment</span>
        </div>
        <span className="text-xs text-blue-400 font-mono">SUDARSHAN PLATFORM</span>
      </div>

      <div className="p-5">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
          {/* Risk Score */}
          <div className="flex items-center gap-4 p-4 bg-slate-50 rounded-lg border border-slate-200">
            <div className={`text-5xl font-black leading-none ${riskStyle.text}`}>
              {data.final_risk_score.toFixed(0)}
            </div>
            <div className="min-w-0">
              <div className="text-xs text-slate-500 uppercase tracking-wide font-semibold">Risk Score</div>
              <div className="text-xs text-slate-400">/ 100</div>
              <div className={`mt-2 inline-flex px-2 py-0.5 rounded font-bold text-xs uppercase tracking-wide ${riskStyle.badge}`}>
                {data.risk_band}
              </div>
            </div>
          </div>

          {/* Key Metrics */}
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: 'Threat Level', value: data.risk_band.toUpperCase(), color: riskStyle.text },
              { label: 'Confidence', value: data.confidence !== undefined && data.confidence !== null ? `${data.confidence.toFixed(0)}%` : 'MISSING BACKEND DATA', color: 'text-blue-700' },
              { label: 'AI Multiplier', value: `×${data.ai_confidence_multiplier.toFixed(2)}`, color: 'text-purple-700' },
              { label: 'Family', value: data.family_classification, color: data.family_classification !== 'Unknown' ? 'text-red-600' : 'text-slate-700' },
            ].map(m => (
              <div key={m.label} className="p-2.5 bg-slate-50 rounded-lg border border-slate-200">
                <div className="text-xs text-slate-500 uppercase tracking-wide">{m.label}</div>
                <div className={`text-sm font-bold mt-0.5 truncate ${m.color}`}>{m.value}</div>
              </div>
            ))}
          </div>

          {/* Core Findings */}
          <div>
            <div className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">Core Findings</div>
            <div className="space-y-1.5 text-xs">
              <div className="flex items-center justify-between">
                <span className="text-slate-600">Accessibility Abuse:</span>
                <span className={data.has_accessibility_abuse ? 'text-red-600 font-bold' : 'text-slate-400'}>
                  {data.has_accessibility_abuse ? 'DETECTED' : 'Clear'}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-600">SMS Interception:</span>
                <span className={data.has_sms_read_write ? 'text-red-600 font-bold' : 'text-slate-400'}>
                  {data.has_sms_read_write ? 'DETECTED' : 'Clear'}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-600">Overlay Window:</span>
                <span className={data.has_system_alert_window ? 'text-orange-600 font-bold' : 'text-slate-400'}>
                  {data.has_system_alert_window ? 'DETECTED' : 'Clear'}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-600">Dynamic Loading:</span>
                <span className={data.obfuscation_score && data.obfuscation_score > 0 ? 'text-purple-600 font-bold' : 'text-slate-400'}>
                  {data.obfuscation_score && data.obfuscation_score > 0 ? 'Active' : 'Clear'}
                </span>
              </div>
            </div>
          </div>

          {/* APK Details */}
          <div>
            <div className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">APK Provenance</div>
            <div className="space-y-1.5 text-xs">
              <div className="flex justify-between items-center">
                <span className="text-slate-500">Package:</span>
                <span className="font-mono text-slate-800 truncate max-w-[120px]" title={data.package_name}>{data.package_name || 'Unknown'}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-slate-500">SHA-256:</span>
                <div className="flex items-center font-mono text-slate-800">
                  <span>{data.sha256.slice(0, 8)}…</span>
                  <CopyButton value={data.sha256} />
                </div>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-slate-500">Mode:</span>
                <Badge label={data.analysis_mode} className="bg-blue-50 text-blue-700 border border-blue-200" />
              </div>
            </div>
          </div>
        </div>
      </div>
    </SocCard>
  );
}

// ─── Attack Narrative ────────────────────────────────────────────────────────────

function AttackNarrativeCard({ data }: { data: FraudCardData }) {
  const [tab, setTab] = useState(0);
  const tabs = ['AI Narrative', 'Banking Impact', 'Recommended Actions', 'Customer Advisory'];
  const intel = data.intelligence_report;

  return (
    <SocCard>
      <SectionHeader
        icon={<MessageSquare className="h-4 w-4" />}
        title="Attack Intelligence Synthesis"
        subtitle="RAG-grounded narrative and assessments"
      />
      <div className="flex border-b border-slate-200 overflow-x-auto">
        {tabs.map((t, i) => (
          <button
            key={t}
            onClick={() => setTab(i)}
            className={`px-4 py-2.5 text-xs font-medium whitespace-nowrap transition-colors border-b-2 ${
              tab === i
                ? 'border-blue-600 text-blue-700 bg-blue-50'
                : 'border-transparent text-slate-500 hover:text-slate-700 hover:bg-slate-50'
            }`}
          >
            {t}
          </button>
        ))}
      </div>
      <div className="p-5">
        {tab === 0 && (
          <p className="text-slate-800 leading-relaxed text-sm bg-blue-50/50 p-4 rounded-lg border border-blue-100">
            {intel?.plain_english_narrative || data.executive_view.plain_english_narrative}
          </p>
        )}
        {tab === 1 && (
          <div className="space-y-3">
            <p className="text-sm text-slate-800 leading-relaxed">
              {intel?.banking_impact_assessment || 'No banking impact assessment provided.'}
            </p>
            {intel?.affected_banking_apps && intel.affected_banking_apps.length > 0 && (
              <div className="pt-2">
                <span className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Targeted App Packages:</span>
                <div className="flex flex-wrap gap-1.5 mt-1.5">
                  {intel.affected_banking_apps.map(app => (
                    <code key={app} className="text-xs bg-red-50 text-red-700 border border-red-200 px-2 py-0.5 rounded font-mono">
                      {app}
                    </code>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
        {tab === 2 && (
          <div className="space-y-2">
            {(intel?.recommended_actions || data.executive_view.recommended_actions).map((act, i) => (
              <div key={i} className="flex items-start gap-2.5 text-sm p-2 bg-slate-50 rounded border border-slate-200">
                <span className="w-5 h-5 rounded-full bg-blue-700 text-white text-xs flex items-center justify-center font-bold flex-shrink-0 mt-0.5">
                  {i + 1}
                </span>
                <span className="text-slate-800">{act}</span>
              </div>
            ))}
          </div>
        )}
        {tab === 3 && (
          <div className="p-4 bg-amber-50 border-l-4 border-amber-400 rounded-r">
            <p className="text-sm text-amber-900 italic leading-relaxed">
              &ldquo;{intel?.customer_advisory_draft || data.executive_view.customer_advisory_draft}&rdquo;
            </p>
          </div>
        )}
      </div>
    </SocCard>
  );
}

// ─── MITRE ATT&CK Panel ──────────────────────────────────────────────────────────

function MitrePanel({ data }: { data: FraudCardData }) {
  const techniques = data.intelligence_report?.mitre_techniques_used || [];

  return (
    <SocCard>
      <SectionHeader
        icon={<Target className="h-4 w-4" />}
        title="MITRE ATT&CK Mobile Techniques"
        subtitle={`${techniques.length} technique(s) mapped from analysis`}
      />
      <div className="p-5">
        {techniques.length === 0 ? (
          <div className="text-center py-6 text-slate-400 text-sm">
            No MITRE ATT&CK techniques mapped for this sample.
          </div>
        ) : (
          <div className="flex flex-wrap gap-2">
            {techniques.map((tech, i) => (
              <div key={i} className="flex items-center gap-2 px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-xs">
                <Target className="h-4 w-4 text-blue-600 flex-shrink-0" />
                <span className="font-mono font-bold text-slate-800">{tech}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </SocCard>
  );
}

// ─── FRS Breakdown Sidebar ───────────────────────────────────────────────────────

function RiskBreakdownSidebar({ data }: { data: FraudCardData }) {
  const frs = data.frs_breakdown;

  if (!frs) return null;

  const items = [
    { label: 'STEI (Static)', score: frs.stei, weight: '50%', color: 'bg-red-500' },
    { label: 'Dynamic Sandbox', score: frs.dynamic, weight: '35%', color: 'bg-purple-500', unavailable: !frs.dynamic_available },
    { label: 'Threat Correlation', score: frs.correlation, weight: '20%', color: 'bg-blue-500' },
    { label: 'Banking Impact', score: frs.banking_impact, weight: '20%', color: 'bg-orange-500' },
  ];

  return (
    <SocCard>
      <SectionHeader icon={<BarChart2 className="h-4 w-4" />} title="FRS Formula Breakdown" subtitle={frs.formula_used} />
      <div className="p-4 space-y-3">
        {items.map(b => (
          <div key={b.label}>
            <div className="flex justify-between items-center mb-1 text-xs">
              <span className="text-slate-600">{b.label}</span>
              <span className="font-bold text-slate-800 font-mono">{b.score.toFixed(1)} / 100</span>
            </div>
            <div className="w-full h-1.5 bg-slate-100 rounded-full overflow-hidden">
              <div
                className={`h-full ${b.unavailable ? 'bg-slate-300' : b.color} rounded-full transition-all`}
                style={{ width: `${Math.min(b.score, 100)}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </SocCard>
  );
}

// ─── Export Options ──────────────────────────────────────────────────────────────

function ExportOptions({ data }: { data: FraudCardData }) {
  const [status, setStatus] = useState<string | null>(null);

  const exportStix = async () => {
    try {
      setStatus('Downloading STIX 2.1...');
      await downloadAuthed(`${API_BASE}/report/stix/${data.sha256}`, `sudarshan_stix_${data.sha256.slice(0, 8)}.json`);
      setStatus('STIX export complete');
    } catch (err: unknown) {
      setStatus(err instanceof Error ? err.message : 'STIX export failed');
    } setTimeout(() => setStatus(null), 3000);
  };

  const exportIocs = async () => {
    try {
      setStatus('Downloading IOC CSV...');
      await downloadAuthed(`${API_BASE}/report/iocs/${data.sha256}`, `sudarshan_iocs_${data.sha256.slice(0, 8)}.csv`);
      setStatus('IOC CSV export complete');
    } catch (err: unknown) {
      setStatus(err instanceof Error ? err.message : 'IOC export failed');
    } setTimeout(() => setStatus(null), 3000);
  };

  const exportPdfReport = async () => {
    try {
      setStatus('Generating Executive PDF Report...');
      const res = await fetch(`${API_BASE}/report/pdf/${data.sha256}`, {
        headers: authHeaders(),
      });
      if (!res.ok) {
        throw new Error(res.status === 401 ? 'Session expired' : `PDF export failed (${res.status})`);
      }
      const htmlBlob = await res.blob();
      const blobUrl = URL.createObjectURL(htmlBlob);
      const win = window.open(blobUrl, '_blank');
      if (!win) {
        await downloadAuthed(`${API_BASE}/report/html/${data.sha256}`, `sudarshan_report_${data.sha256.slice(0, 8)}.html`);
      }
      setStatus('PDF report ready');
    } catch (err: unknown) {
      setStatus(err instanceof Error ? err.message : 'PDF export failed');
    } setTimeout(() => setStatus(null), 3000);
  };

  return (
    <SocCard className="relative">
      <SectionHeader icon={<Download className="h-4 w-4" />} title="Export & SIEM Ingestion" />
      <div className="p-4 grid grid-cols-2 gap-2">
        <button
          onClick={exportStix}
          className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-slate-50 border border-slate-200 rounded-lg hover:bg-blue-50 hover:border-blue-300 hover:text-blue-700 transition-colors"
        >
          <Globe className="h-3.5 w-3.5" /> STIX 2.1 JSON
        </button>
        <button
          onClick={exportIocs}
          className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-slate-50 border border-slate-200 rounded-lg hover:bg-blue-50 hover:border-blue-300 hover:text-blue-700 transition-colors"
        >
          <Database className="h-3.5 w-3.5" /> IOC CSV
        </button>
        <button
          onClick={() => exportJSON(data)}
          className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-slate-50 border border-slate-200 rounded-lg hover:bg-blue-50 hover:border-blue-300 hover:text-blue-700 transition-colors"
        >
          <FileText className="h-3.5 w-3.5" /> Full JSON
        </button>
        <button
          onClick={() => exportCSV(data)}
          className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-slate-50 border border-slate-200 rounded-lg hover:bg-blue-50 hover:border-blue-300 hover:text-blue-700 transition-colors"
        >
          <Download className="h-3.5 w-3.5" /> Summary CSV
        </button>
        <button
          onClick={exportPdfReport}
          className="col-span-2 flex items-center justify-center gap-2 px-3 py-2.5 text-xs font-semibold text-white bg-blue-700 rounded-lg hover:bg-blue-800 transition-colors shadow-sm mt-1"
        >
          <FileText className="h-4 w-4" /> Export Executive PDF Report
        </button>
      </div>
      {status && (
        <div className="px-4 pb-3 text-xs text-blue-700 font-medium">{status}</div>
      )}
    </SocCard>
  );
}

// ─── Persistent Analyst Notes (Floating Drawer) ──────────────────────────────

function AnalystNotesDrawer({ sha256 }: { sha256: string }) {
  const [isOpen, setIsOpen] = useState(false);
  const [notes, setNotes] = useState('');
  const [savedNotes, setSavedNotes] = useState<Array<{ id: number; text: string; author: string; created_at: string }>>([]);
  const [loading, setLoading] = useState(false);

  const fetchNotes = async () => {
    try {
      const res = await fetch(`${API_BASE}/cases/${sha256}/notes`, { headers: authHeaders() });
      if (res.ok) {
        const data = await res.json();
        setSavedNotes(data.notes || []);
      }
    } catch {
      // ignore
    }
  };

  // Load notes when drawer is first opened
  useEffect(() => {
    if (isOpen) fetchNotes();
  }, [isOpen, sha256]);

  const save = async () => {
    if (!notes.trim()) return;
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/cases/${sha256}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ text: notes }),
      });
      if (res.ok) {
        setNotes('');
        await fetchNotes();
      }
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      {/* Floating Toggle Button — bottom right */}
      <button
        onClick={() => setIsOpen(true)}
        className="fixed bottom-6 right-6 z-40 flex items-center gap-2 px-4 py-3 bg-[#0F172A] hover:bg-slate-800 text-white text-xs font-semibold rounded-full shadow-xl border border-slate-700 transition-all hover:scale-105"
        title="Open Investigation Notes"
      >
        <StickyNote className="h-4 w-4 text-blue-400" />
        <span>Analyst Notes</span>
        {savedNotes.length > 0 && (
          <span className="ml-0.5 w-5 h-5 rounded-full bg-blue-600 text-white text-[10px] font-bold flex items-center justify-center">
            {savedNotes.length}
          </span>
        )}
      </button>

      {/* Backdrop + Slide-over Drawer */}
      {isOpen && (
        <div className="fixed inset-0 z-50 flex justify-end">
          {/* Backdrop */}
          <div
            className="absolute inset-0 bg-slate-900/40"
            onClick={() => setIsOpen(false)}
          />

          {/* Drawer panel */}
          <div className="relative w-96 bg-white h-full shadow-2xl border-l border-slate-200 flex flex-col">
            {/* Drawer header */}
            <div className="flex items-center justify-between px-5 py-4 border-b border-slate-200 shrink-0">
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 rounded-lg bg-blue-50 border border-blue-100 flex items-center justify-center">
                  <StickyNote className="h-3.5 w-3.5 text-blue-600" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-slate-900">Analyst Notes</h3>
                  <p className="text-[10px] text-slate-400">Persisted to case file in database</p>
                </div>
              </div>
              <button
                onClick={() => setIsOpen(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Drawer body */}
            <div className="flex-1 overflow-y-auto p-5 space-y-4">
              {/* Note input */}
              <div className="space-y-2">
                <label className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider block">
                  New Entry
                </label>
                <textarea
                  value={notes}
                  onChange={e => setNotes(e.target.value)}
                  placeholder="Add investigation notes, findings, or escalation context…"
                  className="w-full text-xs border border-slate-200 rounded-lg p-3 h-28 resize-none focus:outline-none focus:ring-2 focus:ring-blue-500 placeholder-slate-400"
                />
                <button
                  onClick={save}
                  disabled={!notes.trim() || loading}
                  className="w-full py-2.5 text-xs font-semibold bg-blue-700 text-white rounded-lg hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {loading ? 'Saving…' : 'Save Note to Case'}
                </button>
              </div>

              {/* Saved notes log */}
              {savedNotes.length > 0 ? (
                <div className="space-y-2 pt-2 border-t border-slate-100">
                  <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                    Logged Entries ({savedNotes.length})
                  </span>
                  {savedNotes.map((n) => (
                    <div key={n.id} className="p-3 bg-slate-50 border border-slate-200 rounded-lg">
                      <div className="flex justify-between text-[10px] text-slate-400 mb-1.5 font-mono">
                        <span className="font-semibold text-slate-700">{n.author}</span>
                        <span>{new Date(n.created_at).toLocaleString('en-IN', { dateStyle: 'short', timeStyle: 'short' })}</span>
                      </div>
                      <p className="text-xs text-slate-800 leading-relaxed">{n.text}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-slate-400">
                  <StickyNote className="h-8 w-8 mx-auto mb-2 text-slate-300" />
                  <p className="text-xs">No notes logged yet for this case.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
}

// ─── Static Risk Highlights (MobSF Enrichment Summary) ──────────────────────────

function StaticRiskHighlights({ data }: { data: FraudCardData }) {
  // Only render if MobSF enrichment data is present
  const hasEnrichment = (
    (data.binary_analysis?.length ?? 0) > 0 ||
    (data.trackers?.length ?? 0) > 0 ||
    (data.exported_activities?.length ?? 0) > 0 ||
    data.network_security != null
  );

  if (!hasEnrichment) return null;

  // Binary hardening score (% of SO files with NX + canary)
  const bins = data.binary_analysis || [];
  const hardenedCount = bins.filter(b => String(b.nx).toLowerCase() === 'true' && String(b.stack_canary).toLowerCase() === 'true').length;
  const binaryScore = bins.length > 0 ? Math.round((hardenedCount / bins.length) * 100) : null;

  // Certificate risk — check if cert data has risky algorithms
  const certStr = JSON.stringify(data.certificate || '').toLowerCase();
  const certRisky = certStr.includes('sha1') || certStr.includes('md5') || certStr.includes('v1');

  // Trackers
  const trackerCount = data.trackers?.length ?? 0;

  // Network security risk
  const nscStr = JSON.stringify(data.network_security || '').toLowerCase();
  const cleartext = nscStr.includes('cleartexttraffic') && nscStr.includes('true');
  const pinning = nscStr.includes('pinning') || nscStr.includes('pin');

  // Exported components
  const exportedCount = (data.exported_activities?.length ?? 0) + (data.exported_services?.length ?? 0) + (data.exported_receivers?.length ?? 0);

  const highlights = [
    binaryScore !== null ? {
      label: 'Binary Hardening',
      value: `${binaryScore}%`,
      sub: `${hardenedCount}/${bins.length} SO files (NX+Canary)`,
      risk: binaryScore < 50,
    } : null,
    certRisky ? {
      label: 'Certificate Risk',
      value: 'WEAK',
      sub: 'Legacy SHA-1/MD5 or v1 signature',
      risk: true,
    } : {
      label: 'Certificate',
      value: 'OK',
      sub: 'No weak algorithms detected',
      risk: false,
    },
    trackerCount > 0 ? {
      label: 'Third-Party SDKs',
      value: `${trackerCount}`,
      sub: 'Tracker fingerprints found',
      risk: trackerCount > 5,
    } : null,
    exportedCount > 0 ? {
      label: 'Exported Components',
      value: `${exportedCount}`,
      sub: 'Attack surface entry points',
      risk: exportedCount > 5,
    } : null,
    cleartext ? {
      label: 'Network Security',
      value: 'CLEARTEXT',
      sub: 'Plaintext HTTP traffic allowed',
      risk: true,
    } : pinning ? {
      label: 'Network Security',
      value: 'PINNED',
      sub: 'Certificate pinning configured',
      risk: false,
    } : null,
  ].filter(Boolean) as Array<{ label: string; value: string; sub: string; risk: boolean }>;

  if (highlights.length === 0) return null;

  return (
    <SocCard>
      <SectionHeader
        icon={<FileText className="h-4 w-4" />}
        title="Static Analysis Highlights"
        subtitle="Key security properties from MobSF static scan"
      />
      <div className="p-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {highlights.map((h, i) => (
          <div key={i} className={`p-3 rounded-lg border text-xs ${
            h.risk
              ? 'bg-red-50 border-red-200'
              : 'bg-emerald-50 border-emerald-200'
          }`}>
            <div className="text-slate-500 text-[10px] uppercase font-semibold tracking-wide mb-1">{h.label}</div>
            <div className={`text-base font-black ${h.risk ? 'text-red-700' : 'text-emerald-700'}`}>{h.value}</div>
            <div className="text-slate-500 text-[10px] mt-0.5">{h.sub}</div>
          </div>
        ))}
      </div>
    </SocCard>
  );
}

// ─── Main FraudCard Page ─────────────────────────────────────────────────────────

export default function FraudCard({ data }: { data: FraudCardData | null }) {
  const navigate = useNavigate();

  if (!data) return <Navigate to="/" />;

  return (
    <div className="space-y-5">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Fraud Analyst Intelligence</h1>
          <p className="text-sm text-slate-500 mt-0.5">Executive assessment — {data.package_name || data.sha256.slice(0, 16) + '…'}</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => navigate('/chat')}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 transition-colors"
          >
            <MessageSquare className="h-4 w-4" /> Open AI Assistant
          </button>
          <Badge label={data.risk_band} variant="risk" className="px-4 py-2 text-sm" />
        </div>
      </div>

      {/* Executive Risk Panel */}
      <ExecutiveRiskPanel data={data} />

      {/* Static Risk Highlights (MobSF enrichment — only shown when data present) */}
      <StaticRiskHighlights data={data} />

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2 space-y-5">
          <AttackNarrativeCard data={data} />
          <MitrePanel data={data} />
        </div>

        <div className="space-y-5">
          <RiskBreakdownSidebar data={data} />
          <ExportOptions data={data} />
        </div>
      </div>
      {/* Floating Analyst Notes Drawer */}
      <AnalystNotesDrawer sha256={data.sha256} />
    </div>
  );
}
