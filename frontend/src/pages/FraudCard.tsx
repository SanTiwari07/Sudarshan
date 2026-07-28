import { useState, useEffect } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import {
  Shield, Download, MessageSquare, BarChart2,
  FileText, Target, Database, Globe
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

// ─── Persistent Analyst Notes ────────────────────────────────────────────────────

function AnalystNotes({ sha256 }: { sha256: string }) {
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

  useEffect(() => {
    fetchNotes();
  }, [sha256]);

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
    <SocCard className="flex flex-col">
      <SectionHeader icon={<FileText className="h-4 w-4" />} title="Analyst Notes" subtitle="Persisted to case file in database" />
      <div className="p-4 space-y-3 flex-1">
        <textarea
          value={notes}
          onChange={e => setNotes(e.target.value)}
          placeholder="Add investigation notes, findings, or escalation context…"
          className="w-full text-xs border border-slate-200 rounded-lg p-2.5 h-24 resize-none focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <button
          onClick={save}
          disabled={!notes.trim() || loading}
          className="w-full py-2 text-xs font-medium bg-blue-700 text-white rounded-lg hover:bg-blue-800 disabled:opacity-50 transition-colors"
        >
          {loading ? 'Saving…' : 'Save Note to Case'}
        </button>

        {savedNotes.length > 0 && (
          <div className="space-y-2 max-h-48 overflow-y-auto pt-2 border-t border-slate-100">
            {savedNotes.map((n) => (
              <div key={n.id} className="p-2.5 bg-slate-50 border border-slate-200 rounded-lg">
                <div className="flex justify-between text-xs text-slate-400 mb-1">
                  <span className="font-semibold text-slate-700">{n.author}</span>
                  <span>{new Date(n.created_at).toLocaleString()}</span>
                </div>
                <p className="text-xs text-slate-700 leading-relaxed">{n.text}</p>
              </div>
            ))}
          </div>
        )}
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

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2 space-y-5">
          <AttackNarrativeCard data={data} />
          <MitrePanel data={data} />
        </div>

        <div className="space-y-5">
          <RiskBreakdownSidebar data={data} />
          <ExportOptions data={data} />
          <AnalystNotes sha256={data.sha256} />
        </div>
      </div>
    </div>
  );
}
