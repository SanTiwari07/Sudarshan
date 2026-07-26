import React, { useState, useRef } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import {
  Shield, CheckCircle2, XCircle, AlertTriangle, AlertOctagon,
  ChevronRight, Copy, Download, MessageSquare, User,
  Clock, Send, BarChart2, Zap, Info, FileText, Activity,
  Target, Globe, ExternalLink
} from 'lucide-react';
import type { FraudCardData } from '../App';
import {
  getMitreAttack, getRiskBreakdown, getAttackChain, getTopEvidence,
  getConfidencePercent, riskBandBg, riskBandText,
  severityBg, exportJSON, exportCSV,
} from '../utils/derive';

// ─── Sub-components ─────────────────────────────────────────────────────────────

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

function SocCard({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`bg-white border border-gray-200 rounded-xl shadow-sm overflow-hidden ${className}`}>
      {children}
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
      className="ml-1 p-0.5 rounded hover:bg-gray-100 text-gray-400 hover:text-gray-600 transition-colors"
      title="Copy"
    >
      {copied ? <CheckCircle2 className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3" />}
    </button>
  );
}

// ─── Executive Risk Panel ────────────────────────────────────────────────────────

function ExecutiveRiskPanel({ data, confidence }: { data: FraudCardData; confidence: number }) {
  const DETECTION_METHODS = [
    { name: 'Manifest Analysis', done: true },
    { name: 'Permission Analysis', done: true },
    { name: 'Static Code Analysis', done: true },
    { name: 'URL / String Extraction', done: true },
    { name: 'Explainability Engine', done: true },
    { name: 'Dynamic Sandbox', done: data.dynamic_available },
    { name: 'Network Behaviour', done: data.dynamic_available },
    { name: 'Certificate Validation', done: !!data.certificate && Object.keys(data.certificate).length > 0 },
  ];

  const scoreColor = (() => {
    switch (data.risk_band.toLowerCase()) {
      case 'critical': return 'text-red-600';
      case 'high risk': return 'text-orange-500';
      case 'suspicious': return 'text-yellow-600';
      default: return 'text-green-600';
    }
  })();

  return (
    <SocCard>
      {/* Card header bar */}
      <div className="bg-blue-900 px-5 py-2.5 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-blue-300" />
          <span className="text-xs font-mono text-blue-200 uppercase tracking-widest">Analysis Summary</span>
        </div>
        <span className="text-xs text-blue-400 font-mono">SUDARSHAN CORE ENGINE v1.0</span>
      </div>

      <div className="p-5">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">

          {/* Risk Score */}
          <div className="flex items-center gap-4 p-4 bg-gray-50 rounded-lg border border-gray-200">
            <div className={`text-6xl font-black leading-none ${scoreColor}`}>
              {data.final_risk_score.toFixed(0)}
            </div>
            <div className="min-w-0">
              <div className="text-xs text-gray-500 uppercase tracking-wide font-semibold">Risk Score</div>
              <div className="text-sm text-gray-400">/ 100</div>
              <div className={`mt-2 inline-flex px-2.5 py-1 rounded font-bold text-sm uppercase tracking-wide ${riskBandBg(data.risk_band)}`}>
                {data.risk_band}
              </div>
            </div>
          </div>

          {/* Key Metrics */}
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: 'Threat Level', value: data.risk_band.toUpperCase(), color: riskBandText(data.risk_band) },
              { label: 'Confidence', value: `${confidence}%`, color: 'text-blue-700' },
              { label: 'AI Multiplier', value: `×${data.ai_confidence_multiplier.toFixed(2)}`, color: 'text-purple-700' },
              { label: 'Family', value: data.family_classification, color: data.family_classification !== 'Unknown' ? 'text-red-600' : 'text-gray-700' },
            ].map(m => (
              <div key={m.label} className="p-2.5 bg-gray-50 rounded-lg border border-gray-200">
                <div className="text-xs text-gray-500 uppercase tracking-wide">{m.label}</div>
                <div className={`text-sm font-bold mt-0.5 truncate ${m.color}`}>{m.value}</div>
              </div>
            ))}
          </div>

          {/* Detection Methods */}
          <div>
            <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">Detection Methods</div>
            <div className="space-y-1.5">
              {DETECTION_METHODS.map(m => (
                <div key={m.name} className="flex items-center gap-2 text-xs">
                  {m.done
                    ? <CheckCircle2 className="h-3.5 w-3.5 text-green-500 flex-shrink-0" />
                    : <XCircle className="h-3.5 w-3.5 text-gray-300 flex-shrink-0" />}
                  <span className={m.done ? 'text-gray-700' : 'text-gray-400'}>{m.name}</span>
                </div>
              ))}
            </div>
          </div>

          {/* APK Details */}
          <div>
            <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">APK Details</div>
            <div className="space-y-2 text-xs">
              {[
                { label: 'Package', value: data.package_name || 'Unknown' },
                { label: 'SHA-256', value: `${data.sha256.slice(0, 12)}…`, full: data.sha256 },
                { label: 'Permissions', value: `${data.all_permissions.length} total / ${data.technical_view.permissions_fired.length} critical` },
                { label: 'APIs Flagged', value: `${data.technical_view.apis_fired.length} dangerous` },
                { label: 'Network IOCs', value: `${data.hardcoded_urls_ips.length} URL(s)/IP(s)` },
              ].map(r => (
                <div key={r.label} className="flex justify-between items-start gap-2">
                  <span className="text-gray-500 flex-shrink-0">{r.label}</span>
                  <div className="flex items-center min-w-0">
                    <span className="font-mono text-gray-800 truncate">{r.value}</span>
                    {r.full && <CopyButton value={r.full} />}
                  </div>
                </div>
              ))}
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
  const tabs = ['AI Summary', 'Key Findings', 'Business Impact', 'Classification Rationale', 'Future Risks'];

  const permCount = data.technical_view.permissions_fired.length;
  const apiCount = data.technical_view.apis_fired.length;
  const urlCount = data.hardcoded_urls_ips.length;

  const keyFindings = [
    { found: data.has_accessibility_abuse, label: 'Accessibility abuse detected (OTP harvest risk)', bad: true },
    { found: data.has_sms_read_write, label: 'SMS read/receive permissions detected', bad: true },
    { found: data.has_system_alert_window, label: 'System overlay capability detected', bad: true },
    { found: apiCount > 0, label: `${apiCount} dangerous API(s) detected: ${data.technical_view.apis_fired.join(', ') || '–'}`, bad: true },
    { found: !data.has_accessibility_abuse, label: 'No Accessibility abuse', bad: false },
    { found: !data.has_sms_read_write, label: 'No SMS interception capability', bad: false },
    { found: !data.has_system_alert_window, label: 'No overlay attack capability', bad: false },
    { found: urlCount > 0, label: `${urlCount} hardcoded network indicator(s) in DEX strings`, bad: true },
    { found: data.targets_indian_banks, label: 'Indian banking packages targeted', bad: true },
    { found: !data.targets_indian_banks, label: 'No banking app targeting detected', bad: false },
  ].filter(f => f.found);

  const impact = data.final_risk_score <= 30 ? 'Low'
    : data.final_risk_score <= 60 ? 'Medium'
    : data.final_risk_score <= 89 ? 'High' : 'Critical';

  const impactColor = { Low: 'text-green-600 bg-green-50', Medium: 'text-yellow-700 bg-yellow-50', High: 'text-orange-600 bg-orange-50', Critical: 'text-red-600 bg-red-50' }[impact];

  const futureRisk = (() => {
    if (data.technical_view.apis_fired.some(a => ['DexClassLoader', 'PathClassLoader'].includes(a)))
      return 'HIGH — Dynamic code loading detected. Future payload delivery is possible without a new installation.';
    if (data.final_risk_score > 30)
      return 'MEDIUM — If future versions introduce dynamic loading, SMS permissions, or Accessibility abuse, threat level will escalate significantly.';
    return 'LOW — Based on current static analysis, future risk is minimal. Continue periodic re-scanning on app updates.';
  })();

  const rationale = data.technical_view.matched_rule;

  return (
    <SocCard>
      <SectionHeader
        icon={<MessageSquare className="h-4 w-4" />}
        title="Attack Narrative"
        subtitle="AI-synthesized threat intelligence"
      />
      <div className="flex border-b border-gray-200 overflow-x-auto">
        {tabs.map((t, i) => (
          <button
            key={t}
            onClick={() => setTab(i)}
            className={`px-4 py-2.5 text-xs font-medium whitespace-nowrap transition-colors border-b-2 ${
              tab === i
                ? 'border-blue-600 text-blue-700 bg-blue-50'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:bg-gray-50'
            }`}
          >
            {t}
          </button>
        ))}
      </div>
      <div className="p-5">
        {tab === 0 && (
          <p className="text-gray-700 leading-relaxed text-sm">
            {data.executive_view.plain_english_narrative}
          </p>
        )}
        {tab === 1 && (
          <div className="space-y-2">
            {keyFindings.map((f, i) => (
              <div key={i} className="flex items-start gap-2.5 text-sm">
                {f.bad
                  ? <AlertTriangle className="h-4 w-4 text-orange-500 flex-shrink-0 mt-0.5" />
                  : <CheckCircle2 className="h-4 w-4 text-green-500 flex-shrink-0 mt-0.5" />}
                <span className={f.bad ? 'text-gray-800' : 'text-gray-500'}>{f.label}</span>
              </div>
            ))}
            {keyFindings.length === 0 && (
              <p className="text-gray-500 text-sm">No notable findings. APK appears benign.</p>
            )}
          </div>
        )}
        {tab === 2 && (
          <div className="space-y-4">
            <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg font-bold text-sm ${impactColor}`}>
              Business Impact: {impact}
            </div>
            <p className="text-sm text-gray-700 leading-relaxed">
              {impact === 'Low' && 'Minimal business risk. This APK does not exhibit patterns associated with banking malware or fraud toolkits. Standard deployment with routine monitoring is appropriate.'}
              {impact === 'Medium' && `This APK contains ${permCount > 0 ? `${permCount} sensitive permission(s)` : 'suspicious indicators'} that warrant review. Unauthorised deployment could expose users to privacy risks. Recommend security sign-off before production release.`}
              {impact === 'High' && `This APK exhibits high-risk behaviors including ${[data.has_accessibility_abuse && 'Accessibility abuse', data.has_sms_read_write && 'SMS interception', data.has_system_alert_window && 'overlay attacks'].filter(Boolean).join(', ')}. Deployment could lead to OTP theft, credential harvesting, and financial fraud.`}
              {impact === 'Critical' && 'This APK matches known banking malware behavioral patterns. Immediate isolation and incident response engagement is required. Customer notification may be legally mandated.'}
            </p>
          </div>
        )}
        {tab === 3 && (
          <div className="space-y-3">
            <div className="p-3 bg-blue-50 border border-blue-100 rounded-lg">
              <div className="text-xs font-semibold text-blue-800 uppercase tracking-wide mb-1">Matched Classification Rule</div>
              <p className="text-sm font-mono text-blue-900">{rationale}</p>
            </div>
            <div className="text-xs text-gray-500 flex items-start gap-1.5">
              <Info className="h-3.5 w-3.5 flex-shrink-0 mt-0.5 text-blue-400" />
              Classification uses deterministic pattern matching on static behavioral flags — not LLM inference. Results are reproducible and auditable.
            </div>
          </div>
        )}
        {tab === 4 && (
          <div className="space-y-3">
            <div className={`p-3 rounded-lg border text-sm ${futureRisk.startsWith('HIGH') ? 'bg-red-50 border-red-200 text-red-800' : futureRisk.startsWith('MEDIUM') ? 'bg-yellow-50 border-yellow-200 text-yellow-800' : 'bg-green-50 border-green-200 text-green-700'}`}>
              {futureRisk}
            </div>
            <p className="text-xs text-gray-500">Future risk is assessed based on the presence of dynamic loading vectors and escalation potential from current flag profile.</p>
          </div>
        )}
      </div>
    </SocCard>
  );
}

// ─── MITRE ATT&CK Panel ──────────────────────────────────────────────────────────

function MitrePanel({ data }: { data: FraudCardData }) {
  const techniques = getMitreAttack(data);

  return (
    <SocCard>
      <SectionHeader
        icon={<Target className="h-4 w-4" />}
        title="MITRE ATT&CK for Mobile"
        subtitle={techniques.length > 0 ? `${techniques.length} technique(s) mapped` : 'No techniques mapped'}
      />
      <div className="p-5">
        {techniques.length === 0 ? (
          <div className="text-center py-6">
            <CheckCircle2 className="h-8 w-8 text-green-400 mx-auto mb-2" />
            <p className="text-sm text-gray-500">No MITRE ATT&CK techniques could be mapped from the current evidence. Insufficient behavioral indicators for technique attribution.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {techniques.map(t => (
              <div key={t.id} className="p-3 rounded-lg border border-gray-200 hover:border-blue-300 hover:bg-blue-50/30 transition-colors">
                <div className="flex items-start justify-between gap-2 mb-1.5">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-blue-700 bg-blue-50 px-1.5 py-0.5 rounded border border-blue-200">{t.id}</span>
                    <Badge label={t.severity} className={severityBg(t.severity)} />
                  </div>
                  <div className="flex items-center gap-1 flex-shrink-0">
                    <div className="w-12 h-1.5 bg-gray-200 rounded-full overflow-hidden">
                      <div className="h-full bg-blue-500 rounded-full" style={{ width: `${t.confidence}%` }} />
                    </div>
                    <span className="text-xs text-gray-500">{t.confidence}%</span>
                  </div>
                </div>
                <div className="text-xs font-semibold text-gray-800 mb-0.5">{t.name}</div>
                <div className="text-xs text-gray-400 uppercase tracking-wide mb-1">Tactic: {t.tactic}</div>
                <p className="text-xs text-gray-600 leading-relaxed">{t.description}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </SocCard>
  );
}

// ─── Attack Chain ────────────────────────────────────────────────────────────────

function AttackChainPanel({ data }: { data: FraudCardData }) {
  const chain = getAttackChain(data);

  return (
    <SocCard>
      <SectionHeader icon={<Activity className="h-4 w-4" />} title="Attack Chain" subtitle="Hypothetical execution pathway" />
      <div className="p-5">
        <div className="flex flex-col gap-0">
          {chain.map((node, i) => (
            <div key={i} className="flex items-stretch gap-3">
              {/* Timeline column */}
              <div className="flex flex-col items-center w-6 flex-shrink-0">
                <div className={`w-3 h-3 rounded-full border-2 flex-shrink-0 mt-1 ${node.active ? 'bg-blue-600 border-blue-600' : 'bg-gray-200 border-gray-300'}`} />
                {i < chain.length - 1 && <div className={`w-px flex-1 my-0.5 ${node.active ? 'bg-blue-300' : 'bg-gray-200'}`} />}
              </div>
              {/* Content */}
              <div className={`pb-4 flex-1 ${i < chain.length - 1 ? '' : ''}`}>
                <div className="flex items-center gap-2 mb-0.5">
                  <span className={`text-sm font-semibold ${node.active ? 'text-gray-800' : 'text-gray-400'}`}>{node.phase}</span>
                  {node.active && <Badge label="Active" className="bg-blue-100 text-blue-700 border border-blue-200" />}
                </div>
                <p className={`text-xs leading-relaxed ${node.active ? 'text-gray-600' : 'text-gray-400'}`}>{node.description}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </SocCard>
  );
}

// ─── Recommended Actions ─────────────────────────────────────────────────────────

function RecommendedActions({ data }: { data: FraudCardData }) {
  const priorities: Array<{ priority: 'Critical' | 'High' | 'Medium' | 'Low'; action: string; impact: string; time: string }> = [];

  if (data.has_accessibility_abuse || data.has_sms_read_write) {
    priorities.push({ priority: 'Critical', action: 'Isolate affected devices immediately and revoke app permissions', impact: 'Prevents OTP theft and credential harvesting', time: '< 15 min' });
  }
  if (data.technical_view.apis_fired.some(a => ['DexClassLoader', 'PathClassLoader'].includes(a))) {
    priorities.push({ priority: 'High', action: 'Submit to dynamic sandbox — dynamic loading detected', impact: 'Reveals hidden payload delivery mechanism', time: '1–2 hours' });
  }
  if (data.hardcoded_urls_ips.length > 0) {
    priorities.push({ priority: 'High', action: `Block ${data.hardcoded_urls_ips.length} hardcoded URL(s)/IP(s) at firewall/proxy`, impact: 'Cuts C2 communication channel', time: '30 min' });
  }
  data.executive_view.recommended_actions.forEach((action, i) => {
    const priority = i === 0 ? 'High' : i === 1 ? 'Medium' : 'Low';
    if (!priorities.find(p => p.action.includes(action.slice(0, 20)))) {
      priorities.push({ priority: priority as 'High' | 'Medium' | 'Low', action, impact: 'Reduces overall threat surface', time: '1–4 hours' });
    }
  });
  if (data.final_risk_score <= 30) {
    priorities.push({ priority: 'Low', action: 'Safe to deploy under standard monitoring', impact: 'Minimal risk profile', time: 'Ongoing' });
  }

  const priorityOrder = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  priorities.sort((a, b) => priorityOrder[a.priority] - priorityOrder[b.priority]);

  return (
    <SocCard>
      <SectionHeader icon={<Zap className="h-4 w-4" />} title="Recommended Actions" subtitle="Priority-ordered response playbook" />
      <div className="divide-y divide-gray-100">
        {priorities.slice(0, 6).map((p, i) => (
          <div key={i} className="flex items-start gap-3 p-4 hover:bg-gray-50 transition-colors">
            <Badge label={p.priority} className={`flex-shrink-0 mt-0.5 ${severityBg(p.priority)}`} />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-gray-800">{p.action}</p>
              <p className="text-xs text-gray-500 mt-0.5">{p.impact}</p>
            </div>
            <div className="flex-shrink-0 text-right">
              <div className="flex items-center gap-1 text-xs text-gray-400">
                <Clock className="h-3 w-3" />
                {p.time}
              </div>
            </div>
          </div>
        ))}
      </div>
    </SocCard>
  );
}

// ─── Threat Identity Sidebar ─────────────────────────────────────────────────────

function ThreatIdentitySidebar({ data }: { data: FraudCardData }) {
  return (
    <SocCard>
      <SectionHeader icon={<Shield className="h-4 w-4" />} title="Threat Identity" />
      <div className="p-4 space-y-4">
        <div>
          <div className="text-xs text-gray-500 uppercase tracking-wide mb-1">Determined Family</div>
          <div className={`text-xl font-bold ${data.family_classification !== 'Unknown' ? 'text-red-600' : 'text-gray-700'}`}>
            {data.family_classification}
          </div>
        </div>
        <div>
          <div className="text-xs text-gray-500 uppercase tracking-wide mb-1">SHA-256 Hash</div>
          <div className="flex items-center gap-1">
            <p className="text-xs font-mono text-gray-700 break-all bg-gray-50 p-2 rounded border border-gray-200 flex-1">
              {data.sha256}
            </p>
            <CopyButton value={data.sha256} />
          </div>
        </div>
        <div>
          <div className="text-xs text-gray-500 uppercase tracking-wide mb-1">Package</div>
          <p className="text-xs font-mono text-gray-700 bg-gray-50 p-2 rounded border border-gray-200 break-all">
            {data.package_name || 'Unknown'}
          </p>
        </div>
        <div>
          <div className="text-xs text-gray-500 uppercase tracking-wide mb-1">Risk Band</div>
          <span className={`inline-flex px-3 py-1 rounded font-bold text-sm uppercase ${riskBandBg(data.risk_band)}`}>
            {data.risk_band}
          </span>
        </div>
      </div>
    </SocCard>
  );
}

// ─── AI Confidence Widget ────────────────────────────────────────────────────────

function AIConfidenceWidget({ data, confidence }: { data: FraudCardData; confidence: number }) {
  return (
    <SocCard>
      <SectionHeader icon={<BarChart2 className="h-4 w-4" />} title="AI Confidence" />
      <div className="p-4 space-y-3">
        <div className="flex items-end justify-between">
          <span className="text-3xl font-black text-blue-700">{confidence}%</span>
          <span className="text-xs text-gray-500 pb-1">prediction confidence</span>
        </div>
        <div className="w-full h-2 bg-gray-200 rounded-full overflow-hidden">
          <div
            className="h-full bg-blue-600 rounded-full transition-all"
            style={{ width: `${confidence}%` }}
          />
        </div>
        <p className="text-xs text-gray-500 leading-relaxed">
          Confidence is derived from the number and weight of deterministic flag matches combined with AI reasoning consistency.
          AI multiplier: ×{data.ai_confidence_multiplier.toFixed(2)}.
        </p>
      </div>
    </SocCard>
  );
}

// ─── Risk Breakdown ──────────────────────────────────────────────────────────────

function RiskBreakdownSidebar({ data }: { data: FraudCardData }) {
  const breakdown = getRiskBreakdown(data);

  return (
    <SocCard>
      <SectionHeader icon={<BarChart2 className="h-4 w-4" />} title="Risk Breakdown" subtitle="Score contribution by category" />
      <div className="p-4 space-y-3">
        {breakdown.map(b => (
          <div key={b.label}>
            <div className="flex justify-between items-center mb-1">
              <span className="text-xs text-gray-600">{b.label}</span>
              <span className={`text-xs font-bold font-mono ${b.score > 0 ? 'text-gray-800' : 'text-gray-400'}`}>
                +{b.score.toFixed(1)}
              </span>
            </div>
            <div className="w-full h-1.5 bg-gray-100 rounded-full overflow-hidden">
              <div
                className={`h-full ${b.color} rounded-full transition-all`}
                style={{ width: b.maxScore > 0 ? `${Math.min((b.score / b.maxScore) * 100, 100)}%` : '0%' }}
              />
            </div>
          </div>
        ))}
        <div className="pt-2 border-t border-gray-200 flex justify-between items-center">
          <span className="text-xs font-semibold text-gray-700">Base Score</span>
          <span className="text-sm font-black text-gray-900 font-mono">{data.base_score.toFixed(2)}</span>
        </div>
        <div className="flex justify-between items-center">
          <span className="text-xs font-semibold text-gray-700">Final Score</span>
          <span className={`text-lg font-black font-mono ${riskBandText(data.risk_band)}`}>
            {data.final_risk_score.toFixed(2)} / 100
          </span>
        </div>
      </div>
    </SocCard>
  );
}

// ─── Customer Advisory ───────────────────────────────────────────────────────────

function CustomerAdvisorySidebar({ data }: { data: FraudCardData }) {
  return (
    <SocCard>
      <SectionHeader icon={<FileText className="h-4 w-4" />} title="Customer Advisory" subtitle="Non-technical summary" />
      <div className="p-4 space-y-3">
        <div className="bg-yellow-50 border-l-4 border-yellow-400 p-3 rounded-r">
          <p className="text-sm text-yellow-900 italic leading-relaxed">
            &ldquo;{data.executive_view.customer_advisory_draft}&rdquo;
          </p>
        </div>
        <div className="text-xs text-gray-400">
          For official use only. Review before customer distribution.
        </div>
      </div>
    </SocCard>
  );
}

// ─── Top Evidence ────────────────────────────────────────────────────────────────

function TopEvidenceSidebar({ data }: { data: FraudCardData }) {
  const evidence = getTopEvidence(data);
  const categoryColor: Record<string, string> = {
    permission: 'bg-red-100 text-red-700',
    api: 'bg-orange-100 text-orange-700',
    url: 'bg-blue-100 text-blue-700',
    behavior: 'bg-purple-100 text-purple-700',
    string: 'bg-gray-100 text-gray-600',
  };

  return (
    <SocCard>
      <SectionHeader icon={<ChevronRight className="h-4 w-4" />} title="Top Evidence" subtitle="Ranked by confidence" />
      <div className="divide-y divide-gray-100">
        {evidence.length === 0 ? (
          <div className="p-4 text-center text-sm text-gray-400">No significant evidence detected</div>
        ) : evidence.map(e => (
          <div key={e.rank} className="flex items-start gap-3 p-3 hover:bg-gray-50 transition-colors group">
            <div className="flex-shrink-0 w-5 h-5 rounded-full bg-blue-100 text-blue-700 flex items-center justify-center text-xs font-bold">
              {e.rank}
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-1.5 mb-0.5">
                <span className={`text-xs px-1.5 py-0.5 rounded font-medium ${categoryColor[e.category] || 'bg-gray-100 text-gray-600'}`}>
                  {e.type}
                </span>
                <span className="text-xs text-gray-500">{e.confidence}%</span>
              </div>
              <p className="text-xs font-mono text-gray-700 truncate">{e.value}</p>
            </div>
            <CopyButton value={e.value} />
          </div>
        ))}
      </div>
    </SocCard>
  );
}

// ─── Export Options ──────────────────────────────────────────────────────────────

function ExportOptions({ data }: { data: FraudCardData }) {
  const [toast, setToast] = useState<string | null>(null);
  const showToast = (msg: string) => { setToast(msg); setTimeout(() => setToast(null), 2500); };

  const buttons = [
    { label: 'JSON Report', icon: <Download className="h-3 w-3" />, action: () => exportJSON(data) },
    { label: 'CSV Indicators', icon: <Download className="h-3 w-3" />, action: () => exportCSV(data) },
    { label: 'Executive PDF', icon: <FileText className="h-3 w-3" />, action: () => showToast('PDF export requires server-side rendering — integrate with backend PDF endpoint') },
    { label: 'STIX Package', icon: <Globe className="h-3 w-3" />, action: () => showToast('STIX 2.1 export — connect to threat intelligence platform') },
  ];

  return (
    <SocCard className="relative">
      <SectionHeader icon={<Download className="h-4 w-4" />} title="Export" />
      <div className="p-4 grid grid-cols-2 gap-2">
        {buttons.map(b => (
          <button
            key={b.label}
            onClick={b.action}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-gray-700 bg-gray-50 border border-gray-200 rounded-lg hover:bg-blue-50 hover:border-blue-300 hover:text-blue-700 transition-colors"
          >
            {b.icon}
            {b.label}
          </button>
        ))}
      </div>
      {toast && (
        <div className="absolute bottom-2 left-2 right-2 bg-blue-800 text-white text-xs p-2 rounded shadow-lg z-10">
          {toast}
        </div>
      )}
    </SocCard>
  );
}

// ─── AI Chat ─────────────────────────────────────────────────────────────────────

type ChatMessage = { role: 'user' | 'assistant'; content: string; loading?: boolean };

function AIChat({ data }: { data: FraudCardData }) {
  const navigate = useNavigate();
  const QUICK_QUESTIONS = [
    'Is this APK safe?',
    'Explain the risk score',
    'Did it steal OTP?',
    'Should I block this APK?',
  ];

  const [messages, setMessages] = useState<ChatMessage[]>([
    { role: 'assistant', content: `Investigation loaded for ${data.package_name || 'this APK'}. Risk: ${data.final_risk_score.toFixed(1)}/100 (${data.risk_band}). Ask a quick question or open the full AI Assistant for a complete analysis.` }
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  const send = async (q: string) => {
    if (!q.trim() || isLoading) return;

    setMessages(prev => [
      ...prev,
      { role: 'user', content: q },
      { role: 'assistant', content: '', loading: true },
    ]);
    setInput('');
    setIsLoading(true);
    setTimeout(() => bottomRef.current?.scrollIntoView({ behavior: 'smooth' }), 50);

    try {
      const token = localStorage.getItem('token');
      const res = await fetch('/api/v1/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ sha256: data.sha256, question: q, history: [] }),
      });
      const result = await res.json();
      const answer = result.answer || 'No response received.';
      setMessages(prev => {
        const copy = [...prev];
        const lastIdx = copy.length - 1;
        copy[lastIdx] = { role: 'assistant', content: answer, loading: false };
        return copy;
      });
    } catch (e: any) {
      setMessages(prev => {
        const copy = [...prev];
        copy[copy.length - 1] = { role: 'assistant', content: `Error: ${e.message}`, loading: false };
        return copy;
      });
    } finally {
      setIsLoading(false);
      setTimeout(() => bottomRef.current?.scrollIntoView({ behavior: 'smooth' }), 100);
    }
  };

  return (
    <SocCard className="flex flex-col">
      <SectionHeader icon={<MessageSquare className="h-4 w-4" />} title="AI Investigation Assistant" subtitle="Gemini RAG — evidence-grounded responses" />

      {/* Open full assistant button */}
      <div className="px-4 pt-2.5 pb-1">
        <button
          onClick={() => navigate('/chat')}
          className="w-full flex items-center justify-center gap-2 px-3 py-2 text-xs font-semibold text-blue-700 bg-blue-50 border border-blue-200 rounded-lg hover:bg-blue-100 transition-colors"
        >
          <ExternalLink className="h-3.5 w-3.5" />
          Open Full AI Investigation Assistant
        </button>
      </div>

      {/* Quick questions */}
      <div className="px-4 py-2 border-b border-gray-200 flex flex-wrap gap-1.5">
        {QUICK_QUESTIONS.map(q => (
          <button
            key={q}
            onClick={() => send(q)}
            disabled={isLoading}
            className="text-xs px-2.5 py-1 bg-blue-50 text-blue-700 border border-blue-200 rounded-full hover:bg-blue-100 transition-colors disabled:opacity-50"
          >
            {q}
          </button>
        ))}
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3 max-h-56">
        {messages.map((m, i) => (
          <div key={i} className={`flex gap-2 ${m.role === 'user' ? 'flex-row-reverse' : ''}`}>
            <div className={`flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center text-white ${m.role === 'user' ? 'bg-blue-600' : 'bg-gray-700'}`}>
              {m.role === 'user' ? <User className="h-3 w-3" /> : <Shield className="h-3 w-3" />}
            </div>
            <div className={`max-w-xs lg:max-w-sm ${m.role === 'user' ? 'text-right' : ''}`}>
              <div className={`text-xs p-2.5 rounded-xl leading-relaxed ${
                m.role === 'user' ? 'bg-blue-600 text-white rounded-tr-sm' : 'bg-gray-100 text-gray-800 rounded-tl-sm'
              }`}>
                {m.loading
                  ? <span className="inline-flex gap-1">
                      <span className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style={{animationDelay:'0s'}} />
                      <span className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style={{animationDelay:'0.15s'}} />
                      <span className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style={{animationDelay:'0.3s'}} />
                    </span>
                  : m.content
                }
              </div>
            </div>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
      {/* Input */}
      <div className="p-3 border-t border-gray-200 flex gap-2">
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && send(input)}
          placeholder="Ask about this APK..."
          disabled={isLoading}
          className="flex-1 text-xs border border-gray-200 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:opacity-50"
        />
        <button
          onClick={() => send(input)}
          disabled={!input.trim() || isLoading}
          className="p-2 bg-blue-700 text-white rounded-lg hover:bg-blue-800 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          <Send className="h-3.5 w-3.5" />
        </button>
      </div>
    </SocCard>
  );
}

// ─── Analyst Notes ───────────────────────────────────────────────────────────────

function AnalystNotes() {
  const [notes, setNotes] = useState('');
  const [saved, setSaved] = useState<Array<{ text: string; ts: string; author: string }>>([]);
  const [author, setAuthor] = useState('SOC Analyst');

  const save = () => {
    if (!notes.trim()) return;
    setSaved(prev => [...prev, {
      text: notes.trim(),
      ts: new Date().toLocaleString('en-IN', { dateStyle: 'short', timeStyle: 'short' }),
      author,
    }]);
    setNotes('');
  };

  return (
    <SocCard className="flex flex-col">
      <SectionHeader icon={<FileText className="h-4 w-4" />} title="Analyst Notes" subtitle="Case documentation" />
      <div className="p-4 space-y-3 flex-1">
        <div className="flex gap-2">
          <input
            value={author}
            onChange={e => setAuthor(e.target.value)}
            className="text-xs border border-gray-200 rounded px-2 py-1 w-32 focus:outline-none focus:ring-1 focus:ring-blue-500"
            placeholder="Author"
          />
          <span className="text-xs text-gray-400 self-center">{new Date().toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' })}</span>
        </div>
        <textarea
          value={notes}
          onChange={e => setNotes(e.target.value)}
          placeholder="Add investigation notes, findings, or escalation context…"
          className="w-full text-xs border border-gray-200 rounded-lg p-2.5 h-28 resize-none focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
        <button
          onClick={save}
          disabled={!notes.trim()}
          className="w-full py-2 text-xs font-medium bg-blue-700 text-white rounded-lg hover:bg-blue-800 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          Save Note
        </button>
        {/* Saved notes */}
        {saved.length > 0 && (
          <div className="space-y-2 max-h-48 overflow-y-auto">
            {saved.map((n, i) => (
              <div key={i} className="p-2.5 bg-gray-50 border border-gray-200 rounded-lg">
                <div className="flex justify-between text-xs text-gray-400 mb-1">
                  <div className="flex items-center gap-1">
                    <User className="h-3 w-3" />
                    <span>{n.author}</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    <span>{n.ts}</span>
                  </div>
                </div>
                <p className="text-xs text-gray-700 leading-relaxed">{n.text}</p>
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
  if (!data) return <Navigate to="/" />;

  const confidence = getConfidencePercent(data);

  return (
    <div className="space-y-5">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Fraud Analyst Intelligence</h1>
          <p className="text-sm text-gray-500 mt-0.5">Executive threat assessment — {data.package_name || data.sha256.slice(0, 16) + '…'}</p>
        </div>
        <div className={`flex items-center gap-2 px-5 py-2.5 rounded-lg font-bold text-base uppercase tracking-wider shadow-sm ${riskBandBg(data.risk_band)}`}>
          {data.risk_band.toLowerCase() === 'critical'
            ? <AlertOctagon className="h-5 w-5" />
            : data.risk_band.toLowerCase() === 'safe'
            ? <CheckCircle2 className="h-5 w-5" />
            : <AlertTriangle className="h-5 w-5" />}
          {data.risk_band}
        </div>
      </div>

      {/* Executive Risk Panel — full width */}
      <ExecutiveRiskPanel data={data} confidence={confidence} />

      {/* Main 3-col grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left / Main — 2 cols */}
        <div className="lg:col-span-2 space-y-5">
          <AttackNarrativeCard data={data} />
          <MitrePanel data={data} />
          <RecommendedActions data={data} />
          <AttackChainPanel data={data} />
        </div>

        {/* Right Sidebar — 1 col */}
        <div className="space-y-5">
          <ThreatIdentitySidebar data={data} />
          <AIConfidenceWidget data={data} confidence={confidence} />
          <RiskBreakdownSidebar data={data} />
          <TopEvidenceSidebar data={data} />
          <CustomerAdvisorySidebar data={data} />
          <ExportOptions data={data} />
        </div>
      </div>

      {/* Bottom row — AI Chat + Analyst Notes */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <AIChat data={data} />
        <AnalystNotes />
      </div>
    </div>
  );
}
