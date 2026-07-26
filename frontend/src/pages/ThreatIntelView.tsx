import React, { useState } from 'react';
import { Navigate } from 'react-router-dom';
import {
  Globe, Shield, CheckCircle2, XCircle,
  ExternalLink, Copy, Activity, Target, FileText,
  BarChart2, Info, AlertOctagon,
  Database
} from 'lucide-react';
import type { FraudCardData, IOCReputation } from '../App';
import { API_BASE, downloadAuthed } from '../config';

// ─── Sub-components ──────────────────────────────────────────────────────────

function SocCard({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`bg-white border border-gray-200 rounded-xl shadow-sm overflow-hidden ${className}`}>
      {children}
    </div>
  );
}

function SectionHeader({ icon, title, subtitle, badge }: {
  icon: React.ReactNode; title: string; subtitle?: string; badge?: React.ReactNode
}) {
  return (
    <div className="flex items-center justify-between px-5 py-3 bg-gray-50 border-b border-gray-200">
      <div className="flex items-center gap-2">
        <span className="text-blue-700">{icon}</span>
        <div>
          <h2 className="text-sm font-semibold text-gray-800 tracking-tight">{title}</h2>
          {subtitle && <p className="text-xs text-gray-500">{subtitle}</p>}
        </div>
      </div>
      {badge}
    </div>
  );
}

function ReputationBadge({ rep }: { rep: string }) {
  const map: Record<string, string> = {
    malicious: 'bg-red-100 text-red-700 border border-red-200',
    suspicious: 'bg-yellow-100 text-yellow-700 border border-yellow-200',
    clean: 'bg-green-100 text-green-700 border border-green-200',
    unknown: 'bg-gray-100 text-gray-600 border border-gray-200',
  };
  return (
    <span className={`inline-flex px-2 py-0.5 rounded text-xs font-bold uppercase ${map[rep] || map.unknown}`}>
      {rep}
    </span>
  );
}

function SourceBadge({ source }: { source: string }) {
  const map: Record<string, string> = {
    'VirusTotal': 'bg-blue-100 text-blue-700',
    'AlienVault OTX': 'bg-purple-100 text-purple-700',
    'AbuseIPDB': 'bg-orange-100 text-orange-700',
    'Sudarshan': 'bg-gray-100 text-gray-600',
  };
  return (
    <span className={`inline-flex px-1.5 py-0.5 rounded text-xs font-medium ${map[source] || 'bg-gray-100 text-gray-600'}`}>
      {source}
    </span>
  );
}

function CopyBtn({ value }: { value: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(value); setDone(true); setTimeout(() => setDone(false), 1500); }}
      className="p-0.5 rounded hover:bg-gray-100 text-gray-400 hover:text-gray-600 transition-colors flex-shrink-0"
    >
      {done ? <CheckCircle2 className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3" />}
    </button>
  );
}

// ─── Panel: Correlation Overview ─────────────────────────────────────────────

function CorrelationOverview({ data }: { data: FraudCardData }) {
  const tc = data.threat_correlation;

  if (!tc) {
    return (
      <SocCard>
        <SectionHeader icon={<Globe className="h-4 w-4" />} title="Threat Intelligence Correlation" />
        <div className="p-8 text-center">
          <Database className="h-10 w-10 text-gray-300 mx-auto mb-3" />
          <p className="text-sm font-medium text-gray-600">No Threat Intelligence Available</p>
          <p className="text-xs text-gray-400 mt-1 max-w-xs mx-auto">
            Add API keys to .env to enable VirusTotal, AlienVault OTX, and AbuseIPDB correlation.
          </p>
          <div className="mt-4 grid grid-cols-3 gap-2 max-w-xs mx-auto">
            {['VIRUSTOTAL_API_KEY', 'OTX_API_KEY', 'ABUSEIPDB_API_KEY'].map(k => (
              <div key={k} className="p-2 bg-gray-50 rounded border border-dashed border-gray-300">
                <p className="text-xs font-mono text-gray-400 truncate">{k}</p>
                <p className="text-xs text-gray-400">Not set</p>
              </div>
            ))}
          </div>
        </div>
      </SocCard>
    );
  }

  const vtRatio = tc.vt_detection_ratio;
  const vtColor = vtRatio > 0.5 ? 'text-red-600' : vtRatio > 0.1 ? 'text-orange-500' : 'text-green-600';
  const vtBg = vtRatio > 0.5 ? 'bg-red-500' : vtRatio > 0.1 ? 'bg-orange-500' : 'bg-green-500';

  return (
    <SocCard>
      <SectionHeader
        icon={<Globe className="h-4 w-4" />}
        title="Threat Intelligence Correlation"
        subtitle={`Queried: ${tc.sources_queried.join(', ') || 'No sources configured'}`}
        badge={
          tc.available
            ? <span className="text-xs bg-green-100 text-green-700 border border-green-200 px-2 py-0.5 rounded font-medium">Live Intelligence</span>
            : <span className="text-xs bg-gray-100 text-gray-500 border border-gray-200 px-2 py-0.5 rounded font-medium">No Data</span>
        }
      />
      <div className="p-5 grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* VT Detection */}
        <div className="p-4 bg-gray-50 rounded-lg border border-gray-200 text-center">
          <div className={`text-3xl font-black ${vtColor}`}>{(vtRatio * 100).toFixed(0)}%</div>
          <div className="text-xs text-gray-500 mt-1">VT Detection Rate</div>
          <div className="text-xs text-gray-400">{tc.sha256_detections}/{tc.sha256_total} engines</div>
        </div>

        {/* Threat Score */}
        <div className="p-4 bg-gray-50 rounded-lg border border-gray-200 text-center">
          <div className={`text-3xl font-black ${tc.threat_score > 50 ? 'text-red-600' : tc.threat_score > 20 ? 'text-orange-500' : 'text-green-600'}`}>
            {tc.threat_score.toFixed(0)}
          </div>
          <div className="text-xs text-gray-500 mt-1">Threat Score</div>
          <div className="text-xs text-gray-400">/ 100</div>
        </div>

        {/* Known Family */}
        <div className="p-4 bg-gray-50 rounded-lg border border-gray-200 text-center">
          <div className={`text-sm font-black ${tc.known_family ? 'text-red-600' : 'text-gray-400'}`}>
            {tc.known_family || 'None'}
          </div>
          <div className="text-xs text-gray-500 mt-1">Known Family</div>
          <div className="text-xs text-gray-400">{tc.campaign || 'No campaign'}</div>
        </div>

        {/* IOC Count */}
        <div className="p-4 bg-gray-50 rounded-lg border border-gray-200 text-center">
          <div className={`text-3xl font-black ${(tc.malicious_ips.length + tc.suspicious_domains.length) > 0 ? 'text-red-600' : 'text-green-600'}`}>
            {tc.malicious_ips.length + tc.suspicious_domains.length}
          </div>
          <div className="text-xs text-gray-500 mt-1">Malicious IOCs</div>
          <div className="text-xs text-gray-400">{tc.ioc_reputation.length} total checked</div>
        </div>
      </div>

      {/* VT progress bar */}
      {tc.sha256_total > 0 && (
        <div className="px-5 pb-4">
          <div className="flex items-center justify-between text-xs text-gray-500 mb-1">
            <span>VirusTotal Consensus</span>
            <span>{tc.sha256_detections} of {tc.sha256_total} engines detect as malicious</span>
          </div>
          <div className="w-full h-2.5 bg-gray-200 rounded-full overflow-hidden">
            <div className={`h-full ${vtBg} rounded-full transition-all`} style={{ width: `${vtRatio * 100}%` }} />
          </div>
          {tc.vt_malicious_vendors.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1">
              {tc.vt_malicious_vendors.slice(0, 6).map(v => (
                <span key={v} className="text-xs bg-red-50 text-red-700 border border-red-200 px-1.5 py-0.5 rounded">
                  {v}
                </span>
              ))}
              {tc.vt_malicious_vendors.length > 6 && (
                <span className="text-xs text-gray-400">+{tc.vt_malicious_vendors.length - 6} more</span>
              )}
            </div>
          )}
        </div>
      )}
    </SocCard>
  );
}

// ─── Panel: IOC Reputation Table ─────────────────────────────────────────────

function IOCTable({ data }: { data: FraudCardData }) {
  const tc = data.threat_correlation;
  const iocs: IOCReputation[] = tc?.ioc_reputation || [];
  const [filter, setFilter] = useState<'all' | 'malicious' | 'suspicious'>('all');

  const filtered = iocs.filter(ioc =>
    filter === 'all' || ioc.reputation === filter
  );

  return (
    <SocCard>
      <SectionHeader
        icon={<Database className="h-4 w-4" />}
        title="IOC Reputation"
        subtitle="Per-indicator threat intelligence results"
        badge={
          <div className="flex gap-1">
            {(['all', 'malicious', 'suspicious'] as const).map(f => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`text-xs px-2 py-0.5 rounded capitalize ${
                  filter === f ? 'bg-blue-700 text-white' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
                }`}
              >
                {f}
              </button>
            ))}
          </div>
        }
      />
      {filtered.length === 0 ? (
        <div className="p-6 text-center">
          <CheckCircle2 className="h-8 w-8 text-green-400 mx-auto mb-2" />
          <p className="text-sm text-gray-500">
            {iocs.length === 0
              ? 'No IOCs correlated — configure API keys to enable'
              : `No ${filter} IOCs found`}
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-4 py-2 font-semibold text-gray-600">Indicator</th>
                <th className="text-left px-4 py-2 font-semibold text-gray-600">Type</th>
                <th className="text-left px-4 py-2 font-semibold text-gray-600">Reputation</th>
                <th className="text-left px-4 py-2 font-semibold text-gray-600">Detail</th>
                <th className="text-left px-4 py-2 font-semibold text-gray-600">Source</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {filtered.map((ioc, i) => (
                <tr key={i} className="hover:bg-gray-50 transition-colors group">
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-1.5">
                      <span className="font-mono text-gray-700 truncate max-w-[200px]" title={ioc.indicator}>
                        {ioc.indicator}
                      </span>
                      <CopyBtn value={ioc.indicator} />
                    </div>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="bg-gray-100 text-gray-600 px-1.5 py-0.5 rounded font-mono">{ioc.type}</span>
                  </td>
                  <td className="px-4 py-2.5"><ReputationBadge rep={ioc.reputation} /></td>
                  <td className="px-4 py-2.5 text-gray-500">
                    {ioc.vt_malicious != null && `VT: ${ioc.vt_malicious}/${ioc.vt_total}`}
                    {ioc.abuse_score != null && `Abuse: ${ioc.abuse_score}%`}
                    {ioc.country && ` · ${ioc.country}`}
                    {ioc.otx_pulses != null && `OTX pulses: ${ioc.otx_pulses}`}
                  </td>
                  <td className="px-4 py-2.5"><SourceBadge source={ioc.source} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </SocCard>
  );
}

// ─── Panel: Intelligence Report ───────────────────────────────────────────────

function IntelligenceReportPanel({ data }: { data: FraudCardData }) {
  const intel = data.intelligence_report;
  if (!intel) return null;

  const confidenceColor = intel.confidence === 'High'
    ? 'text-red-600 bg-red-50 border-red-200'
    : intel.confidence === 'Medium'
      ? 'text-orange-600 bg-orange-50 border-orange-200'
      : 'text-gray-600 bg-gray-50 border-gray-200';

  return (
    <SocCard>
      <SectionHeader
        icon={<FileText className="h-4 w-4" />}
        title="AI Intelligence Report"
        subtitle="RAG-grounded analysis — evidence from MITRE, RBI, CERT-In"
        badge={
          <span className={`text-xs px-2 py-0.5 rounded border font-bold uppercase ${confidenceColor}`}>
            {intel.confidence} confidence
          </span>
        }
      />
      <div className="p-5 space-y-5">
        {/* Narrative */}
        <div>
          <div className="text-xs text-gray-500 uppercase tracking-wide font-semibold mb-2">Executive Narrative</div>
          <p className="text-sm text-gray-800 leading-relaxed bg-blue-50 border border-blue-100 rounded-lg p-3">
            {intel.plain_english_narrative}
          </p>
        </div>

        {/* Fraud Objective */}
        {intel.fraud_objective && (
          <div className="flex items-start gap-2 p-3 bg-red-50 border border-red-200 rounded-lg">
            <AlertOctagon className="h-4 w-4 text-red-600 flex-shrink-0 mt-0.5" />
            <div>
              <div className="text-xs font-semibold text-red-700 uppercase tracking-wide mb-0.5">Fraud Objective</div>
              <p className="text-sm text-red-800">{intel.fraud_objective}</p>
            </div>
          </div>
        )}

        {/* Grid: Affected Apps + MITRE */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {intel.affected_banking_apps.length > 0 && (
            <div>
              <div className="text-xs text-gray-500 uppercase tracking-wide font-semibold mb-2">Affected Banking Apps</div>
              <div className="space-y-1">
                {intel.affected_banking_apps.map(app => (
                  <div key={app} className="flex items-center gap-2 px-2.5 py-1.5 bg-gray-50 rounded border border-gray-200">
                    <Shield className="h-3 w-3 text-red-500 flex-shrink-0" />
                    <span className="text-xs font-mono text-gray-700">{app}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {intel.mitre_techniques_used.length > 0 && (
            <div>
              <div className="text-xs text-gray-500 uppercase tracking-wide font-semibold mb-2">MITRE Techniques</div>
              <div className="space-y-1">
                {intel.mitre_techniques_used.map(tech => (
                  <div key={tech} className="flex items-center gap-2 px-2.5 py-1.5 bg-gray-50 rounded border border-gray-200">
                    <Target className="h-3 w-3 text-blue-500 flex-shrink-0" />
                    <span className="text-xs font-mono text-gray-700">{tech}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Banking Impact */}
        {intel.banking_impact_assessment && (
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wide font-semibold mb-2">Banking Impact Assessment</div>
            <p className="text-sm text-gray-700 leading-relaxed">{intel.banking_impact_assessment}</p>
          </div>
        )}

        {/* CERT-In Recommendations */}
        {intel.cert_in_recommendations.length > 0 && (
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wide font-semibold mb-2">CERT-In Recommendations</div>
            <div className="space-y-1.5">
              {intel.cert_in_recommendations.map((rec, i) => (
                <div key={i} className="flex items-start gap-2 text-sm">
                  <span className="flex-shrink-0 w-5 h-5 rounded-full bg-blue-700 text-white text-xs flex items-center justify-center font-bold mt-0.5">{i + 1}</span>
                  <span className="text-gray-700">{rec}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Customer Advisory */}
        <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg">
          <div className="text-xs font-semibold text-amber-700 uppercase tracking-wide mb-1">Customer Advisory Draft</div>
          <p className="text-sm text-amber-900">{intel.customer_advisory_draft}</p>
        </div>

        {/* Analysis Note */}
        {intel.analysis_note && (
          <div className="flex items-center gap-1.5 text-xs text-gray-400">
            <Info className="h-3.5 w-3.5" />
            {intel.analysis_note}
          </div>
        )}
      </div>
    </SocCard>
  );
}

// ─── Panel: FRS Breakdown ─────────────────────────────────────────────────────

function FRSBreakdownPanel({ data }: { data: FraudCardData }) {
  const frs = data.frs_breakdown;
  const score = data.final_risk_score;
  const band = data.risk_band;

  const bandColor = band === 'Critical' ? 'text-red-600'
    : band === 'High Risk' ? 'text-orange-500'
    : band === 'Suspicious' ? 'text-yellow-600'
    : 'text-green-600';

  const components = frs ? [
    { label: 'STEI', subtitle: 'Static Threat Exposure', value: frs.stei, max: 100, color: 'bg-red-500', weight: '25%' },
    { label: 'Dynamic', subtitle: 'Runtime Behavior', value: frs.dynamic, max: 100, color: 'bg-purple-500', weight: '35%', unavailable: !frs.dynamic_available },
    { label: 'Correlation', subtitle: 'Threat Intelligence', value: frs.correlation, max: 100, color: 'bg-blue-500', weight: '20%' },
    { label: 'Banking Impact', subtitle: 'BFCI Score', value: frs.banking_impact, max: 100, color: 'bg-orange-500', weight: '20%' },
  ] : [];

  return (
    <SocCard>
      <SectionHeader
        icon={<BarChart2 className="h-4 w-4" />}
        title="Fraud Risk Score Breakdown"
        subtitle={frs?.formula_used === 'full_frs' ? 'FRS = 0.25×STEI + 0.35×Dynamic + 0.20×Correlation + 0.20×Banking' : 'FRS = 0.50×STEI + 0.25×Correlation + 0.25×Banking (static-only mode)'}
      />
      <div className="p-5">
        <div className="flex items-center gap-4 mb-6">
          <div className={`text-6xl font-black leading-none ${bandColor}`}>{score.toFixed(0)}</div>
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wide">Final Risk Score</div>
            <div className={`text-lg font-bold mt-1 ${bandColor}`}>{band}</div>
            <div className="text-xs text-gray-400 mt-0.5">Confidence: {data.confidence?.toFixed(0) ?? 70}%</div>
          </div>
        </div>

        <div className="space-y-4">
          {components.map(c => (
            <div key={c.label}>
              <div className="flex items-center justify-between mb-1">
                <div>
                  <span className="text-sm font-semibold text-gray-800">{c.label}</span>
                  <span className="text-xs text-gray-500 ml-2">{c.subtitle}</span>
                  {c.unavailable && (
                    <span className="ml-2 text-xs bg-gray-100 text-gray-500 px-1.5 py-0.5 rounded">
                      Not Available
                    </span>
                  )}
                </div>
                <div className="text-right">
                  <span className="text-sm font-bold text-gray-800">{c.value.toFixed(1)}</span>
                  <span className="text-xs text-gray-400"> / 100 × {c.weight}</span>
                </div>
              </div>
              <div className="w-full h-2.5 bg-gray-200 rounded-full overflow-hidden">
                <div
                  className={`h-full ${c.unavailable ? 'bg-gray-300' : c.color} rounded-full transition-all`}
                  style={{ width: `${Math.min(c.value, 100)}%` }}
                />
              </div>
            </div>
          ))}
        </div>

        {frs && !frs.dynamic_available && (
          <div className="mt-4 flex items-start gap-2 p-3 bg-blue-50 border border-blue-100 rounded-lg">
            <Info className="h-3.5 w-3.5 text-blue-500 flex-shrink-0 mt-0.5" />
            <p className="text-xs text-blue-700">
              Dynamic analysis not available. Dynamic weight (35%) redistributed to Static analysis (50%).
              Configure MobSF Docker to enable full FRS formula.
            </p>
          </div>
        )}

        {data.recommended_action && (
          <div className={`mt-4 p-3 rounded-lg border text-sm font-medium ${
            band === 'Critical' ? 'bg-red-50 border-red-200 text-red-800'
            : band === 'High Risk' ? 'bg-orange-50 border-orange-200 text-orange-800'
            : band === 'Suspicious' ? 'bg-yellow-50 border-yellow-200 text-yellow-800'
            : 'bg-green-50 border-green-200 text-green-800'
          }`}>
            <div className="text-xs uppercase tracking-wide font-bold mb-1">Recommended Action</div>
            {data.recommended_action}
          </div>
        )}
      </div>
    </SocCard>
  );
}

// ─── Panel: MITRE ATT&CK Matrix ──────────────────────────────────────────────

const MITRE_TACTICS = [
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0005', name: 'Defense Evasion' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0011', name: 'C2' },
  { id: 'TA0032', name: 'Discovery' },
  { id: 'TA0040', name: 'Impact' },
];

const TECHNIQUE_TACTIC_MAP: Record<string, string> = {
  'T1411': 'TA0009', 'T1412': 'TA0009', 'T1430': 'TA0009',
  'T1444': 'TA0005', 'T1406': 'TA0005', 'T1407': 'TA0005',
  'T1516': 'TA0040', 'T1603': 'TA0002',
  'T1437': 'TA0011', 'T1418': 'TA0032',
};

function MitreMatrix({ data }: { data: FraudCardData }) {
  const intel = data.intelligence_report;
  const techniqueIds = new Set(
    (intel?.mitre_techniques_used || []).map(t => t.split(' ')[0].trim())
  );

  return (
    <SocCard>
      <SectionHeader
        icon={<Target className="h-4 w-4" />}
        title="MITRE ATT&CK for Mobile — Matrix View"
        subtitle="Techniques mapped to this APK's behavior"
      />
      <div className="p-5">
        <div className="grid grid-cols-7 gap-1.5">
          {MITRE_TACTICS.map(tactic => {
            const tacticTechs = Object.entries(TECHNIQUE_TACTIC_MAP)
              .filter(([, ta]) => ta === tactic.id)
              .map(([tid]) => tid);
            const activeTechs = tacticTechs.filter(t => techniqueIds.has(t));

            return (
              <div key={tactic.id} className="flex flex-col gap-1">
                <div className="text-center text-xs font-semibold text-white bg-blue-800 rounded py-1 px-0.5 leading-tight">
                  {tactic.name}
                </div>
                {tacticTechs.map(tech => (
                  <div
                    key={tech}
                    className={`text-center text-xs rounded py-1 px-0.5 border font-mono transition-colors ${
                      activeTechs.includes(tech)
                        ? 'bg-red-100 border-red-300 text-red-700 font-bold'
                        : 'bg-gray-50 border-gray-200 text-gray-400'
                    }`}
                    title={tech}
                  >
                    {tech}
                  </div>
                ))}
              </div>
            );
          })}
        </div>
        <div className="mt-3 flex items-center gap-4 text-xs text-gray-400">
          <div className="flex items-center gap-1"><div className="w-3 h-3 bg-red-100 border border-red-300 rounded" /><span>Active technique</span></div>
          <div className="flex items-center gap-1"><div className="w-3 h-3 bg-gray-50 border border-gray-200 rounded" /><span>Not matched</span></div>
        </div>
      </div>
    </SocCard>
  );
}

// ─── Panel: MobSF Mode Info ───────────────────────────────────────────────────

function AnalysisModeCard({ data }: { data: FraudCardData }) {
  const isMobsf = data.analysis_mode === 'mobsf';

  return (
    <SocCard>
      <SectionHeader icon={<Activity className="h-4 w-4" />} title="Analysis Engine" />
      <div className="p-4 grid grid-cols-2 gap-3">
        <div className={`p-3 rounded-lg border ${isMobsf ? 'bg-green-50 border-green-200' : 'bg-gray-50 border-gray-200'}`}>
          <div className="flex items-center gap-2 mb-1">
            {isMobsf
              ? <CheckCircle2 className="h-4 w-4 text-green-500" />
              : <XCircle className="h-4 w-4 text-gray-300" />}
            <span className="text-sm font-semibold text-gray-800">MobSF</span>
          </div>
          <p className="text-xs text-gray-500">
            {isMobsf
              ? `Active — Scan hash: ${data.mobsf_scan_hash?.slice(0, 12) || 'N/A'}`
              : 'Not available — Start Docker container'}
          </p>
        </div>
        <div className={`p-3 rounded-lg border ${!isMobsf ? 'bg-blue-50 border-blue-200' : 'bg-gray-50 border-gray-200'}`}>
          <div className="flex items-center gap-2 mb-1">
            {!isMobsf
              ? <CheckCircle2 className="h-4 w-4 text-blue-500" />
              : <Info className="h-4 w-4 text-gray-300" />}
            <span className="text-sm font-semibold text-gray-800">Androguard</span>
          </div>
          <p className="text-xs text-gray-500">
            {!isMobsf ? 'Active — Fallback mode' : 'Standby — MobSF takes priority'}
          </p>
        </div>
      </div>
      {isMobsf && data.appsec_score != null && (
        <div className="px-4 pb-4">
          <div className="flex items-center justify-between text-xs text-gray-500 mb-1">
            <span>MobSF AppSec Score</span>
            <span className="font-bold text-gray-800">{data.appsec_score}</span>
          </div>
        </div>
      )}
    </SocCard>
  );
}

// ─── Export Panel ─────────────────────────────────────────────────────────────

function ExportPanel({ data }: { data: FraudCardData }) {
  const [toast, setToast] = useState<string | null>(null);
  const show = (msg: string) => { setToast(msg); setTimeout(() => setToast(null), 2500); };

  const stixUrl = `${API_BASE}/report/stix/${data.sha256}`;
  const iocsUrl = `${API_BASE}/report/iocs/${data.sha256}`;

  // These endpoints require a Bearer token, so they cannot be plain <a href>
  // links — the browser would not attach the Authorization header.
  const exportFile = async (url: string, filename: string) => {
    try {
      await downloadAuthed(url, filename);
      show('Export downloaded');
    } catch (e) {
      show(e instanceof Error ? e.message : 'Export failed');
    }
  };

  return (
    <SocCard className="relative">
      <SectionHeader icon={<FileText className="h-4 w-4" />} title="Export & Share" />
      <div className="p-4 grid grid-cols-2 gap-2">
        <button
          onClick={() => exportFile(stixUrl, `sudarshan_stix_${data.sha256.slice(0, 12)}.json`)}
          className="flex items-center gap-1.5 px-3 py-2.5 text-xs font-medium text-gray-700 bg-gray-50 border border-gray-200 rounded-lg hover:bg-blue-50 hover:border-blue-300 hover:text-blue-700 transition-colors"
        >
          <Globe className="h-3.5 w-3.5" />
          STIX 2.1 Bundle
          <ExternalLink className="h-2.5 w-2.5 ml-auto" />
        </button>
        <button
          onClick={() => exportFile(iocsUrl, `sudarshan_iocs_${data.sha256.slice(0, 12)}.csv`)}
          className="flex items-center gap-1.5 px-3 py-2.5 text-xs font-medium text-gray-700 bg-gray-50 border border-gray-200 rounded-lg hover:bg-blue-50 hover:border-blue-300 hover:text-blue-700 transition-colors"
        >
          <Database className="h-3.5 w-3.5" />
          IOC CSV Export
          <ExternalLink className="h-2.5 w-2.5 ml-auto" />
        </button>
        <button
          onClick={() => { navigator.clipboard.writeText(data.sha256); show('SHA256 copied'); }}
          className="flex items-center gap-1.5 px-3 py-2.5 text-xs font-medium text-gray-700 bg-gray-50 border border-gray-200 rounded-lg hover:bg-blue-50 hover:border-blue-300 hover:text-blue-700 transition-colors"
        >
          <Copy className="h-3.5 w-3.5" />
          Copy SHA256
        </button>
        <button
          onClick={() => {
            const blob = new Blob([JSON.stringify({ sha256: data.sha256, family: data.family_classification, score: data.final_risk_score, band: data.risk_band, intelligence: data.intelligence_report }, null, 2)], { type: 'application/json' });
            const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
            a.download = `sudarshan_${data.sha256.slice(0, 12)}.json`; a.click();
          }}
          className="flex items-center gap-1.5 px-3 py-2.5 text-xs font-medium text-gray-700 bg-gray-50 border border-gray-200 rounded-lg hover:bg-blue-50 hover:border-blue-300 hover:text-blue-700 transition-colors"
        >
          <FileText className="h-3.5 w-3.5" />
          JSON Report
        </button>
      </div>
      {toast && (
        <div className="absolute bottom-2 left-2 right-2 bg-blue-800 text-white text-xs p-2 rounded shadow-lg z-10 text-center">
          {toast}
        </div>
      )}
    </SocCard>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ThreatIntelView({ data }: { data: FraudCardData | null }) {
  if (!data) return <Navigate to="/" />;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="bg-white border border-gray-200 rounded-xl shadow-sm px-5 py-3">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-base font-bold text-gray-900 flex items-center gap-2">
              <Globe className="h-5 w-5 text-blue-700" />
              Threat Intelligence
            </h1>
            <p className="text-xs text-gray-500 mt-0.5 font-mono">
              {data.sha256} · {data.package_name}
            </p>
          </div>
          <div className="flex items-center gap-2">
            {data.threat_correlation?.available ? (
              <span className="flex items-center gap-1.5 text-xs bg-green-100 text-green-700 border border-green-200 px-2.5 py-1 rounded-full font-medium">
                <span className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse" />
                Live TI Active
              </span>
            ) : (
              <span className="flex items-center gap-1.5 text-xs bg-gray-100 text-gray-500 border border-gray-200 px-2.5 py-1 rounded-full font-medium">
                <span className="w-1.5 h-1.5 bg-gray-400 rounded-full" />
                Static Mode
              </span>
            )}
            <span className={`text-xs px-2.5 py-1 rounded-full font-bold uppercase border ${
              data.risk_band === 'Critical' ? 'bg-red-100 text-red-700 border-red-200'
              : data.risk_band === 'High Risk' ? 'bg-orange-100 text-orange-700 border-orange-200'
              : data.risk_band === 'Suspicious' ? 'bg-yellow-100 text-yellow-700 border-yellow-200'
              : 'bg-green-100 text-green-700 border-green-200'
            }`}>
              {data.risk_band}
            </span>
          </div>
        </div>
      </div>

      {/* Row 1: FRS Breakdown + Mode + Export */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2"><FRSBreakdownPanel data={data} /></div>
        <div className="flex flex-col gap-4">
          <AnalysisModeCard data={data} />
          <ExportPanel data={data} />
        </div>
      </div>

      {/* Row 2: Correlation Overview */}
      <CorrelationOverview data={data} />

      {/* Row 3: IOC Table */}
      <IOCTable data={data} />

      {/* Row 4: Intelligence Report */}
      <IntelligenceReportPanel data={data} />

      {/* Row 5: MITRE Matrix */}
      <MitreMatrix data={data} />
    </div>
  );
}
