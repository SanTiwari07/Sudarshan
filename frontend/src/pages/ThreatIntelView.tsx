import { useState } from 'react';
import { Navigate } from 'react-router-dom';
import {
  Globe, CheckCircle2, FileText, Database, ExternalLink
} from 'lucide-react';
import type { FraudCardData, IOCReputation } from '../App';
import { API_BASE, downloadAuthed } from '../config';
import SocCard from '../components/ui/Card';
import SectionHeader from '../components/ui/SectionHeader';
import Badge from '../components/ui/Badge';
import CopyButton from '../components/ui/CopyButton';

// ─── Panel: Correlation Overview ─────────────────────────────────────────────

function CorrelationOverview({ data }: { data: FraudCardData }) {
  const tc = data.threat_correlation;

  if (!tc) {
    return (
      <SocCard>
        <SectionHeader icon={<Globe className="h-4 w-4" />} title="Threat Intelligence Correlation" />
        <div className="p-8 text-center">
          <Database className="h-10 w-10 text-slate-300 mx-auto mb-3" />
          <p className="text-sm font-medium text-slate-600">No Threat Intelligence Available</p>
          <p className="text-xs text-slate-400 mt-1 max-w-xs mx-auto">
            Configure API keys in backend environment to enable live correlation.
          </p>
        </div>
      </SocCard>
    );
  }

  const vtRatio = tc.vt_detection_ratio;
  const vtColor = vtRatio > 0.5 ? 'text-red-600' : vtRatio > 0.1 ? 'text-orange-500' : 'text-emerald-600';
  const vtBg = vtRatio > 0.5 ? 'bg-red-500' : vtRatio > 0.1 ? 'bg-orange-500' : 'bg-emerald-500';

  return (
    <SocCard>
      <SectionHeader
        icon={<Globe className="h-4 w-4" />}
        title="Threat Intelligence Correlation"
        subtitle={`Sources: ${tc.sources_queried.join(', ') || 'No external sources configured'}`}
        badge={
          tc.available
            ? <Badge label="Live Intelligence Active" className="bg-emerald-100 text-emerald-700 border border-emerald-200" />
            : <Badge label="Static Mode" className="bg-slate-100 text-slate-500 border border-slate-200" />
        }
      />
      <div className="p-5 grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* VT Detection */}
        <div className="p-4 bg-slate-50 rounded-lg border border-slate-200 text-center">
          <div className={`text-3xl font-black ${vtColor}`}>{(vtRatio * 100).toFixed(0)}%</div>
          <div className="text-xs text-slate-500 mt-1">VT Detection Ratio</div>
          <div className="text-xs text-slate-400">{tc.sha256_detections}/{tc.sha256_total} engines</div>
        </div>

        {/* Threat Score */}
        <div className="p-4 bg-slate-50 rounded-lg border border-slate-200 text-center">
          <div className={`text-3xl font-black ${tc.threat_score > 50 ? 'text-red-600' : tc.threat_score > 20 ? 'text-orange-500' : 'text-emerald-600'}`}>
            {tc.threat_score.toFixed(0)}
          </div>
          <div className="text-xs text-slate-500 mt-1">Threat Score</div>
          <div className="text-xs text-slate-400">/ 100</div>
        </div>

        {/* Known Family */}
        <div className="p-4 bg-slate-50 rounded-lg border border-slate-200 text-center">
          <div className={`text-sm font-black ${tc.known_family ? 'text-red-600' : 'text-slate-400'}`}>
            {tc.known_family || 'None'}
          </div>
          <div className="text-xs text-slate-500 mt-1">Known Family</div>
          <div className="text-xs text-slate-400">{tc.campaign || 'No campaign'}</div>
        </div>

        {/* IOC Count */}
        <div className="p-4 bg-slate-50 rounded-lg border border-slate-200 text-center">
          <div className={`text-3xl font-black ${(tc.malicious_ips.length + tc.suspicious_domains.length) > 0 ? 'text-red-600' : 'text-emerald-600'}`}>
            {tc.malicious_ips.length + tc.suspicious_domains.length}
          </div>
          <div className="text-xs text-slate-500 mt-1">Malicious IOCs</div>
          <div className="text-xs text-slate-400">{tc.ioc_reputation.length} total checked</div>
        </div>
      </div>

      {/* VT progress bar */}
      {tc.sha256_total > 0 && (
        <div className="px-5 pb-4">
          <div className="flex items-center justify-between text-xs text-slate-500 mb-1">
            <span>VirusTotal Consensus</span>
            <span>{tc.sha256_detections} of {tc.sha256_total} engines detect as malicious</span>
          </div>
          <div className="w-full h-2.5 bg-slate-200 rounded-full overflow-hidden">
            <div className={`h-full ${vtBg} rounded-full transition-all`} style={{ width: `${vtRatio * 100}%` }} />
          </div>
        </div>
      )}
    </SocCard>
  );
}

// ─── Panel: IOC Reputation Table ─────────────────────────────────────────────

function IOCTable({ data }: { data: FraudCardData }) {
  const tc = data.threat_correlation;
  const iocs: IOCReputation[] = tc?.ioc_reputation || [];

  return (
    <SocCard>
      <SectionHeader
        icon={<Database className="h-4 w-4" />}
        title="IOC Reputation Registry"
        subtitle={`${iocs.length} correlated indicator(s)`}
      />
      {iocs.length === 0 ? (
        <div className="p-6 text-center">
          <CheckCircle2 className="h-8 w-8 text-emerald-400 mx-auto mb-2" />
          <p className="text-sm text-slate-500">No correlated IOC indicators recorded.</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="bg-slate-50 border-b border-slate-200">
              <tr>
                <th className="text-left px-4 py-2 font-semibold text-slate-600">Indicator</th>
                <th className="text-left px-4 py-2 font-semibold text-slate-600">Type</th>
                <th className="text-left px-4 py-2 font-semibold text-slate-600">Reputation</th>
                <th className="text-left px-4 py-2 font-semibold text-slate-600">Source</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {iocs.map((ioc, i) => (
                <tr key={i} className="hover:bg-slate-50 transition-colors">
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-1.5 font-mono text-slate-700">
                      <span>{ioc.indicator}</span>
                      <CopyButton value={ioc.indicator} />
                    </div>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="bg-slate-100 text-slate-600 px-1.5 py-0.5 rounded font-mono">{ioc.type}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    <Badge label={ioc.reputation} variant="risk" />
                  </td>
                  <td className="px-4 py-2.5 text-slate-500">{ioc.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </SocCard>
  );
}

// ─── Export Panel ─────────────────────────────────────────────────────────────

function ExportPanel({ data }: { data: FraudCardData }) {
  const [status, setStatus] = useState<string | null>(null);

  const exportStix = async () => {
    try {
      setStatus('Exporting STIX 2.1 bundle...');
      await downloadAuthed(`${API_BASE}/report/stix/${data.sha256}`, `sudarshan_stix_${data.sha256.slice(0, 12)}.json`);
      setStatus('STIX export completed');
    } catch (err: unknown) {
      setStatus(err instanceof Error ? err.message : 'Export failed');
    } setTimeout(() => setStatus(null), 3000);
  };

  const exportIocs = async () => {
    try {
      setStatus('Exporting IOC CSV...');
      await downloadAuthed(`${API_BASE}/report/iocs/${data.sha256}`, `sudarshan_iocs_${data.sha256.slice(0, 12)}.csv`);
      setStatus('IOC export completed');
    } catch (err: unknown) {
      setStatus(err instanceof Error ? err.message : 'Export failed');
    } setTimeout(() => setStatus(null), 3000);
  };

  return (
    <SocCard>
      <SectionHeader icon={<FileText className="h-4 w-4" />} title="Threat Intel Exports" />
      <div className="p-4 grid grid-cols-2 gap-2">
        <button
          onClick={exportStix}
          className="flex items-center justify-between px-3 py-2.5 text-xs font-medium text-slate-700 bg-slate-50 border border-slate-200 rounded-lg hover:bg-blue-50 hover:border-blue-300 hover:text-blue-700 transition-colors"
        >
          <span className="flex items-center gap-1.5"><Globe className="h-3.5 w-3.5" /> STIX 2.1 Bundle</span>
          <ExternalLink className="h-3 w-3" />
        </button>
        <button
          onClick={exportIocs}
          className="flex items-center justify-between px-3 py-2.5 text-xs font-medium text-slate-700 bg-slate-50 border border-slate-200 rounded-lg hover:bg-blue-50 hover:border-blue-300 hover:text-blue-700 transition-colors"
        >
          <span className="flex items-center gap-1.5"><Database className="h-3.5 w-3.5" /> IOC CSV Export</span>
          <ExternalLink className="h-3 w-3" />
        </button>
      </div>
      {status && (
        <div className="px-4 pb-3 text-xs text-blue-700 font-medium">{status}</div>
      )}
    </SocCard>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ThreatIntelView({ data }: { data: FraudCardData | null }) {
  if (!data) return <Navigate to="/" />;

  return (
    <div className="space-y-4">
      <div className="bg-white border border-slate-200 rounded-xl shadow-sm px-5 py-3 flex items-center justify-between">
        <div>
          <h1 className="text-base font-bold text-slate-900 flex items-center gap-2">
            <Globe className="h-5 w-5 text-blue-700" />
            Threat Intelligence Correlation
          </h1>
          <p className="text-xs text-slate-500 mt-0.5 font-mono">
            {data.sha256} · {data.package_name}
          </p>
        </div>
        <Badge label={data.risk_band} variant="risk" />
      </div>

      <CorrelationOverview data={data} />
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          <IOCTable data={data} />
        </div>
        <ExportPanel data={data} />
      </div>
    </div>
  );
}
