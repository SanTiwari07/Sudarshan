import { Database } from 'lucide-react';
import type { IntelApiPayload } from '../../lib/threatIntelModel';
import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import { IntelCard, IntelCardBody, IntelSectionHeader } from './IntelCard';
import { INTEL } from './intelTokens';

type SourceStatus = 'available' | 'matched' | 'unavailable';

type IntelSourceRow = {
  name: string;
  status: SourceStatus;
  detail: string;
};

function buildSources(
  data: FraudCardData,
  intel: IntelApiPayload,
  bundle: InvestigationBundle | null,
): IntelSourceRow[] {
  const staticFindings =
    (data.manifest_findings?.length || 0) + (data.code_findings?.length || 0);
  const runtimeCount = bundle?.counts.runtimeBehaviors ?? 0;
  const mitreCount = data.intelligence_report?.mitre_techniques_used?.length || 0;
  const vt = intel.virus_total;
  const iocCount = intel.iocs?.length || 0;
  const family = intel.malware_family || data.family_classification;

  const staticStatus: SourceStatus =
    staticFindings > 0 ? 'matched' : data.sha256 ? 'available' : 'unavailable';

  let runtimeStatus: SourceStatus = 'unavailable';
  if (data.dynamic_available && runtimeCount > 0) runtimeStatus = 'matched';
  else if (data.dynamic_available) runtimeStatus = 'available';

  const mitreStatus: SourceStatus =
    mitreCount > 0 ? 'matched' : data.intelligence_report ? 'available' : 'unavailable';

  let vtStatus: SourceStatus = 'unavailable';
  if (vt?.available) {
    vtStatus = vt.malicious > 0 ? 'matched' : 'available';
  }

  const iocStatus: SourceStatus = iocCount > 0 ? 'matched' : (intel?.sources_status?.length ?? 0) > 0 ? 'available' : 'unavailable';

  const rulesStatus: SourceStatus =
    family && family !== 'Unknown'
      ? 'matched'
      : data.technical_view?.matched_rule
        ? 'available'
        : 'unavailable';

  return [
    {
      name: 'Static Evidence',
      status: staticStatus,
      detail:
        staticFindings > 0
          ? `${staticFindings} manifest and code findings reviewed`
          : 'Package submitted; limited static findings',
    },
    {
      name: 'Runtime Behaviour',
      status: runtimeStatus,
      detail:
        runtimeStatus === 'matched'
          ? `${runtimeCount} runtime behaviours recorded`
          : data.dynamic_available
            ? 'Sandbox ran; no strong behaviour signals'
            : 'Runtime analysis not available for this case',
    },
    {
      name: 'MITRE ATT&CK',
      status: mitreStatus,
      detail:
        mitreCount > 0
          ? `${mitreCount} techniques mapped to this app`
          : 'No techniques mapped yet',
    },
    {
      name: 'VirusTotal',
      status: vtStatus,
      detail:
        vtStatus === 'unavailable'
          ? 'VirusTotal lookup not available'
          : (vt?.malicious ?? 0) > 0
            ? `${vt?.malicious} vendors flagged this hash`
            : 'Hash seen; no malicious consensus',
    },
    {
      name: 'IOC Correlation',
      status: iocStatus,
      detail:
        iocCount > 0 ? `${iocCount} indicators correlated` : 'No indicators matched external feeds',
    },
    {
      name: 'Malware Family Rules',
      status: rulesStatus,
      detail:
        rulesStatus === 'matched'
          ? `Matched as ${family}`
          : rulesStatus === 'available'
            ? 'Rules ran; family not confirmed'
            : 'No family rule match',
    },
  ];
}

const STATUS_LABEL: Record<SourceStatus, string> = {
  available: 'Available',
  matched: 'Matched',
  unavailable: 'Unavailable',
};

const STATUS_BADGE: Record<SourceStatus, string> = {
  matched: 'bg-blue-50 text-blue-800 border-blue-200',
  available: 'bg-slate-50 text-slate-700 border-slate-200',
  unavailable: 'bg-slate-50 text-slate-400 border-slate-100',
};

export default function IntelligenceSourcesPanel({
  intel,
  data,
  bundle,
}: {
  intel: IntelApiPayload;
  data: FraudCardData;
  bundle: InvestigationBundle | null;
}) {
  const sources = buildSources(data, intel, bundle);

  return (
    <IntelCard>
      <IntelSectionHeader
        icon={<Database className="h-4 w-4" />}
        title="Threat Intelligence Sources"
        subtitle="Where correlations came from - not raw feed metrics"
      />
      <IntelCardBody compact>
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {sources.map((s) => (
            <div
              key={s.name}
              className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm flex flex-col gap-2"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold text-slate-900">{s.name}</span>
                <span
                  className={`text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-md border ${STATUS_BADGE[s.status]}`}
                >
                  {STATUS_LABEL[s.status]}
                </span>
              </div>
              <p className={`${INTEL.caption} leading-relaxed`}>{s.detail}</p>
            </div>
          ))}
        </div>
      </IntelCardBody>
    </IntelCard>
  );
}
