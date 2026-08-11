import type { ReactNode } from 'react';
import type { FraudCardData } from '../../../App';
import {
  buildFrsAxisTransparency,
  buildThreatInfluenceView,
} from '../../../lib/scoreInfluenceModel';
import {
  PROVIDER_STATUS_LABEL,
  providerUiStatus,
  type MergedThreatIntel,
} from '../../../lib/intelPayloadMerge';
import { DetailSection, FlowSteps, FrsAxisTransparencyTable } from './InfluenceDetailShell';

function ProviderStatusBadge({ status }: { status: ReturnType<typeof providerUiStatus> }) {
  const label = PROVIDER_STATUS_LABEL[status?.label] || status?.label || 'STANDBY';
  const cls =
    status?.tone === 'critical'
      ? 'bg-red-50 text-red-800 border-red-200'
      : status?.tone === 'info'
        ? 'bg-blue-50 text-blue-800 border-blue-200'
        : 'bg-slate-50 text-slate-700 border-slate-200';
  return (
    <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${cls}`}>{label}</span>
  );
}

function ProviderCard({
  title,
  status,
  children,
}: {
  title: string;
  status: ReturnType<typeof providerUiStatus>;
  children: ReactNode;
}) {
  return (
    <div className="rounded-lg border border-slate-200 p-3">
      <div className="flex items-center justify-between gap-2 mb-2">
        <span className="text-sm font-semibold text-slate-900">{title}</span>
        <ProviderStatusBadge status={status} />
      </div>
      <div className="text-xs text-slate-600 space-y-1">{children}</div>
    </div>
  );
}

export default function ThreatIntelligenceDetail({
  data,
  merged,
  fetchError,
}: {
  data: FraudCardData;
  merged: MergedThreatIntel;
  fetchState: 'idle' | 'loading' | 'error';
  fetchError: string | null;
}) {
  const view = buildThreatInfluenceView(data, merged);
  const frsRows = buildFrsAxisTransparency('threat_intel', data);
  const corr = data.threat_correlation;
  const iocs = corr?.ioc_reputation ?? [];

  const vtStatus = providerUiStatus(merged?.status);
  const axisExcluded = !view.axisIncluded;
  const matchedRule = data.technical_view?.matched_rule || 'Rule engine match';
  const familySignals = data.family_classification && data.family_classification !== 'Unknown' ? [data.family_classification] : [];

  return (
    <div className="space-y-6">
      {fetchError && (
        <div className="rounded-lg border border-amber-200 bg-amber-50/80 px-3 py-2 text-xs text-amber-900">
          Intelligence API: {fetchError}. Showing case-persisted correlation data only.
        </div>
      )}

      <DetailSection title="Reputation summary">
        <div className="space-y-3">
          <ProviderCard title="Threat Intelligence Summary" status={vtStatus}>
            <p>
              Threat Score:{' '}
              <span className="font-mono font-semibold text-slate-900">
                {view.threatScore}
              </span>
            </p>
          </ProviderCard>
        </div>
      </DetailSection>

      <DetailSection title="Indicators investigated">
        {iocs.length === 0 && !data.sha256 ? (
          <p className="text-sm text-slate-600">No IOCs recorded on this case.</p>
        ) : (
          <ul className="space-y-2">
            {iocs.map((ioc: any, idx: number) => (
              <li key={idx} className="text-xs font-mono bg-slate-50 p-2 rounded border border-slate-200">
                {ioc.value || ioc.indicator || String(ioc)} ({ioc.type || 'IOC'}) - {ioc.reputation || 'Recorded'}
              </li>
            ))}
          </ul>
        )}
      </DetailSection>

      <DetailSection title="Malware family classification">
        <p className="text-xs text-slate-500 mb-2">Rule-based / deterministic - not an LLM verdict.</p>
        <div className="rounded-lg border border-slate-200 p-3 text-sm space-y-2">
          <div>
            <span className="text-slate-500 text-xs">Family</span>
            <div className="font-bold text-slate-900">{data.family_classification || 'Not Classified'}</div>
          </div>
          <div>
            <span className="text-slate-500 text-xs">Matched rule</span>
            <div className="font-mono text-slate-800">{matchedRule}</div>
          </div>
          {familySignals.length > 0 && (
            <div>
              <span className="text-slate-500 text-xs">Evidence flags</span>
              <ul className="text-xs text-slate-700 list-disc pl-4 mt-1">
                {familySignals.map((s: string) => (
                  <li key={s}>{s}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </DetailSection>

      <DetailSection title="How it influenced FRS">
        <FlowSteps
          steps={[
            `Threat intelligence / correlation score: ${view.threatScore.toFixed(1)} / 100`,
            'Correlation axis',
            axisExcluded
              ? 'Excluded from FRS - unavailable or not used'
              : 'Included in FRS weighting',
          ]}
        />
        {corr?.threat_score_sources?.map((line: string) => (
          <p key={line} className="text-xs text-slate-600 mt-2 font-mono">
            {line}
          </p>
        ))}
      </DetailSection>

      <DetailSection title="What this means">
        <p className="text-sm text-slate-700 leading-relaxed">
          Threat intelligence indicates whether observable indicators have reputation or campaign associations in
          external sources. It does not by itself prove that every behavior was executed on the device.
        </p>
      </DetailSection>

      <DetailSection title="FRS contribution">
        <FrsAxisTransparencyTable rows={frsRows} />
      </DetailSection>
    </div>
  );
}
