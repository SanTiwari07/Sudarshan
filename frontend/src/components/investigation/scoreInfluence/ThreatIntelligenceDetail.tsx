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
import { DetailSection, FlowSteps, FrsAxisTransparencyTable, MonoBlock } from './InfluenceDetailShell';

function ProviderStatusBadge({ status }: { status: ReturnType<typeof providerUiStatus> }) {
  const label = PROVIDER_STATUS_LABEL[status];
  const cls =
    status === 'available'
      ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
      : status === 'no_result'
        ? 'bg-slate-50 text-slate-700 border-slate-200'
        : status === 'loading'
          ? 'bg-blue-50 text-blue-800 border-blue-200'
          : status === 'error'
            ? 'bg-red-50 text-red-800 border-red-200'
            : 'bg-slate-50 text-slate-500 border-slate-200';
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
  fetchState,
  fetchError,
}: {
  data: FraudCardData;
  merged: MergedThreatIntel;
  fetchState: 'idle' | 'loading' | 'error';
  fetchError: string | null;
}) {
  const view = buildThreatInfluenceView(data, merged);
  const frsRows = buildFrsAxisTransparency(data);
  const corr = data.threat_correlation;
  const iocs = corr?.ioc_reputation ?? [];

  const vtStatus = providerUiStatus('virustotal', merged, fetchState);
  const otxStatus = providerUiStatus('otx', merged, fetchState);
  const abuseStatus = providerUiStatus('abuseipdb', merged, fetchState);

  const axisExcluded = !view.axisIncluded;

  return (
    <div className="space-y-6">
      {fetchError && (
        <div className="rounded-lg border border-amber-200 bg-amber-50/80 px-3 py-2 text-xs text-amber-900">
          Intelligence API: {fetchError}. Showing case-persisted correlation data only.
        </div>
      )}

      <DetailSection title="Reputation summary">
        <div className="space-y-3">
          <ProviderCard title="VirusTotal" status={vtStatus}>
            {merged.virusTotal.available ? (
              <>
                <p>
                  Detections:{' '}
                  <span className="font-mono font-semibold text-slate-900">
                    {merged.virusTotal.malicious}/{merged.virusTotal.total}
                  </span>
                  {merged.virusTotal.ratio > 0 && (
                    <span className="text-slate-500"> ({(merged.virusTotal.ratio * 100).toFixed(1)}%)</span>
                  )}
                </p>
                {merged.virusTotal.vendors?.length > 0 && (
                  <p className="text-slate-500">Malicious vendors: {merged.virusTotal.vendors.slice(0, 5).join(', ')}</p>
                )}
              </>
            ) : (
              <p>Unavailable — this provider did not contribute to the score.</p>
            )}
          </ProviderCard>

          <ProviderCard title="AlienVault OTX" status={otxStatus}>
            {merged.alienvault.available ? (
              <>
                <p>
                  Pulse count:{' '}
                  <span className="font-mono font-semibold">{merged.alienvault.pulse_count}</span>
                </p>
                {merged.alienvault.campaign && merged.alienvault.campaign !== 'None' && (
                  <p>Campaign: {merged.alienvault.campaign}</p>
                )}
              </>
            ) : (
              <p>Unavailable — this provider did not contribute to the score.</p>
            )}
          </ProviderCard>

          <ProviderCard title="AbuseIPDB" status={abuseStatus}>
            {merged.abuseipdb.available ? (
              <>
                <p>
                  Abuse confidence:{' '}
                  <span className="font-mono font-semibold">{merged.abuseipdb.confidence}%</span>
                </p>
                <p>Reports considered: {merged.abuseipdb.reports}</p>
              </>
            ) : (
              <p>Unavailable — this provider did not contribute to the score.</p>
            )}
          </ProviderCard>
        </div>
      </DetailSection>

      <DetailSection title="Indicators investigated">
        {iocs.length === 0 && !data.sha256 ? (
          <p className="text-sm text-slate-600">No IOCs recorded on this case.</p>
        ) : (
          <ul className="space-y-2">
            {data.sha256 && (
              <li className="rounded-lg border border-slate-200 p-2.5 text-xs">
                <div className="font-semibold text-slate-800">SHA-256</div>
                <MonoBlock>{data.sha256}</MonoBlock>
                {corr && corr.sha256_total > 0 && (
                  <p className="mt-1 text-slate-600">
                    VT: {corr.sha256_detections}/{corr.sha256_total}
                  </p>
                )}
              </li>
            )}
            {iocs.map((ioc) => (
              <li key={`${ioc.type}-${ioc.indicator}`} className="rounded-lg border border-slate-200 p-2.5 text-xs">
                <div className="font-semibold text-slate-800">
                  {ioc.type}: <span className="font-mono font-normal">{ioc.indicator}</span>
                </div>
                <p className="text-slate-600 mt-1">
                  {ioc.reputation} — {ioc.source}
                  {ioc.vt_malicious != null && ioc.vt_total != null && (
                    <span className="font-mono"> (VT {ioc.vt_malicious}/{ioc.vt_total})</span>
                  )}
                  {ioc.otx_pulses != null && <span> · OTX pulses {ioc.otx_pulses}</span>}
                  {ioc.abuse_score != null && <span> · Abuse {ioc.abuse_score}%</span>}
                </p>
              </li>
            ))}
            {(corr?.suspicious_domains ?? []).map((d) => (
              <li key={`dom-${d}`} className="text-xs font-mono text-slate-700">
                Domain: {d}
              </li>
            ))}
            {(corr?.malicious_ips ?? []).map((ip) => (
              <li key={`ip-${ip}`} className="text-xs font-mono text-slate-700">
                IP: {ip}
              </li>
            ))}
          </ul>
        )}
      </DetailSection>

      <DetailSection title="Malware family classification">
        <p className="text-xs text-slate-500 mb-2">Rule-based / deterministic — not an LLM verdict.</p>
        <div className="rounded-lg border border-slate-200 p-3 text-sm space-y-2">
          <div>
            <span className="text-slate-500 text-xs">Family</span>
            <div className="font-bold text-slate-900">{view.family}</div>
          </div>
          <div>
            <span className="text-slate-500 text-xs">Matched rule</span>
            <div className="font-mono text-slate-800">{view.matchedRule}</div>
          </div>
          {view.familySignals.length > 0 && (
            <div>
              <span className="text-slate-500 text-xs">Evidence flags</span>
              <ul className="text-xs text-slate-700 list-disc pl-4 mt-1">
                {view.familySignals.map((s) => (
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
            `Threat intelligence / correlation score: ${view.score.toFixed(1)} / 100`,
            'Correlation axis',
            axisExcluded
              ? 'Excluded from FRS — unavailable or not used'
              : view.merged.correlationScore != null
                ? `Included — contributes to weighted FRS`
                : 'Included in FRS weighting',
          ]}
        />
        {corr?.threat_score_sources?.map((line) => (
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
