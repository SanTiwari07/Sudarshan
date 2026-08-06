import { Target } from 'lucide-react';
import type { FraudCardData } from '../../App';
import type { IntelApiPayload } from '../../lib/threatIntelModel';
import { IntelCard, IntelCardBody, IntelSectionHeader } from './IntelCard';
import { INTEL } from './intelTokens';

export default function CampaignAttributionPanel({
  data,
  intel,
}: {
  data: FraudCardData;
  intel: IntelApiPayload;
}) {
  const tc = data.threat_correlation;
  const campaign =
    intel.campaign && !/^not attributed$/i.test(intel.campaign) && intel.campaign !== 'None'
      ? intel.campaign
      : tc?.campaign && tc.campaign !== 'None'
        ? tc.campaign
        : 'Unknown';

  const fields: { label: string; value: string }[] = [
    { label: 'Campaign', value: campaign },
    { label: 'Threat Actor', value: 'Unknown' },
    {
      label: 'Objective',
      value: data.intelligence_report?.fraud_objective || (data.targets_indian_banks ? 'Financial fraud (banking targeting observed)' : 'Unknown'),
    },
    {
      label: 'Distribution Method',
      value: intel.alienvault.pulse_count > 0 ? `OTX pulse correlation (${intel.alienvault.pulse_count} pulses)` : 'Unknown',
    },
    {
      label: 'Known Variants',
      value: tc?.known_family || intel.virus_total.suggested_label || 'Unknown',
    },
    { label: 'First Seen', value: 'Unknown' },
    { label: 'Last Seen', value: 'Unknown' },
    {
      label: 'Countries',
      value:
        tc?.ioc_reputation
          ?.map((i) => i.country)
          .filter(Boolean)
          .join(', ') || 'Unknown',
    },
    { label: 'Target Region', value: data.targets_indian_banks ? 'India (banking packages)' : 'Unknown' },
    {
      label: 'Confidence',
      value: tc?.correlation_confidence
        ? `${Math.round(tc.correlation_confidence * 100)}% (correlation engine)`
        : intel.confidence
          ? `${Math.round(intel.confidence)}% (case confidence)`
          : 'Unknown',
    },
  ];

  return (
    <IntelCard>
      <IntelSectionHeader
        icon={<Target className="h-4 w-4" />}
        title="Campaign attribution"
        subtitle="Only attributed fields shown; otherwise Unknown"
      />
      <IntelCardBody>
        <dl className="grid sm:grid-cols-2 gap-x-8 gap-y-4 text-xs">
          {fields.map((f) => (
            <div key={f.label} className="border-b border-slate-100 pb-3">
              <dt className={INTEL.caption}>{f.label}</dt>
              <dd className="mt-1 text-sm text-slate-900 font-medium leading-snug">{f.value}</dd>
            </div>
          ))}
        </dl>
        {campaign === 'Unknown' && (
          <p className={`${INTEL.caption} mt-4`}>
            Campaign not identified — no OTX or correlator attribution for this case.
          </p>
        )}
      </IntelCardBody>
    </IntelCard>
  );
}
