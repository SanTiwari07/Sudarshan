import {
  ShieldAlert,
  Bug,
  BadgeCheck,
  Radar,
  Compass,
} from 'lucide-react';
import type { IntelApiPayload } from '../../lib/threatIntelModel';
import { campaignStatus } from '../../lib/threatIntelModel';
import type { FraudCardData } from '../../App';
import { riskBandPlainEnglish } from '../../lib/analystCopy';
import { INTEL } from './intelTokens';

type Props = {
  data: FraudCardData;
  intel: IntelApiPayload;
  evidenceConfidence: number;
};

function campaignMatchText(data: FraudCardData, intel: IntelApiPayload): string {
  const campaign = (intel.campaign || '').trim();
  const attributed =
    campaign &&
    !/^not attributed$/i.test(campaign) &&
    campaign !== 'None' &&
    campaign !== 'Unknown';
  if (attributed) return campaign;
  const family = intel.malware_family || data.family_classification;
  if (family && family !== 'Unknown') return `Patterns similar to ${family}`;
  if ((intel.alienvault?.pulse_count ?? 0) > 0) return 'Pulses found - campaign not named';
  return 'No known campaign match';
}

function recommendedActionText(data: FraudCardData): string {
  if (data.recommended_action) return data.recommended_action;
  if (data.final_risk_score >= 80) return 'Block Application';
  if (data.final_risk_score >= 60) return 'Manual Review';
  if (data.targets_indian_banks) return 'Notify Fraud Team';
  return 'Monitor';
}

function SummaryCard({
  icon,
  label,
  value,
  hint,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  hint?: string;
}) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm h-full flex flex-col gap-2">
      <div className="flex items-center gap-2">
        <span className="p-2 rounded-lg bg-slate-100 text-blue-700 shrink-0">{icon}</span>
        <span className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">{label}</span>
      </div>
      <p className="text-sm font-semibold text-slate-900 leading-snug line-clamp-2" title={value}>
        {value}
      </p>
      {hint ? <p className={`${INTEL.caption} mt-auto`}>{hint}</p> : null}
    </div>
  );
}

export default function ThreatIntelHero({ data, intel, evidenceConfidence }: Props) {
  const band = data.risk_band || intel.risk_band || 'Unknown';
  const family = intel.malware_family || data.family_classification || 'Unknown';
  const campaign = campaignStatus(intel);

  return (
    <section className="space-y-5">
      <div className="flex flex-col gap-1">
        <h1 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight">
          How this application compares with known banking threats
        </h1>
        <p className={`${INTEL.meta} max-w-3xl leading-relaxed`}>
          This page correlates verified evidence against known malware families, threat intelligence databases, banking
          attack techniques, and fraud behaviours.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        <SummaryCard
          icon={<ShieldAlert className="h-4 w-4" />}
          label="Threat Level"
          value={band}
          hint={riskBandPlainEnglish(band)}
        />
        <SummaryCard
          icon={<Bug className="h-4 w-4" />}
          label="Malware Family"
          value={family === 'Unknown' ? 'Not classified' : family}
          hint={family === 'Unknown' ? 'No family rule matched' : 'Best match from rules and intel'}
        />
        <SummaryCard
          icon={<BadgeCheck className="h-4 w-4" />}
          label="Evidence Confidence"
          value={`${evidenceConfidence}%`}
          hint="Average across static, runtime, IOC, and classification sources"
        />
        <SummaryCard
          icon={<Radar className="h-4 w-4" />}
          label="Known Campaign Match"
          value={campaignMatchText(data, intel)}
          hint={
            campaign.tone === 'active'
              ? 'Linked to a named campaign'
              : campaign.tone === 'unknown'
                ? 'Intel pulses without attribution'
                : 'No campaign attribution'
          }
        />
        <SummaryCard
          icon={<Compass className="h-4 w-4" />}
          label="Recommended Action"
          value={recommendedActionText(data)}
          hint="From risk engine and correlated findings"
        />
      </div>
    </section>
  );
}
