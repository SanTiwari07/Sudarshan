import { getRiskAccent } from '../../theme/colors';
import type { IntelApiPayload } from '../../lib/threatIntelModel';
import { campaignStatus, malwareTypeLabel, analysisCoveragePercent } from '../../lib/threatIntelModel';
import type { FraudCardData } from '../../App';
import CopyButton from '../ui/CopyButton';
import IntelBadge, { RiskBandBadge, toneFromPercent } from './IntelBadge';
import { INTEL } from './intelTokens';

type Props = {
  data: FraudCardData;
  intel: IntelApiPayload;
  evidenceConfidence: number;
};

export default function ThreatIntelHero({ data, intel, evidenceConfidence }: Props) {
  const band = data.risk_band || intel.risk_band || 'Unknown';
  const accent = getRiskAccent(band);
  const campaign = campaignStatus(intel);
  const coverage = analysisCoveragePercent(data, intel);
  const family = intel.malware_family || data.family_classification;
  const classConf = Math.round(data.confidence || intel.confidence || 0);
  const threatConf = Math.round(intel.confidence || data.confidence || 0);

  const campaignTone =
    campaign.tone === 'active' ? 'critical' : campaign.tone === 'unknown' ? 'medium' : 'neutral';

  return (
    <section
      className={`rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden ring-1 ${accent.ring} border-l-[5px] ${accent.bar}`}
    >
      <div className="px-6 py-6 lg:px-8 lg:py-7">
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-8 items-start">
          <div className="xl:col-span-5 space-y-4 min-w-0">
            <p className={INTEL.eyebrow}>Threat intelligence profile</p>
            <div>
              <h1 className="text-2xl lg:text-3xl font-bold text-slate-800 tracking-tight">
                {family !== 'Unknown' ? family : 'Unclassified sample'}
              </h1>
              <p className={`${INTEL.meta} mt-1`}>{malwareTypeLabel(data, family)}</p>
            </div>
            <div className="flex flex-wrap gap-2">
              <RiskBandBadge band={band} />
              <IntelBadge tone={campaignTone}>{campaign.label}</IntelBadge>
              <IntelBadge tone={toneFromPercent(evidenceConfidence)}>{evidenceConfidence}% evidence</IntelBadge>
              <IntelBadge tone={toneFromPercent(coverage)}>{coverage}% coverage</IntelBadge>
            </div>
            <div className="space-y-2 pt-2 border-t border-slate-100">
              <div className="flex items-start gap-2 min-w-0">
                <span className={`${INTEL.caption} shrink-0 w-16`}>Package</span>
                <span className="text-xs font-mono text-slate-800 truncate" title={data.package_name}>
                  {data.package_name}
                </span>
              </div>
              <div className="flex items-start gap-2 min-w-0">
                <span className={`${INTEL.caption} shrink-0 w-16`}>SHA-256</span>
                <span className="text-xs font-mono text-slate-700 truncate flex-1" title={data.sha256}>
                  {data.sha256}
                </span>
                <CopyButton value={data.sha256} />
              </div>
            </div>
          </div>

          <div className="xl:col-span-7 grid grid-cols-2 md:grid-cols-4 gap-3">
            <HeroStat label="Threat level" value={band.toUpperCase()} />
            <HeroStat label="Malware family" value={family} />
            <HeroStat
              label="Classification"
              value={family === 'Unknown' ? 'Reduced' : `${classConf}%`}
            />
            <HeroStat label="Threat confidence" value={threatConf ? `${threatConf}%` : '—'} />
            <HeroStat label="Evidence confidence" value={`${evidenceConfidence}%`} />
            <HeroStat label="Analysis coverage" value={`${coverage}%`} />
            <HeroStat
              label="Runtime"
              value={data.dynamic_available ? 'Available' : 'Unavailable'}
            />
            <HeroStat
              label="Verdict"
              value={data.recommended_action || 'See risk engine'}
              truncate
            />
          </div>
        </div>
      </div>
    </section>
  );
}

function HeroStat({
  label,
  value,
  truncate: trunc,
}: {
  label: string;
  value: string;
  tone?: 'critical' | 'high' | 'medium' | 'low' | 'safe' | 'neutral' | 'info';
  truncate?: boolean;
}) {
  return (
    <div className="rounded-lg border border-slate-200 bg-slate-50/80 px-3 py-3 hover:bg-white hover:border-slate-300 transition-colors min-h-[4.5rem]">
      <div className={INTEL.caption}>{label}</div>
      <div className={`mt-1 text-sm font-bold text-slate-800 leading-snug ${trunc ? 'truncate' : 'line-clamp-2'}`} title={value}>
        {value}
      </div>
    </div>
  );
}
