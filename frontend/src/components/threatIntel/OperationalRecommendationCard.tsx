import { Compass } from 'lucide-react';
import type { FraudCardData } from '../../App';
import type { AnalystAction, IntelApiPayload } from '../../lib/threatIntelModel';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import { INTEL } from './intelTokens';

function normalizeActionLabel(raw: string): string {
  const lower = raw.toLowerCase();
  if (/block|quarantine|reject/.test(lower)) return 'Block Application';
  if (/manual|review|investigate/.test(lower)) return 'Manual Review';
  if (/fraud|soc|escalat|notify/.test(lower)) return 'Notify Fraud Team';
  if (/ioc|domain|url|indicator/.test(lower)) return 'Recommend IOC Blocking';
  if (/monitor|watch/.test(lower)) return 'Monitor';
  return raw;
}

function buildRecommendationParagraph(
  action: string,
  data: FraudCardData,
  intel: IntelApiPayload,
  actions: AnalystAction[],
): string {
  const family = intel.malware_family || data.family_classification;
  const parts: string[] = [];

  if (action === 'Block Application') {
    parts.push(
      `Evidence supports a high-risk banking threat profile${family !== 'Unknown' ? ` aligned with ${family}` : ''}.`,
    );
    parts.push('Blocking reduces exposure while you validate indicators and customer impact.');
  } else if (action === 'Notify Fraud Team') {
    parts.push('Banking-targeting behaviours or high fraud scores warrant coordinated fraud operations review.');
    parts.push('Share IOCs and observed attack stages with the fraud team for customer outreach planning.');
  } else if (action === 'Recommend IOC Blocking') {
    parts.push('Correlated domains, URLs, or network indicators tie this sample to known malicious infrastructure.');
    parts.push('Blocking at the perimeter limits command-and-control and phishing follow-through.');
  } else if (action === 'Manual Review') {
    parts.push('Signals are present but not all intelligence sources confirmed a full campaign match.');
    parts.push('An analyst should validate findings against internal playbooks before enforcement.');
  } else if (action === 'Monitor') {
    parts.push('Risk is elevated but enforcement may be premature without stronger runtime or campaign correlation.');
    parts.push('Continue monitoring accounts and re-run analysis if new evidence appears.');
  } else {
    parts.push(`The risk engine suggests: ${action}.`);
  }

  const topEvidence = actions.find((a) => a.priority === 'high')?.evidenceRef;
  if (topEvidence) {
    parts.push(`Primary driver: ${topEvidence}.`);
  }

  if (data.final_risk_score >= 70) {
    parts.push(`Overall risk score is ${data.final_risk_score.toFixed(0)}/100 (${data.risk_band}).`);
  }

  return parts.join(' ');
}

export default function OperationalRecommendationCard({
  data,
  intel,
  actions,
}: {
  data: FraudCardData;
  intel: IntelApiPayload;
  actions: AnalystAction[];
}) {
  const raw =
    data.recommended_action ||
    actions.find((a) => a.priority === 'high')?.label ||
    actions[0]?.label ||
    'Manual Review';
  const action = normalizeActionLabel(raw);
  const paragraph = buildRecommendationParagraph(action, data, intel, actions);

  return (
    <SocCard className="border-slate-200 shadow-sm">
      <SectionHeader
        icon={<Compass className="h-4 w-4" />}
        title="Operational Recommendation"
        subtitle="What to do next, based on correlated evidence"
      />
      <div className="px-5 sm:px-6 pb-6 pt-2 space-y-4">
        <div className="inline-flex items-center gap-2 rounded-lg border border-blue-200 bg-blue-50 px-3 py-2">
          <span className="text-xs font-semibold text-blue-900">{action}</span>
        </div>
        <p className={`${INTEL.meta} leading-relaxed max-w-3xl text-slate-700`}>{paragraph}</p>
        {actions.length > 1 && (
          <ul className="space-y-2 pt-2 border-t border-slate-100">
            {actions.slice(0, 4).map((a) => (
              <li key={`${a.label}-${a.evidenceRef}`} className="text-[11px] text-slate-600">
                <span className="font-semibold text-slate-800">{normalizeActionLabel(a.label)}</span>
                <span className="text-slate-400 mx-1">—</span>
                {a.evidenceRef}
              </li>
            ))}
          </ul>
        )}
      </div>
    </SocCard>
  );
}
