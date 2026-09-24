import { Compass } from 'lucide-react';
import type { FraudCardData } from '../../types/case';
import type { AnalystAction, IntelApiPayload } from '../../lib/threatIntelModel';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import { INTEL } from './intelTokens';
import { TYPOGRAPHY } from '../../theme/typography';

function normalizeActionLabel(raw: string): string {
  const lower = raw.toLowerCase();
  if (/block|quarantine|reject/.test(lower)) return 'Block Application';
  if (/manual|review|investigate/.test(lower)) return 'Manual Review';
  if (/fraud|soc|escalat|notify/.test(lower)) return 'Notify Fraud Team';
  if (/ioc|domain|url|indicator/.test(lower)) return 'Recommend IOC Blocking';
  if (/monitor|watch/.test(lower)) return 'Monitor';
  return raw;
}

/**
 * One row per distinct action.
 *
 * The engine emits an action per source, so "Monitor" arrived twice - once
 * from the risk engine, once from the intelligence report - and rendered as
 * two identical rows with different justifications. Same instruction, so it
 * is one row carrying both reasons.
 */
function mergeActions(actions: AnalystAction[]): { label: string; reasons: string[] }[] {
  const merged = new Map<string, { label: string; reasons: string[] }>();
  for (const action of actions) {
    const label = normalizeActionLabel(action.label);
    const entry = merged.get(label) ?? { label, reasons: [] };
    if (action.evidenceRef && !entry.reasons.includes(action.evidenceRef)) {
      entry.reasons.push(action.evidenceRef);
    }
    merged.set(label, entry);
  }
  return [...merged.values()];
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
  dense = false,
}: {
  data: FraudCardData;
  intel: IntelApiPayload;
  actions: AnalystAction[];
  /*
   * Lay out for a narrow column rather than for the viewport.
   *
   * Tailwind's `lg:` is keyed to the window, not to this card's box, so when
   * the page places it in a half-width column the two-up split still fires and
   * tries to fit a 58ch measure and a 260px rail into ~430px. There is no
   * breakpoint that can express "narrow parent on a wide screen", so the
   * parent has to say so. Container queries would remove the need for this
   * prop; until the plugin is in, this is the honest version of the same idea.
   */
  dense?: boolean;
}) {
  const raw =
    data.recommended_action ||
    actions.find((a) => a.priority === 'high')?.label ||
    actions[0]?.label ||
    'Manual Review';
  const action = normalizeActionLabel(raw);
  const paragraph = buildRecommendationParagraph(action, data, intel, actions);
  /*
   * The primary action is stated in the pill above; repeating it as the first
   * row of "also do this" was the third mention of the same word on one card.
   */
  const supporting = mergeActions(actions).filter((a) => a.label !== action);

  return (
    <SocCard rank="primary">
      <SectionHeader
        icon={<Compass className="h-4 w-4" />}
        title="Operational recommendation"
        subtitle="What to do next, based on correlated evidence"
      />
      {/*
        Verdict left, supporting actions right.

        The card used to be a single narrow column of 11px lines against a
        two-thirds-empty card. The two halves are separate questions - "what do
        I do" and "what else follows" - so they sit side by side and the card
        stops being mostly margin.
      */}
      <div
        className={`grid grid-cols-1 gap-6 px-5 py-5 sm:px-6 ${
          dense ? '' : 'lg:grid-cols-[minmax(0,58ch)_minmax(260px,1fr)] lg:gap-10'
        }`}
      >
        <div className="min-w-0 space-y-3">
          <span className="inline-flex items-center rounded-md border border-blue-200 bg-blue-50 px-2.5 py-1 text-[15px] font-semibold text-blue-900">
            {action}
          </span>
          <p className={TYPOGRAPHY.bodySmall}>{paragraph}</p>
        </div>

        {supporting.length > 0 && (
          <div>
            <p className={`${INTEL.eyebrow} mb-2`}>Supporting actions</p>
            {/*
              Flat rows, not a bordered list inside a bordered card.

              This was a grey box with its own border and radius sitting inside
              the recommendation card - two surfaces to deliver four lines, and
              the inner one competed with the card that owned it. The rows now
              sit directly on the card, separated by a hairline each, which is
              the only separation four short items need.
            */}
            <ul>
              {supporting.slice(0, 4).map((a) => (
                <li key={a.label} className="border-t border-slate-200 py-4 first:border-t-0 first:pt-0">
                  <p className="font-sans text-[14px] font-medium leading-snug tracking-[-0.005em] text-slate-900">
                    {a.label}
                  </p>
                  {a.reasons.length > 0 && (
                    <p className={`${TYPOGRAPHY.caption} mt-1`}>{a.reasons.join(' · ')}</p>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </SocCard>
  );
}
