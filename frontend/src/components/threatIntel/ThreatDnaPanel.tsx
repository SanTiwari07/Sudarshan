import { ScanEye } from 'lucide-react';
import type { DnaTrait } from '../../lib/threatIntelModel';
import { IntelCard, IntelCardBody, IntelSectionHeader } from './IntelCard';
import { INTEL } from './intelTokens';
import { ProgressBar } from '../ui/primitives';

const BEHAVIOUR_ORDER: {
  key: string;
  label: string;
  aliases: string[];
  explanation: string;
}[] = [
  {
    key: 'a11y',
    label: 'Accessibility Abuse',
    aliases: ['Accessibility Abuse'],
    explanation: 'Used to automate banking apps',
  },
  {
    key: 'cred',
    label: 'Credential Theft',
    aliases: ['Credential Theft'],
    explanation: 'Attempts to capture user credentials',
  },
  {
    key: 'sms',
    label: 'SMS Interception',
    aliases: ['SMS Interception'],
    explanation: 'Can read OTP messages',
  },
  {
    key: 'overlay',
    label: 'Overlay Attack',
    aliases: ['Overlay Attack'],
    explanation: 'Can imitate banking screens',
  },
  {
    key: 'persist',
    label: 'Persistence',
    aliases: ['Persistence'],
    explanation: 'Attempts to remain active',
  },
  {
    key: 'remote',
    label: 'Remote Communication',
    aliases: ['Remote Access', 'Remote Communication'],
    explanation: 'May communicate with attacker infrastructure',
  },
];

function confidenceLabel(percent: number): string {
  if (percent >= 70) return 'High confidence';
  if (percent >= 35) return 'Medium confidence';
  if (percent > 0) return 'Low confidence';
  return 'Not observed';
}

/*
 * The meter is coloured by what it reads, not decorated.
 *
 * Every bar drew in the same blue-500-to-blue-700 gradient regardless of the
 * value behind it, so "Low confidence" and "High confidence" were the same
 * colour and only the length differed - and a gradient on a 6px track is a
 * texture nobody can resolve anyway. Worse, blue is this product's action
 * colour: a blue bar beside a label reads as something to press.
 *
 * These four steps match confidenceLabel exactly, so the words and the colour
 * can never disagree.
 */
function confidenceBar(percent: number): string {
  if (percent >= 70) return 'bg-slate-800';
  if (percent >= 35) return 'bg-slate-600';
  if (percent > 0) return 'bg-slate-400';
  return 'bg-transparent';
}

function resolveTrait(traits: DnaTrait[], aliases: string[]): DnaTrait | undefined {
  return traits.find((t) => aliases.some((a) => t.label.toLowerCase() === a.toLowerCase()));
}

export default function ThreatDnaPanel({ traits }: { traits: DnaTrait[] }) {
  return (
    <IntelCard>
      <IntelSectionHeader
        icon={<ScanEye className="h-4 w-4" />}
        title="Observed Fraud Behaviours"
        subtitle="Banking-relevant behaviours seen in static and runtime evidence"
      />
      <IntelCardBody>
        {/*
          Three across on a wide console.

          At two columns each meter was ~850px of track, so a behaviour that
          was never observed rendered as an empty bar the width of a paragraph.
        */}
        <div className="grid grid-cols-1 gap-x-8 gap-y-6 md:grid-cols-2 xl:grid-cols-3">
          {BEHAVIOUR_ORDER.map((behaviour) => {
            const trait = resolveTrait(traits, behaviour.aliases);
            const percent = trait?.percent ?? 0;
            const detail = trait?.rationale
              ? trait.rationale.replace(/BIND_ACCESSIBILITY_SERVICE|SYSTEM_ALERT_WINDOW/gi, (m) =>
                  m.includes('ACCESSIBILITY') ? 'accessibility service' : 'overlay permission',
                )
              : behaviour.explanation;

            return (
              <div key={behaviour.key} className="space-y-2">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="font-sans text-[14px] font-medium tracking-[-0.005em] text-slate-900">
                      {behaviour.label}
                    </div>
                    <p className={`${INTEL.caption} mt-0.5`}>{behaviour.explanation}</p>
                  </div>
                  <span className={`${INTEL.caption} shrink-0 font-medium ${percent > 0 ? 'text-slate-700' : 'text-slate-400'}`}>
                    {confidenceLabel(percent)}
                  </span>
                </div>
                <ProgressBar
                  percent={percent}
                  fill={confidenceBar(percent)}
                  label={`${behaviour.label}: ${confidenceLabel(percent)}`}
                />
                <p className={`${INTEL.caption} leading-relaxed`}>{detail}</p>
              </div>
            );
          })}
        </div>
      </IntelCardBody>
    </IntelCard>
  );
}
