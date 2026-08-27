import { ScanEye } from 'lucide-react';
import type { DnaObservation, DnaTrait } from '../../lib/threatIntelModel';
import { IntelCard, IntelCardBody, IntelSectionHeader } from './IntelCard';
import { INTEL } from './intelTokens';

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

/*
 * How the behaviour was established, not how strongly.
 *
 * This row used to carry a percentage and a meter. The percentages were
 * literals picked per branch in buildThreatDna - 72% credential theft, 81%
 * overlay - so a categorical fact (the permission is declared) reached the
 * analyst as a measurement nobody took. The four states below are what the
 * evidence actually distinguishes, and they keep the same four-step scale the
 * meter used, so the wording and the colour still cannot disagree.
 */
function observationLabel(observation: DnaObservation): string {
  switch (observation) {
    case 'runtime_observed':
      return 'Observed at runtime';
    case 'statically_declared':
      return 'Declared in package';
    case 'inferred':
      return 'Indirect signal';
    default:
      return 'Not observed';
  }
}

function observationDot(observation: DnaObservation): string {
  switch (observation) {
    case 'runtime_observed':
      return 'bg-slate-800';
    case 'statically_declared':
      return 'bg-slate-600';
    case 'inferred':
      return 'bg-slate-400';
    default:
      return 'bg-transparent ring-1 ring-inset ring-slate-300';
  }
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
        {/* Three across on a wide console, so a run with few observed
            behaviours does not stretch each row across the full width. */}
        <div className="grid grid-cols-1 gap-x-8 gap-y-6 md:grid-cols-2 xl:grid-cols-3">
          {BEHAVIOUR_ORDER.map((behaviour) => {
            const trait = resolveTrait(traits, behaviour.aliases);
            const observation: DnaObservation = trait?.observation ?? 'not_observed';
            const detected = observation !== 'not_observed';
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
                  <span
                    className={`${INTEL.caption} flex shrink-0 items-center gap-1.5 font-medium ${
                      detected ? 'text-slate-700' : 'text-slate-400'
                    }`}
                  >
                    <span
                      aria-hidden
                      className={`h-1.5 w-1.5 rounded-full ${observationDot(observation)}`}
                    />
                    {observationLabel(observation)}
                  </span>
                </div>
                <p className={`${INTEL.caption} leading-relaxed`}>{detail}</p>
              </div>
            );
          })}
        </div>
      </IntelCardBody>
    </IntelCard>
  );
}
