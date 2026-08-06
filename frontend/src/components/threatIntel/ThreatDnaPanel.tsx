import { ScanEye } from 'lucide-react';
import type { DnaTrait } from '../../lib/threatIntelModel';
import { IntelCard, IntelCardBody, IntelSectionHeader } from './IntelCard';
import { INTEL, INTEL_THEME } from './intelTokens';

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
        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-6">
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
                    <div className="text-sm font-semibold text-slate-900">{behaviour.label}</div>
                    <p className={`${INTEL.caption} mt-0.5`}>{behaviour.explanation}</p>
                  </div>
                  <span className={`${INTEL.caption} shrink-0 font-medium text-slate-600`}>
                    {confidenceLabel(percent)}
                  </span>
                </div>
                <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${INTEL_THEME.barGradient} transition-all duration-700 ease-out`}
                    style={{ width: `${Math.min(100, percent)}%` }}
                  />
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
