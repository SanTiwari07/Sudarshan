import {
  Package,
  Download,
  Accessibility,
  Layers,
  KeyRound,
  MessageSquare,
  Wallet,
  Radio,
  Banknote,
  Route,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import type { AttackStage } from '../../lib/threatIntelModel';
import type { FraudCardData } from '../../App';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { IntelCard, IntelCardBody, IntelSectionHeader } from './IntelCard';
import { INTEL } from './intelTokens';

type StageStatus = 'completed' | 'observed' | 'missing' | 'na';

const STAGE_META: Record<
  string,
  { icon: LucideIcon; meaning: string; fraudImpact: string }
> = {
  apk: {
    icon: Package,
    meaning: 'The malicious application package was submitted for analysis.',
    fraudImpact: 'Establishes the artifact under investigation.',
  },
  install: {
    icon: Download,
    meaning: 'The app can be installed on a victim device like a normal application.',
    fraudImpact: 'Enables delivery of fraud capabilities to the user.',
  },
  a11y: {
    icon: Accessibility,
    meaning: 'Abuse of accessibility services to read screen content and automate taps.',
    fraudImpact: 'Can drive banking apps and harvest credentials without user awareness.',
  },
  overlay: {
    icon: Layers,
    meaning: 'Drawing fake screens on top of legitimate banking apps.',
    fraudImpact: 'Tricks users into entering credentials on attacker-controlled UI.',
  },
  cred: {
    icon: KeyRound,
    meaning: 'Capturing login details, PINs, or card data.',
    fraudImpact: 'Direct account takeover if credentials are exfiltrated.',
  },
  otp: {
    icon: MessageSquare,
    meaning: 'Reading SMS messages that contain one-time passwords.',
    fraudImpact: 'Bypasses OTP step during fraudulent transfers.',
  },
  upi: {
    icon: Wallet,
    meaning: 'Targeting UPI or wallet apps for unauthorized payments.',
    fraudImpact: 'Enables immediate movement of funds from victim accounts.',
  },
  c2: {
    icon: Radio,
    meaning: 'Communication with attacker-controlled servers.',
    fraudImpact: 'Allows remote commands, exfiltration, and campaign updates.',
  },
  transfer: {
    icon: Banknote,
    meaning: 'Automated or guided steps toward moving money out of accounts.',
    fraudImpact: 'Realizes financial loss for customers and the bank.',
  },
};

const STATUS_LABEL: Record<StageStatus, string> = {
  completed: 'Completed',
  observed: 'Observed',
  missing: 'Missing',
  na: 'Not Applicable',
};

const STATUS_STYLE: Record<StageStatus, string> = {
  completed: 'border-slate-800 bg-slate-900 text-white',
  observed: 'border-blue-700 bg-blue-700 text-white',
  missing: 'border-slate-200 bg-white text-slate-500',
  na: 'border-slate-100 bg-slate-50 text-slate-400',
};

function resolveStatus(stage: AttackStage, data: FraudCardData): StageStatus {
  if (stage.id === 'apk' || stage.id === 'install') return 'completed';
  if (stage.id === 'upi' && !data.targets_indian_banks) return 'na';
  if (stage.id === 'transfer' && !data.targets_indian_banks && !stage.detected) return 'na';
  if (stage.detected) return 'observed';
  return 'missing';
}

function evidenceSummary(stage: AttackStage): string {
  if (stage.detail) return stage.detail;
  if (stage.evidenceIds.length) return `Linked evidence: ${stage.evidenceIds.join(', ')}`;
  if (stage.detected) return 'Supported by static or runtime findings';
  return 'No supporting evidence in this case';
}

export default function AttackChainFlow({
  stages,
  data,
}: {
  stages: AttackStage[];
  data: FraudCardData;
}) {
  const { openEvidence } = useInvestigationUI();

  return (
    <IntelCard>
      <IntelSectionHeader
        icon={<Route className="h-4 w-4" />}
        title="Observed Attack Flow"
        subtitle="Shows which stages of a typical banking malware attack were observed during analysis"
      />
      <IntelCardBody>
        <div className="flex flex-wrap items-stretch gap-3">
          {stages.map((stage) => {
            const meta = STAGE_META[stage.id] || {
              icon: Package,
              meaning: stage.label,
              fraudImpact: 'Banking fraud impact varies by stage.',
            };
            const Icon = meta.icon;
            const status = resolveStatus(stage, data);
            const clickable = stage.evidenceIds[0] && status === 'observed';

            return (
              <div key={stage.id} className="relative group w-[7.5rem] sm:w-[8.25rem]">
                <button
                  type="button"
                  disabled={!clickable}
                  onClick={() => clickable && openEvidence(stage.evidenceIds[0])}
                  className={`w-full flex flex-col items-center text-center rounded-xl border px-2 py-3 transition-all duration-200 ${STATUS_STYLE[status]} ${
                    clickable ? 'hover:-translate-y-0.5 cursor-pointer' : 'cursor-default'
                  }`}
                >
                  <span
                    className={`flex h-9 w-9 items-center justify-center rounded-lg mb-2 ${
                      status === 'missing' || status === 'na'
                        ? 'bg-slate-100 border border-slate-200'
                        : 'bg-white/15'
                    }`}
                  >
                    <Icon
                      className={`h-4 w-4 ${
                        status === 'missing' || status === 'na' ? 'text-slate-400' : 'text-current'
                      }`}
                    />
                  </span>
                  <span className="text-[11px] font-semibold leading-tight line-clamp-2">{stage.label}</span>
                  <span className="mt-2 text-[9px] font-semibold uppercase tracking-wide opacity-90">
                    {STATUS_LABEL[status]}
                  </span>
                </button>

                <div
                  role="tooltip"
                  className="pointer-events-none absolute z-20 left-1/2 -translate-x-1/2 top-full mt-2 w-56 rounded-lg border border-slate-200 bg-white p-3 shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-opacity"
                >
                  <p className="text-[11px] font-semibold text-slate-900 mb-1">What this stage means</p>
                  <p className={`${INTEL.caption} leading-relaxed`}>{meta.meaning}</p>
                  <p className="text-[11px] font-semibold text-slate-900 mt-2 mb-1">Evidence</p>
                  <p className={`${INTEL.caption} leading-relaxed`}>{evidenceSummary(stage)}</p>
                  <p className="text-[11px] font-semibold text-slate-900 mt-2 mb-1">Fraud impact</p>
                  <p className={`${INTEL.caption} leading-relaxed`}>{meta.fraudImpact}</p>
                </div>
              </div>
            );
          })}
        </div>
        <p className={`${INTEL.caption} mt-4`}>
          Hover a stage for meaning, evidence, and impact. Click observed stages when evidence links are available.
        </p>
      </IntelCardBody>
    </IntelCard>
  );
}
