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
  Smartphone,
  ChevronRight,
  CheckCircle2,
  Circle,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import type { AttackStage } from '../../lib/threatIntelModel';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { IntelCard, IntelCardBody, IntelSectionHeader } from './IntelCard';
import { INTEL, INTEL_THEME } from './intelTokens';

const STAGE_META: Record<string, { icon: LucideIcon; short: string }> = {
  apk: { icon: Package, short: 'Artifact' },
  install: { icon: Download, short: 'Deploy' },
  a11y: { icon: Accessibility, short: 'A11y' },
  overlay: { icon: Layers, short: 'Overlay' },
  cred: { icon: KeyRound, short: 'Creds' },
  otp: { icon: MessageSquare, short: 'OTP' },
  upi: { icon: Wallet, short: 'UPI' },
  c2: { icon: Radio, short: 'C2' },
  transfer: { icon: Banknote, short: 'Transfer' },
};

export default function AttackChainFlow({ stages }: { stages: AttackStage[] }) {
  const { openEvidence } = useInvestigationUI();
  const detectedCount = stages.filter((s) => s.detected).length;

  return (
    <IntelCard>
      <IntelSectionHeader
        icon={<Smartphone className="h-4 w-4" />}
        title="Attack chain"
        subtitle="Inferred kill chain from static flags and runtime workflow"
        action={
          <span className={`${INTEL.caption} font-mono tabular-nums`}>
            {detectedCount}/{stages.length} observed
          </span>
        }
      />
      <IntelCardBody className="flex-1 flex flex-col justify-center">
        <div className="flex flex-wrap items-stretch gap-2">
          {stages.map((stage, idx) => {
            const meta = STAGE_META[stage.id] || { icon: Circle, short: 'Step' };
            const Icon = meta.icon;
            const tooltip = [stage.label, stage.detail, stage.detected ? 'Observed' : 'Not observed']
              .filter(Boolean)
              .join(' · ');

            return (
              <div key={stage.id} className="flex items-center gap-2 min-w-0">
                <button
                  type="button"
                  title={tooltip}
                  onClick={() => stage.evidenceIds[0] && openEvidence(stage.evidenceIds[0])}
                  className={`group flex flex-col items-center text-center w-[5.5rem] sm:w-[6.25rem] rounded-lg border px-2 py-2.5 transition-all duration-200 ${
                    stage.detected
                      ? `${INTEL_THEME.observed} hover:-translate-y-0.5`
                      : INTEL_THEME.inactive
                  }`}
                >
                  <span
                    className={`flex h-8 w-8 items-center justify-center rounded-md mb-1.5 ${
                      stage.detected ? INTEL_THEME.observedIcon : 'bg-white border border-slate-200'
                    }`}
                  >
                    <Icon className={`h-4 w-4 ${stage.detected ? 'text-white' : 'text-slate-400'}`} />
                  </span>
                  <span className="text-[10px] font-semibold leading-tight line-clamp-2">{stage.label}</span>
                  <span className="mt-1 flex items-center gap-0.5 text-[9px] uppercase tracking-wide opacity-80">
                    {stage.detected ? (
                      <>
                        <CheckCircle2 className="h-3 w-3" /> Live
                      </>
                    ) : (
                      <>
                        <Circle className="h-3 w-3" /> Missing
                      </>
                    )}
                  </span>
                </button>
                {idx < stages.length - 1 && (
                  <ChevronRight
                    className={`h-4 w-4 shrink-0 hidden sm:block ${stage.detected ? 'text-slate-500' : 'text-slate-300'}`}
                    aria-hidden
                  />
                )}
              </div>
            );
          })}
        </div>
        <p className={`${INTEL.caption} mt-4`}>
          Dark nodes have supporting evidence. Hover for status. Click when an evidence link is available.
        </p>
      </IntelCardBody>
    </IntelCard>
  );
}
