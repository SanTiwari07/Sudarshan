import type { InvestigationCounts } from '../../types/investigation';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { securityFindingsTotal } from '../../lib/analystCopy';
import {
  Camera,
  Crosshair,
  FileSearch,
  Fingerprint,
  ShieldAlert,
} from 'lucide-react';

function MetricCard({
  icon,
  value,
  title,
  blurb,
  onClick,
}: {
  icon: React.ReactNode;
  value: number;
  title: string;
  blurb: string;
  onClick?: () => void;
}) {
  const Wrapper = onClick ? 'button' : 'div';
  return (
    <Wrapper
      type={onClick ? 'button' : undefined}
      onClick={onClick}
      className={`text-left p-4 rounded-xl border border-slate-200 bg-white shadow-sm h-full flex flex-col gap-2 ${
        onClick ? 'hover:border-blue-300 hover:bg-blue-50/40 transition-colors' : ''
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="p-2 rounded-lg bg-slate-100 text-blue-700">{icon}</span>
        <span className="text-2xl font-black text-slate-900 tabular-nums">{value}</span>
      </div>
      <div>
        <div className="text-xs font-bold text-slate-800">{title}</div>
        <p className="text-[11px] text-slate-500 mt-1 leading-snug">{blurb}</p>
      </div>
    </Wrapper>
  );
}

export default function CaseSummaryStrip({
  counts,
}: {
  riskScore?: number;
  counts: InvestigationCounts;
}) {
  const { openLedger } = useInvestigationUI();
  const findings = securityFindingsTotal(counts);

  return (
    <div className="mb-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
      <MetricCard
        icon={<ShieldAlert className="h-4 w-4" />}
        value={findings}
        title="Security Findings"
        blurb="Everything discovered across inspection and runtime."
        onClick={() => openLedger('stei')}
      />
      <MetricCard
        icon={<Fingerprint className="h-4 w-4" />}
        value={counts.iocMatches}
        title="Threat Indicators"
        blurb="Known malicious infrastructure matched to this app."
        onClick={() => openLedger('correlation')}
      />
      <MetricCard
        icon={<Crosshair className="h-4 w-4" />}
        value={counts.mitreTechniques}
        title="Attack Techniques"
        blurb="Mapped to MITRE ATT&CK Mobile."
      />
      <MetricCard
        icon={<FileSearch className="h-4 w-4" />}
        value={counts.evidenceRecords}
        title="Verified Evidence"
        blurb="Evidence used for scoring."
        onClick={() => openLedger('full')}
      />
      <MetricCard
        icon={<Camera className="h-4 w-4" />}
        value={counts.screenshots}
        title="Runtime Screenshots"
        blurb="Captured during sandbox execution."
      />
    </div>
  );
}
