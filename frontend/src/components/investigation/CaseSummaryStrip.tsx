import { useNavigate } from 'react-router-dom';
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
      className={`text-left p-3.5 rounded-md border border-slate-200 bg-white shadow-[0_1px_2px_rgba(0,0,0,0.01)] h-full flex flex-col gap-2 ${
        onClick ? 'hover:border-blue-400 hover:bg-slate-50 cursor-pointer transition-colors' : ''
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="p-1.5 rounded bg-slate-100 text-blue-700">{icon}</span>
        <span className="text-xl font-bold text-slate-900 tabular-nums font-mono">{value}</span>
      </div>
      <div>
        <div className="text-[11px] font-bold uppercase tracking-wider text-slate-700 font-mono">{title}</div>
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
  const navigate = useNavigate();
  const { openLedger } = useInvestigationUI();
  const findings = securityFindingsTotal(counts);

  return (
    <div className="mb-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
      <MetricCard
        icon={<ShieldAlert className="h-4 w-4" />}
        value={findings}
        title="Security Findings"
        blurb="Discovered across static, dynamic, and cert audits."
        onClick={() => openLedger('stei')}
      />
      <MetricCard
        icon={<Fingerprint className="h-4 w-4" />}
        value={counts.iocMatches}
        title="Threat Indicators"
        blurb="Known malicious infrastructure matches."
        onClick={() => openLedger('correlation')}
      />
      <MetricCard
        icon={<Crosshair className="h-4 w-4" />}
        value={counts.mitreTechniques}
        title="Attack Techniques"
        blurb="Mapped directly to MITRE ATT&CK Mobile."
        onClick={() => openLedger('stei')}
      />
      <MetricCard
        icon={<FileSearch className="h-4 w-4" />}
        value={counts.evidenceRecords}
        title="Verified Evidence"
        blurb="Observations logged in the case ledger."
        onClick={() => openLedger('full')}
      />
      <MetricCard
        icon={<Camera className="h-4 w-4" />}
        value={counts.screenshots}
        title="Runtime Screenshots"
        blurb="Frames captured during emulator sandbox run."
        onClick={() => navigate('/technical')}
      />
    </div>
  );
}
