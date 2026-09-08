import { useNavigate } from 'react-router-dom';
import type { InvestigationCounts } from '../../types/investigation';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { securityFindingsTotal } from '../../lib/analystCopy';
import { TYPOGRAPHY } from '../../theme/typography';
import { useCaseLinks } from '../../hooks/useCaseLinks';
import {
  Camera,
  ArrowRight,
  Crosshair,
  FileSearch,
  Fingerprint,
  ShieldAlert,
} from 'lucide-react';

interface MetricCardProps {
  icon: React.ReactNode;
  value: number;
  title: string;
  blurb: string;
  statusBadge?: React.ReactNode;
  onClick?: () => void;
  accentBarColor?: string;
}

function MetricCard({
  icon,
  value,
  title,
  blurb,
  statusBadge,
  onClick,
  accentBarColor = 'bg-blue-600',
}: MetricCardProps) {
  const Wrapper = onClick ? 'button' : 'div';

  return (
    <Wrapper
      type={onClick ? 'button' : undefined}
      onClick={onClick}
      aria-label={`View ${title.toLowerCase()} details`}
      className={`group relative w-full text-left p-4 rounded-lg border border-slate-200 bg-white shadow-[0_1px_2px_rgba(0,0,0,0.02)] flex flex-col justify-between transition-all duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 overflow-hidden ${
        onClick ? 'cursor-pointer hover:border-slate-300 hover:bg-slate-50/50' : ''
      }`}
    >
      {/* Top Subtle Accent Bar */}
      <div className={`absolute top-0 left-0 right-0 h-0.5 ${accentBarColor}`} />

      <div>
        {/* Top Header: Title & Icon */}
        <div className="flex items-center justify-between gap-2 mb-2.5">
          <span className={TYPOGRAPHY.label}>
            {title}
          </span>
          <div className="p-1.5 rounded bg-slate-100 text-slate-600 border border-slate-200/60 shrink-0">
            {icon}
          </div>
        </div>

        {/* Metric Value & Optional Status Badge */}
        <div className="flex items-baseline justify-between gap-2 mb-2 font-mono">
          <span className="text-3xl font-semibold font-mono text-slate-900 tracking-tight">
            {value}
          </span>
          {statusBadge}
        </div>

        {/* Descriptive Blurb */}
        <p className={TYPOGRAPHY.caption}>
          {blurb}
        </p>
      </div>

      {/* Footer link button */}
      {onClick && (
        <div className={`pt-2.5 mt-3 border-t border-slate-100 flex items-center justify-between ${TYPOGRAPHY.linkAction} group-hover:text-blue-600`}>
          <span>View details</span>
          <ArrowRight className="h-3.5 w-3.5 text-slate-400 group-hover:text-blue-600 transition-transform duration-150 group-hover:translate-x-0.5" aria-hidden />
        </div>
      )}
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
  const links = useCaseLinks();
  const findings = securityFindingsTotal(counts);

  const totalSignals = findings + counts.iocMatches + counts.mitreTechniques + counts.evidenceRecords + counts.screenshots;

  return (
    <div className="space-y-4 rounded-[var(--card-radius)] border border-slate-200 bg-white p-5 shadow-[var(--card-elevation)]">
      {/* Header + Supporting Description */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-3.5">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <h3 className={TYPOGRAPHY.sectionTitle}>
              Evidence &amp; Risk Signals
            </h3>
            <span className={`${TYPOGRAPHY.badgePill} bg-slate-900 text-slate-100 border-slate-800 gap-1.5`}>
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              {totalSignals} SIGNALS
            </span>
          </div>
          <p className={TYPOGRAPHY.bodySmall}>
            Supporting evidence collected across static analysis, runtime investigation, threat intelligence, and the case evidence ledger.
          </p>
        </div>
      </div>

      {/* Balanced 5-Column Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-3.5">
        <MetricCard
          icon={<ShieldAlert className="h-4 w-4" />}
          value={findings}
          title="Security Findings"
          blurb="Discovered across static, dynamic, and cert audits."
          accentBarColor={findings > 0 ? 'bg-red-500' : 'bg-emerald-500'}
          statusBadge={
            findings > 0 ? (
              <span className={`${TYPOGRAPHY.badge} bg-red-50 text-red-700 border-red-200`}>
                Action Needed
              </span>
            ) : (
              <span className={`${TYPOGRAPHY.badge} bg-emerald-50 text-emerald-700 border-emerald-200`}>
                Clean
              </span>
            )
          }
          onClick={() => openLedger('stei')}
        />

        <MetricCard
          icon={<Fingerprint className="h-4 w-4" />}
          value={counts.iocMatches}
          title="Threat Indicators"
          blurb="Known malicious infrastructure matches."
          accentBarColor={counts.iocMatches > 0 ? 'bg-red-500' : 'bg-emerald-500'}
          statusBadge={
            counts.iocMatches === 0 ? (
              <span className={`${TYPOGRAPHY.badge} bg-emerald-50 text-emerald-700 border-emerald-200`}>
                Clean
              </span>
            ) : (
              <span className={`${TYPOGRAPHY.badge} bg-red-50 text-red-700 border-red-200`}>
                Matched
              </span>
            )
          }
          onClick={() => openLedger('correlation')}
        />

        <MetricCard
          icon={<Crosshair className="h-4 w-4" />}
          value={counts.mitreTechniques}
          title="Attack Techniques"
          blurb="Mapped directly to MITRE ATT&CK Mobile."
          accentBarColor="bg-blue-600"
          statusBadge={
            counts.mitreTechniques > 0 ? (
              <span className={`${TYPOGRAPHY.badge} bg-blue-50 text-blue-700 border-blue-200`}>
                MITRE
              </span>
            ) : undefined
          }
          onClick={() => openLedger('stei')}
        />

        <MetricCard
          icon={<FileSearch className="h-4 w-4" />}
          value={counts.evidenceRecords}
          title="Verified Evidence"
          blurb="Observations logged in the case ledger."
          accentBarColor="bg-blue-600"
          statusBadge={
            <span className={`${TYPOGRAPHY.badge} bg-slate-100 text-slate-700 border-slate-200`}>
              Ledger
            </span>
          }
          onClick={() => openLedger('full')}
        />

        <MetricCard
          icon={<Camera className="h-4 w-4" />}
          value={counts.screenshots}
          title="Runtime Captures"
          blurb="Frames captured during emulator sandbox run."
          accentBarColor="bg-blue-600"
          statusBadge={
            <span className={`${TYPOGRAPHY.badge} bg-slate-100 text-slate-700 border-slate-200`}>
              Sandbox
            </span>
          }
          onClick={() => navigate(links.evidence)}
        />
      </div>
    </div>
  );
}

