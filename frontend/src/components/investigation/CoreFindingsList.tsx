import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import HelpTerm from './HelpTerm';
import { countFindingEvidence } from '../../lib/analystCopy';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import { AlertTriangle } from 'lucide-react';
import { COLORS } from '../../theme/colors';

type FindingRow = {
  title: string;
  helpTerm: string;
  explanation: string;
  severity: keyof typeof COLORS.severity;
  detected: boolean;
  evidenceId: string;
  ledgerScope: 'stei' | 'dynamic';
  evidenceKeywords: string[];
};

const SEVERITY_LABEL: Record<string, string> = {
  critical: 'Critical Risk',
  high: 'High Risk',
  medium: 'Moderate Risk',
  low: 'Lower Risk',
};

export default function CoreFindingsList({
  data,
  bundle,
}: {
  data: FraudCardData;
  bundle?: InvestigationBundle | null;
}) {
  const { openEvidence, openLedger } = useInvestigationUI();

  const rows: FindingRow[] = [
    {
      title: 'Accessibility Service Abuse',
      helpTerm: 'Accessibility Abuse',
      explanation:
        'Allows malware to control the phone without the user\'s knowledge — including reading banking screens and automating taps.',
      severity: 'critical',
      detected: data.has_accessibility_abuse,
      evidenceId: 'STAT-A11Y',
      ledgerScope: 'stei',
      evidenceKeywords: ['a11y', 'accessibility', 'STAT-A11Y'],
    },
    {
      title: 'SMS & OTP Interception',
      helpTerm: 'SMS Interception',
      explanation: 'SMS read permissions may allow theft of one-time passwords sent by banks.',
      severity: 'critical',
      detected: data.has_sms_read_write,
      evidenceId: 'STAT-SMS',
      ledgerScope: 'stei',
      evidenceKeywords: ['sms', 'STAT-SMS'],
    },
    {
      title: 'Overlay Window Capability',
      helpTerm: 'Overlay Attack',
      explanation: 'Can display fake banking login screens over legitimate apps.',
      severity: 'high',
      detected: data.has_system_alert_window,
      evidenceId: 'STAT-OVERLAY',
      ledgerScope: 'stei',
      evidenceKeywords: ['overlay', 'STAT-OVERLAY', 'alert'],
    },
    {
      title: 'Runtime Code Loading',
      helpTerm: 'Runtime Code Loading',
      explanation: 'Downloads or loads hidden code after installation, evading static inspection.',
      severity: 'medium',
      detected: Boolean(data.obfuscation_score && data.obfuscation_score > 0),
      evidenceId: 'STAT-CODE-0',
      ledgerScope: 'stei',
      evidenceKeywords: ['code', 'load', 'dex', 'STAT-CODE'],
    },
    {
      title: 'Obfuscation',
      helpTerm: 'Obfuscation',
      explanation: 'Makes the application\'s code difficult to inspect and reverse-engineer.',
      severity: 'medium',
      detected: Boolean(data.obfuscation_score && data.obfuscation_score > 0.25),
      evidenceId: 'STAT-CODE-0',
      ledgerScope: 'stei',
      evidenceKeywords: ['obfus', 'STAT-CODE'],
    },
  ];

  const detected = rows.filter((r) => r.detected);
  const clear = rows.filter((r) => !r.detected);

  return (
    <SocCard>
      <SectionHeader
        icon={<AlertTriangle className="h-4 w-4" />}
        title="Technical Findings"
        subtitle="Key fraud techniques with one-line explanations for non-security stakeholders."
      />
      <div className="p-5 sm:p-6 space-y-3">
        {detected.length === 0 && (
          <div className="text-center py-8 px-4 rounded-xl border border-dashed border-slate-200 bg-slate-50">
            <p className="text-sm text-slate-700">No high-priority fraud patterns were flagged on this case.</p>
            <p className="text-xs text-slate-500 mt-2">Review verified evidence and threat indicators before clearing.</p>
          </div>
        )}
        {detected.map((row) => {
          const count = Math.max(1, countFindingEvidence(bundle, row.evidenceKeywords));
          const sevClass = COLORS.severity[row.severity] || COLORS.severity.info;
          return (
            <button
              key={row.title}
              type="button"
              onClick={() => openEvidence(row.evidenceId)}
              className="w-full text-left rounded-xl border border-slate-200 p-4 hover:border-blue-300 hover:bg-blue-50/30 transition-colors"
            >
              <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                <h3 className="text-sm font-bold text-slate-900">
                  <HelpTerm term={row.helpTerm}>{row.title}</HelpTerm>
                </h3>
                <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${sevClass}`}>
                  {SEVERITY_LABEL[row.severity] || 'Risk'}
                </span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed">{row.explanation}</p>
              <p className="text-[11px] text-blue-700 font-semibold mt-3">
                Verified evidence · {count} observation{count === 1 ? '' : 's'}
              </p>
            </button>
          );
        })}
        {clear.length > 0 && detected.length > 0 && (
          <div className="pt-2 border-t border-slate-100">
            <div className="text-[10px] font-bold uppercase text-slate-400 mb-2">Not detected</div>
            <div className="flex flex-wrap gap-2">
              {clear.map((row) => (
                <button
                  key={row.title}
                  type="button"
                  onClick={() => openLedger(row.ledgerScope)}
                  className="text-[11px] px-2.5 py-1 rounded-lg bg-slate-50 border border-slate-200 text-slate-600 hover:bg-slate-100"
                >
                  {row.title}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </SocCard>
  );
}
