import type { ReactNode } from 'react';
import type { InvestigationEvidence } from '../../types/investigation';
import { formatEvidenceSource, formatSeverityLabel } from '../../lib/findingAnalystView';
import { confidenceTierLabel } from '../../lib/findingExplanation';
import { Activity, FileCode, Globe } from 'lucide-react';

type SeverityVisual = {
  label: string;
  dot: string;
  text: string;
};

function severityVisual(severity?: string): SeverityVisual {
  const raw = (severity || 'info').toLowerCase();
  if (raw.includes('critical')) {
    return { label: 'CRITICAL', dot: 'bg-red-500', text: 'text-red-700' };
  }
  if (raw.includes('high')) {
    return { label: 'HIGH', dot: 'bg-orange-500', text: 'text-orange-700' };
  }
  if (raw === 'good' || raw.includes('positive')) {
    return { label: 'GOOD', dot: 'bg-emerald-500', text: 'text-emerald-700' };
  }
  if (raw.includes('warning') || raw.includes('medium') || raw.includes('moderate')) {
    return { label: raw.includes('warning') ? 'WARNING' : 'MODERATE', dot: 'bg-amber-500', text: 'text-amber-800' };
  }
  if (raw.includes('low')) {
    return { label: 'LOW', dot: 'bg-sky-500', text: 'text-sky-700' };
  }
  const formatted = formatSeverityLabel(severity || '').toUpperCase();
  return { label: formatted, dot: 'bg-slate-400', text: 'text-slate-600' };
}

export function SeverityIndicator({ severity }: { severity?: string }) {
  const v = severityVisual(severity);
  return (
    <span className={`inline-flex items-center gap-1.5 text-[11px] font-semibold tracking-wide ${v.text}`}>
      <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${v.dot}`} aria-hidden />
      {v.label}
    </span>
  );
}

function sourceMeta(evidence: InvestigationEvidence): { label: string; icon: ReactNode } {
  const src = formatEvidenceSource(evidence);
  if (evidence.category === 'runtime' || src === 'Runtime Analysis') {
    return { label: 'Runtime', icon: <Activity className="h-3 w-3" aria-hidden /> };
  }
  if (src === 'Threat Intelligence') {
    return { label: 'Threat', icon: <Globe className="h-3 w-3" aria-hidden /> };
  }
  return { label: 'Static', icon: <FileCode className="h-3 w-3" aria-hidden /> };
}

export function SourceIndicator({ evidence }: { evidence: InvestigationEvidence }) {
  const { label, icon } = sourceMeta(evidence);
  return (
    <span className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-600">
      <span className="text-slate-400">{icon}</span>
      {label}
    </span>
  );
}

export function ConfidenceIndicator({ confidence }: { confidence: number }) {
  const pct = Math.max(0, Math.min(100, confidence));
  const tier = confidenceTierLabel(pct);
  return (
    <div className="text-right min-w-[4.75rem]">
      <div className="text-[13px] font-semibold text-slate-800 tabular-nums leading-none">{pct}%</div>
      <div className="text-[10px] text-slate-600 mt-1 leading-tight">{tier}</div>
      <div className="text-[10px] text-slate-400 mt-0.5">Verified</div>
    </div>
  );
}

export function RiskBandLabel({ band }: { band: string }) {
  const b = (band || '').toLowerCase();
  const cls =
    b.includes('critical')
      ? 'text-red-700'
      : b.includes('high')
        ? 'text-orange-700'
        : b.includes('suspicious')
          ? 'text-amber-800'
          : 'text-slate-700';
  return <span className={`text-xs font-bold uppercase tracking-wide ${cls}`}>{band}</span>;
}

export function PipelineStatusChip({
  label,
  state,
}: {
  label: string;
  state: 'complete' | 'inconclusive' | 'failed' | 'pending';
}) {
  const sym =
    state === 'complete' ? '✓' : state === 'inconclusive' ? '!' : state === 'failed' ? '×' : '·';
  const symCls =
    state === 'complete'
      ? 'text-emerald-600'
      : state === 'inconclusive'
        ? 'text-amber-600'
        : state === 'failed'
          ? 'text-red-600'
          : 'text-slate-400';
  return (
    <span className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-600">
      {label}
      <span className={`font-bold ${symCls}`} aria-hidden>{sym}</span>
    </span>
  );
}
