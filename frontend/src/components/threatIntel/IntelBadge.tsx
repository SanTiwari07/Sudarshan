import { getRiskStyle } from '../../theme/colors';

export type IntelBadgeTone = 'critical' | 'high' | 'medium' | 'low' | 'safe' | 'neutral' | 'info';

const TONE_CLASS: Record<IntelBadgeTone, string> = {
  critical: 'bg-red-50 text-red-800 border-red-200',
  high: 'bg-orange-50 text-orange-900 border-orange-200',
  medium: 'bg-amber-50 text-amber-900 border-amber-200',
  low: 'bg-blue-50 text-blue-800 border-blue-200',
  safe: 'bg-emerald-50 text-emerald-800 border-emerald-200',
  neutral: 'bg-slate-100 text-slate-700 border-slate-200',
  info: 'bg-slate-50 text-slate-600 border-slate-200',
};

export function toneFromRiskBand(band: string | null | undefined): IntelBadgeTone {
  const n = (band || '').toLowerCase();
  if (n.includes('critical')) return 'critical';
  if (n.includes('high')) return 'high';
  if (n.includes('suspicious')) return 'medium';
  if (n.includes('safe')) return 'safe';
  return 'neutral';
}

export function toneFromPercent(value: number | null | undefined): IntelBadgeTone {
  if (value == null) return 'neutral';
  if (value >= 85) return 'high';
  if (value >= 65) return 'medium';
  if (value >= 40) return 'low';
  return 'neutral';
}

export default function IntelBadge({
  children,
  tone = 'neutral',
  className = '',
}: {
  children: React.ReactNode;
  tone?: IntelBadgeTone;
  className?: string;
}) {
  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-md border text-[10px] font-semibold uppercase tracking-wide ${TONE_CLASS[tone]} ${className}`}
    >
      {children}
    </span>
  );
}

export function RiskBandBadge({ band }: { band: string }) {
  const style = getRiskStyle(band);
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wide ${style.badge}`}>
      {band}
    </span>
  );
}
