// Centralized design system color palette and styling tokens for Sudarshan BOI

export const COLORS = {
  // Brand & Layout
  brand: {
    primary: '#1e3a8a', // BOI Blue
    primaryHover: '#1e40af',
    navyDark: '#0f172a',
    canvasBg: '#f8fafc',
    cardBg: '#ffffff',
    border: '#e2e8f0',
    borderSubtle: '#f1f5f9',
  },

  // Risk Bands
  riskBand: {
    critical: {
      bg: 'bg-red-600',
      bgLight: 'bg-red-50',
      text: 'text-red-600',
      textDark: 'text-red-700',
      border: 'border-red-200',
      badge: 'bg-red-600 text-white',
    },
    high: {
      bg: 'bg-orange-500',
      bgLight: 'bg-orange-50',
      text: 'text-orange-500',
      textDark: 'text-orange-700',
      border: 'border-orange-200',
      badge: 'bg-orange-500 text-white',
    },
    suspicious: {
      bg: 'bg-amber-500',
      bgLight: 'bg-amber-50',
      text: 'text-amber-600',
      textDark: 'text-amber-800',
      border: 'border-amber-200',
      badge: 'bg-amber-400 text-gray-900',
    },
    safe: {
      bg: 'bg-emerald-600',
      bgLight: 'bg-emerald-50',
      text: 'text-emerald-600',
      textDark: 'text-emerald-700',
      border: 'border-emerald-200',
      badge: 'bg-emerald-600 text-white',
    },
    unknown: {
      bg: 'bg-slate-500',
      bgLight: 'bg-slate-50',
      text: 'text-slate-600',
      textDark: 'text-slate-700',
      border: 'border-slate-200',
      badge: 'bg-slate-500 text-white',
    },
  },

  // Technical Severities
  severity: {
    critical: 'bg-red-100 text-red-800 border-red-200',
    high: 'bg-orange-100 text-orange-800 border-orange-200',
    medium: 'bg-amber-100 text-amber-800 border-amber-200',
    low: 'bg-blue-100 text-blue-800 border-blue-200',
    info: 'bg-slate-100 text-slate-700 border-slate-200',
  },
} as const;

export function getRiskStyle(band: string | null | undefined) {
  const normalized = (band || '').toLowerCase();
  if (normalized.includes('critical')) return COLORS.riskBand.critical;
  if (normalized.includes('high')) return COLORS.riskBand.high;
  if (normalized.includes('suspicious')) return COLORS.riskBand.suspicious;
  if (normalized.includes('safe')) return COLORS.riskBand.safe;
  return COLORS.riskBand.unknown;
}

export function getSeverityStyle(severity: string | null | undefined): string {
  const normalized = (severity || '').toLowerCase();
  if (normalized.includes('critical')) return COLORS.severity.critical;
  if (normalized.includes('high')) return COLORS.severity.high;
  if (normalized.includes('medium')) return COLORS.severity.medium;
  if (normalized.includes('low')) return COLORS.severity.low;
  return COLORS.severity.info;
}
