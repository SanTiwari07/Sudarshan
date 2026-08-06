/** Spacing + layout tokens for Threat Intel (8px grid) */
export const INTEL = {
  sectionGap: 'space-y-8',
  gridGap: 'gap-6',
  cardBody: 'p-6',
  cardBodyCompact: 'p-4',
  headerPx: 'px-6 py-4',
  caption: 'text-[11px] leading-snug text-slate-500',
  meta: 'text-xs text-slate-600',
  title: 'text-sm font-semibold text-slate-800 tracking-tight',
  subtitle: 'text-xs text-slate-500 mt-0.5',
  eyebrow: 'text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-500',
} as const;

/** Sudarshan BOI theme — align with FraudCard / CaseHeader (blue-700, slate surfaces) */
export const INTEL_THEME = {
  accent: 'bg-blue-700',
  accentHover: 'hover:bg-blue-800',
  accentBorder: 'border-blue-700',
  accentText: 'text-blue-800',
  accentIcon: 'text-blue-700',
  accentSoft: 'bg-blue-50 text-blue-900 border-blue-200',
  observed:
    'bg-blue-700 text-white border-blue-700 shadow-sm hover:bg-blue-800 hover:border-blue-800',
  observedIcon: 'bg-white/15 text-white',
  inactive: 'bg-slate-50 text-slate-500 border-slate-200 hover:border-slate-300',
  bar: 'bg-blue-600',
  barGradient: 'bg-gradient-to-r from-blue-500 to-blue-700',
  ringStroke: '#1d4ed8',
} as const;
