/**
 * Centralized typography design system for Sudarshan BOI Enterprise SOC Portal.
 * Establishes a unified typography hierarchy and reusable class compositions across all components.
 */

export const TYPOGRAPHY = {
  // DISPLAY / HERO - Score numbers & major executive metrics
  display: 'font-mono text-5xl sm:text-6xl font-extrabold tracking-tight text-slate-900 tabular-nums leading-none',
  displaySub: 'font-mono text-xs sm:text-sm font-semibold text-slate-400 uppercase tracking-wide',

  // HEADINGS
  h1: 'font-sans text-xl sm:text-2xl font-bold tracking-tight text-slate-900 leading-snug',
  h2: 'font-sans text-lg sm:text-xl font-semibold tracking-tight text-slate-900 leading-snug',
  h3: 'font-sans text-sm sm:text-base font-semibold tracking-tight text-slate-900 leading-snug',
  
  // CARD & SECTION TITLES
  cardTitle: 'font-sans text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center gap-1.5',
  sectionTitle: 'font-sans text-xs font-bold uppercase tracking-widest text-slate-800 flex items-center gap-2',
  drawerTitle: 'font-sans text-base font-bold text-slate-900 tracking-tight',

  // PROSE & TEXT BODY
  body: 'font-sans text-sm font-normal text-slate-800 leading-relaxed',
  bodySmall: 'font-sans text-xs font-normal text-slate-600 leading-normal',
  
  // METADATA LABELS & CAPTIONS
  label: 'font-sans text-[11px] font-semibold uppercase tracking-wider text-slate-500 shrink-0',
  labelDark: 'font-sans text-[11px] font-semibold uppercase tracking-wider text-slate-400 shrink-0',
  caption: 'font-sans text-[11px] font-normal text-slate-500 leading-normal',
  helper: 'font-sans text-xs text-slate-500 leading-relaxed',

  // TABLES
  tableHeader: 'font-sans text-[11px] font-bold uppercase tracking-wider text-slate-700 bg-slate-100/90',
  tableCell: 'font-sans text-xs font-normal text-slate-800',
  tableCellMono: 'font-mono text-xs font-medium text-slate-800 tabular-nums break-all',

  // BADGES & STATUS INDICATORS
  badge: 'font-sans text-[11px] font-bold uppercase tracking-wider inline-flex items-center px-2 py-0.5 rounded border shadow-2xs',
  badgePill: 'font-sans text-[11px] font-bold uppercase tracking-wider inline-flex items-center px-2.5 py-0.5 rounded-full border shadow-2xs',

  // BUTTONS & ACTIONS
  button: 'font-sans text-xs font-semibold uppercase tracking-wider inline-flex items-center justify-center gap-2 rounded-md shadow-xs transition-all cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 disabled:opacity-60',
  buttonSm: 'font-sans text-[11px] font-semibold uppercase tracking-wider inline-flex items-center justify-center gap-1.5 rounded px-2.5 py-1 transition-all cursor-pointer',
  linkAction: 'font-sans text-xs font-semibold text-blue-700 hover:text-blue-800 hover:underline inline-flex items-center gap-1 transition-colors',

  // TECHNICAL & CODE (Monospace reserved for hashes, code, package names, logs, API paths)
  code: 'font-mono text-xs font-medium text-slate-800 tabular-nums break-all select-all',
  codeSm: 'font-mono text-[11px] font-medium text-slate-700 tabular-nums break-all select-all',
  hash: 'font-mono text-[11px] font-semibold text-slate-700 break-all select-all',
} as const;

export type TypographyVariant = keyof typeof TYPOGRAPHY;
