/**
 * Typography system for the Sudarshan SOC portal.
 *
 * Two deliberate constraints, both reactions to how the console read before:
 *
 * 1. Uppercase is reserved for badges and nothing else. Card titles, section
 *    titles, buttons and labels were all `uppercase tracking-wider`, so every
 *    element on a page shouted at the same volume and none of them ranked.
 * 2. The scale is short. Six sizes carry the whole product (48 / 18 / 15 / 13 /
 *    12 / 11px). Hierarchy comes from weight and colour, not from inventing a
 *    new size per component.
 *
 * `font-display` (Inter Tight) is for headings and numerals; `font-sans`
 * (Inter) is for prose; `font-mono` (JetBrains Mono) is for anything the
 * analyst may need to copy verbatim — hashes, packages, logs, code.
 */

export const TYPOGRAPHY = {
  // DISPLAY - score numerals and executive metrics.
  display:
    'font-display text-5xl sm:text-6xl font-semibold tracking-[-0.045em] text-slate-900 tabular-nums leading-none',
  displaySub: 'font-display text-sm font-medium text-slate-400 tabular-nums',

  // HEADINGS - sentence case, tightened, never uppercase.
  h1: 'font-display text-lg sm:text-xl font-semibold tracking-[-0.02em] text-slate-900 leading-snug',
  h2: 'font-display text-base sm:text-lg font-semibold tracking-[-0.018em] text-slate-900 leading-snug',
  h3: 'font-display text-sm font-semibold tracking-[-0.01em] text-slate-900 leading-snug',

  // CARD & SECTION TITLES - one step above body, distinguished by weight.
  cardTitle:
    'font-display text-[13px] font-semibold tracking-[-0.01em] text-slate-900 flex items-center gap-2',
  sectionTitle:
    'font-display text-[13px] font-semibold tracking-[-0.01em] text-slate-900 flex items-center gap-2',
  drawerTitle: 'font-display text-base font-semibold tracking-[-0.015em] text-slate-900',

  // PROSE
  body: 'font-sans text-[13px] font-normal text-slate-700 leading-relaxed',
  bodySmall: 'font-sans text-xs font-normal text-slate-600 leading-relaxed',

  // METADATA LABELS & CAPTIONS
  label: 'font-sans text-[11px] font-medium text-slate-500 shrink-0',
  labelDark: 'font-sans text-[11px] font-medium text-slate-400 shrink-0',
  caption: 'font-sans text-[11px] font-normal text-slate-500 leading-normal',
  helper: 'font-sans text-xs text-slate-500 leading-relaxed',

  // TABLES
  tableHeader:
    'font-sans text-[11px] font-medium text-slate-500 bg-slate-50 border-b border-slate-200',
  tableCell: 'font-sans text-xs font-normal text-slate-700',
  tableCellMono: 'font-mono text-xs font-normal text-slate-700 tabular-nums break-all',

  // BADGES - the only place uppercase survives, and only at 10px.
  badge:
    'font-sans text-[10px] font-semibold uppercase tracking-[0.06em] inline-flex items-center px-1.5 py-0.5 rounded border',
  badgePill:
    'font-sans text-[10px] font-semibold uppercase tracking-[0.06em] inline-flex items-center px-2 py-0.5 rounded-full border',

  // BUTTONS & ACTIONS
  button:
    'font-sans text-[13px] font-medium inline-flex items-center justify-center gap-2 rounded-md transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-1 disabled:opacity-50 disabled:cursor-not-allowed',
  buttonSm:
    'font-sans text-xs font-medium inline-flex items-center justify-center gap-1.5 rounded-md px-2.5 py-1.5 transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500',
  linkAction:
    'font-sans text-xs font-medium text-blue-700 hover:text-blue-800 inline-flex items-center gap-1 transition-colors',

  // TECHNICAL & CODE
  code: 'font-mono text-xs font-normal text-slate-700 tabular-nums break-all select-all',
  codeSm: 'font-mono text-[11px] font-normal text-slate-600 tabular-nums break-all select-all',
  hash: 'font-mono text-[11px] font-normal text-slate-500 break-all select-all',
} as const;

export type TypographyVariant = keyof typeof TYPOGRAPHY;
