/**
 * Typography system for the Sudarshan SOC portal.
 *
 * Three constraints:
 *
 * 1. One family. Headings used Inter Tight while body used Inter, and at the
 *    sizes this product actually renders - 15px body against an 18px heading -
 *    a narrower face does not read as hierarchy, it reads as two fonts. The
 *    console now sets everything in Inter and earns hierarchy from weight,
 *    size and colour. JetBrains Mono stays for anything an analyst may need to
 *    copy verbatim: hashes, packages, logs, code.
 * 2. Uppercase is reserved for badges and nothing else. Card titles, section
 *    titles, buttons and labels were all `uppercase tracking-wider`, so every
 *    element shouted at the same volume and none of them ranked.
 * 3. The scale is short, and it is not small. It previously bottomed out at
 *    11px with 13px body, which is a density that suits a trading terminal and
 *    punishes a bank manager reading a verdict on a projector. Body is now
 *    17px and the smallest label is 13px - one step up again, because the
 *    console is read across a room as often as it is read at a desk. The
 *    named Tailwind steps (text-xs .. text-6xl) are rescaled to match in
 *    tailwind.config.js, so the two ways of asking for a size agree.
 */

export const TYPOGRAPHY = {
  // DISPLAY - score numerals and executive metrics.
  display:
    'font-sans text-5xl sm:text-6xl font-semibold tracking-[-0.04em] text-slate-900 tabular-nums leading-none',
  displaySub: 'font-sans text-[17px] font-medium text-slate-500 tabular-nums',

  // HEADINGS - sentence case, tightened, never uppercase.
  h1: 'font-sans text-xl sm:text-2xl font-semibold tracking-[-0.02em] text-slate-900 leading-snug',
  h2: 'font-sans text-lg sm:text-xl font-semibold tracking-[-0.018em] text-slate-900 leading-snug',
  h3: 'font-sans text-[17px] font-semibold tracking-[-0.01em] text-slate-900 leading-snug',

  // CARD & SECTION TITLES - one step above body, distinguished by weight.
  cardTitle:
    'font-sans text-[17px] font-semibold tracking-[-0.01em] text-slate-900 flex items-center gap-2',
  sectionTitle:
    'font-sans text-[17px] font-semibold tracking-[-0.01em] text-slate-900 flex items-center gap-2',
  drawerTitle: 'font-sans text-lg font-semibold tracking-[-0.015em] text-slate-900',

  // PROSE
  body: 'font-sans text-[17px] font-normal text-slate-700 leading-relaxed',
  bodySmall: 'font-sans text-[15px] font-normal text-slate-600 leading-relaxed',

  // METADATA LABELS & CAPTIONS
  label: 'font-sans text-xs font-medium text-slate-500 shrink-0',
  labelDark: 'font-sans text-xs font-medium text-slate-400 shrink-0',
  caption: 'font-sans text-xs font-normal text-slate-500 leading-normal',
  helper: 'font-sans text-[15px] text-slate-500 leading-relaxed',

  // TABLES
  tableHeader:
    'font-sans text-xs font-medium text-slate-500 bg-slate-50 border-b border-slate-200',
  tableCell: 'font-sans text-[15px] font-normal text-slate-700',
  tableCellMono: 'font-mono text-[15px] font-normal text-slate-700 tabular-nums break-all',

  // BADGES - the only place uppercase survives, and the smallest thing here.
  badge:
    'font-sans text-[13px] font-semibold uppercase tracking-[0.06em] inline-flex items-center px-2 py-0.5 rounded border',
  badgePill:
    'font-sans text-[13px] font-semibold uppercase tracking-[0.06em] inline-flex items-center px-2.5 py-0.5 rounded-full border',

  // BUTTONS & ACTIONS
  button:
    'font-sans text-[17px] font-medium inline-flex items-center justify-center gap-2 rounded-md transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-1 disabled:opacity-50 disabled:cursor-not-allowed',
  buttonSm:
    'font-sans text-[15px] font-medium inline-flex items-center justify-center gap-1.5 rounded-md px-2.5 py-1.5 transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500',
  linkAction:
    'font-sans text-[15px] font-medium text-blue-700 hover:text-blue-800 inline-flex items-center gap-1 transition-colors',

  /*
   * TECHNICAL & CODE
   *
   * These carried `select-all`, so one click selected the whole element. It
   * reads as a convenience, but it removes partial selection - and grabbing the
   * first twelve characters of a hash to paste into a search is something
   * analysts do constantly. `CopyButton` already sits beside every hash and
   * package name for whole-value copying, which is the affordance that should
   * own that job.
   */
  code: 'font-mono text-[15px] font-normal text-slate-700 tabular-nums break-all',
  codeSm: 'font-mono text-xs font-normal text-slate-600 tabular-nums break-all',
  hash: 'font-mono text-xs font-normal text-slate-500 break-all',
} as const;

export type TypographyVariant = keyof typeof TYPOGRAPHY;
