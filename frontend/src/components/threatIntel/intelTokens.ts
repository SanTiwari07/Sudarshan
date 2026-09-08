/** Spacing + layout tokens for Threat Intel (8px grid) */
export const INTEL = {
  /*
   * 16px between siblings, matching --card-gap.
   *
   * These were 32px and 24px, set when every band was a full-width block and
   * the space was the only thing separating them. Now that the bands are
   * cards on a tinted page, the surface edge does that work and the large gaps
   * only pushed content below the fold.
   */
  sectionGap: 'space-y-4',
  gridGap: 'gap-4',
  cardBody: 'p-6',
  cardBodyCompact: 'p-4',
  headerPx: 'px-6 py-4',
  caption: 'text-[13px] leading-snug text-slate-500',
  meta: 'text-xs text-slate-600',
  title: 'text-sm font-semibold text-slate-800 tracking-tight',
  subtitle: 'text-xs text-slate-500 mt-0.5',
  /*
   * Sentence case, ranked by weight and colour.
   *
   * This was `uppercase tracking-[0.14em]`, which the product's own type rules
   * reserve for badges - "card titles, section titles, buttons and labels were
   * all uppercase, so every element shouted at the same volume and none of
   * them ranked". This page never got that pass, so a metric label read at the
   * same volume as the number under it, and there were eight of them on one
   * screen. Small text also wants tracking opened slightly, not to 0.14em -
   * that is a display-type value applied at 13px, which is what made these
   * read as decoration rather than as labels.
   */
  eyebrow: 'text-[13px] font-medium tracking-[0.01em] text-slate-500',
} as const;

/** Sudarshan BOI theme - align with FraudCard / CaseHeader (blue-700, slate surfaces) */
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
  bar: 'bg-slate-700',
  barGradient: 'bg-gradient-to-r from-blue-500 to-blue-700',
  ringStroke: '#1d4ed8',
} as const;
