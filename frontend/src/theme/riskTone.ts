/**
 * One meaning, two palettes: one for marks, one for text.
 *
 * A colour that is legible as a 3px tick is not necessarily legible as a word,
 * and the gap is not small. The amber the gauge draws with, `#7c3aed`, sits at
 * 2.15:1 against white - it fails WCAG AA even at large-text sizes, where the
 * bar is only 3:1. Painting "Moderate" in the same amber as its meter would
 * have produced a label a lot of readers simply cannot read.
 *
 * So each tone carries both. `mark` is the fill the palette validator cleared
 * for the gauge zones (green/amber/red, worst adjacent pair deltaE 24.1 for normal
 * vision, 13.0 protan). `text` is the darker step of the same hue that clears
 * 4.5:1 - emerald-700 at 5.48, amber-700 at 5.02, red-700 at 6.47 - so the
 * words stay readable while the marks stay distinguishable.
 *
 * On the general rule that text should wear text tokens rather than series
 * colour: that rule exists to stop categorical series hues leaking into
 * labels, where colour would become the only thing identifying a series. These
 * are status tones on a single value whose state is the whole message, and in
 * both places the state is also written out in words beside the number - the
 * band under the gauge, the level as the value itself. Colour is never the
 * only carrier here.
 */

export type RiskTone = {
  /** Fill for gauge ticks and meters. Validated for adjacency, not for text. */
  mark: string;
  /** Tailwind background for bars. */
  bar: string;
  /** Tailwind foreground, >= 4.5:1 on white. */
  text: string;
};

export const RISK_TONES = {
  good: { mark: '#059669', bar: 'bg-emerald-600', text: 'text-emerald-700' },
  caution: { mark: '#7c3aed', bar: 'bg-amber-500', text: 'text-amber-700' },
  bad: { mark: '#dc2626', bar: 'bg-red-600', text: 'text-red-700' },
  /** No reading, or a reading the run did not earn. */
  neutral: { mark: '#94a3b8', bar: 'bg-slate-400', text: 'text-slate-500' },
} as const satisfies Record<string, RiskTone>;

/**
 * Where a 0-100 risk score sits.
 *
 * Three zones against the engine's four bands: High and Critical share the red
 * tone because four warm hues on one continuous scale cannot be separated
 * reliably. The exact band is always printed in words alongside.
 */
export function scoreTone(value: number): RiskTone {
  if (!Number.isFinite(value)) return RISK_TONES.neutral;
  if (value < 35) return RISK_TONES.good;
  if (value < 60) return RISK_TONES.caution;
  return RISK_TONES.bad;
}

/** How much of the pipeline reported. Higher is better, so the scale inverts. */
export function confidenceTone(label: string): RiskTone {
  if (label === 'High') return RISK_TONES.good;
  if (label === 'Moderate') return RISK_TONES.caution;
  return RISK_TONES.neutral;
}
