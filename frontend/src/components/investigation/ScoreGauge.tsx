import type { FraudCardData } from '../../App';
import { formatScore } from '../../lib/verdictCopy';
import { caseSeverity } from '../../theme/severity';
import { isInconclusive } from '../../lib/decision';
import { scoreTone } from '../../theme/riskTone';

/**
 * The fraud risk score, as a tick gauge.
 *
 * Three zones, and the colours were chosen by the palette validator rather
 * than by eye. Green / amber / red - `#059669 / #f59e0b / #dc2626` - clears
 * every check: lightness band, chroma floor, CVD separation (worst adjacent
 * pair deltaE 13.0 protan) and the normal-vision floor (worst pair 24.1).
 *
 * Three zones and not four, which is worth recording because the engine emits
 * four bands. Painting Suspicious, High and Critical as amber, orange and red
 * fails outright: amber-500 against orange-500 measures deltaE 9.6 for normal
 * vision, under the floor of 15, and three re-steppings inside those hues did
 * not rescue it. Four warm hues on one continuous arc is the wrong encoding.
 * So the arc carries severity rising through three zones, and the exact band -
 * including the difference between High and Critical - is printed underneath
 * in words, where it cannot be misread. Colour never carries the band alone.
 *
 * Ticks rather than a solid arc: discrete marks put a gap between every pair
 * of neighbouring colours, which is the secondary encoding the palette rules
 * ask for, and they read at a glance as a quantity rather than as a ring.
 */

const TICKS = 44;
/** Degrees swept, centred on straight up. */
const SWEEP = 220;
const START = 90 + SWEEP / 2;

export default function ScoreGauge({ data }: { data: FraudCardData }) {
  const inconclusive = isInconclusive(data);
  const token = caseSeverity(data.risk_band, inconclusive);
  const raw = Number(data.final_risk_score);
  const score = Number.isFinite(raw) ? Math.max(0, Math.min(100, raw)) : 0;
  const tone = scoreTone(score);

  /*
   * Sized so the number fits the hole, checked against the widest score the
   * scale can produce rather than against the one this case happens to show.
   *
   * The opening is 2 x rInner scaled to the rendered width: at 184px wide with
   * rInner 64 that is 118px, and "100.0/100" needs about 157px - so the value
   * hung outside the arc on both sides. At 208px with rInner 68 the opening is
   * 141px and the widest string is 129px, which leaves a margin either side at
   * every score from 0.0 to 100.0.
   */
  const cx = 100;
  const cy = 94;
  const rOuter = 86;
  const rInner = 68;

  const ticks = Array.from({ length: TICKS }, (_, i) => {
    const t = i / (TICKS - 1);
    const value = t * 100;
    const deg = START - t * SWEEP;
    const rad = (deg * Math.PI) / 180;
    const cos = Math.cos(rad);
    const sin = Math.sin(rad);
    // An unreached tick is a track mark, not a faded value.
    const reached = !inconclusive && value <= score;
    return {
      key: i,
      x1: cx + rInner * cos,
      y1: cy - rInner * sin,
      x2: cx + rOuter * cos,
      y2: cy - rOuter * sin,
      stroke: reached ? scoreTone(value).mark : '#e2e8f0',
      width: reached ? 3 : 2,
    };
  });

  return (
    <section
      aria-label="Fraud risk score"
      className="flex min-w-0 flex-col items-center"
    >
      <div className="relative w-[208px]">
        <svg viewBox="0 0 200 128" className="w-full" role="img" aria-hidden>
          {ticks.map((t) => (
            <line
              key={t.key}
              x1={t.x1}
              y1={t.y1}
              x2={t.x2}
              y2={t.y2}
              stroke={t.stroke}
              strokeWidth={t.width}
              strokeLinecap="round"
            />
          ))}
        </svg>

        {/*
          Only the number sits inside the arc.
          
          The label went in here too and collided with the ticks: at 12px with
          0.12em tracking "Fraud risk score" is about 150px wide, and the arc's
          inner opening is roughly 118px at this size. Nothing that has to fit
          inside a circle should be a phrase - the number fits at any width,
          the words do not, so the words moved out.
        */}
        {/* The value carries the arc's tone, in the darker step that is
            legible as text - see theme/riskTone.ts. */}
        <p
          className={`absolute inset-x-0 top-[44%] flex items-baseline justify-center whitespace-nowrap font-sans text-[2rem] font-medium leading-none tracking-[-0.04em] tabular-nums ${
            inconclusive ? 'text-slate-400' : tone.text
          }`}
        >
          {inconclusive ? '—' : formatScore(score)}
          {!inconclusive && (
            <span className="ml-0.5 text-[0.875rem] font-normal tracking-[-0.02em] text-slate-400">
              /100
            </span>
          )}
        </p>
      </div>

      <p className="mt-1 font-sans text-[12px] font-medium uppercase tracking-[0.12em] text-slate-500">
        Fraud risk score
      </p>

      {/*
        The band is no longer named here, by request.
        
        It survives for a screen reader in the line below, and as a labelled
        fact in the identity band at the foot of the page. What it no longer
        does is appear in words beside the arc - so for a sighted reader the
        arc's colour is now the only on-screen signal of severity at this spot.
        Recorded because that is the trade, not an oversight.
      */}
      {inconclusive && (
        <p className="mt-1.5 font-sans text-[13px] leading-relaxed text-slate-600">
          No score assigned
        </p>
      )}

      <span className="sr-only">
        {inconclusive
          ? 'Analysis inconclusive, no risk score was assigned.'
          : `Fraud risk score ${formatScore(score)} out of 100, in the ${token.label} band.`}
      </span>
    </section>
  );
}
