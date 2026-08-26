import type { ReactNode } from 'react';
import { Check } from 'lucide-react';
import { TYPOGRAPHY } from '../../theme/typography';

/**
 * The six shapes every restyled page is built from.
 *
 * These exist so the next page does not re-derive them. Each reads its
 * geometry from the `--card-*` tokens in index.css, so a change to the corner
 * radius or the card rhythm happens in one declaration rather than in three
 * hundred class strings - which is the drift that produced seven radii and
 * seven shadows across this product.
 *
 * They carry no colour of their own beyond the existing slate/blue palette.
 * Severity and accent colours stay where they already live, in
 * `theme/severity.ts` and the page's own tokens, because those encode meaning
 * and a layout primitive must not have an opinion about meaning.
 *
 * Every one forwards `className` for placement and accepts the accessibility
 * attributes its role needs. Compose with them; do not restyle them from
 * outside.
 */

/** A white surface on the page. The only elevation in the system. */
export function Card({
  children,
  className = '',
  roomy = false,
  ...rest
}: {
  children: ReactNode;
  className?: string;
  /** 24px padding instead of 20px, for cards carrying prose or a chart. */
  roomy?: boolean;
} & React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={`border border-slate-200 bg-white ${className}`}
      style={{
        borderRadius: 'var(--card-radius)',
        padding: roomy ? '24px' : 'var(--card-pad)',
        boxShadow: 'var(--card-elevation)',
      }}
      {...rest}
    >
      {children}
    </div>
  );
}

/** The gap between sibling cards, so no caller invents its own. */
export function CardGrid({
  children,
  className = '',
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={`grid ${className}`} style={{ gap: 'var(--card-gap)' }}>
      {children}
    </div>
  );
}

/**
 * A soft status pill.
 *
 * `tone` selects an existing palette pair rather than introducing one. Solid
 * saturated fills are deliberately not offered here - a badge that shouts is
 * the thing this restyle is removing.
 */
export function Pill({
  children,
  tone = 'neutral',
  className = '',
}: {
  children: ReactNode;
  tone?: 'neutral' | 'positive' | 'caution' | 'danger' | 'accent';
  className?: string;
}) {
  const tones = {
    neutral: 'bg-slate-100 text-slate-600',
    positive: 'bg-emerald-50 text-emerald-700',
    caution: 'bg-amber-50 text-amber-700',
    danger: 'bg-red-50 text-red-700',
    accent: 'bg-blue-50 text-blue-700',
  } as const;

  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 font-sans text-[12px] font-medium tracking-[0.01em] ${tones[tone]} ${className}`}
    >
      {children}
    </span>
  );
}

/**
 * Label, value, and one line saying what the value is.
 *
 * The context line is not decoration: a bare number and its noun say how many
 * and of what, never where it came from. `delta` is optional and must be
 * omitted unless there is a real prior value to compare against - a trend chip
 * with nothing behind it is a finding invented by the layout.
 */
export function MetricTile({
  label,
  value,
  context,
  delta,
  children,
  className = '',
}: {
  label: string;
  value: ReactNode;
  context?: string;
  delta?: { text: string; tone: 'positive' | 'danger' | 'neutral' };
  /** Anything that belongs under the value, such as a ProgressBar. */
  children?: ReactNode;
  className?: string;
}) {
  return (
    <Card className={className}>
      <div className="flex items-start justify-between gap-3">
        <span className={`${TYPOGRAPHY.label} block`}>{label}</span>
        {delta && <Pill tone={delta.tone}>{delta.text}</Pill>}
      </div>
      <div className="mt-2 font-sans text-[30px] font-medium leading-none tabular-nums tracking-[-0.03em] text-slate-900">
        {value}
      </div>
      {children}
      {context && (
        <p className="mt-2 font-sans text-[13px] leading-tight tracking-[0.01em] text-slate-500">
          {context}
        </p>
      )}
    </Card>
  );
}

/**
 * A reading, drawn as a track.
 *
 * No gradient and no label inside the bar: at four pixels a gradient is a
 * texture nobody can resolve, and text inside a track is unreadable at every
 * value except the ones where it happens to fit.
 */
export function ProgressBar({
  percent,
  fill = 'bg-slate-700',
  className = '',
  label,
}: {
  percent: number;
  /** A palette class. Pass a severity token where the value carries severity. */
  fill?: string;
  className?: string;
  /** Voices the value for a reader who cannot see the track. */
  label?: string;
}) {
  const clamped = Math.max(0, Math.min(100, percent));
  return (
    <div
      className={`w-full overflow-hidden rounded-full bg-slate-200 ${className}`}
      style={{ height: 'var(--bar-height)' }}
      role="meter"
      aria-valuenow={Math.round(clamped)}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label={label}
    >
      <div
        className={`h-full rounded-full ${fill} transition-[width] duration-700 ease-out`}
        style={{ width: `${clamped}%` }}
      />
    </div>
  );
}

/** A white pill naming one contributing source. */
export function Chip({
  children,
  checked = false,
  className = '',
}: {
  children: ReactNode;
  checked?: boolean;
  className?: string;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border border-slate-200 bg-white px-2.5 py-1 font-sans text-[12px] font-medium tracking-[0.01em] text-slate-700 ${className}`}
    >
      {checked && <Check className="h-3 w-3 shrink-0 text-emerald-600" aria-hidden />}
      {children}
    </span>
  );
}

/**
 * A row of mutually exclusive choices, as a tinted track with a raised active
 * segment. Matches the case bar's section nav, so the two read as one control
 * vocabulary rather than two.
 */
export function SegmentedControl<T extends string>({
  value,
  options,
  onChange,
  ariaLabel,
  className = '',
}: {
  value: T;
  options: { id: T; label: string }[];
  onChange: (id: T) => void;
  ariaLabel: string;
  className?: string;
}) {
  return (
    <div
      role="radiogroup"
      aria-label={ariaLabel}
      className={`inline-flex items-center gap-1 rounded-full bg-slate-100 p-1 ${className}`}
    >
      {options.map((option) => {
        const selected = option.id === value;
        return (
          <button
            key={option.id}
            type="button"
            role="radio"
            aria-checked={selected}
            onClick={() => onChange(option.id)}
            className={`rounded-full px-3.5 py-1.5 font-sans text-[13px] font-medium tracking-[0.01em] transition-[color,background-color,transform] duration-150 active:scale-[0.97] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
              selected
                ? 'bg-white text-slate-900 shadow-[var(--card-elevation)]'
                : 'text-slate-500 hover:text-slate-900'
            }`}
          >
            {option.label}
          </button>
        );
      })}
    </div>
  );
}
