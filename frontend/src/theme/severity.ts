import type { LucideIcon } from 'lucide-react';
import {
  OctagonAlert,
  TriangleAlert,
  CircleAlert,
  ShieldCheck,
  SearchX,
  CircleHelp,
} from 'lucide-react';

/**
 * The severity vocabulary, in one place.
 *
 * Two things this fixes.
 *
 * 1. Colour was carrying meaning on its own. A red dot and an amber dot were
 *    the whole difference between "critical" and "suspicious" in several
 *    places, which fails for a colour-blind reader and for anyone reading a
 *    printed report. Every level here ships a label, an icon and a sentence, so
 *    the colour is reinforcement rather than the message.
 *
 * 2. There was no token for "we could not tell". Every renderer had four states
 *    and had to put an unassessed case into one of them - which in practice
 *    meant green, because a low score looks like a good score. INCOMPLETE is a
 *    first-class level here, and it is slate: an inconclusive result is the
 *    absence of a conclusion and must not read as either good news or bad news.
 */

export type SeverityLevel =
  | 'CRITICAL'
  | 'HIGH'
  | 'SUSPICIOUS'
  | 'SAFE'
  | 'INCOMPLETE'
  | 'UNKNOWN';

export type SeverityToken = {
  level: SeverityLevel;
  /** Sentence-case name, for headings and badges. */
  label: string;
  /** What this level means for the reader, in one clause. Never omitted. */
  meaning: string;
  icon: LucideIcon;
  /** Foreground for text on a light surface. AA against white. */
  fg: string;
  /** Tinted surface. */
  bg: string;
  /** Hairline border matching `bg`. */
  border: string;
  /** Solid fill, for meters and rails. */
  bar: string;
  /** Solid badge: fill + contrasting text. */
  badge: string;
  /** Left accent rule. */
  accent: string;
};

export const SEVERITY: Record<SeverityLevel, SeverityToken> = {
  CRITICAL: {
    level: 'CRITICAL',
    label: 'Critical',
    meaning: 'Immediate security action recommended',
    icon: OctagonAlert,
    fg: 'text-red-700',
    bg: 'bg-red-50',
    border: 'border-red-200',
    bar: 'bg-red-600',
    badge: 'bg-red-600 text-white',
    accent: 'border-l-red-600',
  },
  HIGH: {
    level: 'HIGH',
    label: 'High risk',
    meaning: 'Strong evidence of malicious capability',
    icon: TriangleAlert,
    fg: 'text-orange-700',
    bg: 'bg-orange-50',
    border: 'border-orange-200',
    bar: 'bg-orange-500',
    badge: 'bg-orange-500 text-white',
    accent: 'border-l-orange-500',
  },
  SUSPICIOUS: {
    level: 'SUSPICIOUS',
    label: 'Suspicious',
    meaning: 'Potentially harmful behaviour detected',
    icon: CircleAlert,
    fg: 'text-amber-800',
    bg: 'bg-amber-50',
    border: 'border-amber-200',
    bar: 'bg-amber-500',
    badge: 'bg-amber-400 text-slate-950',
    accent: 'border-l-amber-500',
  },
  SAFE: {
    level: 'SAFE',
    label: 'Safe',
    meaning: 'No significant malicious behaviour identified',
    icon: ShieldCheck,
    fg: 'text-emerald-700',
    bg: 'bg-emerald-50',
    border: 'border-emerald-200',
    bar: 'bg-emerald-600',
    badge: 'bg-emerald-600 text-white',
    accent: 'border-l-emerald-600',
  },
  INCOMPLETE: {
    level: 'INCOMPLETE',
    label: 'Incomplete',
    meaning: 'Analysis coverage was insufficient for a safe conclusion',
    icon: SearchX,
    // Slate on purpose. See the note at the top of this file.
    fg: 'text-slate-700',
    bg: 'bg-slate-50',
    border: 'border-slate-300',
    bar: 'bg-slate-400',
    badge: 'bg-slate-600 text-white',
    accent: 'border-l-slate-400',
  },
  UNKNOWN: {
    level: 'UNKNOWN',
    label: 'Not assessed',
    meaning: 'This dimension was not evaluated for this case',
    icon: CircleHelp,
    fg: 'text-slate-600',
    bg: 'bg-slate-50',
    border: 'border-slate-200',
    bar: 'bg-slate-300',
    badge: 'bg-slate-500 text-white',
    accent: 'border-l-slate-300',
  },
};

/**
 * Resolve any of the loosely-typed severity strings flowing in from the engine,
 * MobSF and the LLM onto the vocabulary above.
 *
 * Deliberately does not guess: an unrecognised string returns UNKNOWN rather
 * than falling through to SAFE, because the failure mode of guessing here is a
 * clean bill of health nobody issued.
 */
export function severityOf(raw: string | null | undefined): SeverityToken {
  const s = (raw ?? '').trim().toLowerCase();
  if (!s) return SEVERITY.UNKNOWN;
  if (s.includes('critical')) return SEVERITY.CRITICAL;
  if (s.includes('incomplete') || s.includes('inconclusive')) return SEVERITY.INCOMPLETE;
  if (s.includes('high')) return SEVERITY.HIGH;
  if (s.includes('suspicious') || s.includes('medium') || s.includes('warning')) {
    return SEVERITY.SUSPICIOUS;
  }
  if (s.includes('safe') || s.includes('clean') || s.includes('low') || s.includes('info')) {
    return s.includes('safe') || s.includes('clean') ? SEVERITY.SAFE : SEVERITY.UNKNOWN;
  }
  return SEVERITY.UNKNOWN;
}

/**
 * The severity of a whole case, honouring the safety floors.
 *
 * `isInconclusive` lives in lib/decision.ts and is passed in rather than
 * imported, so this module stays free of any dependency on the case model and
 * can be used by the design-system layer.
 */
export function caseSeverity(band: string | null | undefined, inconclusive: boolean): SeverityToken {
  if (inconclusive) return SEVERITY.INCOMPLETE;
  const t = severityOf(band);
  return t.level === 'UNKNOWN' ? SEVERITY.UNKNOWN : t;
}
