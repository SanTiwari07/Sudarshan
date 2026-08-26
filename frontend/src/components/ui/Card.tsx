import React from 'react';

/**
 * Severity accent for a card.
 *
 * Every panel used to render as the same white box with the same grey border,
 * so a critical finding and a metadata table were visually identical and the
 * eye had nothing to anchor on. The accent is a left border rather than a
 * filled background: it separates severities without turning the page into a
 * traffic light, and it leaves the card's own content contrast untouched.
 *
 * `undefined` keeps the original neutral card, so existing callers are
 * unaffected.
 */
export type CardSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/**
 * Reading rank, which is a separate axis from severity.
 *
 * Severity says how bad a finding is. Rank says how much of the analyst's
 * attention the panel has earned on this screen. A certificate table can be
 * perfectly benign and still be the least important thing on the page; before
 * this existed it occupied exactly as much visual weight as a confirmed
 * runtime C2 callback, which is why the console read as an undifferentiated
 * wall of boxes.
 *
 *   primary   - the answer. One or two per page, at most.
 *   standard  - supporting evidence. The default.
 *   reference - raw lookup material. Recedes; expected to be collapsed.
 */
export type CardRank = 'primary' | 'standard' | 'reference';

const SEVERITY_ACCENT: Record<CardSeverity, string> = {
  critical: 'border-l-4 border-l-red-500',
  high: 'border-l-4 border-l-orange-400',
  medium: 'border-l-4 border-l-amber-400',
  low: 'border-l-4 border-l-sky-400',
  info: 'border-l-4 border-l-slate-300',
};

const RANK_SURFACE: Record<CardRank, string> = {
  primary: 'bg-white border-slate-300 shadow-[0_1px_3px_rgba(15,23,42,0.06)]',
  standard: 'bg-white border-slate-200/80 shadow-[0_1px_2px_rgba(0,0,0,0.02)]',
  reference: 'bg-slate-50/60 border-slate-200/60 shadow-none',
};

interface SocCardProps {
  children: React.ReactNode;
  className?: string;
  id?: string;
  onClick?: () => void;
  severity?: CardSeverity;
  rank?: CardRank;
}

export function SocCard({
  children,
  className = '',
  id,
  onClick,
  severity,
  rank = 'standard',
}: SocCardProps) {
  const accent = severity ? SEVERITY_ACCENT[severity] : '';
  return (
    <div
      id={id}
      onClick={onClick}
      data-severity={severity}
      data-rank={rank}
      className={`border rounded-xl overflow-hidden ${RANK_SURFACE[rank]} ${accent} ${className}`}
    >
      {children}
    </div>
  );
}

export default SocCard;
