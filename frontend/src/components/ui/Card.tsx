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

const SEVERITY_ACCENT: Record<CardSeverity, string> = {
  critical: 'border-l-4 border-l-red-500',
  high: 'border-l-4 border-l-orange-400',
  medium: 'border-l-4 border-l-amber-400',
  low: 'border-l-4 border-l-sky-400',
  info: 'border-l-4 border-l-slate-300',
};

interface SocCardProps {
  children: React.ReactNode;
  className?: string;
  id?: string;
  onClick?: () => void;
  severity?: CardSeverity;
}

export function SocCard({
  children,
  className = '',
  id,
  onClick,
  severity,
}: SocCardProps) {
  const accent = severity ? SEVERITY_ACCENT[severity] : '';
  return (
    <div
      id={id}
      onClick={onClick}
      data-severity={severity}
      className={`bg-white border border-slate-200/80 rounded-md shadow-[0_1px_2px_rgba(0,0,0,0.02)] overflow-hidden ${accent} ${className}`}
    >
      {children}
    </div>
  );
}

export default SocCard;
