import type { ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';

type PageHeaderProps = {
  title: string;
  description?: ReactNode;
  icon?: LucideIcon;
  /** Buttons or controls aligned to the right of the title. */
  actions?: ReactNode;
  /** Small label above the title, e.g. a section name. */
  eyebrow?: string;
  className?: string;
};

/**
 * The one page header. Every workspace page opens with the same shape -
 * icon, title, one-line description, actions on the right - so an analyst
 * moving between pages never has to re-learn where things are.
 */
export default function PageHeader({
  title,
  description,
  icon: Icon,
  actions,
  eyebrow,
  className = '',
}: PageHeaderProps) {
  return (
    <header className={`flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between ${className}`}>
      <div className="flex items-start gap-4 min-w-0">
        {Icon && (
          <span className="hidden sm:flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-blue-600 text-white">
            <Icon className="h-[22px] w-[22px]" aria-hidden />
          </span>
        )}
        <div className="min-w-0">
          {eyebrow && (
            <p className="text-xs font-semibold uppercase tracking-[0.08em] text-blue-600 mb-1">
              {eyebrow}
            </p>
          )}
          <h1 className="text-2xl sm:text-[28px] font-semibold tracking-[-0.025em] text-slate-900 leading-tight">
            {title}
          </h1>
          {description && (
            <p className="mt-1.5 text-[15px] text-slate-500 leading-relaxed max-w-2xl">{description}</p>
          )}
        </div>
      </div>
      {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
    </header>
  );
}
