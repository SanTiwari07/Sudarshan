import { HelpCircle } from 'lucide-react';
import { TERM_HELP } from '../../lib/analystCopy';

type HelpTermProps = {
  children: React.ReactNode;
  /** Glossary key; falls back to children text */
  term?: string;
  helper?: string;
  className?: string;
};

export default function HelpTerm({ children, term, helper, className = '' }: HelpTermProps) {
  const key = term || (typeof children === 'string' ? children : '');
  const text = helper || TERM_HELP[key] || TERM_HELP[String(children)] || '';

  if (!text) {
    return <span className={className}>{children}</span>;
  }

  return (
    <span className={`inline-flex items-center gap-1 ${className}`}>
      <span>{children}</span>
      <span className="relative group">
        <HelpCircle
          className="h-3.5 w-3.5 text-slate-400 hover:text-blue-600 cursor-help shrink-0"
          aria-label={text}
        />
        <span
          role="tooltip"
          className="pointer-events-none absolute left-1/2 -translate-x-1/2 bottom-full mb-1.5 z-50 w-56 px-2.5 py-2 rounded-lg bg-slate-900 text-white text-[11px] leading-snug opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 transition-opacity shadow-lg"
        >
          {text}
        </span>
      </span>
    </span>
  );
}

export function SectionBlurb({ children }: { children: React.ReactNode }) {
  return <p className="text-xs text-slate-500 mt-0.5 leading-relaxed max-w-3xl">{children}</p>;
}
