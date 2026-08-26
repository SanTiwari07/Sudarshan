import { useCallback, useEffect, useRef, useState } from 'react';
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
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLSpanElement>(null);

  const close = useCallback(() => setOpen(false), []);

  useEffect(() => {
    if (!open) return;
    const onDocPointer = (e: MouseEvent | TouchEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) {
        close();
      }
    };
    document.addEventListener('mousedown', onDocPointer);
    document.addEventListener('touchstart', onDocPointer);
    return () => {
      document.removeEventListener('mousedown', onDocPointer);
      document.removeEventListener('touchstart', onDocPointer);
    };
  }, [open, close]);

  if (!text) {
    return <span className={className}>{children}</span>;
  }

  return (
    <span className={`inline-flex items-center gap-1 ${className}`}>
      <span>{children}</span>
      <span ref={rootRef} className="relative inline-flex shrink-0 group/help">
        <span
          role="button"
          tabIndex={0}
          className="rounded-full p-0.5 text-slate-500 hover:text-blue-600 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40 cursor-help"
          aria-label={text}
          aria-expanded={open}
          onClick={(e) => {
            e.stopPropagation();
            e.preventDefault();
            setOpen((v) => !v);
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.stopPropagation();
              e.preventDefault();
              setOpen((v) => !v);
            }
          }}
        >
          <HelpCircle className="h-3.5 w-3.5" />
        </span>
        <span
          role="tooltip"
          className={`pointer-events-none absolute left-0 top-full z-[60] mt-1.5 w-56 px-3 py-2 rounded-lg border border-slate-200 bg-white text-slate-600 text-[11px] leading-snug shadow-md transition-opacity ${
            open ? 'opacity-100' : 'opacity-0 group-hover/help:opacity-100 group-focus-within/help:opacity-100'
          }`}
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
