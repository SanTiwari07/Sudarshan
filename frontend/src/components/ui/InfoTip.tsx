import { useEffect, useId, useRef, useState } from 'react';
import { Info } from 'lucide-react';

type InfoTipProps = {
  /** Plain-language explanation of what the card shows and how to read it. */
  text: string;
  /** Short label for screen readers, e.g. the card title. */
  label?: string;
  /** Which way the bubble opens. */
  align?: 'left' | 'right';
  tone?: 'light' | 'dark';
};

/**
 * The "i" next to a card title. Hover or focus previews it; click pins it open
 * (so it also works on touch), and Escape or an outside click closes it.
 */
export default function InfoTip({ text, label = 'this card', align = 'left', tone = 'light' }: InfoTipProps) {
  const [pinned, setPinned] = useState(false);
  const [hover, setHover] = useState(false);
  const ref = useRef<HTMLSpanElement>(null);
  const id = useId();
  const open = pinned || hover;

  useEffect(() => {
    if (!pinned) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setPinned(false);
    };
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setPinned(false);
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [pinned]);

  return (
    <span
      ref={ref}
      className="relative inline-flex normal-case tracking-normal"
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
    >
      <button
        type="button"
        aria-label={`What does ${label} mean?`}
        aria-describedby={open ? id : undefined}
        aria-expanded={open}
        onClick={(e) => {
          e.stopPropagation();
          e.preventDefault();
          setPinned((v) => !v);
        }}
        onFocus={() => setHover(true)}
        onBlur={() => setHover(false)}
        className={`flex h-5 w-5 items-center justify-center rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
          tone === 'dark'
            ? 'text-slate-400 hover:text-white hover:bg-white/10'
            : `hover:text-blue-600 hover:bg-blue-50 ${open ? 'text-blue-600 bg-blue-50' : 'text-slate-400'}`
        }`}
      >
        <Info className="h-3.5 w-3.5" aria-hidden />
      </button>
      {open && (
        <span
          id={id}
          role="tooltip"
          className={`absolute top-full z-50 mt-2 w-72 rounded-xl bg-slate-900 px-3.5 py-3 text-left text-[13px] font-normal leading-relaxed text-slate-100 shadow-xl ${
            align === 'right' ? 'right-0' : 'left-0'
          }`}
        >
          {text}
        </span>
      )}
    </span>
  );
}
