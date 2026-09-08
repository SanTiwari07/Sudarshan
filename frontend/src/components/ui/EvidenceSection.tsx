import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { ChevronDown } from 'lucide-react';
import { TYPOGRAPHY } from '../../theme/typography';

/**
 * One collapsible evidence section.
 *
 * The evidence view rendered every panel expanded, so an analyst looking for
 * the certificate scrolled past the whole behavioural section to reach it, and
 * a critical runtime finding occupied a box identical to the network security
 * config table. Tabs fixed some of that; inside a tab it was still a stack of
 * seventeen open panels.
 *
 * Three properties that matter more than the animation:
 *
 * - **Children unmount when closed.** A case can carry 1,284 evidence records;
 *   keeping every closed panel's rows in the tree costs render time on every
 *   parent update for content nobody is looking at.
 * - **The count is on the header.** A closed section still has to answer "is
 *   there anything in here", or collapsing just moves the hunting from
 *   scrolling to clicking.
 * - **A section opens itself when the URL points at it.** The assistant cites
 *   evidence by anchor; a citation that lands on a collapsed panel is a
 *   citation the reader has to go and find.
 *
 * Open state persists for the session so an analyst's arrangement survives
 * moving between sections and coming back.
 */

function storageKey(id: string) {
  return `sudarshan_evidence_section:${id}`;
}

function readStored(id: string, fallback: boolean): boolean {
  try {
    const raw = sessionStorage.getItem(storageKey(id));
    if (raw === '1') return true;
    if (raw === '0') return false;
  } catch {
    // Storage disabled. The default is still correct.
  }
  return fallback;
}

export default function EvidenceSection({
  id,
  title,
  subtitle,
  count,
  icon,
  defaultOpen = false,
  children,
}: {
  /** Also the anchor: `#<id>` opens and scrolls to this section. */
  id: string;
  title: string;
  subtitle?: string;
  /** Shown on the header so a closed section still reports what it holds. */
  count?: number;
  icon?: ReactNode;
  defaultOpen?: boolean;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(() => readStored(id, defaultOpen));
  const ref = useRef<HTMLElement | null>(null);

  const setOpenPersisted = useCallback(
    (next: boolean) => {
      setOpen(next);
      try {
        sessionStorage.setItem(storageKey(id), next ? '1' : '0');
      } catch {
        // Persisting is a convenience, never a precondition.
      }
    },
    [id],
  );

  // Open and reveal when the URL names this section.
  useEffect(() => {
    const target = () => decodeURIComponent(window.location.hash.replace(/^#/, ''));
    const reveal = () => {
      if (target() !== id) return;
      setOpenPersisted(true);
      // After the panel has been given a chance to render its contents.
      requestAnimationFrame(() => {
        ref.current?.scrollIntoView({ block: 'start', behavior: 'auto' });
      });
    };
    reveal();
    window.addEventListener('hashchange', reveal);
    return () => window.removeEventListener('hashchange', reveal);
  }, [id, setOpenPersisted]);

  const hasCount = typeof count === 'number';
  const empty = hasCount && count === 0;

  return (
    <section
      ref={ref}
      id={id}
      className="scroll-mt-28 overflow-hidden rounded-xl border border-slate-200 bg-white shadow-[0_1px_2px_rgba(0,0,0,0.02)]"
    >
      <h3>
        <button
          type="button"
          onClick={() => setOpenPersisted(!open)}
          aria-expanded={open}
          aria-controls={`${id}-panel`}
          className="w-full flex items-center justify-between gap-3 px-4 py-3 text-left hover:bg-slate-50 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-blue-500"
        >
          <span className="flex items-center gap-2.5 min-w-0">
            {icon && (
              <span className="text-slate-400 shrink-0" aria-hidden>
                {icon}
              </span>
            )}
            <span className="min-w-0">
              <span className={`${TYPOGRAPHY.h3} block truncate`}>{title}</span>
              {subtitle && (
                <span className={`${TYPOGRAPHY.caption} block truncate`}>{subtitle}</span>
              )}
            </span>
          </span>

          <span className="flex items-center gap-2.5 shrink-0">
            {hasCount && (
              <span
                className={`rounded-full px-2 py-0.5 text-[13px] font-medium tabular-nums tracking-[0.01em] ${
                  empty ? 'bg-slate-50 text-slate-500' : 'bg-slate-100 text-slate-700'
                }`}
              >
                {count}
              </span>
            )}
            <ChevronDown
              className={`h-4 w-4 text-slate-500 transition-transform ${open ? 'rotate-180' : ''}`}
              aria-hidden
            />
          </span>
        </button>
      </h3>

      {/* Unmounted rather than hidden - see the note at the top of this file. */}
      {open && (
        <div id={`${id}-panel`} className="border-t border-slate-200 p-4 space-y-4">
          {children}
        </div>
      )}
    </section>
  );
}
