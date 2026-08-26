import { useRef, type ReactNode } from 'react';
import { ArrowLeft, X } from 'lucide-react';
import { TYPOGRAPHY } from '../../theme/typography';
import { useDialogBehavior } from '../../hooks/useDialogBehavior';

/**
 * The one drawer shell.
 *
 * There were five overlay surfaces, each with its own hand-rolled chrome: two
 * shared `FindingDrawerShell`, three rolled their own `fixed inset-0`, and they
 * disagreed about z-index (`z-50` against `z-[60]`), width, header typography
 * and whether Escape worked at all. An analyst who opened evidence from a
 * finding, from a score row and from a workflow stage got three
 * different-looking panels showing overlapping records.
 *
 * What this adds beyond consolidation:
 *
 * - **Focus trap.** None of the five had one. Tabbing out of an open drawer put
 *   focus on the page behind it, which for a keyboard or screen-reader user
 *   means the drawer is a visual overlay and nothing more.
 * - **Focus restore.** Closing returns focus to whatever opened the drawer, so
 *   drilling into evidence and coming back does not dump you at the top of the
 *   document.
 * - **Scroll lock.** The page behind no longer scrolls under the overlay.
 * - **A back affordance.** Drawers open other drawers by design - the score
 *   ledger opens evidence, the influence detail opens the ledger - so when
 *   there is somewhere to go back to, the header says so.
 */
export default function DrawerShell({
  open,
  onClose,
  onBack,
  title,
  subtitle,
  headerExtra,
  footer,
  labelledById = 'drawer-title',
  children,
}: {
  open: boolean;
  onClose: () => void;
  /** Provided when this drawer was opened from another one. */
  onBack?: () => void;
  title: string;
  subtitle?: ReactNode;
  headerExtra?: ReactNode;
  footer?: ReactNode;
  labelledById?: string;
  children: ReactNode;
}) {
  const panelRef = useRef<HTMLDivElement | null>(null);

  // Focus trap, focus restore, scroll lock and Escape - shared with the
  // screenshot lightbox, which needs identical behaviour and a different shape.
  useDialogBehavior({ open, panelRef, onClose });

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div
        className="absolute inset-0 bg-slate-900/40 dialog-backdrop-enter"
        onClick={onClose}
        aria-hidden
      />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelledById}
        tabIndex={-1}
        className="relative w-full max-w-lg sm:max-w-xl bg-white h-full shadow-2xl border-l border-slate-200 flex flex-col focus:outline-none drawer-panel-enter"
      >
        <header className="px-5 py-4 border-b border-slate-200 shrink-0">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              {onBack && (
                <button
                  type="button"
                  onClick={onBack}
                  className={`${TYPOGRAPHY.linkAction} mb-1.5`}
                >
                  <ArrowLeft className="h-3.5 w-3.5" aria-hidden />
                  Back
                </button>
              )}
              <h2 id={labelledById} className={TYPOGRAPHY.drawerTitle}>
                {title}
              </h2>
              {subtitle && <p className={`${TYPOGRAPHY.caption} mt-1`}>{subtitle}</p>}
              {headerExtra}
            </div>
            <button
              type="button"
              onClick={onClose}
              className="p-1.5 rounded hover:bg-slate-100 shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
              aria-label="Close"
            >
              <X className="h-4 w-4 text-slate-500" aria-hidden />
            </button>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-5">{children}</div>

        {footer && (
          <footer className="px-5 py-3 border-t border-slate-200 bg-slate-50/70 shrink-0">
            {footer}
          </footer>
        )}
      </div>
    </div>
  );
}
