import { useEffect, useRef, type RefObject } from 'react';

/**
 * The behaviour every modal surface owes its user, in one place.
 *
 * Focus trap, focus restore, scroll lock and Escape. Extracted as a hook rather
 * than folded into a shell component because the product has two legitimate
 * modal *geometries* - a side drawer for records, a centred lightbox for
 * screenshots - and they should share behaviour without being forced to share
 * layout. Making the lightbox a side panel to reuse a shell would be the
 * consolidation tail wagging the design dog.
 *
 * Returns nothing; it wires listeners against the element you pass.
 */
export function useDialogBehavior({
  open,
  panelRef,
  onClose,
  autoFocus = true,
}: {
  open: boolean;
  panelRef: RefObject<HTMLElement | null>;
  onClose: () => void;
  /** Set false when the surface manages its own initial focus target. */
  autoFocus?: boolean;
}) {
  const restoreTo = useRef<HTMLElement | null>(null);

  // Remember what had focus, and put it back on close.
  useEffect(() => {
    if (!open) return;
    restoreTo.current = document.activeElement as HTMLElement | null;
    return () => {
      const el = restoreTo.current;
      // The opener can be gone by now - a drawer that replaced its own trigger,
      // for instance - so only restore to something still in the document.
      if (el && document.contains(el)) el.focus();
    };
  }, [open]);

  // Lock the page behind the overlay.
  useEffect(() => {
    if (!open) return;
    const previous = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = previous;
    };
  }, [open]);

  // Move focus in once the surface exists.
  useEffect(() => {
    if (!open || !autoFocus) return;
    panelRef.current?.focus();
  }, [open, autoFocus, panelRef]);

  // Escape closes; Tab cycles inside.
  useEffect(() => {
    if (!open) return;

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onClose();
        return;
      }
      if (e.key !== 'Tab') return;

      const panel = panelRef.current;
      if (!panel) return;

      /*
       * Deliberately not a layout-based visibility test.
       *
       * The obvious filter is `offsetParent !== null`, but that is null for any
       * `position: fixed` element - which is what these surfaces are - and it is
       * always null under jsdom, so the trap silently degrades to "no focusable
       * elements" in tests and can do the same in a real browser depending on
       * how the panel is positioned. Attribute-based hiding expresses the
       * intent and behaves the same in both.
       */
      const focusable = Array.from(
        panel.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ),
      ).filter(
        (el) =>
          !el.hasAttribute('hidden') &&
          el.getAttribute('aria-hidden') !== 'true' &&
          !el.closest('[aria-hidden="true"]'),
      );

      if (focusable.length === 0) {
        // Nothing to land on, so keep focus on the panel rather than letting it
        // escape to the page behind.
        e.preventDefault();
        panel.focus();
        return;
      }

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement;

      if (e.shiftKey && (active === first || active === panel)) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && active === last) {
        e.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', onKey, true);
    return () => document.removeEventListener('keydown', onKey, true);
  }, [open, onClose, panelRef]);
}
