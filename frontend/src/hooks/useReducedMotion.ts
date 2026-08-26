import { useEffect, useState } from 'react';

/**
 * Whether the reader has asked their operating system for less motion.
 *
 * The CSS guard in index.css handles declarative animation, but JavaScript
 * animation runs outside it entirely - a spring driven from `motion` does not
 * consult a media query. Every animated component reads this and shortens its
 * transition to zero rather than skipping the state change, so the information
 * still arrives; only the interpolation stops.
 *
 * Subscribes to changes, because the preference can be toggled while the app is
 * open and a security console is a thing people leave running for hours.
 */
export function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return false;
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  });

  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return;
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    const onChange = (e: MediaQueryListEvent) => setReduced(e.matches);

    // Safari below 14 only has the deprecated form.
    if (mq.addEventListener) {
      mq.addEventListener('change', onChange);
      return () => mq.removeEventListener('change', onChange);
    }
    mq.addListener(onChange);
    return () => mq.removeListener(onChange);
  }, []);

  return reduced;
}
