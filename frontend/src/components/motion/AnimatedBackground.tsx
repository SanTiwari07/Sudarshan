import { useCallback, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from 'react';

/**
 * A single highlight that slides between the items of a control group.
 *
 * The behaviour is Motion Primitives' Animated Background; the implementation
 * is not. That library expresses this with `layoutId` shared-layout animation,
 * which is the right tool and reads beautifully - but it arrives with the
 * `motion` runtime, and measuring that here gave:
 *
 *     entry chunk  387.03 kB -> 517.43 kB   (+130 kB)
 *     gzipped      115.65 kB -> 159.10 kB   (+43 kB, +37.6%)
 *
 * on the chunk that loads before anything renders, in a console that has to
 * work on whatever hardware a bank branch has. Forty-three kilobytes for a
 * sliding pill is not a trade this product should make, and the project's own
 * motion rule is that performance outranks animation. So the highlight is
 * measured and moved with a CSS transform instead: same signal, same easing
 * curve as the rest of the product, no dependency.
 *
 * What the highlight is for: saying where you are. Four case sections and three
 * reading depths are groups a reader moves between constantly, and a highlight
 * that travels carries the relationship between where they were and where they
 * now are, which one that blinks between boxes does not.
 *
 * Under `prefers-reduced-motion` the highlight still moves - it just stops
 * interpolating. The global guard in index.css collapses the transition
 * duration, so the "where am I" signal survives while the travel does not.
 * Motion may never be the only carrier of information.
 */
export default function AnimatedBackground({
  children,
  value,
  className,
}: {
  children: ReactNode;
  /** Must match a `data-id` on one of the rendered children. */
  value: string;
  /** Applied to the highlight itself, e.g. "rounded-md bg-slate-900". */
  className?: string;
}) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [box, setBox] = useState<{ left: number; width: number } | null>(null);

  const measure = useCallback(() => {
    const container = containerRef.current;
    if (!container) return;
    const target = container.querySelector<HTMLElement>(`[data-id="${CSS.escape(value)}"]`);
    if (!target) {
      setBox(null);
      return;
    }
    setBox({ left: target.offsetLeft, width: target.offsetWidth });
  }, [value]);

  // Before paint, so the highlight never renders in the wrong place first.
  useLayoutEffect(measure, [measure]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    // Re-measure on anything that can move the items: viewport changes, a
    // container resize, and web fonts landing after first paint - which shifts
    // label widths and would otherwise leave the highlight misaligned until the
    // next interaction.
    const ro = new ResizeObserver(measure);
    ro.observe(container);
    Array.from(container.children).forEach((c) => ro.observe(c));

    window.addEventListener('resize', measure);
    void document.fonts?.ready.then(measure).catch(() => {});

    return () => {
      ro.disconnect();
      window.removeEventListener('resize', measure);
    };
  }, [measure]);

  return (
    <div ref={containerRef} className="relative inline-flex items-center">
      {box && (
        <span
          aria-hidden
          className={`absolute top-0 bottom-0 left-0 transition-[transform,width] duration-200 ease-[cubic-bezier(0.16,1,0.3,1)] ${
            className ?? ''
          }`}
          style={{ transform: `translateX(${box.left}px)`, width: box.width }}
        />
      )}
      {children}
    </div>
  );
}
