import { useEffect, useRef, useState } from 'react';

/**
 * Reveal a section once, as it scrolls into view.
 *
 * The purpose is hierarchy, not decoration: the case page is one argument read
 * top to bottom, and revealing it a section at a time reinforces that order.
 * So the unit is a *section*, never an individual card or line - content that
 * animates item-by-item as you read it is content that runs away from you.
 *
 * Three rules, all of them about not making motion load-bearing:
 *
 * - The children are always mounted and always in the accessibility tree. The
 *   animation is opacity and transform over content that is already there, so a
 *   reader with JavaScript throttled, motion disabled, or a screen reader gets
 *   the complete page.
 * - It fires once. Re-animating on scroll-back would make a long investigation
 *   page feel unstable.
 * - Under `prefers-reduced-motion` it renders visible immediately and never
 *   registers an observer at all.
 *
 * Uses IntersectionObserver directly rather than an animation library: this and
 * AnimatedNumber are the only two motion primitives the product needs, and
 * neither justifies a dependency.
 */
export default function InView({
  children,
  /** Delay in ms, for staggering sibling sections. Keep small. */
  delayMs = 0,
  className,
  as: Tag = 'div',
}: {
  children: React.ReactNode;
  delayMs?: number;
  className?: string;
  as?: 'div' | 'section';
}) {
  const ref = useRef<HTMLDivElement | null>(null);
  const [visible, setVisible] = useState(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return true;
    // Start visible when the reader has asked for less motion, or when the
    // browser cannot observe intersections - failing open keeps content
    // readable rather than trapping it behind an effect that never runs.
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return true;
    return typeof IntersectionObserver === 'undefined';
  });

  useEffect(() => {
    if (visible) return;
    const el = ref.current;
    if (!el) return;

    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setVisible(true);
          observer.disconnect();
        }
      },
      // Fire slightly before the section reaches the viewport, so the reveal
      // has finished by the time the reader's eye arrives.
      { rootMargin: '0px 0px -10% 0px', threshold: 0.05 },
    );

    observer.observe(el);
    return () => observer.disconnect();
  }, [visible]);

  return (
    <Tag
      ref={ref as React.Ref<HTMLDivElement & HTMLElement>}
      className={className}
      style={{
        opacity: visible ? 1 : 0,
        transform: visible ? 'none' : 'translateY(8px)',
        transition: 'opacity 220ms cubic-bezier(0.16,1,0.3,1), transform 220ms cubic-bezier(0.16,1,0.3,1)',
        transitionDelay: visible && delayMs ? `${delayMs}ms` : '0ms',
      }}
    >
      {children}
    </Tag>
  );
}
