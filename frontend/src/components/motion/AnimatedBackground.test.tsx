import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import AnimatedBackground from './AnimatedBackground';

/**
 * The highlight says "this is where you are". These lock the two properties
 * that matter: it tracks the active item, and it is decorative - never the only
 * carrier of the state it illustrates.
 */

beforeEach(() => {
  // jsdom reports 0 for every layout property; stub enough to measure with.
  vi.spyOn(HTMLElement.prototype, 'offsetLeft', 'get').mockImplementation(function (
    this: HTMLElement,
  ) {
    return Number(this.dataset.testLeft ?? 0);
  });
  vi.spyOn(HTMLElement.prototype, 'offsetWidth', 'get').mockImplementation(function (
    this: HTMLElement,
  ) {
    return Number(this.dataset.testWidth ?? 0);
  });
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      disconnect() {}
      unobserve() {}
    },
  );
});

function Group({ value }: { value: string }) {
  return (
    <AnimatedBackground value={value} className="rounded bg-slate-900">
      <button data-id="a" data-test-left="0" data-test-width="60">
        Alpha
      </button>
      <button data-id="b" data-test-left="60" data-test-width="80">
        Bravo
      </button>
    </AnimatedBackground>
  );
}

const highlight = (c: HTMLElement) => c.querySelector('span[aria-hidden]') as HTMLElement | null;

describe('AnimatedBackground', () => {
  it('positions the highlight over the active item', () => {
    const { container } = render(<Group value="a" />);
    const h = highlight(container)!;
    expect(h.style.transform).toBe('translateX(0px)');
    expect(h.style.width).toBe('60px');
  });

  it('moves and resizes when the active item changes', () => {
    const { container, rerender } = render(<Group value="a" />);
    rerender(<Group value="b" />);

    const h = highlight(container)!;
    expect(h.style.transform).toBe('translateX(60px)');
    expect(h.style.width).toBe('80px');
  });

  it('renders no highlight when nothing matches', () => {
    const { container } = render(<Group value="nonexistent" />);
    expect(highlight(container)).toBeNull();
  });

  it('keeps the highlight out of the accessibility tree', () => {
    // It illustrates state that aria-current and aria-checked already carry.
    // Exposing it would announce the decoration as content.
    const { container } = render(<Group value="a" />);
    expect(highlight(container)).toHaveAttribute('aria-hidden');
  });

  it('still renders every child, so state is never motion-only', () => {
    render(<Group value="a" />);
    expect(screen.getByText('Alpha')).toBeInTheDocument();
    expect(screen.getByText('Bravo')).toBeInTheDocument();
  });

  it('animates transform and width only - never layout properties', () => {
    // left/top would trigger layout on every frame; transform composites.
    const { container } = render(<Group value="a" />);
    expect(highlight(container)!.className).toContain('transition-[transform,width]');
  });
});
