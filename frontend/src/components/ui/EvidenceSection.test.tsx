import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import EvidenceSection from './EvidenceSection';

/**
 * The evidence view stacked seventeen expanded panels inside one tab, so an
 * analyst looking for the certificate scrolled past everything between them and
 * it, and a critical runtime finding sat in a box identical to the network
 * security config table.
 */

beforeEach(() => {
  sessionStorage.clear();
  window.location.hash = '';
  // jsdom has no layout, so scrollIntoView is not implemented.
  Element.prototype.scrollIntoView = vi.fn();
  vi.stubGlobal('requestAnimationFrame', (cb: FrameRequestCallback) => {
    cb(0);
    return 0;
  });
});

afterEach(() => {
  window.location.hash = '';
  vi.unstubAllGlobals();
});

function Section(props: Partial<React.ComponentProps<typeof EvidenceSection>> = {}) {
  return (
    <EvidenceSection id="permissions" title="Permissions" {...props}>
      <p>panel body</p>
    </EvidenceSection>
  );
}

describe('EvidenceSection', () => {
  it('is collapsed by default', () => {
    render(<Section />);
    expect(screen.getByRole('button', { name: /permissions/i })).toHaveAttribute(
      'aria-expanded',
      'false',
    );
    expect(screen.queryByText('panel body')).not.toBeInTheDocument();
  });

  it('unmounts its children when closed rather than hiding them', () => {
    // A case can carry 1,284 evidence records; keeping closed panels in the
    // tree costs render time on every parent update for nothing on screen.
    const { container } = render(<Section />);
    expect(container.textContent).not.toContain('panel body');

    fireEvent.click(screen.getByRole('button', { name: /permissions/i }));
    expect(screen.getByText('panel body')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /permissions/i }));
    expect(screen.queryByText('panel body')).not.toBeInTheDocument();
  });

  it('opens on request via defaultOpen', () => {
    render(<Section defaultOpen />);
    expect(screen.getByText('panel body')).toBeInTheDocument();
  });

  it('reports its count on the header so a closed section still answers "is there anything here"', () => {
    render(<Section count={47} />);
    expect(screen.getByText('47')).toBeInTheDocument();
  });

  it('distinguishes an empty section from a populated one without opening it', () => {
    // The distinction is carried by both foreground and background, so it does
    // not depend on a contrast step that would put the text below WCAG AA.
    const { rerender } = render(<Section count={0} />);
    // Captured as a string: React reuses the DOM node across a rerender, so
    // holding the element would compare the badge with itself.
    const emptyClasses = screen.getByText('0').className;
    expect(emptyClasses).toMatch(/text-slate-500/);
    expect(emptyClasses).toMatch(/bg-slate-50/);

    rerender(<Section count={12} />);
    const fullClasses = screen.getByText('12').className;
    expect(fullClasses).toMatch(/text-slate-700/);
    expect(fullClasses).toMatch(/bg-slate-100/);
    expect(fullClasses).not.toBe(emptyClasses);
  });

  it('omits the badge entirely when no count is known', () => {
    // Better than asserting a number the panel below might disagree with.
    const { container } = render(<Section />);
    expect(container.querySelector('.tabular-nums')).toBeNull();
  });

  it('remembers open state for the session', () => {
    const { unmount } = render(<Section />);
    fireEvent.click(screen.getByRole('button', { name: /permissions/i }));
    unmount();

    render(<Section />);
    expect(screen.getByText('panel body')).toBeInTheDocument();
  });

  it('remembers a deliberate close, overriding defaultOpen', () => {
    const { unmount } = render(<Section defaultOpen />);
    fireEvent.click(screen.getByRole('button', { name: /permissions/i }));
    unmount();

    render(<Section defaultOpen />);
    expect(screen.queryByText('panel body')).not.toBeInTheDocument();
  });
});

describe('EvidenceSection deep links', () => {
  it('opens itself when the URL already names it', () => {
    // The assistant cites evidence by anchor. A citation landing on a collapsed
    // panel is a citation the reader has to go and find.
    window.location.hash = '#permissions';
    render(<Section />);
    expect(screen.getByText('panel body')).toBeInTheDocument();
  });

  it('opens when the hash changes to name it', () => {
    render(<Section />);
    expect(screen.queryByText('panel body')).not.toBeInTheDocument();

    act(() => {
      window.location.hash = '#permissions';
      window.dispatchEvent(new HashChangeEvent('hashchange'));
    });

    expect(screen.getByText('panel body')).toBeInTheDocument();
  });

  it('ignores a hash naming a different section', () => {
    window.location.hash = '#certificate';
    render(<Section />);
    expect(screen.queryByText('panel body')).not.toBeInTheDocument();
  });

  it('scrolls the targeted section into view', () => {
    window.location.hash = '#permissions';
    render(<Section />);
    expect(Element.prototype.scrollIntoView).toHaveBeenCalled();
  });
});
