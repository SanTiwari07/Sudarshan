import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import AppSidebar from './AppSidebar';
import { AuthProvider } from '../../context/AuthContext';
import { AnalysisProvider } from '../../context/AnalysisContext';

/**
 * Hover-preview was removed from this rail once before, for three reasons: the
 * trigger was a 12px invisible strip, the rail re-animated its width on every
 * pointer pass and dragged the page with it, and labels flashed under the
 * cursor. These lock the mitigations rather than the feature.
 */

function stubPointer(fine: boolean) {
  vi.stubGlobal(
    'matchMedia',
    vi.fn((q: string) => ({
      matches: q.includes('hover: hover') ? fine : false,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
    })),
  );
}

beforeEach(() => {
  localStorage.clear();
  vi.useFakeTimers({ shouldAdvanceTime: true });
  stubPointer(true);
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

function draw() {
  return render(
    <MemoryRouter>
      <AuthProvider>
        <AnalysisProvider>
          <AppSidebar onLogout={() => {}} />
        </AnalysisProvider>
      </AuthProvider>
    </MemoryRouter>,
  );
}

const rail = () => screen.getByRole('complementary', { name: /primary navigation/i });
const collapse = () => screen.getByRole('button', { name: /collapse|expand/i });

describe('AppSidebar hover preview', () => {
  it('starts expanded, with labels visible', () => {
    draw();
    expect(screen.getByText('Cases')).toBeInTheDocument();
    expect(rail().className).toMatch(/w-56/);
  });

  it('collapses to an icon rail on an explicit click', () => {
    draw();
    fireEvent.click(collapse());
    expect(rail().className).toMatch(/w-14/);
    expect(screen.queryByText('Cases')).not.toBeInTheDocument();
  });

  it('previews on hover once collapsed', () => {
    draw();
    fireEvent.click(collapse());
    fireEvent.mouseEnter(rail());
    expect(screen.getByText('Cases')).toBeInTheDocument();
    expect(rail().className).toMatch(/w-56/);
  });

  it('does not reflow the page while previewing', () => {
    // The width variable drives the main column's padding. Peek must not touch
    // it, or every pointer pass drags the whole page sideways.
    draw();
    fireEvent.click(collapse());
    const before = document.documentElement.style.getPropertyValue('--app-sidebar-width');

    fireEvent.mouseEnter(rail());
    expect(document.documentElement.style.getPropertyValue('--app-sidebar-width')).toBe(before);
    expect(before).toBe('3.5rem');
  });

  it('waits before closing, so crossing the rail does not flash it', () => {
    draw();
    fireEvent.click(collapse());
    fireEvent.mouseEnter(rail());
    fireEvent.mouseLeave(rail());

    // Still open immediately after leaving.
    expect(screen.getByText('Cases')).toBeInTheDocument();

    act(() => void vi.advanceTimersByTime(300));
    expect(screen.queryByText('Cases')).not.toBeInTheDocument();
  });

  it('cancels the pending close when the pointer returns', () => {
    draw();
    fireEvent.click(collapse());
    fireEvent.mouseEnter(rail());
    fireEvent.mouseLeave(rail());
    act(() => void vi.advanceTimersByTime(120));
    fireEvent.mouseEnter(rail());
    act(() => void vi.advanceTimersByTime(300));

    expect(screen.getByText('Cases')).toBeInTheDocument();
  });

  it('ignores hover on a touch device', () => {
    // There, "hover" fires on tap and would fight the link being pressed.
    stubPointer(false);
    draw();
    fireEvent.click(collapse());
    fireEvent.mouseEnter(rail());
    expect(screen.queryByText('Cases')).not.toBeInTheDocument();
  });

  it('previews on keyboard focus too, so the rail is not mouse-only', () => {
    draw();
    fireEvent.click(collapse());
    fireEvent.focus(rail(), { bubbles: true });
    fireEvent.focusIn(rail());
    expect(screen.getByText('Cases')).toBeInTheDocument();
  });

  it('never lets a preview overwrite the remembered choice', () => {
    draw();
    fireEvent.click(collapse());
    fireEvent.mouseEnter(rail());
    expect(localStorage.getItem('sudarshan.sidebar.collapsed')).toBe('1');
  });

  it('labels the toggle by its action, not its state', () => {
    draw();
    expect(screen.getByRole('button', { name: /collapse/i })).toBeInTheDocument();

    fireEvent.click(collapse());
    fireEvent.mouseEnter(rail());
    // Expanded-looking, but still collapsed: clicking it expands.
    expect(screen.getByRole('button', { name: /expand/i })).toBeInTheDocument();
  });
});
