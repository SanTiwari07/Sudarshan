import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import AnalysisTabs, { type AnalysisTab } from './AnalysisTabs';

beforeEach(() => {
  window.location.hash = '';
  Element.prototype.scrollIntoView = vi.fn();
});

afterEach(() => {
  window.location.hash = '';
});

const TABS: AnalysisTab[] = [
  { id: 'overview', label: 'Overview', content: <p>overview body</p> },
  {
    id: 'static',
    label: 'Static',
    anchors: ['permissions', 'certificate'],
    content: <p>static body</p>,
  },
  {
    id: 'network',
    label: 'Network',
    anchors: ['network-capture'],
    content: <p>network body</p>,
  },
];

function draw(entry = '/case/abc/evidence', urlParam?: string) {
  return render(
    <MemoryRouter initialEntries={[entry]}>
      <AnalysisTabs tabs={TABS} urlParam={urlParam} />
    </MemoryRouter>,
  );
}

describe('AnalysisTabs', () => {
  it('shows the first tab by default', () => {
    draw();
    expect(screen.getByText('overview body')).toBeInTheDocument();
    expect(screen.queryByText('static body')).not.toBeInTheDocument();
  });

  it('switches tabs on click', () => {
    draw();
    fireEvent.click(screen.getByRole('tab', { name: /static/i }));
    expect(screen.getByText('static body')).toBeInTheDocument();
  });

  it('keeps tab state out of the URL unless asked', () => {
    // The tab a reader happens to be on is a view preference, not a location.
    draw('/case/abc/evidence');
    fireEvent.click(screen.getByRole('tab', { name: /static/i }));
    expect(window.location.search).not.toContain('section=');
  });

  it('honours a tab named in the query string', () => {
    draw('/case/abc/evidence?section=network', 'section');
    expect(screen.getByText('network body')).toBeInTheDocument();
  });

  it('falls back to the first tab for an unknown query value', () => {
    draw('/case/abc/evidence?section=nonsense', 'section');
    expect(screen.getByText('overview body')).toBeInTheDocument();
  });
});

describe('AnalysisTabs keyboard navigation', () => {
  it('keeps the tablist to a single tab stop', () => {
    // Otherwise reaching the panel from the first of six tabs costs six Tab
    // presses through controls the reader has already rejected.
    draw();
    const tabs = screen.getAllByRole('tab');
    expect(tabs.filter((t) => t.getAttribute('tabindex') === '0')).toHaveLength(1);
    expect(tabs[0]).toHaveAttribute('tabindex', '0');
    expect(tabs[1]).toHaveAttribute('tabindex', '-1');
  });

  it('moves to the next tab on ArrowRight', () => {
    draw();
    const tabs = screen.getAllByRole('tab');
    tabs[0].focus();
    fireEvent.keyDown(tabs[0], { key: 'ArrowRight' });
    expect(screen.getByText('static body')).toBeInTheDocument();
    expect(screen.getAllByRole('tab')[1]).toHaveFocus();
  });

  it('wraps from the last tab to the first', () => {
    draw();
    const tabs = screen.getAllByRole('tab');
    tabs[2].focus();
    fireEvent.keyDown(tabs[2], { key: 'ArrowRight' });
    expect(screen.getByText('overview body')).toBeInTheDocument();
  });

  it('wraps backwards from the first tab to the last', () => {
    draw();
    const tabs = screen.getAllByRole('tab');
    tabs[0].focus();
    fireEvent.keyDown(tabs[0], { key: 'ArrowLeft' });
    expect(screen.getByText('network body')).toBeInTheDocument();
  });

  it('jumps to the ends with Home and End', () => {
    draw();
    let tabs = screen.getAllByRole('tab');
    fireEvent.keyDown(tabs[0], { key: 'End' });
    expect(screen.getByText('network body')).toBeInTheDocument();

    tabs = screen.getAllByRole('tab');
    fireEvent.keyDown(tabs[2], { key: 'Home' });
    expect(screen.getByText('overview body')).toBeInTheDocument();
  });

  it('ignores keys that are not navigation', () => {
    draw();
    const tabs = screen.getAllByRole('tab');
    fireEvent.keyDown(tabs[0], { key: 'a' });
    expect(screen.getByText('overview body')).toBeInTheDocument();
  });

  it('announces the active panel politely', () => {
    const { container } = draw();
    const live = container.querySelector('[aria-live="polite"]');
    expect(live).toBeInTheDocument();
    expect(live).toHaveTextContent('Overview panel');
  });
});

describe('AnalysisTabs hash targeting', () => {
  it('selects the tab that owns an anchor named in the URL', () => {
    // Without this an assistant citation to #permissions lands on a page that
    // does not visibly contain what was cited - the section is real, but it is
    // inside a tab nobody opened.
    window.location.hash = '#permissions';
    draw('/case/abc/evidence', 'section');
    expect(screen.getByText('static body')).toBeInTheDocument();
  });

  it('follows a hash change to another tab', () => {
    draw('/case/abc/evidence', 'section');
    expect(screen.getByText('overview body')).toBeInTheDocument();

    act(() => {
      window.location.hash = '#network-capture';
      window.dispatchEvent(new HashChangeEvent('hashchange'));
    });

    expect(screen.getByText('network body')).toBeInTheDocument();
  });

  it('ignores a hash no tab claims', () => {
    window.location.hash = '#something-else';
    draw('/case/abc/evidence', 'section');
    expect(screen.getByText('overview body')).toBeInTheDocument();
  });

  it('marks the active tab for assistive technology', () => {
    draw('/case/abc/evidence?section=static', 'section');
    expect(screen.getByRole('tab', { name: /static/i })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('tab', { name: /overview/i })).toHaveAttribute(
      'aria-selected',
      'false',
    );
  });
});
