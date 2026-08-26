import React, { useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

/**
 * Tabbed navigation for the technical view.
 *
 * The technical view rendered ~40 panels in one scroll, every one of them
 * expanded by default. Everything was on screen, so nothing was: an analyst
 * looking for the certificate had to scroll past the whole behavioural
 * section to find it.
 *
 * Tabs are progressive disclosure, not decoration - each one answers a
 * different question ("what is it?", "what does it do?", "what does it
 * touch?"), which is why the labels are questions rather than data-source
 * names.
 *
 * Tab state is local by default, because the tab a reader happens to be on is a
 * view preference rather than a location.
 *
 * Pass `urlParam` to opt a tab group into the URL. That is for the evidence
 * view specifically: the assistant cites its answers by anchor, and an anchor
 * inside an inactive tab is unreachable - the citation lands on a page that
 * does not visibly contain what was cited. Sharing that URL carries a tab
 * choice, which is the correct trade when the alternative is a broken
 * evidence trail.
 */

export interface AnalysisTab {
  id: string;
  label: string;
  /** Shown under the label - what question this tab answers. */
  hint?: string;
  /** Optional count badge, e.g. number of findings in this tab. */
  count?: number;
  /** Section anchors this tab owns, so a `#hash` can select it. */
  anchors?: string[];
  content: React.ReactNode;
}

interface AnalysisTabsProps {
  tabs: AnalysisTab[];
  initialTabId?: string;
  /** Query parameter to sync the active tab to, e.g. "section". */
  urlParam?: string;
}

export function AnalysisTabs({ tabs, initialTabId, urlParam }: AnalysisTabsProps) {
  const available = tabs.filter(Boolean);
  const [searchParams, setSearchParams] = useSearchParams();
  const [localId, setLocalId] = useState(initialTabId ?? available[0]?.id ?? '');

  const fromUrl = urlParam ? searchParams.get(urlParam) : null;
  const activeId = fromUrl ?? localId;

  const selectTab = useCallback(
    (id: string) => {
      setLocalId(id);
      if (!urlParam) return;
      setSearchParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          next.set(urlParam, id);
          return next;
        },
        // Replace rather than push: clicking through four tabs should not put
        // four entries between the reader and the page they came from.
        { replace: true },
      );
    },
    [urlParam, setSearchParams],
  );

  /*
   * A hash can name a section inside a tab that is not open. Selecting the tab
   * that owns it is what makes an assistant citation land.
   */
  useEffect(() => {
    const syncToHash = () => {
      const hash = decodeURIComponent(window.location.hash.replace(/^#/, ''));
      if (!hash) return;
      const owner = available.find((t) => t.anchors?.includes(hash));
      if (owner && owner.id !== activeId) selectTab(owner.id);
    };
    syncToHash();
    window.addEventListener('hashchange', syncToHash);
    return () => window.removeEventListener('hashchange', syncToHash);
  }, [available, activeId, selectTab]);

  if (available.length === 0) return null;

  const active =
    available.find((t) => t.id === activeId) ?? available[0];

  /*
   * Keyboard support, per the WAI-ARIA tabs pattern.
   *
   * Every tab was in the tab order, so reaching the panel from the first tab of
   * a six-tab group meant six Tab presses through controls the reader had
   * already rejected. A tablist is one stop: Tab enters it, arrows move within
   * it, Tab leaves it for the content.
   */
  const onTabKeyDown = (e: React.KeyboardEvent, index: number) => {
    const last = available.length - 1;
    let next: number | null = null;

    if (e.key === 'ArrowRight') next = index === last ? 0 : index + 1;
    else if (e.key === 'ArrowLeft') next = index === 0 ? last : index - 1;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = last;
    if (next === null) return;

    e.preventDefault();
    selectTab(available[next].id);
    document.getElementById(`tab-${available[next].id}`)?.focus();
  };

  return (
    <div className="analysis-tabs">
      <div
        role="tablist"
        aria-label="Analysis sections"
        /*
         * Scrolls rather than wraps. `flex-wrap` produced three ragged rows of
         * tabs at 375px, which turns a one-line control into a third of the
         * viewport before any content is reached.
         */
        className="flex gap-1 border-b border-slate-200 mb-4 overflow-x-auto scrollbar-hidden snap-x snap-mandatory"
      >
        {available.map((tab, index) => {
          const selected = tab.id === active.id;
          return (
            <button
              key={tab.id}
              role="tab"
              id={`tab-${tab.id}`}
              aria-selected={selected}
              aria-controls={`panel-${tab.id}`}
              tabIndex={selected ? 0 : -1}
              onKeyDown={(e) => onTabKeyDown(e, index)}
              onClick={() => selectTab(tab.id)}
              className={[
                'px-4 py-2.5 text-left rounded-t-md shrink-0 snap-start',
                'border-b-2 -mb-px transition-colors',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-blue-500',
                selected
                  ? 'border-b-blue-600 text-slate-900'
                  : 'border-b-transparent text-slate-500 hover:text-slate-900 hover:bg-slate-50',
              ].join(' ')}
            >
              <span className="flex items-center gap-2 font-display text-[13px] font-semibold tracking-[-0.01em]">
                {tab.label}
                {typeof tab.count === 'number' && tab.count > 0 && (
                  <span
                    className={`text-[11px] font-medium tabular-nums px-1.5 py-0.5 rounded ${
                      selected ? 'bg-blue-50 text-blue-700' : 'bg-slate-100 text-slate-600'
                    }`}
                  >
                    {tab.count}
                  </span>
                )}
              </span>
              {tab.hint && (
                <span className="block text-[11px] font-normal text-slate-500 mt-0.5">
                  {tab.hint}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Announces the change for a reader who cannot see the panel swap. */}
      <span aria-live="polite" className="sr-only">
        {active.label} panel
      </span>

      <div
        role="tabpanel"
        id={`panel-${active.id}`}
        aria-labelledby={`tab-${active.id}`}
        className="space-y-4"
      >
        {active.content}
      </div>
    </div>
  );
}

export default AnalysisTabs;
