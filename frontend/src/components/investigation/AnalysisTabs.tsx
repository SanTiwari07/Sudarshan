import React, { useState } from 'react';

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
 * State is local rather than routed. The tab a reader is on is a view
 * preference, not a location: deep-linking to it would make "share this case"
 * links carry an arbitrary panel choice.
 */

export interface AnalysisTab {
  id: string;
  label: string;
  /** Shown under the label - what question this tab answers. */
  hint?: string;
  /** Optional count badge, e.g. number of findings in this tab. */
  count?: number;
  content: React.ReactNode;
}

interface AnalysisTabsProps {
  tabs: AnalysisTab[];
  initialTabId?: string;
}

export function AnalysisTabs({ tabs, initialTabId }: AnalysisTabsProps) {
  const available = tabs.filter(Boolean);
  const [activeId, setActiveId] = useState(
    initialTabId ?? available[0]?.id ?? '',
  );

  if (available.length === 0) return null;

  const active =
    available.find((t) => t.id === activeId) ?? available[0];

  return (
    <div className="analysis-tabs">
      <div
        role="tablist"
        aria-label="Analysis sections"
        className="flex flex-wrap gap-1 border-b border-slate-200 mb-4"
      >
        {available.map((tab) => {
          const selected = tab.id === active.id;
          return (
            <button
              key={tab.id}
              role="tab"
              id={`tab-${tab.id}`}
              aria-selected={selected}
              aria-controls={`panel-${tab.id}`}
              onClick={() => setActiveId(tab.id)}
              className={[
                'px-4 py-2.5 text-left rounded-t-md',
                'border-b-2 -mb-px transition-colors',
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
                      selected ? 'bg-blue-50 text-blue-700' : 'bg-slate-100 text-slate-500'
                    }`}
                  >
                    {tab.count}
                  </span>
                )}
              </span>
              {tab.hint && (
                <span className="block text-[11px] font-normal text-slate-400 mt-0.5">
                  {tab.hint}
                </span>
              )}
            </button>
          );
        })}
      </div>

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
