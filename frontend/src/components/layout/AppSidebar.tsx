import { useState, useEffect, useRef } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { FileText, LogOut, PanelLeftClose, PanelLeftOpen, Search } from 'lucide-react';
import logoImg from '../../../logo/SUDARSHAN_LOGO_COLOUR.png';
import { useAuth } from '../../context/AuthContext';
import { useCaseLinks } from '../../hooks/useCaseLinks';
import { useAnalysis } from '../../context/AnalysisContext';
import {
  NAV_NEW_ANALYSIS,
  NAV_WORKSPACE,
  NAV_SYSTEM,
  isNavActive,
  type NavItem,
} from '../../layout/navItems';

type AppSidebarProps = {
  onLogout: () => void;
  /** Opens the command palette. */
  onSearch?: () => void;
};

const COLLAPSED_KEY = 'sudarshan.sidebar.collapsed';

/**
 * Collapsing is an explicit, remembered choice; hovering a collapsed rail
 * previews it.
 *
 * An earlier version of this component expanded on hover and was removed for
 * three specific reasons, all of them fair. This reintroduces the behaviour
 * without reintroducing the failures:
 *
 *  - The trigger was a 12px transparent strip at the screen edge, which is a
 *    thing to hunt for. The trigger is now the rail itself: 56px of visible,
 *    always-present target.
 *  - The rail animated its width on every pointer pass, dragging the whole page
 *    with it. The hover preview is an overlay - it floats above the content and
 *    the layout never reflows, so a pointer crossing the edge costs nothing.
 *  - Labels appeared and vanished under the cursor. Leaving now waits 240ms, so
 *    crossing the rail on the way somewhere else does not flash it open, and
 *    re-entering within that window cancels the close.
 *
 * Hover only previews. It never changes the remembered state, and it does
 * nothing at all when the rail is already expanded or when the pointer is a
 * touch device.
 */
export default function AppSidebar({ onLogout, onSearch }: AppSidebarProps) {
  const { pathname } = useLocation();
  const links = useCaseLinks();
  const { analysisResult, activeSha256 } = useAnalysis();
  const openCase = analysisResult?.sha256 || activeSha256;
  const caseLabel =
    analysisResult?.app_name || analysisResult?.package_name || openCase?.slice(0, 12);
  const { user: username, role } = useAuth();
  const [peek, setPeek] = useState(false);
  const closeTimer = useRef<number | null>(null);

  const [collapsed, setCollapsed] = useState<boolean>(() => {
    try {
      return window.localStorage.getItem(COLLAPSED_KEY) === '1';
    } catch {
      return false;
    }
  });

  /*
   * Hover intent. A pointer that merely crosses the rail should not open it, so
   * closing is delayed and re-entry cancels the pending close.
   */
  const openPeek = () => {
    if (!collapsed) return;
    // Fine pointers only: on touch, "hover" fires on tap and would fight the
    // link the user is actually trying to press.
    if (!window.matchMedia?.('(hover: hover) and (pointer: fine)').matches) return;
    if (closeTimer.current) {
      window.clearTimeout(closeTimer.current);
      closeTimer.current = null;
    }
    setPeek(true);
  };

  const closePeek = () => {
    if (closeTimer.current) window.clearTimeout(closeTimer.current);
    closeTimer.current = window.setTimeout(() => setPeek(false), 240);
  };

  useEffect(() => () => {
    if (closeTimer.current) window.clearTimeout(closeTimer.current);
  }, []);

  // An expanded rail has nothing to preview.
  useEffect(() => {
    if (!collapsed) setPeek(false);
  }, [collapsed]);

  useEffect(() => {
    try {
      window.localStorage.setItem(COLLAPSED_KEY, collapsed ? '1' : '0');
    } catch {
      /* private mode - the preference simply does not persist */
    }
    document.documentElement.style.setProperty(
      '--app-sidebar-width',
      collapsed ? '4rem' : '15rem',
    );
  }, [collapsed]);

  const expanded = !collapsed || peek;

  const renderNavItem = (item: NavItem) => {
    const active = isNavActive(pathname, item);
    const Icon = item.icon;

    return (
      <Link
        key={`${item.to}-${item.label}`}
        to={item.to}
        aria-current={active ? 'page' : undefined}
        title={expanded ? undefined : item.label}
        className={`group relative flex items-center h-9 mx-3 rounded-lg transition-colors select-none ${
          active
            ? 'bg-white/[0.08] text-white'
            : 'text-slate-400 hover:text-white hover:bg-white/[0.04]'
        }`}
      >
        {/* Active marker sits outside the pill so the pill keeps its shape. */}
        <span
          className={`absolute -left-3 top-2 bottom-2 w-[3px] rounded-r-full transition-colors ${
            active ? 'bg-blue-400' : 'bg-transparent'
          }`}
          aria-hidden
        />
        <span className="w-10 h-9 flex items-center justify-center shrink-0">
          <Icon className={`h-[18px] w-[18px] ${active ? 'text-blue-300' : ''}`} aria-hidden />
        </span>
        {expanded && (
          <span className="text-sm font-medium whitespace-nowrap pr-3 truncate">{item.label}</span>
        )}
      </Link>
    );
  };

  const groupLabel = (text: string) =>
    expanded ? (
      <p className="px-6 pt-5 pb-2 text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-500 whitespace-nowrap">
        {text}
      </p>
    ) : (
      <div className="mx-4 my-3 border-t border-white/[0.06]" aria-hidden />
    );

  const newActive = isNavActive(pathname, NAV_NEW_ANALYSIS);
  const NewIcon = NAV_NEW_ANALYSIS.icon;

  return (
    <aside
      onMouseEnter={openPeek}
      onMouseLeave={closePeek}
      onFocusCapture={openPeek}
      onBlurCapture={closePeek}
      className={`fixed top-0 left-0 bottom-0 z-[60] bg-[#0b1120] text-slate-100 border-r border-white/[0.06] flex flex-col transition-[width] duration-200 ease-out overflow-x-hidden ${
        expanded ? 'w-60' : 'w-16'
      } ${peek ? 'shadow-2xl shadow-slate-950/50' : ''}`}
      aria-label="Primary navigation"
    >
      {/* Brand */}
      <div className="h-16 flex items-center shrink-0">
        <Link to="/history" className="flex items-center min-w-0 flex-1 h-full focus:outline-none">
          <span className="w-16 h-16 flex items-center justify-center shrink-0">
            <img src={logoImg} alt="Sudarshan" className="h-7 w-auto" />
          </span>
          {expanded && (
            <span className="min-w-0">
              <span className="font-semibold text-[15px] tracking-[-0.01em] block leading-none text-white">
                Sudarshan
              </span>
              <span className="text-xs text-slate-500 leading-none mt-1.5 block whitespace-nowrap">
                Fraud intelligence
              </span>
            </span>
          )}
        </Link>
      </div>

      {/* Primary action: a button, not a row among peers. */}
      <div className="px-3 pb-1 shrink-0">
        <Link
          to={NAV_NEW_ANALYSIS.to}
          title={expanded ? undefined : NAV_NEW_ANALYSIS.label}
          aria-current={newActive ? 'page' : undefined}
          className={`flex items-center justify-center gap-2 h-10 rounded-lg text-sm font-semibold text-white transition-colors shadow-sm shadow-blue-950/40 ${
            newActive ? 'bg-blue-500' : 'bg-blue-600 hover:bg-blue-500'
          }`}
        >
          <NewIcon className="h-4 w-4 shrink-0" aria-hidden />
          {expanded && <span className="whitespace-nowrap">{NAV_NEW_ANALYSIS.label}</span>}
        </Link>
      </div>

      {onSearch && (
        <div className="px-3 pt-2 shrink-0">
          <button
            type="button"
            onClick={onSearch}
            title={expanded ? undefined : 'Search (Ctrl+K)'}
            className="w-full flex items-center h-9 rounded-lg text-slate-400 hover:text-white bg-white/[0.04] hover:bg-white/[0.07] ring-1 ring-inset ring-white/[0.06] transition-colors"
          >
            <span className="w-10 h-9 flex items-center justify-center shrink-0">
              <Search className="h-4 w-4" aria-hidden />
            </span>
            {expanded && (
              <>
                <span className="text-sm flex-1 text-left whitespace-nowrap">Search</span>
                <kbd className="mr-2 rounded-md bg-white/[0.08] px-1.5 py-0.5 text-[11px] font-medium text-slate-400 whitespace-nowrap">
                  Ctrl K
                </kbd>
              </>
            )}
          </button>
        </div>
      )}

      <nav className="flex-1 pb-3 space-y-0.5 overflow-y-auto scrollbar-hidden">
        {groupLabel('Workspace')}
        {NAV_WORKSPACE.map(renderNavItem)}

        {openCase && (
          <>
            {groupLabel('Open case')}
            {renderNavItem({
              to: links.summary,
              label: caseLabel || 'Current case',
              shortLabel: 'Case',
              icon: FileText,
              matchPrefix: links.root,
            })}
          </>
        )}

        {groupLabel('System')}
        {NAV_SYSTEM.map(renderNavItem)}
      </nav>

      {/* Account + collapse control */}
      <div className="border-t border-white/[0.06] shrink-0 p-2 space-y-0.5">
        <div
          className="flex items-center h-12 select-none"
          title={collapsed ? `${username || 'Analyst'} (${role || 'analyst'})` : undefined}
        >
          <span className="w-12 h-12 flex items-center justify-center shrink-0">
            <span className="relative flex items-center justify-center">
              <span className="h-8 w-8 rounded-full bg-blue-600 flex items-center justify-center text-white text-[13px] font-semibold">
                {username?.[0]?.toUpperCase() || 'A'}
              </span>
              <span className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full bg-emerald-500 ring-2 ring-[#0b1120]" />
            </span>
          </span>
          {expanded && (
            <span className="min-w-0 flex-1 pr-1">
              <span className="block text-sm font-medium text-slate-100 truncate leading-tight">
                {username || 'Analyst'}
              </span>
              <span className="block text-xs text-slate-500 truncate leading-tight mt-0.5 capitalize">
                {(role || 'analyst').replace('_', ' ')}
              </span>
            </span>
          )}
          {expanded && (
            <button
              type="button"
              onClick={onLogout}
              aria-label="Sign out"
              title="Sign out"
              className="h-8 w-8 mr-1 shrink-0 flex items-center justify-center rounded-md text-slate-400 hover:text-red-300 hover:bg-red-500/10 transition-colors"
            >
              <LogOut className="h-4 w-4" aria-hidden />
            </button>
          )}
        </div>

        <button
          type="button"
          onClick={() => setCollapsed((v) => !v)}
          aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}
          title={collapsed ? 'Expand navigation' : 'Collapse navigation'}
          className="w-full flex items-center h-9 rounded-lg text-slate-500 hover:text-slate-200 hover:bg-white/[0.04] transition-colors text-left select-none"
        >
          <span className="w-12 h-9 flex items-center justify-center shrink-0">
            {collapsed ? (
              <PanelLeftOpen className="h-4 w-4" aria-hidden />
            ) : (
              <PanelLeftClose className="h-4 w-4" aria-hidden />
            )}
          </span>
          {expanded && (
            <span className="text-sm font-medium pr-3">
              {/* During a peek the rail reads expanded but is still collapsed, so
                  the label has to name the action, not the current state. */}
              {collapsed ? 'Expand' : 'Collapse'}
            </span>
          )}
        </button>
      </div>
    </aside>
  );
}
