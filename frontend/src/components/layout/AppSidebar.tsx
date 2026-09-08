import { useState, useEffect, useRef } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { LogOut, PanelLeftClose, PanelLeftOpen } from 'lucide-react';
import logoImg from '../../../logo/SUDARSHAN_LOGO_COLOUR.png';
import { useAuth } from '../../context/AuthContext';
import { useCaseLinks } from '../../hooks/useCaseLinks';
import {
  ENTERPRISE_NAV_END,
  isNavActive,
  type NavItem,
} from '../../layout/navItems';

type AppSidebarProps = {
  onLogout: () => void;
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
export default function AppSidebar({ onLogout }: AppSidebarProps) {
  const { pathname } = useLocation();
  const links = useCaseLinks();
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
      collapsed ? '3.5rem' : '14rem',
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
        className={`group relative flex items-center h-9 mx-2 rounded-md transition-colors select-none ${
          active
            ? 'bg-slate-800 text-white'
            : 'text-slate-400 hover:text-slate-100 hover:bg-slate-900'
        }`}
      >
        {/* Active marker sits outside the pill so the pill keeps its shape. */}
        <span
          className={`absolute -left-2 top-1.5 bottom-1.5 w-0.5 rounded-full transition-colors ${
            active ? 'bg-blue-500' : 'bg-transparent'
          }`}
          aria-hidden
        />
        <span className="w-10 h-9 flex items-center justify-center shrink-0">
          <Icon className="h-4 w-4" aria-hidden />
        </span>
        {expanded && (
          <span className="text-[15px] font-medium tracking-[-0.01em] whitespace-nowrap pr-3 truncate">
            {item.label}
          </span>
        )}
      </Link>
    );
  };

  return (
    <aside
      onMouseEnter={openPeek}
      onMouseLeave={closePeek}
      onFocusCapture={openPeek}
      onBlurCapture={closePeek}
      className={`fixed top-0 left-0 bottom-0 z-[60] bg-slate-950 text-slate-100 border-r border-slate-800 flex flex-col transition-[width] duration-200 ease-out overflow-x-hidden ${
        expanded ? 'w-56' : 'w-14'
      } ${peek ? 'shadow-2xl shadow-slate-950/50' : ''}`}
      aria-label="Primary navigation"
    >
      {/* Brand */}
      <div className="h-14 border-b border-slate-800 flex items-center shrink-0">
        <Link to={links.summary} className="flex items-center min-w-0 flex-1 h-full focus:outline-none">
          <span className="w-14 h-14 flex items-center justify-center shrink-0">
            <img src={logoImg} alt="Sudarshan Logo" className="h-6 w-auto" />
          </span>
          {expanded && (
            <span className="min-w-0">
              <span className="font-sans font-semibold text-sm tracking-[-0.01em] block leading-none text-white">
                Sudarshan
              </span>
              <span className="text-[13px] text-slate-500 leading-none mt-1 block">
                Fraud intelligence
              </span>
            </span>
          )}
        </Link>
      </div>

      <nav className="flex-1 py-3 space-y-0.5 overflow-y-auto scrollbar-hidden">
        {expanded && (
          <p className="px-4 pb-1.5 text-[13px] font-medium text-slate-600">Workspace</p>
        )}
        {ENTERPRISE_NAV_END.map(renderNavItem)}
      </nav>

      {/* Account + collapse control */}
      <div className="border-t border-slate-800 shrink-0 py-2 space-y-0.5">
        <div
          className="flex items-center h-10 select-none"
          title={collapsed ? `${username || 'Analyst'} (${role || 'SOC Analyst'})` : undefined}
        >
          <span className="w-14 h-10 flex items-center justify-center shrink-0">
            <span className="relative flex items-center justify-center">
              <span className="h-6 w-6 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-200 text-[13px] font-semibold">
                {username?.[0]?.toUpperCase() || 'A'}
              </span>
              <span className="absolute -bottom-0.5 -right-0.5 h-2 w-2 rounded-full bg-emerald-500 ring-2 ring-slate-950" />
            </span>
          </span>
          {expanded && (
            <span className="min-w-0 flex-1 pr-3">
              <span className="block text-[15px] font-medium text-slate-200 truncate leading-tight">
                {username || 'Analyst'}
              </span>
              <span className="block text-[13px] text-slate-500 truncate leading-tight">
                {role || 'SOC Analyst'}
              </span>
            </span>
          )}
        </div>

        <button
          type="button"
          onClick={onLogout}
          title={collapsed ? 'Sign out' : undefined}
          className="w-full flex items-center h-9 text-slate-400 hover:text-red-400 hover:bg-red-950/30 transition-colors text-left select-none"
        >
          <span className="w-14 h-9 flex items-center justify-center shrink-0">
            <LogOut className="h-4 w-4" aria-hidden />
          </span>
          {expanded && <span className="text-[15px] font-medium pr-3">Sign out</span>}
        </button>

        <button
          type="button"
          onClick={() => setCollapsed((v) => !v)}
          aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}
          title={collapsed ? 'Expand navigation' : 'Collapse navigation'}
          className="w-full flex items-center h-9 text-slate-500 hover:text-slate-200 hover:bg-slate-900 transition-colors text-left select-none"
        >
          <span className="w-14 h-9 flex items-center justify-center shrink-0">
            {collapsed ? (
              <PanelLeftOpen className="h-4 w-4" aria-hidden />
            ) : (
              <PanelLeftClose className="h-4 w-4" aria-hidden />
            )}
          </span>
          {expanded && (
            <span className="text-[15px] font-medium pr-3">
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
