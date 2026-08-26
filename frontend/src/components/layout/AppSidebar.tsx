import { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Shield, LogOut, PanelLeftClose, PanelLeftOpen } from 'lucide-react';
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
 * The rail used to be 48px wide with every label hidden until the pointer
 * entered a 12px transparent strip on the screen edge. That is a trick, not
 * navigation: labels appeared and vanished under the cursor, the whole rail
 * animated its width on every pass, and anyone driving with a trackpad or a
 * projector had to hunt for the trigger zone. Labels are now always visible,
 * and collapsing is an explicit, remembered choice.
 */
export default function AppSidebar({ onLogout }: AppSidebarProps) {
  const { pathname } = useLocation();
  const links = useCaseLinks();
  const { user: username, role } = useAuth();

  const [collapsed, setCollapsed] = useState<boolean>(() => {
    try {
      return window.localStorage.getItem(COLLAPSED_KEY) === '1';
    } catch {
      return false;
    }
  });

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

  const renderNavItem = (item: NavItem) => {
    const active = isNavActive(pathname, item);
    const Icon = item.icon;

    return (
      <Link
        key={`${item.to}-${item.label}`}
        to={item.to}
        aria-current={active ? 'page' : undefined}
        title={collapsed ? item.label : undefined}
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
        {!collapsed && (
          <span className="text-[13px] font-medium tracking-[-0.01em] whitespace-nowrap pr-3 truncate">
            {item.label}
          </span>
        )}
      </Link>
    );
  };

  return (
    <aside
      className={`fixed top-0 left-0 bottom-0 z-[60] bg-slate-950 text-slate-100 border-r border-slate-800 flex flex-col transition-[width] duration-200 ease-out overflow-x-hidden ${
        collapsed ? 'w-14' : 'w-56'
      }`}
      aria-label="Primary navigation"
    >
      {/* Brand */}
      <div className="h-14 border-b border-slate-800 flex items-center shrink-0">
        <Link to={links.summary} className="flex items-center min-w-0 flex-1 h-full focus:outline-none">
          <span className="w-14 h-14 flex items-center justify-center shrink-0">
            <Shield className="h-5 w-5 text-blue-500" aria-hidden />
          </span>
          {!collapsed && (
            <span className="min-w-0">
              <span className="font-display font-semibold text-sm tracking-[-0.01em] block leading-none text-white">
                Sudarshan
              </span>
              <span className="text-[11px] text-slate-500 leading-none mt-1 block">
                Fraud intelligence
              </span>
            </span>
          )}
        </Link>
      </div>

      <nav className="flex-1 py-3 space-y-0.5 overflow-y-auto scrollbar-hidden">
        {!collapsed && (
          <p className="px-4 pb-1.5 text-[11px] font-medium text-slate-600">Workspace</p>
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
              <span className="h-6 w-6 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-200 text-[11px] font-semibold">
                {username?.[0]?.toUpperCase() || 'A'}
              </span>
              <span className="absolute -bottom-0.5 -right-0.5 h-2 w-2 rounded-full bg-emerald-500 ring-2 ring-slate-950" />
            </span>
          </span>
          {!collapsed && (
            <span className="min-w-0 flex-1 pr-3">
              <span className="block text-[13px] font-medium text-slate-200 truncate leading-tight">
                {username || 'Analyst'}
              </span>
              <span className="block text-[11px] text-slate-500 truncate leading-tight">
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
          {!collapsed && <span className="text-[13px] font-medium pr-3">Sign out</span>}
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
          {!collapsed && <span className="text-[13px] font-medium pr-3">Collapse</span>}
        </button>
      </div>
    </aside>
  );
}
