import { useState, useRef, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Shield, LogOut, User } from 'lucide-react';
import { getUser } from '../../pages/Login';
import {
  ENTERPRISE_NAV_MAIN,
  ENTERPRISE_NAV_END,
  isNavActive,
  type NavItem,
} from '../../layout/navItems';

type AppSidebarProps = {
  onLogout: () => void;
};

export default function AppSidebar({ onLogout }: AppSidebarProps) {
  const [isHovered, setIsHovered] = useState(false);
  const { pathname } = useLocation();
  const user = getUser();
  const hoverTimeoutRef = useRef<any>(null);

  // Clean up timer on unmount
  useEffect(() => {
    return () => {
      if (hoverTimeoutRef.current) clearTimeout(hoverTimeoutRef.current);
    };
  }, []);

  const handleMouseEnter = () => {
    if (hoverTimeoutRef.current) clearTimeout(hoverTimeoutRef.current);
    setIsHovered(true);
  };

  const handleMouseLeave = () => {
    hoverTimeoutRef.current = setTimeout(() => {
      setIsHovered(false);
    }, 150);
  };

  const navItemClass = (active: boolean) =>
    `group relative flex items-center h-10 rounded-md transition-all duration-200 select-none ${
      active
        ? 'bg-blue-600/20 text-blue-400 font-semibold border-l-2 border-blue-500 shadow-sm'
        : 'text-slate-400 hover:text-slate-100 hover:bg-slate-900/80 border-l-2 border-transparent'
    }`;

  const renderNavItem = (item: NavItem) => {
    const active = isNavActive(pathname, item);
    const Icon = item.icon;

    return (
      <Link
        key={`${item.to}-${item.label}`}
        to={item.to}
        className={navItemClass(active)}
        title={!isHovered ? item.label : undefined}
      >
        <div className="w-12 h-10 flex items-center justify-center shrink-0">
          <Icon className={`h-4 w-4 transition-colors ${active ? 'text-blue-400' : 'text-slate-400 group-hover:text-slate-200'}`} />
        </div>
        <span
          className={`text-xs font-mono tracking-wider whitespace-nowrap transition-opacity duration-200 pr-3 ${
            isHovered ? 'opacity-100' : 'opacity-0 w-0 overflow-hidden'
          }`}
        >
          {item.label}
        </span>

        {/* Floating tooltip on collapsed hover */}
        {!isHovered && (
          <div className="fixed left-14 px-2.5 py-1 bg-slate-900 text-slate-100 text-[11px] font-mono rounded-md shadow-xl border border-slate-800 whitespace-nowrap opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity duration-150 z-[70]">
            {item.label}
          </div>
        )}
      </Link>
    );
  };

  return (
    <>
      {/* 1. Transparent trigger zone on extreme left edge */}
      <div
        className="fixed top-0 left-0 bottom-0 w-3 z-[55] pointer-events-auto"
        onMouseEnter={handleMouseEnter}
        aria-hidden="true"
      />

      {/* 2. Backdrop for mobile view when expanded */}
      {isHovered && (
        <div
          className="fixed inset-0 bg-slate-950/40 backdrop-blur-xs z-[58] md:hidden transition-opacity duration-200"
          onClick={() => setIsHovered(false)}
          aria-hidden="true"
        />
      )}

      {/* 3. Main Sidebar Container */}
      <aside
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
        className={`fixed top-0 left-0 bottom-0 z-[60] bg-slate-950 text-slate-100 border-r border-slate-800/80 shadow-2xl flex flex-col transition-all duration-300 ease-in-out overflow-x-hidden ${
          isHovered ? 'w-64' : 'w-12'
        }`}
        aria-label="Sidebar Navigation"
      >
        {/* Branding Section */}
        <div className="h-14 border-b border-slate-800/80 flex items-center px-0 shrink-0 overflow-hidden">
          <Link
            to="/fraud-card"
            className="flex items-center w-full h-full text-left focus:outline-none"
          >
            <div className="w-12 h-14 flex items-center justify-center shrink-0">
              <Shield className="h-5 w-5 text-blue-500 shrink-0" />
            </div>
            <div
              className={`min-w-0 transition-opacity duration-200 pr-3 ${
                isHovered ? 'opacity-100' : 'opacity-0 w-0 overflow-hidden'
              }`}
            >
              <span className="font-extrabold text-xs tracking-widest block leading-none text-white font-mono">
                SUDARSHAN
              </span>
              <span className="text-[9px] text-blue-400 font-bold leading-none tracking-wider uppercase mt-1 block">
                ENTERPRISE SOC
              </span>
            </div>
          </Link>
        </div>

        {/* Primary Navigation Items */}
        <nav className="flex-1 py-3 space-y-1 overflow-y-auto scrollbar-hidden">
          {pathname !== '/' && ENTERPRISE_NAV_MAIN.map(renderNavItem)}

          {/* Subtle Divider */}
          {pathname !== '/' && <div className="my-3 border-t border-slate-800/80 mx-2" />}

          {/* Secondary Navigation Items */}
          {ENTERPRISE_NAV_END.map(renderNavItem)}
        </nav>

        {/* Bottom User & Logout Section */}
        <div className="py-2 border-t border-slate-800/80 shrink-0 space-y-1 bg-slate-950/90">
          {/* User Profile Info */}
          <div
            className="group relative flex items-center h-10 transition-all duration-200 select-none hover:bg-slate-900/80 border-l-2 border-transparent hover:border-blue-500/40 cursor-default"
            title={!isHovered ? `${user?.username || 'User'} (${user?.role || 'SOC Analyst'})` : undefined}
          >
            <div className="w-12 h-10 flex items-center justify-center shrink-0">
              <div className="relative flex items-center justify-center">
                <div className="h-6 w-6 rounded bg-blue-950/90 border border-blue-800/80 flex items-center justify-center text-blue-400 font-mono text-[10px] font-bold shadow-xs group-hover:border-blue-500 transition-colors">
                  {user?.username?.[0]?.toUpperCase() || <User className="h-3.5 w-3.5" />}
                </div>
                <span className="absolute -bottom-0.5 -right-0.5 h-2 w-2 rounded-full bg-emerald-500 ring-2 ring-slate-950" />
              </div>
            </div>

            <div
              className={`min-w-0 flex-1 transition-opacity duration-200 pr-3 ${
                isHovered ? 'opacity-100' : 'opacity-0 w-0 overflow-hidden'
              }`}
            >
              <div className="text-xs font-mono font-bold text-slate-200 truncate group-hover:text-white">
                {user?.username || 'Analyst'}
              </div>
              <div className="text-[9px] text-blue-400/90 truncate font-mono uppercase tracking-wider font-semibold">
                {user?.role || 'SOC Analyst'}
              </div>
            </div>

            {!isHovered && (
              <div className="fixed left-14 px-2.5 py-1 bg-slate-900 text-slate-100 text-[11px] font-mono rounded-md shadow-xl border border-slate-800 whitespace-nowrap opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity duration-150 z-[70]">
                {user?.username || 'Analyst'} ({user?.role || 'SOC Analyst'})
              </div>
            )}
          </div>

          {/* Logout Button */}
          <button
            type="button"
            onClick={onLogout}
            className="group relative w-full flex items-center h-10 text-slate-400 hover:text-red-400 hover:bg-red-950/30 border-l-2 border-transparent hover:border-red-500/50 transition-all duration-200 text-left select-none"
            title={!isHovered ? 'Logout' : undefined}
          >
            <div className="w-12 h-10 flex items-center justify-center shrink-0">
              <LogOut className="h-4 w-4 text-slate-500 group-hover:text-red-400 transition-colors" />
            </div>
            <span
              className={`text-xs font-mono tracking-wider whitespace-nowrap transition-opacity duration-200 pr-3 ${
                isHovered ? 'opacity-100' : 'opacity-0 w-0 overflow-hidden'
              }`}
            >
              Logout
            </span>

            {!isHovered && (
              <div className="fixed left-14 px-2.5 py-1 bg-slate-900 text-red-400 text-[11px] font-mono rounded-md shadow-xl border border-slate-800 whitespace-nowrap opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity duration-150 z-[70]">
                Logout
              </div>
            )}
          </button>
        </div>
      </aside>
    </>
  );
}
