import { useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { X } from 'lucide-react';
import { useNavDrawer } from '../../context/NavDrawerContext';
import { NAV_ITEMS, type NavItem } from '../../layout/navItems';

function isNavActive(pathname: string, item: NavItem) {
  if (item.to === '/') {
    return pathname === '/';
  }
  const prefix = item.matchPrefix || item.to;
  return pathname === item.to || pathname.startsWith(`${prefix}/`);
}

export default function NavDrawer() {
  const { open, closeDrawer } = useNavDrawer();
  const { pathname } = useLocation();

  useEffect(() => {
    closeDrawer();
  }, [pathname, closeDrawer]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') closeDrawer();
    };
    document.addEventListener('keydown', onKey);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = prevOverflow;
    };
  }, [open, closeDrawer]);

  return (
    <>
      <div
        className={`fixed inset-0 z-[70] bg-slate-900/40 backdrop-blur-[2px] transition-opacity duration-[250ms] ${
          open ? 'opacity-100 pointer-events-auto' : 'opacity-0 pointer-events-none'
        }`}
        onClick={closeDrawer}
        aria-hidden={!open}
      />
      <aside
        id="app-nav-drawer"
        aria-hidden={!open}
        className={`fixed top-0 left-0 z-[80] h-full w-[280px] bg-blue-950 text-white shadow-2xl border-r border-blue-900 flex flex-col transition-transform duration-[250ms] ease-out will-change-transform ${
          open ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="flex items-center justify-between px-4 h-14 border-b border-blue-900 shrink-0">
          <span className="text-xs font-bold uppercase tracking-[0.14em] text-blue-300">Navigation</span>
          <button
            type="button"
            onClick={closeDrawer}
            className="p-1.5 rounded-lg hover:bg-blue-900 text-blue-200"
            aria-label="Close menu"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <nav className="flex-1 overflow-y-auto py-3 px-2 space-y-0.5">
          {NAV_ITEMS.map((item) => {
            const active = isNavActive(pathname, item);
            const Icon = item.icon;
            return (
              <Link
                key={item.to}
                to={item.to}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  active
                    ? 'bg-blue-800 text-white shadow-sm'
                    : 'text-blue-100 hover:bg-blue-900 hover:text-white'
                }`}
              >
                <Icon className={`h-4 w-4 shrink-0 ${active ? 'text-blue-300' : 'text-blue-400'}`} />
                <span className="min-w-0 truncate">{item.label}</span>
              </Link>
            );
          })}
        </nav>
        <div className="px-4 py-3 border-t border-blue-900 text-[10px] text-blue-400 font-mono">
          Sudarshan BOI · Enterprise SOC
        </div>
      </aside>
    </>
  );
}
