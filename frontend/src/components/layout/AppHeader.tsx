import { Link, useLocation } from 'react-router-dom';
import { Bell, LogOut, LogIn, Shield } from 'lucide-react';
import { getUser } from '../../pages/Login';
import NavigationBar from './NavigationBar';
import { ENTERPRISE_NAV_END } from '../../layout/navItems';

type AppHeaderProps = {
  isAuthed: boolean;
  onLogout: () => void;
};

export default function AppHeader({ isAuthed, onLogout }: AppHeaderProps) {
  const user = getUser();
  const { pathname } = useLocation();
  const isUploadPage = pathname === '/';

  return (
    <header
      className="sticky top-0 z-50 shrink-0 bg-slate-950 text-slate-100 border-b border-slate-800/80"
      style={{ minHeight: 'var(--app-header-height)' }}
    >
      <div className="flex flex-col">
        <div className="h-12 flex items-center gap-3 px-4 min-w-0">
          <Link
            to={isAuthed ? '/' : '/login'}
            className="flex items-center gap-2.5 shrink-0 min-w-0"
          >
            <Shield className="h-5 w-5 text-blue-500 shrink-0" />
            <div className="min-w-0 hidden sm:block">
              <span className="font-extrabold text-[11px] tracking-widest block leading-none text-white font-mono">SUDARSHAN</span>
              <span className="text-[9px] text-blue-400 font-bold leading-none tracking-wider uppercase">ENTERPRISE SOC</span>
            </div>
          </Link>

          {isAuthed && !isUploadPage && (
            <div className="hidden lg:flex flex-1 min-w-0 px-2">
              <NavigationBar variant="main" />
            </div>
          )}

          {isAuthed && (
            <div className={`hidden lg:flex items-center shrink-0 ${isUploadPage ? 'ml-auto' : ''}`}>
              <NavigationBar variant="end" />
            </div>
          )}

          <div className="flex items-center gap-2 shrink-0 ml-auto lg:ml-0">
            {isAuthed && (
              <button
                type="button"
                className="p-1.5 rounded hover:bg-slate-900 text-slate-400 hover:text-white transition-colors relative"
                title="Notifications"
                aria-label="Notifications"
              >
                <Bell className="h-3.5 w-3.5" />
                <span className="absolute top-1 right-1 w-1.5 h-1.5 rounded-full bg-blue-500" />
              </button>
            )}

            {isAuthed ? (
              <button
                type="button"
                onClick={onLogout}
                className="flex items-center gap-2 px-2.5 py-1 rounded bg-slate-900 border border-slate-800/80 text-slate-300 hover:text-white hover:border-slate-700 transition-all text-xs font-mono max-w-[10rem]"
                title={`Logged in as ${user?.username} (${user?.role})`}
              >
                <span className="truncate hidden md:inline">{user?.username}</span>
                <LogOut className="h-3.5 w-3.5 shrink-0 text-slate-500" />
              </button>
            ) : (
              <Link
                to="/login"
                className="flex items-center gap-1.5 px-3 py-1 rounded bg-blue-600 hover:bg-blue-700 text-white text-xs font-medium transition-colors"
              >
                <LogIn className="h-3.5 w-3.5" />
                <span>Sign in</span>
              </Link>
            )}
          </div>
        </div>

        {isAuthed && !isUploadPage && (
          <div className="lg:hidden border-t border-slate-900 px-3 pb-2 pt-1.5">
            <NavigationBar variant="all" />
          </div>
        )}
        {isAuthed && isUploadPage && (
          <div className="lg:hidden border-t border-slate-900 px-3 pb-2 pt-1.5">
            <NavigationBar items={ENTERPRISE_NAV_END} variant="end" />
          </div>
        )}
      </div>
    </header>
  );
}
