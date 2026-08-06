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
      className="sticky top-0 z-50 shrink-0 bg-blue-900 text-white border-b border-blue-950 shadow-md"
      style={{ minHeight: 'var(--app-header-height)' }}
    >
      <div className="flex flex-col">
        <div className="h-14 flex items-center gap-2 sm:gap-3 px-2 sm:px-4 min-w-0">
          <Link
            to={isAuthed ? '/' : '/login'}
            className="flex items-center gap-2 shrink-0 min-w-0"
          >
            <Shield className="h-6 w-6 text-blue-400 shrink-0" />
            <div className="min-w-0 hidden sm:block">
              <span className="font-bold text-sm tracking-wider block leading-tight">SUDARSHAN</span>
              <span className="text-[10px] text-blue-400 font-mono leading-none">ENTERPRISE SOC</span>
            </div>
          </Link>

          {isAuthed && !isUploadPage && (
            <div className="hidden lg:flex flex-1 min-w-0">
              <NavigationBar variant="main" />
            </div>
          )}

          {isAuthed && (
            <div className={`hidden lg:flex items-center shrink-0 ${isUploadPage ? 'ml-auto' : ''}`}>
              <NavigationBar variant="end" />
            </div>
          )}

          <div className="flex items-center gap-1 shrink-0 ml-auto lg:ml-0">
            {isAuthed && (
              <button
                type="button"
                className="p-2 rounded-lg hover:bg-blue-800 text-blue-200 relative"
                title="Notifications"
                aria-label="Notifications"
              >
                <Bell className="h-4 w-4" />
                <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full bg-cyan-400" />
              </button>
            )}

            {isAuthed ? (
              <button
                type="button"
                onClick={onLogout}
                className="flex items-center gap-1.5 px-2 sm:px-3 py-1.5 rounded-lg hover:bg-blue-800 text-blue-100 text-xs font-medium max-w-[9rem]"
                title={`Logged in as ${user?.username} (${user?.role})`}
              >
                <span className="truncate hidden md:inline">{user?.username}</span>
                <LogOut className="h-4 w-4 shrink-0" />
              </button>
            ) : (
              <Link
                to="/login"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg hover:bg-blue-800 text-blue-100 text-xs font-medium"
              >
                <LogIn className="h-4 w-4" />
                <span className="hidden sm:inline">Sign in</span>
              </Link>
            )}
          </div>
        </div>

        {isAuthed && !isUploadPage && (
          <div className="lg:hidden border-t border-blue-800/80 px-2 pb-2 pt-1">
            <NavigationBar variant="all" />
          </div>
        )}
        {isAuthed && isUploadPage && (
          <div className="lg:hidden border-t border-blue-800/80 px-2 pb-2 pt-1">
            <NavigationBar items={ENTERPRISE_NAV_END} variant="end" />
          </div>
        )}
      </div>
    </header>
  );
}
