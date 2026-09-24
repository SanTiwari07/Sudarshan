import { useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import AppHeader from './AppHeader';
import AppSidebar from './AppSidebar';

type AppShellProps = {
  children: React.ReactNode;
};

export default function AppShell({ children }: AppShellProps) {
  const { status, logout } = useAuth();
  const location = useLocation();

  const isAuthed = status === 'AUTHENTICATED';
  const isLoginPage = location.pathname === '/login';

  if (!isAuthed || isLoginPage) {
    return <>{children}</>;
  }

  return (
    <div className="h-screen min-h-screen flex bg-surface-page min-w-0 relative overflow-hidden">
      <AppSidebar onLogout={logout} />
      <div 
        className="flex-1 flex flex-col min-w-0 transition-[padding] duration-200 ease-out"
        style={{ paddingLeft: 'var(--app-sidebar-width)' }}
      >
        <AppHeader isAuthed={isAuthed} />
        <main className="flex-1 w-full min-w-0 flex flex-col analyst-main overflow-y-auto">
          {children}
        </main>
      </div>
    </div>
  );
}
