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
    <div className="h-screen min-h-screen flex flex-col bg-slate-100 min-w-0 relative overflow-hidden">
      <AppSidebar onLogout={logout} />
      <AppHeader isAuthed={isAuthed} onLogout={logout} />
      <main className="flex-1 w-full min-w-0 flex flex-col analyst-main pl-14 overflow-y-auto">
        {children}
      </main>
    </div>
  );
}
