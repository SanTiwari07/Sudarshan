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
  const showNavigation = isAuthed && !isLoginPage;

  return (
    <div className="min-h-screen flex flex-col bg-slate-100 min-w-0 relative">
      {showNavigation && <AppSidebar onLogout={logout} />}
      {showNavigation && <AppHeader isAuthed={isAuthed} onLogout={logout} />}
      <main className={`flex-1 w-full min-w-0 flex flex-col analyst-main ${showNavigation ? 'pl-14' : ''}`}>
        {children}
      </main>
    </div>
  );
}
