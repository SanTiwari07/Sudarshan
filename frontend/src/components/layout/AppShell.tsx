import { useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import AppSidebar from './AppSidebar';
import CommandPalette from './CommandPalette';

type AppShellProps = {
  children: React.ReactNode;
};

/**
 * Sidebar + content. There is no top bar: every page opens with its own
 * header, the account lives at the foot of the sidebar, and search is the
 * command palette (Ctrl/Cmd+K), so a bar would only repeat what is already on
 * screen and cost 64px of height on every page.
 */
export default function AppShell({ children }: AppShellProps) {
  const { status, logout } = useAuth();
  const location = useLocation();
  const [paletteOpen, setPaletteOpen] = useState(false);

  const isAuthed = status === 'AUTHENTICATED';
  const isLoginPage = location.pathname === '/login';

  useEffect(() => {
    if (!isAuthed) return;
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen((v) => !v);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isAuthed]);

  if (!isAuthed || isLoginPage) {
    return <>{children}</>;
  }

  return (
    <div className="h-screen min-h-screen flex bg-surface-page min-w-0 relative overflow-hidden">
      <AppSidebar onLogout={logout} onSearch={() => setPaletteOpen(true)} />
      <div
        className="flex-1 flex flex-col min-w-0 transition-[padding] duration-200 ease-out"
        style={{ paddingLeft: 'var(--app-sidebar-width)' }}
      >
        <main className="flex-1 w-full min-w-0 flex flex-col analyst-main overflow-y-auto">
          {children}
        </main>
      </div>
      <CommandPalette isOpen={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </div>
  );
}
