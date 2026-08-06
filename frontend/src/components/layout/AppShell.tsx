import { NavDrawerProvider } from '../../context/NavDrawerContext';
import NavDrawer from './NavDrawer';
import AppHeader from './AppHeader';

type AppShellProps = {
  isAuthed: boolean;
  onLogout: () => void;
  children: React.ReactNode;
};

export default function AppShell({ isAuthed, onLogout, children }: AppShellProps) {
  return (
    <NavDrawerProvider>
      <div className="min-h-screen flex flex-col bg-slate-100 min-w-0">
        <AppHeader isAuthed={isAuthed} onLogout={onLogout} />
        <NavDrawer />
        <main className="flex-1 w-full min-w-0 flex flex-col analyst-main">{children}</main>
      </div>
    </NavDrawerProvider>
  );
}
