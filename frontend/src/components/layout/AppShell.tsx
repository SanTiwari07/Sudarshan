import AppHeader from './AppHeader';
import AppSidebar from './AppSidebar';

type AppShellProps = {
  isAuthed: boolean;
  onLogout: () => void;
  children: React.ReactNode;
};

export default function AppShell({ isAuthed, onLogout, children }: AppShellProps) {
  return (
    <div className="min-h-screen flex flex-col bg-slate-100 min-w-0 relative">
      {isAuthed && <AppSidebar onLogout={onLogout} />}
      <AppHeader isAuthed={isAuthed} onLogout={onLogout} />
      <main className={`flex-1 w-full min-w-0 flex flex-col analyst-main ${isAuthed ? 'pl-14' : ''}`}>
        {children}
      </main>
    </div>
  );
}
