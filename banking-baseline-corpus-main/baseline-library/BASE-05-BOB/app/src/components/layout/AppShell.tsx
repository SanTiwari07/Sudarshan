import type { ReactNode } from 'react';
import { Home, List, User, Settings } from 'lucide-react';
import './AppShell.css';

interface AppShellProps {
  children: ReactNode;
}

export function AppShell({ children }: AppShellProps) {
  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="header-brand">
          <h1>bob World</h1>
        </div>
      </header>

      <main className="app-main">
        {children}
      </main>

      <nav className="app-bottom-nav">
        <button className="nav-item active">
          <Home size={24} />
          <span>Home</span>
        </button>
        <button className="nav-item">
          <List size={24} />
          <span>Accounts</span>
        </button>
        <button className="nav-item">
          <User size={24} />
          <span>Profile</span>
        </button>
        <button className="nav-item">
          <Settings size={24} />
          <span>Settings</span>
        </button>
      </nav>
    </div>
  );
}
