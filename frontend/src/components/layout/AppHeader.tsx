import { Link } from 'react-router-dom';
import { LogIn, Shield } from 'lucide-react';

type AppHeaderProps = {
  isAuthed: boolean;
  onLogout: () => void;
};

export default function AppHeader({ isAuthed }: AppHeaderProps) {
  if (!isAuthed) {
    return (
      <header className="sticky top-0 z-40 shrink-0 bg-slate-950 text-slate-100 border-b border-slate-800/80 h-12 flex items-center px-4 justify-between min-w-0">
        <Link to="/login" className="flex items-center gap-2.5 shrink-0">
          <Shield className="h-5 w-5 text-blue-500 shrink-0" />
          <div>
            <span className="font-extrabold text-[11px] tracking-widest block leading-none text-white font-mono">
              SUDARSHAN
            </span>
            <span className="text-[9px] text-blue-400 font-bold leading-none tracking-wider uppercase">
              ENTERPRISE SOC
            </span>
          </div>
        </Link>
        <Link
          to="/login"
          className="flex items-center gap-1.5 px-3 py-1 rounded bg-blue-600 hover:bg-blue-700 text-white text-xs font-medium transition-colors"
        >
          <LogIn className="h-3.5 w-3.5" />
          <span>Sign in</span>
        </Link>
      </header>
    );
  }

  return null;
}
