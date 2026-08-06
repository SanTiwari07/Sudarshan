import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Bell,
  LogOut,
  LogIn,
  Menu,
  Search,
  Shield,
} from 'lucide-react';
import { getUser } from '../../pages/Login';
import { useAnalysis } from '../../context/AnalysisContext';
import { useNavDrawer } from '../../context/NavDrawerContext';
import { getRiskStyle } from '../../theme/colors';

type AppHeaderProps = {
  isAuthed: boolean;
  onLogout: () => void;
};

export default function AppHeader({ isAuthed, onLogout }: AppHeaderProps) {
  const { openDrawer } = useNavDrawer();
  const { analysisResult } = useAnalysis();
  const navigate = useNavigate();
  const user = getUser();
  const [search, setSearch] = useState('');

  const caseLabel =
    analysisResult?.app_name ||
    analysisResult?.package_name ||
    (analysisResult?.sha256 ? analysisResult.sha256.slice(0, 12) + '…' : null);

  const riskStyle = analysisResult ? getRiskStyle(analysisResult.risk_band) : null;

  const submitSearch = () => {
    const q = search.trim().toLowerCase();
    if (!q) {
      navigate('/history');
      return;
    }
    navigate(`/history?q=${encodeURIComponent(q)}`);
  };

  return (
    <header
      className="sticky top-0 z-50 h-14 shrink-0 bg-blue-900 text-white border-b border-blue-950 shadow-md"
      style={{ height: 'var(--app-header-height)' }}
    >
      <div className="h-full flex items-center gap-2 sm:gap-3 px-2 sm:px-4 min-w-0">
        <button
          type="button"
          onClick={openDrawer}
          className="p-2 rounded-lg hover:bg-blue-800 text-blue-100 shrink-0"
          aria-label="Open navigation menu"
          aria-controls="app-nav-drawer"
        >
          <Menu className="h-5 w-5" />
        </button>

        <Link to={isAuthed ? '/fraud-card' : '/login'} className="flex items-center gap-2 shrink-0 min-w-0">
          <Shield className="h-6 w-6 text-blue-400 shrink-0" />
          <div className="min-w-0 hidden sm:block">
            <span className="font-bold text-sm tracking-wider block leading-tight">SUDARSHAN</span>
            <span className="text-[10px] text-blue-400 font-mono leading-none">ENTERPRISE SOC</span>
          </div>
        </Link>

        {isAuthed && caseLabel && (
          <div className="hidden lg:flex items-center gap-2 min-w-0 max-w-[min(28rem,35vw)] px-3 py-1.5 rounded-lg bg-blue-950/60 border border-blue-800">
            <span className="text-[10px] uppercase tracking-wider text-blue-400 shrink-0">Case</span>
            <span className="text-xs font-medium truncate text-blue-50" title={caseLabel}>{caseLabel}</span>
            {analysisResult && riskStyle && (
              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded shrink-0 ${riskStyle.badge}`}>
                {analysisResult.final_risk_score.toFixed(0)}
              </span>
            )}
          </div>
        )}

        <div className="flex-1 min-w-0 flex justify-center px-1 sm:px-3">
          {isAuthed && (
            <form
              className="w-full max-w-xl flex items-center"
              onSubmit={(e) => {
                e.preventDefault();
                submitSearch();
              }}
            >
              <div className="relative w-full">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-blue-400" />
                <input
                  type="search"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search cases by hash, package, family…"
                  className="w-full pl-8 pr-3 py-1.5 text-xs rounded-lg bg-blue-950/70 border border-blue-800 text-blue-50 placeholder:text-blue-400 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                />
              </div>
            </form>
          )}
        </div>

        <div className="flex items-center gap-1 shrink-0">
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
    </header>
  );
}
