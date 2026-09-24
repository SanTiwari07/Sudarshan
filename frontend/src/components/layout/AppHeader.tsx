import { useState, useEffect, useRef } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import {
  LogIn,
  Shield,
  Bell,
  ChevronRight,
  Search,
  User as UserIcon,
  LogOut,
  Settings as SettingsIcon,
  CheckCircle2,
  X,
} from 'lucide-react';
import { useAnalysis } from '../../context/AnalysisContext';
import { useAuth } from '../../context/AuthContext';
import CommandPalette from './CommandPalette';

type AppHeaderProps = {
  isAuthed: boolean;
};

export default function AppHeader({ isAuthed }: AppHeaderProps) {
  const { analysisResult } = useAnalysis();
  const { user, role, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);

  const userMenuRef = useRef<HTMLDivElement>(null);
  const notifMenuRef = useRef<HTMLDivElement>(null);

  // Keyboard shortcut Ctrl+K / Cmd+K
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        setCommandPaletteOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Close menus on outside click
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (userMenuRef.current && !userMenuRef.current.contains(e.target as Node)) {
        setUserMenuOpen(false);
      }
      if (notifMenuRef.current && !notifMenuRef.current.contains(e.target as Node)) {
        setNotificationsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  if (!isAuthed) {
    return (
      <header className="sticky top-0 z-40 shrink-0 bg-slate-950 text-slate-100 border-b border-slate-800/80 h-12 flex items-center px-4 justify-between min-w-0">
        <Link to="/login" className="flex items-center gap-2.5 shrink-0">
          <Shield className="h-5 w-5 text-blue-500 shrink-0" />
          <div>
            <span className="font-semibold text-[13px] tracking-widest block leading-none text-white font-mono">
              SUDARSHAN
            </span>
            <span className="text-[11px] text-blue-400 font-bold leading-none tracking-wider uppercase">
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

  const isCasePage = location.pathname.startsWith('/case/') || !!analysisResult;
  const username = user || 'SOC Analyst';
  const userRole = (role || 'analyst').toUpperCase();

  return (
    <>
      <header className="sticky top-0 z-40 flex h-14 w-full items-center justify-between border-b border-slate-200 bg-white px-4">
        {/* Left: Breadcrumbs / Case info */}
        <div className="flex items-center gap-2 text-sm font-medium text-slate-600 min-w-0 max-w-[35%]">
          {isCasePage && analysisResult ? (
            <>
              <Link to="/history" className="hover:text-slate-900 transition-colors shrink-0">
                Cases
              </Link>
              <ChevronRight className="h-4 w-4 text-slate-400 shrink-0" />
              <span
                className="text-slate-900 font-semibold truncate"
                title={analysisResult.package_name}
              >
                {analysisResult.package_name || analysisResult.app_name || 'Unknown package'}
              </span>
              <span className="text-slate-400 font-mono text-xs hidden xl:inline shrink-0">
                {analysisResult.sha256?.substring(0, 8)}
              </span>
            </>
          ) : (
            <span className="text-slate-900 font-semibold">SOC Workspace</span>
          )}
        </div>

        {/* Center: Global Search Bar */}
        <div className="flex-1 max-w-md px-4 hidden md:block">
          <button
            type="button"
            onClick={() => setCommandPaletteOpen(true)}
            className="w-full flex items-center justify-between px-3 py-1.5 text-xs text-slate-500 bg-slate-50 hover:bg-slate-100 hover:text-slate-700 border border-slate-200 rounded-lg transition-colors cursor-pointer group"
          >
            <div className="flex items-center gap-2">
              <Search className="h-3.5 w-3.5 text-slate-400 group-hover:text-slate-600" />
              <span>Search cases, commands, evidence...</span>
            </div>
            <kbd className="inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[10px] font-semibold text-slate-400 bg-white border border-slate-200 rounded shadow-2xs">
              <span className="text-xs">⌘</span>K
            </kbd>
          </button>
        </div>

        {/* Right: Notifications & User Menu */}
        <div className="flex items-center justify-end gap-3 min-w-0">
          {/* Mobile search button */}
          <button
            type="button"
            onClick={() => setCommandPaletteOpen(true)}
            className="md:hidden p-1.5 text-slate-500 hover:bg-slate-100 hover:text-slate-900 rounded-md"
            title="Search (Ctrl+K)"
          >
            <Search className="h-5 w-5" />
          </button>

          {/* Notifications Dropdown */}
          <div className="relative" ref={notifMenuRef}>
            <button
              type="button"
              onClick={() => setNotificationsOpen((prev) => !prev)}
              className="relative rounded-full p-1.5 text-slate-500 hover:bg-slate-100 hover:text-slate-900 transition-colors"
              title="Notifications"
            >
              <Bell className="h-5 w-5" />
              <span className="absolute top-1 right-1 h-2 w-2 rounded-full bg-blue-600 ring-2 ring-white" />
            </button>

            {notificationsOpen && (
              <div className="absolute right-0 mt-2 w-80 bg-white rounded-xl shadow-xl border border-slate-200 py-2 z-50 animate-in fade-in zoom-in-95 duration-100">
                <div className="flex items-center justify-between px-4 py-2 border-b border-slate-100">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-500">
                    SOC Notifications
                  </span>
                  <span className="text-[11px] font-semibold text-blue-600">All caught up</span>
                </div>
                <div className="py-2 divide-y divide-slate-100 text-xs">
                  <div className="px-4 py-2.5 hover:bg-slate-50 transition-colors">
                    <div className="flex items-center gap-2">
                      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 shrink-0" />
                      <span className="font-semibold text-slate-800">
                        Deterministic Risk Engine active
                      </span>
                    </div>
                    <p className="text-slate-500 mt-0.5 text-[11px]">
                      Formula: CT, BT, PR, OB, IR calibrated against malware baselines.
                    </p>
                  </div>
                  {analysisResult && (
                    <div className="px-4 py-2.5 hover:bg-slate-50 transition-colors">
                      <div className="flex items-center gap-2">
                        <Shield className="h-3.5 w-3.5 text-blue-600 shrink-0" />
                        <span className="font-semibold text-slate-800 truncate">
                          Case indexed: {analysisResult.package_name}
                        </span>
                      </div>
                      <p className="text-slate-500 mt-0.5 text-[11px]">
                        Final Risk Score {Number(analysisResult.final_risk_score).toFixed(1)} / 100 ({analysisResult.risk_band}).
                      </p>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          <div className="h-6 w-px bg-slate-200" />

          {/* User Profile Dropdown */}
          <div className="relative" ref={userMenuRef}>
            <button
              type="button"
              onClick={() => setUserMenuOpen((prev) => !prev)}
              className="flex items-center gap-2.5 p-1 rounded-lg hover:bg-slate-100 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <div className="h-8 w-8 rounded-full bg-slate-900 text-white flex items-center justify-center font-bold text-xs shadow-xs">
                {username.substring(0, 2).toUpperCase()}
              </div>
              <div className="hidden lg:block text-left">
                <span className="text-xs font-semibold text-slate-800 block leading-tight truncate max-w-[120px]">
                  {username}
                </span>
                <span className="text-[10px] font-medium text-slate-500 block leading-tight">
                  {userRole}
                </span>
              </div>
            </button>

            {userMenuOpen && (
              <div className="absolute right-0 mt-2 w-56 bg-white rounded-xl shadow-xl border border-slate-200 py-1.5 z-50 animate-in fade-in zoom-in-95 duration-100">
                <div className="px-4 py-2 border-b border-slate-100">
                  <p className="text-xs font-semibold text-slate-900 truncate">{username}</p>
                  <div className="mt-1 flex items-center gap-1.5">
                    <span className="text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200">
                      {userRole}
                    </span>
                    <span className="text-[11px] text-slate-400">Online</span>
                  </div>
                </div>

                <div className="py-1">
                  <button
                    type="button"
                    onClick={() => {
                      setUserMenuOpen(false);
                      navigate('/settings');
                    }}
                    className="w-full flex items-center gap-2.5 px-4 py-2 text-xs text-slate-700 hover:bg-slate-50 hover:text-slate-900 transition-colors"
                  >
                    <SettingsIcon className="h-4 w-4 text-slate-400" />
                    <span>Preferences & Settings</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setUserMenuOpen(false);
                      navigate('/history');
                    }}
                    className="w-full flex items-center gap-2.5 px-4 py-2 text-xs text-slate-700 hover:bg-slate-50 hover:text-slate-900 transition-colors"
                  >
                    <UserIcon className="h-4 w-4 text-slate-400" />
                    <span>Investigated Cases</span>
                  </button>
                </div>

                <div className="border-t border-slate-100 pt-1">
                  <button
                    type="button"
                    onClick={() => {
                      setUserMenuOpen(false);
                      logout();
                      navigate('/login');
                    }}
                    className="w-full flex items-center gap-2.5 px-4 py-2 text-xs text-red-600 hover:bg-red-50 transition-colors"
                  >
                    <LogOut className="h-4 w-4 text-red-500" />
                    <span>Sign out</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Global Command Palette */}
      <CommandPalette
        isOpen={commandPaletteOpen}
        onClose={() => setCommandPaletteOpen(false)}
      />
    </>
  );
}
