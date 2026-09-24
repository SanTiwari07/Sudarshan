import { Link, useLocation } from 'react-router-dom';
import { LogIn, Shield, Search, Bell, Share2, Download, FileText, ChevronRight } from 'lucide-react';
import { useAnalysis } from '../../context/AnalysisContext';

type AppHeaderProps = {
  isAuthed: boolean;
};

export default function AppHeader({ isAuthed }: AppHeaderProps) {
  const { analysisResult } = useAnalysis();
  const location = useLocation();

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

  return (
    <header className="sticky top-0 z-40 flex h-14 w-full items-center justify-between border-b border-slate-200 bg-white px-4">
      {/* Left: Breadcrumbs / Case info */}
      <div className="flex items-center gap-2 text-sm font-medium text-slate-600 w-1/3">
        {isCasePage && analysisResult ? (
          <>
            <Link to="/history" className="hover:text-slate-900 transition-colors">Cases</Link>
            <ChevronRight className="h-4 w-4 text-slate-400" />
            <span className="text-slate-900 truncate max-w-[200px]" title={analysisResult.package_name}>
              {analysisResult.package_name || analysisResult.app_name || 'Unknown package'}
            </span>
            <span className="text-slate-400 ml-2 font-mono text-xs hidden lg:inline">
              {analysisResult.sha256?.substring(0, 8)}
            </span>
          </>
        ) : (
          <span className="text-slate-900">Workspace</span>
        )}
      </div>

      {/* Center: Global Search */}
      <div className="flex-1 max-w-lg px-4 hidden md:block">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search cases, hashes, package names..."
            className="w-full rounded-md border border-slate-300 bg-slate-50 py-1.5 pl-9 pr-10 text-sm outline-none transition-colors focus:border-blue-500 focus:bg-white focus:ring-1 focus:ring-blue-500"
          />
          <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
            <kbd className="hidden sm:inline-block rounded border border-slate-200 bg-white px-1.5 py-0.5 text-[10px] font-sans font-medium text-slate-400">Ctrl</kbd>
            <kbd className="hidden sm:inline-block rounded border border-slate-200 bg-white px-1.5 py-0.5 text-[10px] font-sans font-medium text-slate-400">K</kbd>
          </div>
        </div>
      </div>

      {/* Right: Actions & User */}
      <div className="flex items-center justify-end gap-3 w-1/3">
        {isCasePage && analysisResult && (
          <div className="hidden lg:flex items-center gap-2 mr-2">
            <button className="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-slate-600 hover:bg-slate-100 hover:text-slate-900 transition-colors">
              <Share2 className="h-4 w-4" />
              Share
            </button>
            <button className="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-slate-600 hover:bg-slate-100 hover:text-slate-900 transition-colors">
              <Download className="h-4 w-4" />
              Export
            </button>
            <button className="flex items-center gap-1.5 rounded-md bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700 transition-colors shadow-sm">
              <FileText className="h-4 w-4" />
              Generate Report
            </button>
          </div>
        )}
        
        <div className="h-6 w-px bg-slate-200 hidden lg:block" />

        <button className="relative rounded-full p-1.5 text-slate-500 hover:bg-slate-100 hover:text-slate-900 transition-colors">
          <Bell className="h-5 w-5" />
          <span className="absolute top-1 right-1 h-2 w-2 rounded-full bg-red-500 ring-2 ring-white"></span>
        </button>
      </div>
    </header>
  );
}
