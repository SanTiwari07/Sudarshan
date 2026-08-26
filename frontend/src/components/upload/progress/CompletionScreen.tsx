import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Loader2 } from 'lucide-react';
import { useCaseLinks } from '../../../hooks/useCaseLinks';

type CompletionScreenProps = {
  fileName: string;
  /** Auto-navigate delay in ms */
  autoNavigateMs?: number;
};

export default function CompletionScreen({
  fileName,
  autoNavigateMs = 2800,
}: CompletionScreenProps) {
  const navigate = useNavigate();
  const links = useCaseLinks();

  useEffect(() => {
    const t = window.setTimeout(() => {
      navigate(links.summary, { replace: true });
    }, autoNavigateMs);
    return () => clearTimeout(t);
  }, [navigate, autoNavigateMs, links.summary]);

  return (
    <div className="upload-fade-in w-full flex justify-center px-4 py-16 sm:py-24">
      <div className="w-full max-w-md text-center space-y-6">
        <div className="space-y-2">
          <h1 className="text-2xl sm:text-3xl font-semibold text-slate-900">Investigation complete</h1>
          <p className="text-lg text-slate-800">{fileName}</p>
        </div>
        <p className="text-sm text-slate-600">Analysis completed successfully.</p>
        <p className="text-sm text-slate-500 flex items-center justify-center gap-2">
          <Loader2 className="h-4 w-4 animate-spin text-slate-400" aria-hidden />
          Preparing investigation report…
        </p>
        <button
          type="button"
          onClick={() => navigate(links.summary, { replace: true })}
          className="mt-4 inline-flex items-center justify-center px-5 py-2.5 rounded-lg bg-blue-700 text-white text-sm font-medium hover:bg-blue-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
        >
          Open investigation
        </button>
      </div>
    </div>
  );
}
