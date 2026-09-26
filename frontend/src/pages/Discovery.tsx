import { useNavigate } from 'react-router-dom';
import UrlDiscoveryArea from '../components/discovery/UrlDiscoveryArea';
import { Compass, ShieldCheck } from 'lucide-react';
import PageHeader from '../components/ui/PageHeader';

export default function Discovery() {
  const navigate = useNavigate();

  const handleAnalyzeCandidate = async (candidateId: string, sessionId: string, filename: string) => {
    // When a discovered APK candidate is selected for analysis, we can trigger analysis via upload workflow or direct endpoint
    navigate('/', {
      state: {
        discoveredCandidate: {
          candidateId,
          sessionId,
          filename,
        },
      },
    });
  };

  return (
    <div className="page-frame">
      <PageHeader
        icon={Compass}
        title="URL discovery"
        description="Paste a suspicious link - a phishing page, SMS lure or dropper site. Sudarshan crawls it, finds any APKs it serves, and lets you send them for analysis."
      />

      <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_320px] gap-6 items-start">
        <div className="bg-white rounded-2xl border border-slate-200/80 p-5 sm:p-7 shadow-[0_1px_3px_rgba(15,23,42,0.04)]">
          <UrlDiscoveryArea onAnalyzeCandidate={handleAnalyzeCandidate} />
        </div>

        <aside className="space-y-4">
          <div className="rounded-2xl border border-slate-200/80 bg-white p-5">
            <h2 className="text-base font-semibold text-slate-900">How it works</h2>
            <ol className="mt-4 space-y-4">
              {[
                ['Crawl', 'The page is fetched from an isolated crawler, never your browser.'],
                ['Find payloads', 'Download links and redirects are followed to any APK files.'],
                ['Analyse', 'Pick a candidate and it goes through the full analysis pipeline.'],
              ].map(([title, text], i) => (
                <li key={title} className="flex gap-3">
                  <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-blue-50 text-[13px] font-semibold text-blue-700">
                    {i + 1}
                  </span>
                  <div>
                    <p className="text-sm font-semibold text-slate-900">{title}</p>
                    <p className="text-[13px] text-slate-500 leading-snug mt-0.5">{text}</p>
                  </div>
                </li>
              ))}
            </ol>
          </div>
          <div className="rounded-2xl bg-emerald-50/70 border border-emerald-100 p-4 flex items-start gap-3">
            <ShieldCheck className="h-5 w-5 text-emerald-600 shrink-0 mt-0.5" />
            <p className="text-[13px] text-emerald-900/80 leading-snug">
              Downloaded files are quarantined and only ever executed inside the sandbox.
            </p>
          </div>
        </aside>
      </div>
    </div>
  );
}
