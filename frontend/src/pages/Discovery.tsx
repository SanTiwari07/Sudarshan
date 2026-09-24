import { useNavigate } from 'react-router-dom';
import UrlDiscoveryArea from '../components/discovery/UrlDiscoveryArea';
import { Compass, Shield } from 'lucide-react';

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
    <div className="w-[92%] max-w-[1550px] mx-auto py-8 px-4 sm:px-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600">
            <Compass className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-slate-900 tracking-tight">
              URL & Infrastructure Threat Discovery
            </h1>
            <p className="text-sm text-slate-500 mt-0.5">
              Probe suspected landing pages, dropper links, and C2 distribution endpoints for malicious APK payloads.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6">
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
          <UrlDiscoveryArea onAnalyzeCandidate={handleAnalyzeCandidate} />
        </div>

        {/* Informational Guidance */}
        <div className="rounded-xl border border-slate-200 bg-slate-50/50 p-5 flex items-start gap-4">
          <Shield className="h-5 w-5 text-blue-600 shrink-0 mt-0.5" />
          <div className="text-xs text-slate-600 space-y-1">
            <p className="font-semibold text-slate-800">
              Deterministic Ingestion & Isolation Guarantee
            </p>
            <p>
              Discovered candidate packages are fetched into the secure ingestion quarantine before entering the static and dynamic analysis pipelines. All network crawls respect crawler boundaries and avoid executing untrusted payloads outside sandbox containment.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
