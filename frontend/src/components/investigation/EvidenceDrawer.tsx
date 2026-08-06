import { useEffect, useState } from 'react';
import { X } from 'lucide-react';
import type { FraudCardData } from '../../App';
import { findEvidenceById } from '../../hooks/useInvestigationModel';
import type { InvestigationBundle } from '../../types/investigation';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { fetchScreenshotBlob } from '../../lib/screenshots';
import ScreenshotLightbox from './ScreenshotLightbox';

export default function EvidenceDrawer({
  data,
  bundle,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle;
}) {
  const { drawerEvidenceId, closeEvidence } = useInvestigationUI();
  const [lightbox, setLightbox] = useState<string | null>(null);
  const [thumb, setThumb] = useState<string | null>(null);

  const evidence = drawerEvidenceId ? findEvidenceById(bundle, drawerEvidenceId) : undefined;

  useEffect(() => {
    if (!evidence?.screenshotRef) {
      setThumb(null);
      return;
    }
    let url: string | null = null;
    fetchScreenshotBlob(data.sha256, evidence.screenshotRef).then((u) => {
      url = u;
      setThumb(u);
    });
    return () => {
      if (url) URL.revokeObjectURL(url);
    };
  }, [evidence?.screenshotRef, data.sha256]);

  if (!drawerEvidenceId) return null;

  return (
    <>
      <div className="fixed inset-0 z-50 flex justify-end">
        <div className="absolute inset-0 bg-slate-900/40" onClick={closeEvidence} />
        <div className="relative w-full max-w-md bg-white h-full shadow-2xl border-l border-slate-200 flex flex-col">
          <div className="px-5 py-4 border-b flex justify-between items-start shrink-0">
            <div>
              <h2 className="text-sm font-bold text-slate-900">Evidence</h2>
              <p className="font-mono text-xs text-blue-700">{drawerEvidenceId}</p>
            </div>
            <button type="button" onClick={closeEvidence} className="p-1.5 rounded hover:bg-slate-100">
              <X className="h-4 w-4" />
            </button>
          </div>
          {evidence ? (
            <div className="flex-1 overflow-y-auto p-5 space-y-4 text-xs">
              <div>
                <div className="text-slate-500 uppercase tracking-wide">Finding</div>
                <div className="font-semibold text-slate-900 mt-1">{evidence.title}</div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <div className="text-slate-500">Severity</div>
                  <div className="font-bold text-red-700">{evidence.severity}</div>
                </div>
                <div>
                  <div className="text-slate-500">Confidence</div>
                  <div className="font-bold">{evidence.confidence}%</div>
                </div>
                <div>
                  <div className="text-slate-500">Source</div>
                  <div>{evidence.sourceEngine}</div>
                </div>
                <div>
                  <div className="text-slate-500">Category</div>
                  <div>{evidence.category}</div>
                </div>
              </div>
              {evidence.description && (
                <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg leading-relaxed">
                  {evidence.description}
                </div>
              )}
              {evidence.mitreId && (
                <div className="font-mono text-blue-800">
                  MITRE {evidence.mitreId} {evidence.mitreName}
                </div>
              )}
              {evidence.hookNames && (
                <div>
                  <div className="text-slate-500 mb-1">Hook</div>
                  <code className="text-[10px] bg-slate-100 p-2 rounded block">{evidence.hookNames.join('\n')}</code>
                </div>
              )}
              {evidence.screenshotRef && (
                <div>
                  <div className="text-slate-500 mb-2">Screenshot</div>
                  {thumb ? (
                    <button type="button" onClick={() => setLightbox(evidence.screenshotRef!)}>
                      <img src={thumb} alt="" className="w-32 rounded border border-slate-200" />
                    </button>
                  ) : (
                    <span className="text-slate-400">No preview</span>
                  )}
                </div>
              )}
              {evidence.artifactRefs && evidence.artifactRefs.length > 0 && (
                <div>
                  <div className="text-slate-500 mb-1">Artifacts</div>
                  <ul className="list-disc pl-4 space-y-1">
                    {evidence.artifactRefs.map((a) => (
                      <li key={a} className="font-mono text-[10px]">{a}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ) : (
            <div className="p-5 text-sm text-slate-500">No structured record for this ID. Check ledger lines.</div>
          )}
        </div>
      </div>
      {lightbox && (
        <ScreenshotLightbox sha256={data.sha256} filename={lightbox} onClose={() => setLightbox(null)} />
      )}
    </>
  );
}
