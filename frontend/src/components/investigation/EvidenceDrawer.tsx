import { useEffect, useState, type ReactNode } from 'react';
import { ChevronDown, ChevronRight, X } from 'lucide-react';
import type { FraudCardData } from '../../App';
import { findEvidenceById } from '../../hooks/useInvestigationModel';
import type { InvestigationBundle } from '../../types/investigation';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import { fetchScreenshotBlob } from '../../lib/screenshots';
import {
  buildFindingExplanation,
  findingHeadline,
  sourceDisplayLabel,
} from '../../lib/findingExplanation';
import { SeverityIndicator } from './FindingIndicators';
import { useAnalysis } from '../../context/AnalysisContext';
import { entryFilename } from '../../lib/screenshotManifest';
import { illustratedByEvidenceId } from '../../lib/visualEvidence';
import VisualEvidenceCard from './VisualEvidenceCard';
import ScreenshotLightbox from './ScreenshotLightbox';

function ExplainSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="border-t border-slate-100 pt-4 first:border-0 first:pt-0">
      <h3 className="text-[10px] font-bold uppercase tracking-[0.12em] text-slate-500 mb-2">{title}</h3>
      <div className="text-[13px] text-slate-700 leading-relaxed">{children}</div>
    </section>
  );
}

function CollapsibleBlock({
  title,
  defaultOpen = false,
  children,
}: {
  title: string;
  defaultOpen?: boolean;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border-t border-slate-100 pt-3">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1.5 text-left text-[12px] font-semibold text-slate-800 hover:text-slate-900"
      >
        {open ? <ChevronDown className="h-3.5 w-3.5 text-slate-400" /> : <ChevronRight className="h-3.5 w-3.5 text-slate-400" />}
        {title}
      </button>
      {open && <div className="mt-2">{children}</div>}
    </div>
  );
}

export default function EvidenceDrawer({
  data,
  bundle,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle;
}) {
  const { drawerEvidenceId, closeEvidence } = useInvestigationUI();
  const { screenshotManifestEntries } = useAnalysis();
  const [lightbox, setLightbox] = useState<string | null>(null);
  const [thumb, setThumb] = useState<string | null>(null);
  const [artifactsOpen, setArtifactsOpen] = useState(false);

  const evidence = drawerEvidenceId ? findEvidenceById(bundle, drawerEvidenceId) : undefined;

  useEffect(() => {
    setArtifactsOpen(false);
  }, [drawerEvidenceId]);

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

  useEffect(() => {
    if (!drawerEvidenceId) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') closeEvidence();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [drawerEvidenceId, closeEvidence]);

  if (!drawerEvidenceId) return null;

  const explanation = evidence ? buildFindingExplanation(evidence, data) : null;
  const headline = evidence ? findingHeadline(evidence) : null;
  const artifacts = evidence?.artifactRefs ?? [];
  const visualEntries = drawerEvidenceId
    ? illustratedByEvidenceId(drawerEvidenceId, screenshotManifestEntries)
    : [];
  const sourceLabel = evidence ? sourceDisplayLabel(evidence) : '';

  return (
    <>
      <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true">
        <div className="absolute inset-0 bg-slate-900/40" onClick={closeEvidence} aria-hidden />
        <div className="relative w-full max-w-md sm:max-w-lg bg-white h-full shadow-2xl border-l border-slate-200 flex flex-col min-w-0">
          <div className="px-5 py-4 border-b border-slate-200 shrink-0">
            <div className="flex justify-between items-start gap-3">
              <div className="min-w-0">
                <h2 className="text-[11px] font-bold uppercase tracking-[0.14em] text-slate-500">Evidence</h2>
                <p className="font-mono text-[12px] text-slate-600 mt-1">{drawerEvidenceId}</p>
              </div>
              <button
                type="button"
                onClick={closeEvidence}
                className="p-1.5 rounded-md hover:bg-slate-100 shrink-0"
                aria-label="Close evidence panel"
              >
                <X className="h-4 w-4 text-slate-600" />
              </button>
            </div>

            {evidence && explanation && headline && (
              <div className="mt-4 space-y-3">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
                  <SeverityIndicator severity={evidence.severity} />
                  <span className="text-slate-300" aria-hidden>|</span>
                  <div>
                    <span className="text-[15px] font-semibold text-slate-900 tabular-nums leading-none">
                      {evidence.confidence}%
                    </span>
                    <p className="text-[11px] text-slate-600 mt-0.5">{explanation.confidenceTierLabel}</p>
                    <p className="text-[10px] text-slate-400">Verified evidence</p>
                  </div>
                  <span className="text-[10px] font-bold uppercase tracking-wide text-slate-500 ml-auto sm:ml-0">
                    {sourceLabel}
                  </span>
                </div>
                <div>
                  <p className="text-[15px] font-semibold text-slate-900 leading-snug">{headline.title}</p>
                  {headline.subtitle && (
                    <p className="text-[13px] text-slate-600 mt-1 leading-relaxed">{headline.subtitle}</p>
                  )}
                </div>
              </div>
            )}
          </div>

          {evidence && explanation ? (
            <div className="flex-1 overflow-y-auto overflow-x-hidden px-5 py-4 space-y-0 min-h-0">
              <ExplainSection title="What was found">{explanation.whatWasFound}</ExplainSection>
              <ExplainSection title="Why does this matter?">{explanation.whyItMatters}</ExplainSection>
              <ExplainSection title="How serious is it?">{explanation.severityExplanation}</ExplainSection>
              <ExplainSection title="What does the evidence show?">{explanation.evidenceInterpretation}</ExplainSection>

              <section className="border-t border-slate-100 pt-4">
                <h3 className="text-[10px] font-bold uppercase tracking-[0.12em] text-slate-500 mb-2">
                  Where was it found?
                </h3>
                <p className="text-[13px] text-slate-700 leading-relaxed">{explanation.artifactIntro}</p>
                {artifacts.length > 0 && (
                  <div className="mt-3">
                    <button
                      type="button"
                      onClick={() => setArtifactsOpen((v) => !v)}
                      className="flex items-center gap-1.5 text-[12px] font-semibold text-slate-800 hover:text-slate-900"
                    >
                      {artifactsOpen ? (
                        <ChevronDown className="h-3.5 w-3.5 text-slate-400" />
                      ) : (
                        <ChevronRight className="h-3.5 w-3.5 text-slate-400" />
                      )}
                      View affected artifacts ({artifacts.length})
                    </button>
                    {artifactsOpen && (
                      <ul className="mt-2 space-y-1.5 pl-1">
                        {artifacts.map((a) => (
                          <li key={a} className="font-mono text-[11px] text-slate-600 break-all">{a}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
              </section>

              <ExplainSection title="What should I do?">{explanation.recommendedAction}</ExplainSection>

              {visualEntries.length > 0 && (
                <section className="border-t border-slate-100 pt-4 space-y-2">
                  <h3 className="text-[10px] font-bold uppercase tracking-[0.12em] text-slate-500">
                    Visual evidence
                  </h3>
                  {visualEntries.map((entry) => (
                    <VisualEvidenceCard
                      key={entry.screenshot_id}
                      sha256={data.sha256}
                      entry={entry}
                      onExpand={() => setLightbox(entryFilename(entry))}
                    />
                  ))}
                </section>
              )}

              {evidence.screenshotRef && visualEntries.length === 0 && (
                <section className="border-t border-slate-100 pt-4">
                  <h3 className="text-[10px] font-bold uppercase tracking-[0.12em] text-slate-500 mb-2">
                    Runtime screenshot
                  </h3>
                  {thumb ? (
                    <button type="button" onClick={() => setLightbox(evidence.screenshotRef!)}>
                      <img src={thumb} alt="" className="w-full max-w-[12rem] rounded-md border border-slate-200" />
                    </button>
                  ) : (
                    <span className="text-[13px] text-slate-500">Loading preview…</span>
                  )}
                </section>
              )}

              {evidence.hookNames && evidence.hookNames.length > 0 && (
                <section className="border-t border-slate-100 pt-4">
                  <h3 className="text-[10px] font-bold uppercase tracking-[0.12em] text-slate-500 mb-2">
                    Runtime hooks
                  </h3>
                  <ul className="space-y-1">
                    {evidence.hookNames.map((hook) => (
                      <li key={hook} className="font-mono text-[11px] text-slate-600 break-all">{hook}</li>
                    ))}
                  </ul>
                </section>
              )}

              <CollapsibleBlock title="Technical details">
                <dl className="grid grid-cols-1 gap-2 text-[12px]">
                  <div>
                    <dt className="text-slate-500">Finding ID</dt>
                    <dd className="font-mono text-slate-800">{evidence.id}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">Source</dt>
                    <dd className="text-slate-800">{evidence.sourceEngine}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">Category</dt>
                    <dd className="text-slate-800">{evidence.category}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">Confidence</dt>
                    <dd className="text-slate-800 tabular-nums">{evidence.confidence}%</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">Severity (raw)</dt>
                    <dd className="text-slate-800">{evidence.severity}</dd>
                  </div>
                  {evidence.contributionLabel && (
                    <div>
                      <dt className="text-slate-500">Score contribution</dt>
                      <dd className="text-slate-800">{evidence.contributionLabel}</dd>
                    </div>
                  )}
                  {evidence.runtimeSubcategory && (
                    <div>
                      <dt className="text-slate-500">Runtime subcategory</dt>
                      <dd className="text-slate-800">{evidence.runtimeSubcategory}</dd>
                    </div>
                  )}
                  <div>
                    <dt className="text-slate-500">Artifact count</dt>
                    <dd className="text-slate-800 tabular-nums">{artifacts.length}</dd>
                  </div>
                  {evidence.mitreId && (
                    <div>
                      <dt className="text-slate-500">MITRE</dt>
                      <dd className="font-mono text-slate-800">
                        {evidence.mitreId}
                        {evidence.mitreName ? ` — ${evidence.mitreName}` : ''}
                      </dd>
                    </div>
                  )}
                  <div>
                    <dt className="text-slate-500">Raw finding title</dt>
                    <dd className="text-slate-800">{evidence.title}</dd>
                  </div>
                  {evidence.description?.trim() && (
                    <div>
                      <dt className="text-slate-500">Raw description</dt>
                      <dd className="text-slate-800 leading-relaxed">{evidence.description.trim()}</dd>
                    </div>
                  )}
                </dl>
                {artifacts.length > 0 && (
                  <div className="mt-3">
                    <p className="text-[11px] font-semibold text-slate-500 mb-1">Artifact paths</p>
                    <ul className="space-y-1">
                      {artifacts.map((a) => (
                        <li key={a} className="font-mono text-[10px] text-slate-600 break-all">{a}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </CollapsibleBlock>

              <p className="text-[11px] text-slate-400 pt-4 border-t border-slate-100 mt-4 leading-relaxed">
                {explanation.confidenceTierExplanation}
              </p>
            </div>
          ) : (
            <div className="p-5 text-sm text-slate-500">
              No structured record for this ID. Check ledger lines or related findings in the registry.
            </div>
          )}
        </div>
      </div>
      {lightbox && evidence && (
        <ScreenshotLightbox
          sha256={data.sha256}
          entries={[
            {
              screenshot_id: 'EVIDENCE',
              filename: lightbox,
              label: evidence.title || 'Evidence screenshot',
            },
          ]}
          index={0}
          onClose={() => setLightbox(null)}
          onIndexChange={() => {}}
        />
      )}
    </>
  );
}
