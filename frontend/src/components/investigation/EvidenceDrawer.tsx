import { useEffect, useState, type ReactNode } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import type { FraudCardData } from '../../App';
import { findEvidenceById } from '../../hooks/useInvestigationModel';
import type { InvestigationBundle } from '../../types/investigation';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import DrawerShell from '../ui/DrawerShell';
import { fetchScreenshotBlob } from '../../lib/screenshots';
import { TYPOGRAPHY } from '../../theme/typography';
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
      <h3 className={`${TYPOGRAPHY.label} mb-2`}>{title}</h3>
      <div className={TYPOGRAPHY.bodySmall}>{children}</div>
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
        className={`flex items-center gap-1.5 text-left ${TYPOGRAPHY.buttonSm} text-slate-800 hover:text-slate-900`}
      >
        {open ? <ChevronDown className="h-3.5 w-3.5 text-slate-500" /> : <ChevronRight className="h-3.5 w-3.5 text-slate-500" />}
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
  const { drawerEvidenceId, closeEvidence, canGoBack } = useInvestigationUI();
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
      <DrawerShell
        open
        onClose={closeEvidence}
        onBack={canGoBack ? closeEvidence : undefined}
        title="Evidence"
        subtitle={<span className={TYPOGRAPHY.codeSm}>{drawerEvidenceId}</span>}
        labelledById="evidence-drawer-title"
        headerExtra={
          evidence && explanation && headline ? (
            <div className="mt-4 space-y-3">
              <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
                <SeverityIndicator severity={evidence.severity} />
                <span className="text-slate-300" aria-hidden>|</span>
                <div>
                  <span className={`${TYPOGRAPHY.h2} tabular-nums leading-none`}>
                    {evidence.confidence}%
                  </span>
                  <p className={`${TYPOGRAPHY.caption} font-medium mt-0.5`}>
                    {explanation.confidenceTierLabel}
                  </p>
                  <p className={TYPOGRAPHY.caption}>Verified evidence</p>
                </div>
                <span className={`${TYPOGRAPHY.label} ml-auto sm:ml-0`}>{sourceLabel}</span>
              </div>
              <div>
                <p className={`${TYPOGRAPHY.h3} leading-snug`}>{headline.title}</p>
                {headline.subtitle && (
                  <p className={`${TYPOGRAPHY.bodySmall} mt-1`}>{headline.subtitle}</p>
                )}
              </div>
            </div>
          ) : null
        }
      >
          {evidence && explanation ? (
            <div className="space-y-0 min-w-0">
              <ExplainSection title="What was found">{explanation.whatWasFound}</ExplainSection>
              <ExplainSection title="Why does this matter?">{explanation.whyItMatters}</ExplainSection>
              <ExplainSection title="How serious is it?">{explanation.severityExplanation}</ExplainSection>
              <ExplainSection title="What does the evidence show?">{explanation.evidenceInterpretation}</ExplainSection>

              <section className="border-t border-slate-100 pt-4">
                <h3 className={`${TYPOGRAPHY.label} mb-2`}>
                  Where was it found?
                </h3>
                <p className={TYPOGRAPHY.bodySmall}>{explanation.artifactIntro}</p>
                {artifacts.length > 0 && (
                  <div className="mt-3">
                    <button
                      type="button"
                      onClick={() => setArtifactsOpen((v) => !v)}
                      className={`flex items-center gap-1.5 ${TYPOGRAPHY.buttonSm} text-slate-800 hover:text-slate-900`}
                    >
                      {artifactsOpen ? (
                        <ChevronDown className="h-3.5 w-3.5 text-slate-500" />
                      ) : (
                        <ChevronRight className="h-3.5 w-3.5 text-slate-500" />
                      )}
                      View affected artifacts ({artifacts.length})
                    </button>
                    {artifactsOpen && (
                      <ul className="mt-2 space-y-1.5 pl-1">
                        {artifacts.map((a) => (
                          <li key={a} className={`${TYPOGRAPHY.codeSm} break-all`}>{a}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
              </section>

              <ExplainSection title="What should I do?">{explanation.recommendedAction}</ExplainSection>

              {visualEntries.length > 0 && (
                <section className="border-t border-slate-100 pt-4 space-y-2">
                  <h3 className={TYPOGRAPHY.label}>
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
                  <h3 className={`${TYPOGRAPHY.label} mb-2`}>
                    Runtime screenshot
                  </h3>
                  {thumb ? (
                    <button type="button" onClick={() => setLightbox(evidence.screenshotRef!)}>
                      <img src={thumb} alt="" className="w-full max-w-[12rem] rounded-md border border-slate-200" />
                    </button>
                  ) : (
                    <span className={TYPOGRAPHY.caption}>Loading preview…</span>
                  )}
                </section>
              )}

              {evidence.hookNames && evidence.hookNames.length > 0 && (
                <section className="border-t border-slate-100 pt-4">
                  <h3 className={`${TYPOGRAPHY.label} mb-2`}>
                    Runtime hooks
                  </h3>
                  <ul className="space-y-1">
                    {evidence.hookNames.map((hook) => (
                      <li key={hook} className={`${TYPOGRAPHY.codeSm} break-all`}>{hook}</li>
                    ))}
                  </ul>
                </section>
              )}

              <CollapsibleBlock title="Technical details">
                <dl className="grid grid-cols-1 gap-2 text-[14px]">
                  <div>
                    <dt className={TYPOGRAPHY.caption}>Finding ID</dt>
                    <dd className={TYPOGRAPHY.codeSm}>{evidence.id}</dd>
                  </div>
                  <div>
                    <dt className={TYPOGRAPHY.caption}>Source</dt>
                    <dd className={TYPOGRAPHY.bodySmall}>{evidence.sourceEngine}</dd>
                  </div>
                  <div>
                    <dt className={TYPOGRAPHY.caption}>Category</dt>
                    <dd className={TYPOGRAPHY.bodySmall}>{evidence.category}</dd>
                  </div>
                  <div>
                    <dt className={TYPOGRAPHY.caption}>Confidence</dt>
                    <dd className={`${TYPOGRAPHY.bodySmall} tabular-nums`}>{evidence.confidence}%</dd>
                  </div>
                  <div>
                    <dt className={TYPOGRAPHY.caption}>Severity (raw)</dt>
                    <dd className={TYPOGRAPHY.bodySmall}>{evidence.severity}</dd>
                  </div>
                  {evidence.contributionLabel && (
                    <div>
                      <dt className={TYPOGRAPHY.caption}>Score contribution</dt>
                      <dd className={TYPOGRAPHY.bodySmall}>{evidence.contributionLabel}</dd>
                    </div>
                  )}
                  {evidence.runtimeSubcategory && (
                    <div>
                      <dt className={TYPOGRAPHY.caption}>Runtime subcategory</dt>
                      <dd className={TYPOGRAPHY.bodySmall}>{evidence.runtimeSubcategory}</dd>
                    </div>
                  )}
                  <div>
                    <dt className={TYPOGRAPHY.caption}>Artifact count</dt>
                    <dd className={`${TYPOGRAPHY.bodySmall} tabular-nums`}>{artifacts.length}</dd>
                  </div>
                  {evidence.mitreId && (
                    <div>
                      <dt className={TYPOGRAPHY.caption}>MITRE</dt>
                      <dd className={TYPOGRAPHY.codeSm}>
                        {evidence.mitreId}
                        {evidence.mitreName ? ` - ${evidence.mitreName}` : ''}
                      </dd>
                    </div>
                  )}
                  <div>
                    <dt className={TYPOGRAPHY.caption}>Raw finding title</dt>
                    <dd className={TYPOGRAPHY.bodySmall}>{evidence.title}</dd>
                  </div>
                  {evidence.description?.trim() && (
                    <div>
                      <dt className={TYPOGRAPHY.caption}>Raw description</dt>
                      <dd className={TYPOGRAPHY.bodySmall}>{evidence.description.trim()}</dd>
                    </div>
                  )}
                </dl>
                {artifacts.length > 0 && (
                  <div className="mt-3">
                    <p className={`${TYPOGRAPHY.label} mb-1`}>Artifact paths</p>
                    <ul className="space-y-1">
                      {artifacts.map((a) => (
                        <li key={a} className={`${TYPOGRAPHY.codeSm} break-all`}>{a}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </CollapsibleBlock>

              <p className={`${TYPOGRAPHY.caption} pt-4 border-t border-slate-100 mt-4`}>
                {explanation.confidenceTierExplanation}
              </p>
            </div>
          ) : (
            <div className={TYPOGRAPHY.bodySmall}>
              No structured record for this ID. Check ledger lines or related findings in the registry.
            </div>
          )}
      </DrawerShell>
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
