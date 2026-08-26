import { Database, Info } from 'lucide-react';
import type { IntelApiPayload } from '../../lib/threatIntelModel';
import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import { IntelCard, IntelCardBody, IntelSectionHeader } from './IntelCard';
import { INTEL } from './intelTokens';
import { TYPOGRAPHY } from '../../theme/typography';

/**
 * Which sources actually looked at this sample, and what each one said.
 *
 * This panel previously derived its own three-state status from result counts
 * and never read `sources_status`, the field the backend computes for exactly
 * this purpose. The consequence was the failure mode the platform's safety
 * model specifically forbids: an external feed that was never queried - because
 * no API key is configured - rendered as
 *
 *     VirusTotal - Unavailable - "VirusTotal lookup not available"
 *
 * beside an IOC row reading "No indicators matched external feeds". Both are
 * assertions about the sample. Neither was earned: nobody asked.
 *
 * The vocabulary now separates the three things that were collapsed together:
 *
 *   matched      we asked, and it found something
 *   clean        we asked, and it found nothing            <- a real result
 *   not queried  we never asked                            <- not a result
 *   error        we asked and the lookup failed            <- not a result
 *
 * and the panel says so in a footer when any source falls in the last two, so
 * a reader cannot mistake an unasked question for a clean answer.
 */

type SourceState = 'matched' | 'clean' | 'not_queried' | 'error';

type IntelSourceRow = {
  name: string;
  state: SourceState;
  detail: string;
  /** True for SUDARSHAN's own engines, which have no external dependency. */
  internal?: boolean;
};

/** Map the backend's own status vocabulary onto ours. */
function stateFromBackend(status: string | undefined, matched: boolean): SourceState {
  switch (status) {
    case 'active':
      return matched ? 'matched' : 'clean';
    case 'no_match':
      return 'clean';
    case 'missing_key':
      return 'not_queried';
    case 'error':
      return 'error';
    default:
      // An unrecognised status is not evidence of anything. Reporting it as
      // clean would be the original defect in a new place.
      return 'not_queried';
  }
}

function findStatus(intel: IntelApiPayload, ...names: string[]) {
  const lowered = names.map((n) => n.toLowerCase());
  return (intel.sources_status ?? []).find((s) =>
    lowered.some((n) => (s.name || '').toLowerCase().includes(n)),
  );
}

function buildSources(
  data: FraudCardData,
  intel: IntelApiPayload,
  bundle: InvestigationBundle | null,
): IntelSourceRow[] {
  const rows: IntelSourceRow[] = [];

  // ── SUDARSHAN's own engines ────────────────────────────────────────────
  const staticFindings =
    (data.manifest_findings?.length || 0) + (data.code_findings?.length || 0);
  rows.push({
    name: 'Static analysis',
    internal: true,
    state: staticFindings > 0 ? 'matched' : 'clean',
    detail:
      staticFindings > 0
        ? `${staticFindings} manifest and code findings`
        : 'Ran; no static findings raised',
  });

  const runtimeCount = bundle?.counts.runtimeBehaviors ?? 0;
  rows.push({
    name: 'Runtime analysis',
    internal: true,
    state: !data.dynamic_available ? 'not_queried' : runtimeCount > 0 ? 'matched' : 'clean',
    detail: !data.dynamic_available
      ? 'Sandbox did not run for this case'
      : runtimeCount > 0
        ? `${runtimeCount} runtime behaviours recorded`
        : 'Sandbox ran; no behaviour signals recorded',
  });

  const mitreCount = data.intelligence_report?.mitre_techniques_used?.length || 0;
  rows.push({
    name: 'MITRE ATT&CK mapping',
    internal: true,
    state: mitreCount > 0 ? 'matched' : 'clean',
    detail: mitreCount > 0 ? `${mitreCount} techniques mapped` : 'No techniques mapped',
  });

  const family = intel.malware_family || data.family_classification;
  const familyMatched = Boolean(family && family !== 'Unknown');
  rows.push({
    name: 'Family classification',
    internal: true,
    state: familyMatched ? 'matched' : 'clean',
    detail: familyMatched ? `Matched as ${family}` : 'Rules ran; no family confirmed',
  });

  // ── External feeds, reported from the backend's own status ─────────────
  const vt = intel.virus_total;
  const vtStatus = findStatus(intel, 'virustotal', 'virus total');
  const vtState = stateFromBackend(vtStatus?.status, (vt?.malicious ?? 0) > 0);
  rows.push({
    name: 'VirusTotal',
    state: vtState,
    detail:
      vtState === 'matched'
        ? `${vt?.malicious} of ${vt?.total} vendors flagged this file`
        : vtState === 'clean'
          ? `Queried; 0 of ${vt?.total || 0} vendors flagged this file`
          : vtStatus?.message || 'Not queried - no API key configured',
  });

  const otx = intel.alienvault;
  const otxStatus = findStatus(intel, 'alienvault', 'otx');
  const otxState = stateFromBackend(otxStatus?.status, (otx?.pulse_count ?? 0) > 0);
  rows.push({
    name: 'AlienVault OTX',
    state: otxState,
    detail:
      otxState === 'matched'
        ? `${otx?.pulse_count} pulse${otx?.pulse_count === 1 ? '' : 's'}${
            otx?.campaign && otx.campaign !== 'None' ? ` · ${otx.campaign}` : ''
          }`
        : otxState === 'clean'
          ? 'Queried; no pulses reference this sample'
          : otxStatus?.message || 'Not queried - no API key configured',
  });

  const abuse = intel.abuseipdb;
  const abuseStatus = findStatus(intel, 'abuseipdb', 'abuse');
  const abuseState = stateFromBackend(abuseStatus?.status, (abuse?.reports ?? 0) > 0);
  rows.push({
    name: 'AbuseIPDB',
    state: abuseState,
    detail:
      abuseState === 'matched'
        ? `${abuse?.reports} report${abuse?.reports === 1 ? '' : 's'} against contacted infrastructure`
        : abuseState === 'clean'
          ? 'Queried; no reports against contacted infrastructure'
          : abuseStatus?.message || 'Not queried - no API key configured',
  });

  return rows;
}

const STATE_LABEL: Record<SourceState, string> = {
  matched: 'Match',
  clean: 'No match',
  not_queried: 'Not queried',
  error: 'Lookup failed',
};

const STATE_BADGE: Record<SourceState, string> = {
  matched: 'bg-blue-50 text-blue-800 border-blue-200',
  clean: 'bg-slate-50 text-slate-700 border-slate-200',
  // Slate and dashed: an unasked question is neither good news nor bad, and
  // must not be mistaken for the "No match" above it.
  not_queried: 'bg-white text-slate-500 border-slate-300 border-dashed',
  error: 'bg-amber-50 text-amber-800 border-amber-200',
};

export default function IntelligenceSourcesPanel({
  intel,
  data,
  bundle,
}: {
  intel: IntelApiPayload;
  data: FraudCardData;
  bundle: InvestigationBundle | null;
}) {
  const sources = buildSources(data, intel, bundle);
  const unqueried = sources.filter((s) => s.state === 'not_queried' || s.state === 'error');
  const queried = sources.length - unqueried.length;

  return (
    <IntelCard>
      <IntelSectionHeader
        icon={<Database className="h-4 w-4" />}
        title="Intelligence sources"
        subtitle={`${queried} of ${sources.length} sources returned a result for this sample`}
      />
      <IntelCardBody compact>
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {sources.map((s) => (
            <div
              key={s.name}
              className="rounded-lg border border-slate-200 bg-white p-4 flex flex-col gap-2"
            >
              <div className="flex items-center justify-between gap-2">
                <span className={TYPOGRAPHY.h3}>{s.name}</span>
                <span
                  className={`text-[13px] font-semibold uppercase tracking-[0.06em] px-2 py-0.5 rounded border shrink-0 ${
                    STATE_BADGE[s.state]
                  }`}
                >
                  {STATE_LABEL[s.state]}
                </span>
              </div>
              <p className={`${INTEL.caption} leading-relaxed`}>{s.detail}</p>
            </div>
          ))}
        </div>

        {/*
          The caveat that makes the grid above honest. Without it, a reader
          scanning six "No match" badges and one "Not queried" has no reason to
          treat them differently - and the difference is the whole point.
        */}
        {unqueried.length > 0 && (
          <p
            className={`${TYPOGRAPHY.bodySmall} flex items-start gap-2 mt-4 pt-3 border-t border-slate-200 max-w-[80ch]`}
          >
            <Info className="h-3.5 w-3.5 shrink-0 mt-0.5 text-slate-400" aria-hidden />
            <span>
              {unqueried.length} source{unqueried.length === 1 ? '' : 's'} returned no result
              because {unqueried.length === 1 ? 'it was' : 'they were'} not queried, not because
              the sample was found to be clean.{' '}
              <strong className="font-semibold text-slate-900">
                Absence of a match from an unqueried source is not evidence of safety.
              </strong>
            </span>
          </p>
        )}
      </IntelCardBody>
    </IntelCard>
  );
}
