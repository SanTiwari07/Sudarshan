import { useState, type ReactNode } from 'react';
import { motion } from 'motion/react';
import { Link } from 'react-router-dom';
import {
  Terminal, Cpu, Search, Lock, Code, Package,
  ChevronDown, ChevronUp, ChevronRight, Shield, Globe, AlertTriangle, Database, Tag, Key
} from 'lucide-react';
import { TYPOGRAPHY } from '../theme/typography';
import { caseSectionPath } from '../lib/caseRoutes';
import type { FraudCardData } from '../types/case';
import VisualImpersonationPanel from '../components/investigation/VisualImpersonationPanel';
import VisualDiffViewer from '../components/investigation/VisualDiffViewer';
import OverlayEvidenceViewer from '../components/investigation/OverlayEvidenceViewer';
import SocCard from '../components/ui/Card';
import SectionHeader from '../components/ui/SectionHeader';
import CopyButton from '../components/ui/CopyButton';
import EvidenceRegistrySection from '../components/investigation/EvidenceRegistrySection';
import ScreenshotGallery from '../components/investigation/ScreenshotGallery';
import DynamicAnalysisSummary from '../components/investigation/DynamicAnalysisSummary';
import ResiliencePanel from '../components/investigation/ResiliencePanel';
import type { AntiEvasionResult } from '../lib/resilience';
import HelpTerm from '../components/investigation/HelpTerm';
import {
  resolveRuntimeDynamicStatus,
  runtimeStatusHeadline,
} from '../lib/investigationRuntime';
import { useAnalysis } from '../context/AnalysisContext';
import { useRuntimeScreenshots } from '../hooks/useRuntimeScreenshots';
import EvidenceSection from '../components/ui/EvidenceSection';
import AnalysisTabs, { type AnalysisTab } from '../components/investigation/AnalysisTabs';
import ActivitySummary from '../components/investigation/ActivitySummary';
import RelationsGraph from '../components/investigation/RelationsGraph';
import SecondaryApkPanel from '../components/investigation/SecondaryApkPanel';
import MitreMatrix from '../components/investigation/MitreMatrix';
import AskAiPopover from '../components/investigation/AskAiPopover';

/**
 * Panel-level open state.
 *
 * These are lookup tables - permissions, exported components, trackers, raw
 * strings. They are the answer to a question the analyst has already decided
 * to ask.
 *
 * That deferral now belongs to the EvidenceSection wrapping each panel, which
 * owns the disclosure and carries the row count on its header. Leaving the
 * inner collapse in place as well meant opening a section revealed a second
 * collapsed header - two clicks to reach one table, and the outer count
 * promising content the panel then hid.
 *
 * Kept as a hook rather than deleted so the panels keep their existing
 * open/close control for a reader who wants to fold one table away without
 * closing the whole section.
 */
function useRowAccordion(_rowCount: number) {
  return useState(true);
}

// ─── Explainability Engine ────────────────────────────────────────────────────────

/**
 * One titled group inside the overview.
 *
 * The overview had no headings at all: a chip row, then a grid of numbers,
 * then a card, then a table, each in its own box at the same visual weight and
 * with nothing saying what any of them was for. That is what made the page read
 * as generated - the reader has to infer the structure, so there isn't one.
 *
 * The heading sits *outside* the panel rather than in another bordered header,
 * which is what stops this becoming a fourth nested box. The numbered eyebrow
 * is load-bearing: these three groups are a sequence (what we saw → what we
 * concluded → what backs it up), so numbering them tells the reader where the
 * conclusion came from rather than just decorating the column.
 */
/*
 * What a tab holds, before its tables do.
 *
 * Every evidence tab opened straight into the first accordion, so a reader
 * arriving at "Static" met a permissions table with no statement of how much
 * static evidence there was in total. These are the same counts the sections
 * below already carry on their headers, lifted to the top of the tab and
 * given the shape used on the overview - so the tab announces its own size,
 * and each figure links to the section it came from.
 *
 * Counts only, never derived rates: a tab summary that computes something the
 * evidence does not state is a finding invented by the layout.
 */
function TabSummary({
  items,
}: {
  items: { label: string; value: number; anchor: string; context: string }[];
}) {
  const present = items.filter((i) => i.value > 0);
  if (present.length === 0) return null;

  return (
    <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-4">
      {present.map((item) => (
        <a
          key={item.label}
          href={`#${item.anchor}`}
          className="group block rounded-xl border border-slate-200 bg-white p-4 text-left shadow-[0_1px_2px_rgba(0,0,0,0.02)] transition-[transform,border-color,box-shadow] duration-150 hover:-translate-y-0.5 hover:border-slate-300 hover:shadow-[0_4px_12px_rgba(15,23,42,0.06)] active:translate-y-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
        >
          <span className={`${TYPOGRAPHY.label} block`}>{item.label}</span>
          <span className="mt-2 block text-[30px] font-semibold leading-none tabular-nums tracking-[-0.03em] text-slate-900">
            {item.value}
          </span>
          <span className="mt-2 block text-[13px] leading-tight tracking-[0.01em] text-slate-500">
            {item.context}
          </span>
        </a>
      ))}
    </div>
  );
}

function OverviewGroup({
  eyebrow,
  title,
  blurb,
  children,
}: {
  eyebrow: string;
  title: string;
  /**
   * One sentence, in plain language, saying what the panel below is.
   *
   * Optional so a group with a self-evident heading can omit it - but the
   * overview groups all set it deliberately. A heading alone tells an analyst
   * who already knows the product what a panel is; it tells a bank manager
   * reading a verdict nothing. This is the line that makes the page work for
   * both readers, so it is content, not decoration.
   */
  blurb?: string;
  children: ReactNode;
}) {
  /*
   * The step and its content are one card, not a floating heading above a box.
   *
   * The three headings sat naked on the page while everything they introduced
   * was boxed, so the page read as loose captions with unrelated panels under
   * them - nothing said which heading owned which box, and the eye had to
   * infer it from vertical order alone. Putting the heading inside the surface
   * it describes is what makes a step a step.
   */
  return (
    <section className="flex h-full flex-col rounded-[var(--card-radius)] border border-slate-200 bg-white p-5 shadow-[var(--card-elevation)] sm:p-6">
      <div className="space-y-1">
        {/*
          Sentence case, and slate rather than blue. Uppercase is reserved for
          badges in this product, and blue is the colour of things you can
          press - "Step 1" is neither, so it was reading as a link shouting at
          the heading directly beneath it.
        */}
        <p className="font-sans text-[13px] font-medium tracking-[0.01em] text-slate-500">
          {eyebrow}
        </p>
        <h2 className={`${TYPOGRAPHY.h2} text-[22px]`}>{title}</h2>
        {blurb && <p className={`${TYPOGRAPHY.helper} max-w-[68ch]`}>{blurb}</p>}
      </div>
      <div className="mt-5 min-w-0 flex-1">{children}</div>
    </section>
  );
}

/**
 * What the rules engine called this sample, and on what grounds.
 *
 * Previously a card containing two bordered grey boxes, each containing a
 * third bordered box - three nested surfaces to deliver two short strings, and
 * no relationship shown between them. Worse, the two could contradict each
 * other in silence: a classification of `trojan.rewardsteal` sat directly
 * above "No specific family signature matched", and the reader was left to
 * work out which one to believe.
 *
 * They are one fact, so they read as one sentence: the label, then the grounds
 * for it. When no rule matched, that is said plainly instead of being printed
 * as a second finding of equal weight.
 */
function ExplainabilityEngine({ data }: { data: FraudCardData }) {
  const family = data.family_classification;
  const isNamed = Boolean(family) && family !== 'Unknown';
  const rule = data.technical_view.matched_rule?.trim();

  // The engine writes prose here when nothing fired, so a rule that names no
  // rule is the "unmatched" case however it happens to be worded.
  const matched = Boolean(rule) && !/^no\b/i.test(rule ?? '');

  return (
    /*
      No card of its own: it is the body of the "What the engine concluded"
      step, and that step is already a surface. A SocCard here put a bordered
      panel inside a bordered panel to deliver one label and one sentence.
    */
    <div>
      <SectionHeader
        icon={<Cpu className="h-4 w-4" />}
        title="Classification"
      />
      <div className="space-y-3 pt-4">
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <span
            className={`text-xl font-semibold tracking-[-0.01em] ${
              isNamed ? 'text-slate-900' : 'text-slate-500'
            }`}
          >
            {isNamed ? family : 'No family assigned'}
          </span>
          <span
            className={`${TYPOGRAPHY.badge} ${
              matched
                ? 'border-slate-300 bg-slate-100 text-slate-700'
                : 'border-amber-300 bg-amber-50 text-amber-800'
            }`}
          >
            {matched ? 'Rule matched' : 'No rule matched'}
          </span>
        </div>

        {!matched && (
          <p className={TYPOGRAPHY.bodySmall}>
            No signature fired, so this label is a provisional grouping, not an
            attribution.
          </p>
        )}

        {matched && (
          <p className="font-mono text-[15px] text-slate-700 bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 leading-relaxed break-words">
            {rule}
          </p>
        )}
      </div>
    </div>
  );
}

// ─── APK Metadata ────────────────────────────────────────────────────────────────

function APKMetadata({ data }: { data: FraudCardData }) {
  const rows = [
    { label: 'Package Name', value: data.package_name || 'Unknown', mono: true },
    { label: 'SHA-256 Hash', value: data.sha256, mono: true, truncate: true, copy: data.sha256 },
    { label: 'Total Permissions', value: `${data.all_permissions.length}`, mono: false },
    { label: 'Critical Permissions', value: `${data.technical_view.permissions_fired.length}`, mono: false, highlight: data.technical_view.permissions_fired.length > 0 },
    { label: 'Dangerous APIs', value: data.technical_view.apis_fired.length > 0 ? data.technical_view.apis_fired.join(', ') : 'None detected', mono: true },
    { label: 'Network Indicators', value: `${data.hardcoded_urls_ips.length} hardcoded URL(s)/IP(s)`, mono: false },
    { label: 'Banking Targeting', value: data.targets_indian_banks ? 'YES - Target Package Found' : 'No', mono: false, highlight: data.targets_indian_banks },
    { label: 'Final Score', value: `${data.final_risk_score.toFixed(2)} / 100`, mono: true, highlight: data.final_risk_score > 30 },
  ];

  return (
    <SocCard>
      <SectionHeader
        icon={<Package className="h-4 w-4" />}
        title="APK Technical Identifiers"
        subtitle="Package identity, hash, and scoring inputs"
      />
      <div className="px-3 py-1 bg-white">
        {rows.map(r => (
          <div
            key={r.label}
            className="grid grid-cols-1 sm:grid-cols-[minmax(9rem,28%)_1fr] gap-x-4 gap-y-0.5 py-1.5 border-b border-slate-150 last:border-0 hover:bg-slate-50/50 rounded px-1.5 -mx-1.5 transition-colors duration-100 items-center"
          >
            <span className="text-[13px] font-semibold text-slate-500">{r.label}</span>
            <div className="flex items-center gap-1.5 min-w-0">
              <span
                className={`text-xs min-w-0 ${r.mono ? 'font-mono' : ''} ${r.highlight ? 'text-red-700 font-semibold' : 'text-slate-800'} ${r.truncate ? 'truncate' : 'break-all'}`}
                title={r.truncate ? String(r.value) : undefined}
              >
                {r.value}
              </span>
              {r.copy && <CopyButton value={r.copy} />}
            </div>
          </div>
        ))}
      </div>
    </SocCard>
  );
}

// ─── Permission Analysis ──────────────────────────────────────────────────────────

function PermissionTable({ data }: { data: FraudCardData }) {
  const [filter, setFilter] = useState('');
  const perms = data.all_permissions.filter(
    (p) => typeof p === 'string' && p.toLowerCase().includes(filter.toLowerCase()),
  );
  const fired = new Set(data.technical_view.permissions_fired);

  return (
    <SocCard>
      <SectionHeader icon={<Lock className="h-4 w-4" />} title="Permission Analysis" subtitle={`${data.all_permissions.length} total permissions extracted`} />
      <div className="p-2 border-b border-slate-200 bg-slate-50/30">
        <div className="relative">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
          <input
            type="text"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter permissions..."
            className="w-full pl-7 pr-3 py-1 text-xs bg-white border border-slate-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>
      </div>
      <div className="soc-table-wrap !border-0 rounded-none max-h-72">
        <table className="soc-table text-xs">
          <thead>
            <tr>
              <th className="!bg-slate-50/80">Permission</th>
              <th className="text-right !bg-slate-50/80">Status</th>
            </tr>
          </thead>
          <tbody className="font-mono">
            {perms.map(p => {
              const isFired = fired.has(p);
              return (
                <tr key={p} className={isFired ? '!bg-red-50/40' : ''}>
                  <td className="break-all">{p}</td>
                  <td className="text-right">
                    {isFired ? (
                      <span className="inline-flex px-1.5 py-0.5 text-[13px] font-semibold bg-red-100 text-red-800 rounded-full border border-red-200/50 whitespace-nowrap">
                        CRITICAL
                      </span>
                    ) : (
                      <span className="text-slate-500">Normal</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </SocCard>
  );
}

// ─── Dangerous API Table ─────────────────────────────────────────────────────────

function DangerousAPITable({ data }: { data: FraudCardData }) {
  const apis = data.technical_view.apis_fired;

  return (
    <SocCard>
      <SectionHeader icon={<Code className="h-4 w-4" />} title="Dangerous API Detection" subtitle={`${apis.length} dangerous API(s) detected`} />
      {apis.length === 0 ? (
        <div className="p-6 text-center text-xs text-slate-500 font-mono">
          No dangerous Java/Android API invocations detected in DEX bytecode.
        </div>
      ) : (
        <div className="soc-table-wrap !border-0 rounded-none max-h-72">
          <table className="soc-table text-xs">
            <thead>
              <tr>
                <th className="!bg-slate-50/80">API Signature</th>
                <th className="text-right !bg-slate-50/80">Category</th>
              </tr>
            </thead>
            <tbody className="font-mono">
              {apis.map((api, i) => (
                <tr key={i} className="!bg-red-50/20">
                  <td className="break-all text-red-700 font-semibold">
                    <span className="inline-flex items-start gap-1">
                      {api}
                      <AskAiPopover value={api} kind="api" />
                    </span>
                  </td>
                  <td className="text-right">
                    <span className="inline-flex px-1.5 py-0.5 text-[13px] font-semibold bg-red-100 text-red-800 rounded-full border border-red-200/50 whitespace-nowrap">
                      DANGEROUS HOOK
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </SocCard>
  );
}

// ─── Digital Certificate & Signature Panel ─────────────────────────────────────────

function CertificatePanel({ certificate }: { certificate?: Record<string, any> }) {
  if (!certificate || Object.keys(certificate).length === 0) {
    return (
      <SocCard>
        <SectionHeader icon={<Lock className="h-4 w-4" />} title="Digital Certificate & Signature" subtitle="X.509 Cryptographic Identity" />
        <div className="p-6 text-center text-xs text-slate-500 font-mono">No certificate metadata available</div>
      </SocCard>
    );
  }

  const entries = Object.entries(certificate);

  return (
    <SocCard>
      <SectionHeader icon={<Lock className="h-4 w-4" />} title="Digital Certificate & Signature" subtitle="X.509 Cryptographic Identity & Attribution" />
      <div className="soc-table-wrap !border-0 rounded-none max-h-72">
        <table className="soc-table text-xs">
          <thead>
            <tr>
              <th className="!bg-slate-50/80 w-1/3">Property</th>
              <th className="!bg-slate-50/80 w-2/3">Value</th>
            </tr>
          </thead>
          <tbody className="font-mono">
            {entries.map(([k, v]) => (
              <tr key={k}>
                <td className="text-slate-500 capitalize">{k.replace(/_/g, ' ')}</td>
                <td className="break-all text-slate-800">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </SocCard>
  );
}

// ─── Decompilation & Static Enrichment Panel ───────────────────────────────────────

function DecompilationPanel({ data }: { data: FraudCardData }) {
  const apktool = (data as any).apktool_enrichment;
  const jadx = (data as any).jadx_enrichment;

  if (!apktool && !jadx) {
    return (
      <SocCard>
        <SectionHeader icon={<Code className="h-4 w-4" />} title="Static Decompilation Intelligence" subtitle="APKTool Resources & JADX Source Pattern Scanner" />
        <div className="p-4 text-center text-xs text-slate-500 font-mono">Decompilation enrichment data unavailable for this scan</div>
      </SocCard>
    );
  }

  return (
    <SocCard>
      <SectionHeader icon={<Code className="h-4 w-4" />} title="Static Decompilation Intelligence" subtitle="APKTool Resources & JADX Java Source Hits" />
      <div className="p-3 space-y-2.5 font-mono text-xs">
        {jadx?.fraud_class_hits?.length > 0 && (
          <div className="p-2.5 bg-red-50/50 border border-red-200 rounded-lg">
            <span className="font-sans text-[13px] font-medium tracking-[0.01em] text-red-800">JADX fraud classes found</span>
            <div className="mt-1 text-red-900 text-xs break-all leading-relaxed">{jadx.fraud_class_hits.join(', ')}</div>
          </div>
        )}
        {apktool?.decoded_manifest_xml && (
          <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-lg text-slate-700">
            <span className="font-sans text-[13px] font-medium tracking-[0.01em] text-slate-600">Decoded manifest excerpt</span>
            <pre className="mt-1 text-[13px] text-slate-600 overflow-x-auto whitespace-pre-wrap font-mono leading-normal bg-white p-2 border border-slate-150 rounded">
              {apktool.decoded_manifest_xml.slice(0, 300)}...
            </pre>
          </div>
        )}
      </div>
    </SocCard>
  );
}

// ─── Network Capture Panel ─────────────────────────────────────────────────────────

function NetworkCapturePanel({ networkLogs }: { networkLogs?: any[] }) {
  if (!networkLogs || networkLogs.length === 0) {
    return (
      <SocCard>
        <SectionHeader icon={<Terminal className="h-4 w-4" />} title="Network Capture & C2 Telemetry" subtitle="Runtime mitmproxy & PCAP logs" />
        <div className="p-6 text-center text-xs text-slate-500 font-mono">No dynamic network traffic captured</div>
      </SocCard>
    );
  }

  return (
    <SocCard>
      <SectionHeader icon={<Terminal className="h-4 w-4" />} title="Network Capture & C2 Telemetry" subtitle={`${networkLogs.length} network request(s) captured`} />
      <div className="soc-table-wrap !border-0 rounded-none max-h-72">
        <table className="soc-table text-xs">
          <thead>
            <tr>
              <th className="!bg-slate-50/80">Method</th>
              <th className="!bg-slate-50/80">Host / IP</th>
              <th className="!bg-slate-50/80">URL / Endpoint</th>
              <th className="text-right !bg-slate-50/80">Status</th>
            </tr>
          </thead>
          <tbody className="font-mono">
            {networkLogs.map((req, i) => (
              <tr key={i} className={req.is_suspicious ? '!bg-red-50/40' : ''}>
                <td className="font-semibold text-slate-900">{req.method || 'GET'}</td>
                <td className="break-all text-slate-700">{req.domain || req.ip || '-'}</td>
                <td className="max-w-[14rem] truncate text-slate-600" title={req.url || undefined}>{req.url || '-'}</td>
                <td className="text-right font-semibold tabular-nums text-slate-900">{req.response_status || 200}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </SocCard>
  );
}

// ─── Logcat Inspector Panel ─────────────────────────────────────────────────────────

function LogcatInspectorPanel({ logcat }: { logcat?: string }) {
  if (!logcat || !logcat.trim()) {
    return (
      <SocCard>
        <SectionHeader icon={<Terminal className="h-4 w-4" />} title="Logcat System Diagnostics" subtitle="Android OS Event Stream" />
        <div className="p-6 text-center text-xs text-slate-500 font-mono">No logcat telemetry collected</div>
      </SocCard>
    );
  }

  return (
    <SocCard>
      <SectionHeader icon={<Terminal className="h-4 w-4" />} title="Logcat System Diagnostics" subtitle="Monospace Android System Log Inspector" />
      <div className="p-3 bg-slate-950 font-mono text-[13px] text-slate-200 max-h-60 overflow-y-auto scrollbar-hidden rounded-b-md whitespace-pre-wrap leading-normal border-t border-slate-800">
        {logcat}
      </div>
    </SocCard>
  );
}

// ─── Dynamic Sandbox Panel ────────────────────────────────────────────────────────

function DynamicAnalysisPanel({ data }: { data: FraudCardData }) {
  const dyn =
    data.dynamic_result && typeof data.dynamic_result === 'object' && !Array.isArray(data.dynamic_result)
      ? data.dynamic_result
      : {};
  const runtimeStatus = resolveRuntimeDynamicStatus(data);
  const headline = runtimeStatusHeadline(runtimeStatus);
  const isOk = runtimeStatus === 'COMPLETED';

  return (
    <SocCard>
      <SectionHeader
        icon={<Terminal className="h-4 w-4" />}
        title="Dynamic Sandbox Execution"
        subtitle="Frida runtime instrumentation and telemetry"
      />

      <div className="p-3 border-b border-slate-200 bg-slate-50/40">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-2.5">
          <div className="flex items-center gap-2">
            <span className="text-[13px] font-semibold text-slate-500">Runtime status:</span>
            <span
              className={`px-1.5 py-0.5 text-[13px] font-semibold rounded border font-mono uppercase ${
                isOk
                  ? 'bg-emerald-50 text-emerald-800 border-emerald-200/50'
                  : 'bg-amber-50 text-amber-800 border-amber-200/50'
              }`}
            >
              {headline}
            </span>
          </div>
          <div className="flex items-center gap-2 text-[13px] font-mono text-slate-600">
            <span>
              Engine: <strong className="text-slate-800">{dyn.engine || 'frida'}</strong>
            </span>
            <span>•</span>
            <span>
              Canary: <strong className="text-slate-800">{dyn.canary_received ? '✓ LOADED' : '✗ UNRECEIVED'}</strong>
            </span>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs">
          {data.frs_breakdown?.dynamic_ran && (
            <div className="p-2 bg-white rounded border border-slate-200">
              <span className="block font-sans text-[13px] font-medium tracking-[0.01em] text-slate-500">
                <HelpTerm term="BFCI">Observed BFCI</HelpTerm>
              </span>
              <span className="font-mono font-semibold text-slate-800 text-sm">
                {(dyn.bfci ?? data.frs_breakdown?.dynamic ?? 0).toFixed(1)} / 100
              </span>
            </div>
          )}
          <div className="p-2 bg-white rounded border border-slate-200">
            <span className="block font-sans text-[13px] font-medium tracking-[0.01em] text-slate-500">Raw events</span>
            <span className="font-mono font-semibold text-slate-800 text-sm">
              {dyn.evidence_record_count || (dyn.api_calls || []).length}
            </span>
          </div>
          <div className="p-2 bg-white rounded border border-slate-200">
            <span className="block font-sans text-[13px] font-medium tracking-[0.01em] text-slate-500">Hook errors</span>
            <span className="font-mono font-semibold text-slate-800 text-sm">{(dyn.hook_errors || []).length}</span>
          </div>
        </div>
      </div>

      {/*
        The reconstructed chain used to render here, thirteen panels down in the
        behaviour tab, below the certificate table. It is the most
        executive-legible artifact the engine produces, so it now leads the case
        summary instead - and this points at it rather than rendering a second
        copy that could drift from the first.
      */}
      {data.fraud_workflow?.fraud_sequence_detected && (
        <div className="p-3 bg-white border-t border-slate-200">
          <Link to={caseSectionPath(data.sha256, 'summary')} className={TYPOGRAPHY.linkAction}>
            View the reconstructed attack chain
            {typeof data.fraud_workflow.stage_count === 'number' &&
              ` (${data.fraud_workflow.stage_count} stages)`}
            <ChevronRight className="h-3.5 w-3.5" aria-hidden />
          </Link>
        </div>
      )}
    </SocCard>
  );
}


// ─── Manifest Findings Panel ─────────────────────────────────────────────────────

function ManifestFindingsPanel({ data }: { data: FraudCardData }) {
  const [open, setOpen] = useRowAccordion((data.manifest_findings || []).length);
  const [filter, setFilter] = useState('');
  const [sev, setSev] = useState<string>('all');
  const findings = (data.manifest_findings || []).filter(
    (f) => f && typeof f === 'object' && typeof f.title === 'string',
  );

  if (findings.length === 0) return null;

  const sevCounts = findings.reduce((acc, f) => {
    const s = f.severity?.toLowerCase() || 'info';
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const visible = findings.filter(f => {
    const matchSev = sev === 'all' || (f.severity?.toLowerCase() === sev);
    const matchText =
      !filter ||
      f.title.toLowerCase().includes(filter.toLowerCase()) ||
      String(f.component || '').toLowerCase().includes(filter.toLowerCase());
    return matchSev && matchText;
  });

  const sevColor = (s?: string) => ({
    high: 'bg-red-50 text-red-800 border-red-200/50',
    warning: 'bg-orange-50 text-orange-800 border-orange-200/50',
    info: 'bg-blue-50 text-blue-800 border-blue-200/50',
  }[(s || 'info').toLowerCase()] || 'bg-slate-50 text-slate-600 border-slate-200/50');

  return (
    <SocCard>
      <button onClick={() => setOpen(o => !o)} className="w-full text-left">
        <SectionHeader
          icon={<AlertTriangle className="h-4 w-4" />}
          title="Manifest Security Findings"
          subtitle={`${findings.length} finding(s) from AndroidManifest.xml analysis`}
          action={open ? <ChevronUp className="h-4 w-4 text-slate-500" /> : <ChevronDown className="h-4 w-4 text-slate-500" />}
        />
      </button>
      {open && (
        <>
          <div className="flex flex-wrap items-center justify-between gap-2 p-2 border-b border-slate-200 bg-slate-50/40">
            <div className="relative flex-1 min-w-[140px]">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
              <input type="text" value={filter} onChange={e => setFilter(e.target.value)}
                placeholder="Filter findings..." className="w-full pl-7 pr-3 py-1 text-xs bg-white border border-slate-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-blue-500" />
            </div>
            <div className="flex items-center gap-1">
              {['all', 'high', 'warning', 'info'].map(s => (
                <button key={s} onClick={() => setSev(s)}
                  className={`px-2 py-0.5 text-[13px] font-semibold uppercase rounded border transition-all ${sev === s ? 'bg-slate-700 text-white border-slate-700' : 'bg-white text-slate-500 border-slate-200 hover:bg-slate-50'}`}>
                  {s}{s !== 'all' && sevCounts[s] ? ` (${sevCounts[s]})` : ''}
                </button>
              ))}
            </div>
          </div>
          <div className="divide-y divide-slate-150 max-h-72 overflow-y-auto scrollbar-hidden">
            {visible.map((f, i) => (
              <div key={i} className="p-3 hover:bg-slate-50/50 transition-colors">
                <div className="flex items-start gap-2.5">
                  <span className={`mt-0.5 px-1.5 py-0.5 text-[13px] font-semibold rounded border flex-shrink-0 ${sevColor(f.severity)}`}>{f.severity?.toUpperCase()}</span>
                  <div className="min-w-0">
                    <p className="text-xs font-semibold text-slate-800 leading-tight">{f.title}</p>
                    {f.component && <p className="text-[13px] font-mono text-slate-500 truncate mt-0.5">{f.component}</p>}
                    {f.description && <p className="text-[13px] text-slate-500 mt-1 leading-normal">{f.description}</p>}
                  </div>
                </div>
              </div>
            ))}
            {visible.length === 0 && <div className="p-6 text-center text-xs text-slate-500 font-mono">No findings match the current filter.</div>}
          </div>
        </>
      )}
    </SocCard>
  );
}

// ─── Code Findings Panel (with MASVS/CWE/OWASP) ────────────────────────────────────

const CODE_CATEGORIES = [
  { id: 'all', label: 'All' },
  { id: 'crypto', label: 'Crypto', keywords: ['crypto', 'cipher', 'des', 'md5', 'sha1', 'ecb', 'aes', 'rsa', 'rc4', 'encryption', 'digest', 'random'] },
  { id: 'webview', label: 'WebView', keywords: ['webview', 'javascript', 'addjavascriptinterface', 'loadurl', 'evaluatejavascript', 'allowfileaccess'] },
  { id: 'ssl', label: 'SSL/TLS', keywords: ['ssl', 'tls', 'trustmanager', 'hostname', 'pinning', 'hostnamevalidator', 'x509', 'cleartext'] },
  { id: 'antiana', label: 'Anti-Analysis', keywords: ['root', 'debug', 'frida', 'emulator', 'hooking', 'isdebugg', 'systemproperties', 'buildtags'] },
];

function CodeFindingsPanel({ data }: { data: FraudCardData }) {
  const [open, setOpen] = useRowAccordion((data.code_findings || []).length);
  const [filter, setFilter] = useState('');
  const [cat, setCat] = useState('all');
  const [sev, setSev] = useState<string>('all');
  const findings = (data.code_findings || []).filter(
    (f) => f && typeof f === 'object' && typeof f.title === 'string',
  );

  if (findings.length === 0) return null;

  const activeCat = CODE_CATEGORIES.find(c => c.id === cat);
  const visible = findings.filter(f => {
    const text = `${f.title} ${f.description} ${(f as any).rule_id || ''}`.toLowerCase();
    const matchCat = cat === 'all' || (activeCat?.keywords || []).some(k => text.includes(k));
    const matchSev = sev === 'all' || (f.severity?.toLowerCase() === sev);
    const matchFilter = !filter || text.includes(filter.toLowerCase());
    return matchCat && matchSev && matchFilter;
  });

  const sevColor = (s?: string) => ({
    high: 'text-red-800 bg-red-50 border-red-200/50',
    warning: 'text-orange-800 bg-orange-50 border-orange-200/50',
    info: 'text-blue-800 bg-blue-50 border-blue-200/50',
  }[(s || 'info').toLowerCase()] || 'text-slate-600 bg-slate-50 border-slate-200/50');

  return (
    <SocCard>
      <button onClick={() => setOpen(o => !o)} className="w-full text-left">
        <SectionHeader
          icon={<Code className="h-4 w-4" />}
          title="Static Code Security Findings"
          subtitle={`${findings.length} finding(s) from source analysis - with MASVS/CWE/OWASP`}
          action={open ? <ChevronUp className="h-4 w-4 text-slate-500" /> : <ChevronDown className="h-4 w-4 text-slate-500" />}
        />
      </button>
      {open && (
        <>
          <div className="flex flex-wrap items-center gap-2 p-2.5 border-b border-slate-200 bg-slate-50/40">
            <div className="relative min-w-[130px]">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
              <input type="text" value={filter} onChange={e => setFilter(e.target.value)}
                placeholder="Search..." className="pl-7 pr-3 py-1 text-xs bg-white border border-slate-200 rounded-lg w-36 focus:outline-none focus:ring-1 focus:ring-blue-500" />
            </div>
            <div className="flex gap-1">
              {CODE_CATEGORIES.map(c => (
                <button key={c.id} onClick={() => setCat(c.id)}
                  className={`px-2 py-0.5 text-[13px] font-semibold rounded border transition-all ${cat === c.id ? 'bg-blue-600 text-white border-blue-600' : 'bg-white text-slate-500 border-slate-200 hover:bg-slate-50'}`}>
                  {c.label}
                </button>
              ))}
            </div>
            <div className="flex gap-1 ml-auto">
              {['all', 'high', 'warning', 'info'].map(s => (
                <button key={s} onClick={() => setSev(s)}
                  className={`px-1.5 py-0.5 text-[13px] font-semibold rounded border transition-all ${sev === s ? 'bg-slate-700 text-white border-slate-700' : 'bg-white text-slate-400 border-slate-200 hover:bg-slate-50'}`}>
                  {s}
                </button>
              ))}
            </div>
          </div>
          <div className="divide-y divide-slate-150 max-h-96 overflow-y-auto scrollbar-hidden">
            {visible.map((f, i) => (
              <div key={i} className="p-3 hover:bg-slate-50/50 transition-colors">
                <div className="flex items-start justify-between gap-2.5 mb-1.5">
                  <p className="text-xs font-semibold text-slate-800 leading-tight">{f.title}</p>
                  <span className={`px-1.5 py-0.5 text-[13px] font-semibold rounded border flex-shrink-0 ${sevColor(f.severity)}`}>{f.severity?.toUpperCase()}</span>
                </div>
                {f.description && <p className="text-[13px] text-slate-500 mb-2 leading-relaxed">{f.description}</p>}
                <div className="flex flex-wrap gap-1.5">
                  {(f as any).rule_id && <code className="text-[13px] bg-slate-100 text-slate-600 border border-slate-200 px-1.5 py-0.5 rounded font-mono">{(f as any).rule_id}</code>}
                  {(f as any).masvs && <span className="text-[13px] bg-purple-50 text-purple-700 border border-purple-200/50 px-1.5 py-0.5 rounded font-mono">MASVS: {(f as any).masvs}</span>}
                  {(f as any).cwe && <span className="text-[13px] bg-orange-50 text-orange-700 border border-orange-200/50 px-1.5 py-0.5 rounded font-mono">{(f as any).cwe}</span>}
                  {(f as any).owasp && <span className="text-[13px] bg-green-50 text-green-700 border border-green-200/50 px-1.5 py-0.5 rounded font-mono">{(f as any).owasp}</span>}
                </div>
                {f.files?.length > 0 && (
                  <div className="mt-2 space-y-0.5 border-t border-slate-100 pt-1.5">
                    {f.files.slice(0, 3).map((file, fi) => (
                      <p key={fi} className="text-[13px] font-mono text-slate-500 truncate">{file}</p>
                    ))}
                  </div>
                )}
              </div>
            ))}
            {visible.length === 0 && <div className="p-6 text-center text-xs text-slate-500 font-mono">No findings match the current filter.</div>}
          </div>
        </>
      )}
    </SocCard>
  );
}

// ─── Exported Components Panel ──────────────────────────────────────────────────────

function ExportedComponentsPanel({ data }: { data: FraudCardData }) {
  const [open, setOpen] = useRowAccordion(((data.exported_activities||[]).length + (data.exported_services||[]).length + (data.exported_receivers||[]).length));
  const [filter, setFilter] = useState('');
  const acts = data.exported_activities || [];
  const svcs = data.exported_services || [];
  const rcvs = data.exported_receivers || [];
  const prvs = data.providers || [];
  const total = acts.length + svcs.length + rcvs.length + prvs.length;

  if (total === 0) return null;

  type ComponentRow = { name: string; type: string; color: string };
  const rows: ComponentRow[] = [
    ...acts.map(n => ({ name: n, type: 'Activity', color: 'bg-red-50 text-red-700 border-red-200/50' })),
    ...svcs.map(n => ({ name: n, type: 'Service', color: 'bg-orange-50 text-orange-700 border-orange-200/50' })),
    ...rcvs.map(n => ({ name: n, type: 'Receiver', color: 'bg-yellow-50 text-yellow-700 border-yellow-200/50' })),
    ...prvs.map(n => ({ name: n, type: 'Provider', color: 'bg-purple-50 text-purple-700 border-purple-200/50' })),
  ];

  const visible = filter ? rows.filter(r => r.name.toLowerCase().includes(filter.toLowerCase())) : rows;

  return (
    <SocCard>
      <button onClick={() => setOpen(o => !o)} className="w-full text-left">
        <SectionHeader
          icon={<Shield className="h-4 w-4" />}
          title="Exported Components - Attack Surface"
          subtitle={`${total} exported component(s) accessible by external apps / intents`}
          action={open ? <ChevronUp className="h-4 w-4 text-slate-500" /> : <ChevronDown className="h-4 w-4 text-slate-500" />}
        />
      </button>
      {open && (
        <>
          <div className="p-2 border-b border-slate-200 bg-slate-50/40">
            <div className="relative">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
              <input type="text" value={filter} onChange={e => setFilter(e.target.value)}
                placeholder="Filter by component name..." className="w-full pl-7 pr-3 py-1 text-xs bg-white border border-slate-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-blue-500" />
            </div>
          </div>
          <div className="soc-table-wrap !border-0 rounded-none max-h-72">
            <table className="soc-table text-xs">
              <thead>
                <tr>
                  <th className="!bg-slate-50/80 w-24">Type</th>
                  <th className="!bg-slate-50/80">Component Name</th>
                  <th className="text-right !bg-slate-50/80 w-16">Actions</th>
                </tr>
              </thead>
              <tbody className="font-mono">
                {visible.map((row, i) => (
                  <tr key={i}>
                    <td>
                      <span className={`px-1.5 py-0.5 text-[13px] font-semibold rounded border ${row.color}`}>{row.type}</span>
                    </td>
                    <td className="break-all text-slate-800 text-xs">{row.name}</td>
                    <td className="text-right">
                      <CopyButton value={row.name} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {visible.length === 0 && <div className="p-6 text-center text-xs text-slate-500 font-mono">No components match filter.</div>}
          </div>
        </>
      )}
    </SocCard>
  );
}

// ─── Native Binary Analysis Panel ──────────────────────────────────────────────────

function BinaryAnalysisPanel({ data }: { data: FraudCardData }) {
  const [open, setOpen] = useRowAccordion((data.binary_analysis || []).length);
  const bins = data.binary_analysis || [];

  if (bins.length === 0) return null;

  const flagStyle = (val?: string | null) => {
    if (!val) return 'text-slate-500';
    const v = String(val).toLowerCase();
    if (v === 'true' || v === 'full' || v === 'enabled') return 'text-emerald-700 font-semibold';
    if (v === 'false' || v === 'none' || v === 'disabled') return 'text-red-700 font-semibold';
    if (v === 'partial') return 'text-orange-700 font-semibold';
    return 'text-slate-600';
  };

  return (
    <SocCard>
      <button onClick={() => setOpen(o => !o)} className="w-full text-left">
        <SectionHeader
          icon={<Database className="h-4 w-4" />}
          title="Native Binary Analysis"
          subtitle={`${bins.length} native library (SO) file(s) - NX, Stack Canary, RELRO, RPATH`}
          action={open ? <ChevronUp className="h-4 w-4 text-slate-500" /> : <ChevronDown className="h-4 w-4 text-slate-500" />}
        />
      </button>
      {open && (
        <div className="soc-table-wrap !border-0 rounded-none max-h-72">
          <table className="soc-table text-xs">
            <thead>
              <tr>
                <th className="!bg-slate-50/80">Library</th>
                <th className="text-center !bg-slate-50/80 w-16">NX</th>
                <th className="text-center !bg-slate-50/80 w-24">Stack Canary</th>
                <th className="text-center !bg-slate-50/80 w-20">RELRO</th>
                <th className="text-center !bg-slate-50/80 w-16">RPATH</th>
                <th className="text-center !bg-slate-50/80 w-16">Fortify</th>
              </tr>
            </thead>
            <tbody>
              {bins.map((b, i) => (
                <tr key={i}>
                  <td className="font-mono break-all text-slate-800">{b.name || '-'}</td>
                  <td className={`text-center font-mono ${flagStyle(b.nx)}`}>{String(b.nx ?? '-')}</td>
                  <td className={`text-center font-mono ${flagStyle(b.stack_canary)}`}>{String(b.stack_canary ?? '-')}</td>
                  <td className={`text-center font-mono ${flagStyle(b.relro)}`}>{String(b.relro ?? '-')}</td>
                  <td className={`text-center font-mono ${b.rpath && String(b.rpath) !== 'False' ? 'text-red-700 font-semibold' : 'text-emerald-700'}`}>{String(b.rpath ?? '-')}</td>
                  <td className={`text-center font-mono ${flagStyle(b.fortify)}`}>{String(b.fortify ?? '-')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </SocCard>
  );
}

// ─── Network Security Config Panel ──────────────────────────────────────────────────

function NetworkSecurityPanel({ data }: { data: FraudCardData }) {
  const [open, setOpen] = useRowAccordion(Object.keys(data.network_security || {}).length);
  const nsc = data.network_security;

  if (!nsc || Object.keys(nsc).length === 0) return null;

  const entries = Object.entries(nsc);

  return (
    <SocCard>
      <button onClick={() => setOpen(o => !o)} className="w-full text-left">
        <SectionHeader
          icon={<Globe className="h-4 w-4" />}
          title="Network Security Config"
          subtitle={`${entries.length} NSC configuration entries (cleartext, pinning, trust anchors)`}
          action={open ? <ChevronUp className="h-4 w-4 text-slate-500" /> : <ChevronDown className="h-4 w-4 text-slate-500" />}
        />
      </button>
      {open && (
        <div className="soc-table-wrap !border-0 rounded-none max-h-60">
          <table className="soc-table text-xs">
            <thead>
              <tr>
                <th className="!bg-slate-50/80 w-1/2">Property</th>
                <th className="!bg-slate-50/80 w-1/2 text-right">Setting</th>
              </tr>
            </thead>
            <tbody className="font-mono">
              {entries.map(([k, v]) => (
                <tr key={k}>
                  <td className="text-slate-500 capitalize">{k.replace(/_/g, ' ')}</td>
                  <td className={`text-right break-all ${String(v) === 'true' ? 'text-red-700 font-semibold' : String(v) === 'false' ? 'text-emerald-700' : 'text-slate-800'}`}>
                    {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </SocCard>
  );
}

// ─── Trackers & Third-Party SDKs Panel ─────────────────────────────────────────────

function TrackersPanel({ data }: { data: FraudCardData }) {
  const [open, setOpen] = useRowAccordion(((data as any).trackers || []).length);
  const trackers = data.trackers || [];

  if (trackers.length === 0) return null;

  const catColor = (cats: string[]) => {
    const s = cats.join(' ').toLowerCase();
    if (s.includes('analytics') || s.includes('tracker')) return 'bg-orange-50 text-orange-800 border-orange-200/50';
    if (s.includes('crash') || s.includes('error')) return 'bg-red-50 text-red-800 border-red-200/50';
    if (s.includes('ads') || s.includes('advertis')) return 'bg-yellow-50 text-yellow-800 border-yellow-200/50';
    return 'bg-slate-50 text-slate-600 border-slate-200/50';
  };

  return (
    <SocCard>
      <button onClick={() => setOpen(o => !o)} className="w-full text-left">
        <SectionHeader
          icon={<Tag className="h-4 w-4" />}
          title="Third-Party SDKs & Trackers"
          subtitle={`${trackers.length} SDK fingerprint(s) identified`}
          action={open ? <ChevronUp className="h-4 w-4 text-slate-500" /> : <ChevronDown className="h-4 w-4 text-slate-500" />}
        />
      </button>
      {open && (
        <div className="p-3 flex flex-wrap gap-2 bg-white">
          {trackers.map((t, i) => (
            <div key={i} className="flex items-center gap-2 px-2.5 py-1 bg-slate-50 border border-slate-200 rounded-lg text-xs">
              <span className="font-semibold text-slate-800">{t.name}</span>
              {t.categories.length > 0 && (
                <div className="flex gap-1">
                  {t.categories.slice(0, 2).map((c, ci) => (
                    <span key={ci} className={`px-1.5 py-0.2 text-[13px] font-semibold rounded border uppercase ${catColor([c])}`}>{c}</span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </SocCard>
  );
}

// ─── Secrets Inspector Panel ─────────────────────────────────────────────────────────

function SecretsPanel({ data }: { data: FraudCardData }) {
  const [open, setOpen] = useRowAccordion((data.hardcoded_secrets || []).length);
  const [filter, setFilter] = useState('');
  const [showAll, setShowAll] = useState(false);
  const secrets = data.hardcoded_secrets || [];

  if (secrets.length === 0) return null;

  const visible = secrets.filter(s => !filter || s.toLowerCase().includes(filter.toLowerCase()));
  const display = showAll ? visible : visible.slice(0, 15);

  return (
    <SocCard>
      <button onClick={() => setOpen(o => !o)} className="w-full text-left">
        <SectionHeader
          icon={<Key className="h-4 w-4" />}
          title="Hardcoded Secrets & Credentials"
          subtitle={`${secrets.length} secret(s) found - API keys, tokens, Firebase configs, JWT`}
          action={open ? <ChevronUp className="h-4 w-4 text-slate-500" /> : <ChevronDown className="h-4 w-4 text-slate-500" />}
        />
      </button>
      {open && (
        <>
          <div className="p-2 border-b border-slate-200 bg-slate-50/40">
            <div className="relative">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
              <input type="text" value={filter} onChange={e => setFilter(e.target.value)}
                placeholder="Filter secrets..." className="w-full pl-7 pr-3 py-1 text-xs bg-white border border-slate-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-blue-500" />
            </div>
          </div>
          <div className="soc-table-wrap !border-0 rounded-none max-h-72">
            <table className="soc-table text-xs">
              <thead>
                <tr>
                  <th className="!bg-slate-50/80 w-20">Type</th>
                  <th className="!bg-slate-50/80">Value</th>
                  <th className="text-right !bg-slate-50/80 w-16">Copy</th>
                </tr>
              </thead>
              <tbody className="font-mono">
                {display.map((s, i) => (
                  <tr key={i}>
                    <td>
                      <span className="px-1 py-0.5 text-[13px] font-semibold bg-red-100 text-red-800 border border-red-200/50 rounded uppercase whitespace-nowrap">SECRET</span>
                    </td>
                    <td className="break-all text-xs text-slate-700">
                      <span className="inline-flex items-start gap-1">
                        {s}
                        {/* Obfuscated secrets are decoded locally first; the
                            model is only asked for semantic intent. */}
                        <AskAiPopover value={s} kind="string" />
                      </span>
                    </td>
                    <td className="text-right">
                      <CopyButton value={s} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {visible.length > 15 && (
            <div className="p-2.5 border-t border-slate-200 text-center bg-slate-50/50">
              <button onClick={() => setShowAll(a => !a)} className="text-xs text-blue-700 font-semibold hover:text-blue-800 transition-colors">
                {showAll ? 'Show fewer' : `Show all ${visible.length} secrets`}
              </button>
            </div>
          )}
        </>
      )}
    </SocCard>
  );
}


// ─── Main TechnicalView Page ──────────────────────────────────────────────────────

export default function TechnicalView({ data }: { data: FraudCardData | null }) {
  const { investigationBundle, loading } = useAnalysis();
  // The gallery renders manifest entries, while bundle.counts.screenshots is
  // derived from dynamic_analysis.screenshots - the two disagree. A header
  // count has to come from the same place as the panel under it.
  const { entries: screenshotEntries } = useRuntimeScreenshots(data?.sha256);
  if (!data) return null;

  const dyn = data.dynamic_analysis;

  /*
   * Five questions, five tabs, and inside each one nothing but collapsed
   * sections.
   *
   * The previous shape had four tabs, and the behaviour tab alone stacked
   * thirteen expanded panels - so the fix that tabs had made at the top level
   * had simply not been applied one level down. A reader looking for the
   * certificate still scrolled past everything between them and it.
   *
   * Every section carries a count on its header, so collapsing moves the work
   * from scrolling to reading rather than from scrolling to clicking, and every
   * section has a stable anchor so the assistant can cite it.
   */
  const tabs: AnalysisTab[] = [
    {
      id: 'overview',
      label: 'Overview',
      count: investigationBundle?.counts.evidenceRecords,
      anchors: ['evidence-registry'],
      content: (
        <>
          {/*
           * Three questions in reading order: how much did we find, what did we
           * call it, and where is each record. Every group carries a plain
           * heading, because the previous shape opened straight into a grid of
           * numbers with no statement of what they counted - fine for the
           * analyst who built it, opaque to the manager reading the verdict.
           */}
          {/*
            Steps 1 and 2 answer short questions - how much did we find, and
            what did we call it - and each was spending a full console width on
            three numbers and one label. Side by side they fit one glance, and
            `items-stretch` keeps their two cards the same height so the row
            reads as a row rather than as two cards that happen to be adjacent.

            Step 3 stays full width below: it is a filterable table of every
            record in the case, and it is the reason anyone scrolls this far.
          */}
          <div className="grid grid-cols-1 items-stretch gap-4 xl:grid-cols-2">
            <OverviewGroup
              eyebrow="Step 1"
              title="What this analysis recorded"
              blurb="Counts taken directly from the run. Click any number to jump to the records behind it."
            >
              <ActivitySummary data={data} counts={investigationBundle?.counts} />
            </OverviewGroup>

            <OverviewGroup
              eyebrow="Step 2"
              title="What the engine concluded"
              blurb="A deterministic rules engine assigns the label. No AI output contributes to it."
            >
              <ExplainabilityEngine data={data} />
            </OverviewGroup>
          </div>

          <OverviewGroup
            eyebrow="Step 3"
            title="The evidence behind the verdict"
            blurb="Every record is individually traceable. Filter by source, or search the finding text."
          >
            <EvidenceSection
              id="evidence-registry"
              title="Evidence registry"
              subtitle="Static, runtime and threat-correlation records"
              count={investigationBundle?.counts.evidenceRecords}
              icon={<Database className="h-4 w-4" />}
              defaultOpen
            >
              <EvidenceRegistrySection data={data} bundle={investigationBundle} loading={loading} />
            </EvidenceSection>
          </OverviewGroup>
        </>
      ),
    },
    {
      id: 'static',
      label: 'Static',
      count: (data.manifest_findings ?? []).length + (data.code_findings ?? []).length,
      anchors: [
        'permissions',
        'manifest-findings',
        'code-findings',
        'certificate',
        'exported-components',
        'decompilation',
        'secrets',
        'apk-metadata',
      ],
      content: (
        <>
          <TabSummary
            items={[
              {
                label: 'Permissions',
                value: (data.all_permissions ?? []).length,
                anchor: 'permissions',
                context: 'Requested in the manifest',
              },
              {
                label: 'Manifest findings',
                value: (data.manifest_findings ?? []).length,
                anchor: 'manifest-findings',
                context: 'Components and flags of note',
              },
              {
                label: 'Code findings',
                value: (data.code_findings ?? []).length,
                anchor: 'code-findings',
                context: 'Matches in decompiled source',
              },
              {
                label: 'Hardcoded secrets',
                value: (data.hardcoded_secrets ?? []).length,
                anchor: 'secrets',
                context: 'Keys and tokens left in the build',
              },
            ]}
          />
          <EvidenceSection
            id="permissions"
            title="Permissions"
            subtitle="What the application asked the device for"
            count={(data.all_permissions ?? []).length}
            icon={<Lock className="h-4 w-4" />}
            defaultOpen
          >
            <PermissionTable data={data} />
          </EvidenceSection>

          <EvidenceSection
            id="manifest-findings"
            title="Manifest findings"
            count={(data.manifest_findings ?? []).length}
            icon={<Shield className="h-4 w-4" />}
          >
            <ManifestFindingsPanel data={data} />
          </EvidenceSection>

          <EvidenceSection
            id="code-findings"
            title="Code findings"
            subtitle="Static source analysis, with MASVS / CWE / OWASP mapping"
            count={(data.code_findings ?? []).length}
            icon={<Code className="h-4 w-4" />}
          >
            <CodeFindingsPanel data={data} />
          </EvidenceSection>

          <EvidenceSection
            id="exported-components"
            title="Exported components"
            subtitle="Attack surface reachable by other applications"
            count={
              (data.exported_activities ?? []).length +
              (data.exported_services ?? []).length +
              (data.exported_receivers ?? []).length +
              (data.providers ?? []).length
            }
            icon={<Package className="h-4 w-4" />}
          >
            <ExportedComponentsPanel data={data} />
          </EvidenceSection>

          <EvidenceSection
            id="secrets"
            title="Hardcoded secrets"
            count={(data.hardcoded_secrets ?? []).length}
            icon={<Key className="h-4 w-4" />}
          >
            <SecretsPanel data={data} />
          </EvidenceSection>

          {/*
            Two narrow panels, paired.

            Both are label-and-value lists roughly 400px wide, and each was
            spending the whole console on one column of pairs with white to the
            right of it. Paired only at xl: below that the split would put a
            9rem label column and its value into half a tablet, and a truncated
            certificate subject is worse than a taller page. `items-start` so
            one expanding does not stretch the other.
          */}
          <div className="grid grid-cols-1 items-start gap-4 xl:grid-cols-2">
            <EvidenceSection
              id="certificate"
              title="Signing certificate"
              subtitle="X.509 identity and attribution"
              icon={<Lock className="h-4 w-4" />}
            >
              <CertificatePanel certificate={data.certificate} />
            </EvidenceSection>

            <EvidenceSection
              id="apk-metadata"
              title="APK identifiers"
              icon={<Tag className="h-4 w-4" />}
            >
              <APKMetadata data={data} />
            </EvidenceSection>
          </div>

          <EvidenceSection
            id="decompilation"
            title="Decompilation"
            subtitle="APKTool resources and JADX source hits"
            icon={<Code className="h-4 w-4" />}
          >
            <DecompilationPanel data={data} />
          </EvidenceSection>
        </>
      ),
    },
    {
      id: 'dynamic',
      label: 'Runtime',
      count: investigationBundle?.counts.runtimeBehaviors,
      anchors: ['dynamic-analysis', 'mitre', 'dangerous-apis', 'resilience'],
      content: (
        <>
          <TabSummary
            items={[
              {
                label: 'Runtime behaviours',
                value: investigationBundle?.counts.runtimeBehaviors ?? 0,
                anchor: 'dynamic-analysis',
                context: 'Actions seen while the app ran',
              },
              {
                label: 'MITRE techniques',
                value: data.intelligence_report?.mitre_techniques_used?.length ?? 0,
                anchor: 'mitre',
                context: 'Mapped to the ATT&CK matrix',
              },
              {
                label: 'Dangerous APIs',
                value: (data.technical_view?.apis_fired ?? []).length,
                anchor: 'dangerous-apis',
                context: 'Sensitive calls actually invoked',
              },
            ]}
          />
          <EvidenceSection
            id="dynamic-analysis"
            title="Runtime behaviour"
            subtitle="Observed during sandbox execution"
            count={investigationBundle?.counts.runtimeBehaviors}
            icon={<Cpu className="h-4 w-4" />}
            defaultOpen
          >
            <DynamicAnalysisSummary data={data} />
          </EvidenceSection>

                    {/*
            Two reference panels, paired.

            Neither carries a viewport-keyed grid inside it, so neither
            collapses into slivers at half width - checked before pairing,
            because that is exactly what would happen to the panels that do.
            Paired at xl only, and `items-start` so opening one does not
            stretch the other to match.
          */}
          <div className="grid grid-cols-1 items-start gap-4 xl:grid-cols-2">
  <EvidenceSection
              id="mitre"
              title="MITRE ATT&amp;CK mapping"
              count={data.intelligence_report?.mitre_techniques_used?.length}
              icon={<Shield className="h-4 w-4" />}
            >
              <MitreMatrix data={data} />
            </EvidenceSection>

  <EvidenceSection
              id="dangerous-apis"
              title="Dangerous API calls"
              count={(data.technical_view?.apis_fired ?? []).length}
              icon={<Terminal className="h-4 w-4" />}
            >
              <DangerousAPITable data={data} />
            </EvidenceSection>
          </div>

          

          <EvidenceSection
            id="resilience"
            title="Sandbox resilience"
            subtitle="Evasion attempts, and what was done about them"
            icon={<Shield className="h-4 w-4" />}
          >
            <ResiliencePanel
              sessionId={data.sha256}
              packageName={data.package_name}
              antiEvasion={
                // The stored case keeps the raw dynamic result; the API response
                // model exposes the same field. Either is the run that happened
                // while the sample was live, so prefer whichever this view has.
                (data.dynamic_result?.anti_evasion ??
                  data.dynamic_analysis?.anti_evasion ??
                  null) as AntiEvasionResult | null
              }
            />
          </EvidenceSection>
        </>
      ),
    },
    {
      id: 'visual',
      label: 'Visual',
      count: screenshotEntries.length,
      anchors: ['screenshots', 'impersonation', 'overlay-payloads'],
      content: (
        <>
          <TabSummary
            items={[
              {
                label: 'Screenshots',
                value: screenshotEntries.length,
                anchor: 'screenshots',
                context: 'Frames captured in the sandbox',
              },
            ]}
          />
          <EvidenceSection
            id="screenshots"
            title="Screenshots"
            subtitle="Captured during the sandbox run"
            count={screenshotEntries.length}
            icon={<Search className="h-4 w-4" />}
            defaultOpen
          >
            <ScreenshotGallery data={data} bundle={investigationBundle} />
          </EvidenceSection>

          <EvidenceSection
            id="impersonation"
            title="Visual impersonation"
            subtitle="Comparison against banking design baselines"
            icon={<Globe className="h-4 w-4" />}
          >
            <VisualImpersonationPanel data={data} />
            {data.vide && <VisualDiffViewer vide={data.vide} />}
          </EvidenceSection>

          {data.vide && (
            <EvidenceSection
              id="overlay-payloads"
              title="Intercepted overlay payloads"
              subtitle="Raw HTML captured from WebView hooks"
              count={data.vide.overlay_payloads?.length}
              icon={<Code className="h-4 w-4" />}
            >
              <OverlayEvidenceViewer vide={data.vide} />
            </EvidenceSection>
          )}
        </>
      ),
    },
    {
      id: 'network',
      label: 'Network',
      count: (data.hardcoded_urls_ips ?? []).length,
      anchors: [
        'network-capture',
        'relations',
        'secondary-apks',
        'network-security',
        'trackers',
      ],
      content: (
        <>
          <TabSummary
            items={[
              {
                label: 'Hardcoded endpoints',
                value: (data.hardcoded_urls_ips ?? []).length,
                anchor: 'network-capture',
                context: 'URLs and IPs found in the build',
              },
              {
                label: 'Secondary APKs',
                value: (
                  (data.dynamic_analysis as Record<string, unknown> | undefined)
                    ?.secondary_apks as unknown[] | undefined ?? []
                ).length,
                anchor: 'secondary-apks',
                context: 'Payloads dropped or bundled',
              },
            ]}
          />
          <EvidenceSection
            id="network-capture"
            title="Network capture"
            subtitle="Runtime requests observed in the sandbox"
            count={(dyn?.network_logs ?? []).length}
            icon={<Globe className="h-4 w-4" />}
            defaultOpen
          >
            <NetworkCapturePanel networkLogs={dyn?.network_logs} />
          </EvidenceSection>

          <EvidenceSection
            id="relations"
            title="Indicator relationships"
            icon={<Database className="h-4 w-4" />}
          >
            <RelationsGraph data={data} />
          </EvidenceSection>

          <EvidenceSection
            id="secondary-apks"
            title="Secondary payloads"
            subtitle="Additional packages the sample tried to install"
            icon={<Package className="h-4 w-4" />}
          >
            <SecondaryApkPanel data={data} />
          </EvidenceSection>

                    {/*
            Two reference panels, paired.

            Neither carries a viewport-keyed grid inside it, so neither
            collapses into slivers at half width - checked before pairing,
            because that is exactly what would happen to the panels that do.
            Paired at xl only, and `items-start` so opening one does not
            stretch the other to match.
          */}
          <div className="grid grid-cols-1 items-start gap-4 xl:grid-cols-2">
  <EvidenceSection
              id="network-security"
              title="Network security config"
              subtitle="Cleartext policy, pinning and trust anchors"
              icon={<Lock className="h-4 w-4" />}
            >
              <NetworkSecurityPanel data={data} />
            </EvidenceSection>

  <EvidenceSection
              id="trackers"
              title="Third-party SDKs"
              count={(data.trackers ?? []).length}
              icon={<Tag className="h-4 w-4" />}
            >
              <TrackersPanel data={data} />
            </EvidenceSection>
          </div>

          
        </>
      ),
    },
    /*
     * Raw forensics: Logcat, Frida instrumentation events, and native binary hardening.
     */
    {
      id: 'raw',
      label: 'Raw',
      anchors: ['logcat', 'frida-events', 'binary-analysis'],
      content: (
        <>
          <EvidenceSection
            id="frida-events"
            title="Instrumentation events"
            subtitle="Unaggregated Frida hook records"
            icon={<Terminal className="h-4 w-4" />}
          >
            <DynamicAnalysisPanel data={data} />
          </EvidenceSection>

          <EvidenceSection
            id="logcat"
            title="Logcat"
            subtitle="Android system event stream"
            icon={<Terminal className="h-4 w-4" />}
          >
            <LogcatInspectorPanel logcat={dyn?.logcat} />
          </EvidenceSection>

          <EvidenceSection
            id="binary-analysis"
            title="Native binary hardening"
            subtitle="NX, stack canary, RELRO, RPATH"
            count={(data.binary_analysis ?? []).length}
            icon={<Cpu className="h-4 w-4" />}
          >
            <BinaryAnalysisPanel data={data} />
          </EvidenceSection>
        </>
      ),
    },
  ];

  /*
   * The behaviour-tag chip row used to sit above the tabs. It restated three
   * static flags that the Static tab already lists in full, in monospace, at
   * the very top of the reading order - so the first thing on the page was
   * also the least specific thing on it, and it pushed the tabs down without
   * telling the reader anything they could act on.
   */
  const records = investigationBundle?.counts.evidenceRecords || 0;
  
  const counts = (investigationBundle?.evidenceRecords || []).reduce(
    (acc, record) => {
      const sev = record.severity?.toLowerCase();
      if (sev === 'critical' || sev === 'high') acc.high++;
      else if (sev === 'medium') acc.medium++;
      else acc.informational++;
      return acc;
    },
    { high: 0, medium: 0, informational: 0 }
  );

  return (
    <motion.main
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
      className="technical-view max-w-[1920px] mx-auto p-4 sm:p-6 lg:p-8 space-y-6"
    >
      <div className="flex items-end justify-between border-b border-slate-200 pb-4">
        <div>
          <h1 className="text-2xl sm:text-[28px] font-semibold text-slate-900 tracking-[-0.025em]">Evidence</h1>
          <div className="flex items-center gap-3 mt-2 text-sm">
            <span className="font-semibold text-slate-900">{records} records</span>
            <span className="text-slate-300">|</span>
            <span className="text-red-700 font-medium">{counts.high} high</span>
            <span className="text-slate-300">|</span>
            <span className="text-amber-700 font-medium">{counts.medium} medium</span>
            <span className="text-slate-300">|</span>
            <span className="text-blue-700 font-medium">{counts.informational} informational</span>
          </div>
        </div>
      </div>
      <AnalysisTabs tabs={tabs} urlParam="section" />
    </motion.main>
  );
}
