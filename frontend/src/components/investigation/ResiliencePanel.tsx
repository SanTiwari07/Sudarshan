import { useState } from 'react';
import {
  BatteryMedium,
  CheckCircle2,
  ChevronDown,
  Circle,
  Clock,
  EyeOff,
  Lightbulb,
  Loader2,
  RotateCcw,
  Save,
  ShieldAlert,
  ShieldCheck,
  UserPlus,
  XCircle,
  Zap,
} from 'lucide-react';
import SocCard from '../ui/Card';
import { useResilience, type AntiEvasionStepState } from '../../hooks/useResilience';
import type {
  AntiEvasionApplied,
  AntiEvasionResult,
  Suggestion,
} from '../../lib/resilience';

const PRIORITY_STYLE: Record<string, string> = {
  CRITICAL: 'bg-red-50/50 text-red-900 border-red-200/70',
  HIGH: 'bg-amber-50/50 text-amber-900 border-amber-200/70',
  MEDIUM: 'bg-slate-50/50 text-slate-800 border-slate-200/70',
};

/**
 * Checkpoint status pill.
 *
 * Shows whether the run is resumable, and how much work resuming would save -
 * "restore" is a meaningless offer without knowing what is in the snapshot.
 */
function CheckpointPill({
  checkpoint,
  busy,
  onRestore,
}: {
  checkpoint: ReturnType<typeof useResilience>['checkpoint'];
  busy: string | null;
  onRestore: () => void;
}) {
  if (!checkpoint?.exists) {
    return (
      <div className="flex items-center gap-2 text-xs text-slate-500">
        <Save className="h-3.5 w-3.5" />
        No checkpoint saved for this session
      </div>
    );
  }

  const goals = checkpoint.satisfied_goals?.length ?? 0;
  return (
    <div className="flex flex-wrap items-center gap-3">
      <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-200 bg-emerald-50 px-2.5 py-1 text-xs font-semibold text-emerald-800">
        <Save className="h-3.5 w-3.5" />
        Checkpoint saved
      </span>
      <span className="text-xs text-slate-600">
        iteration {checkpoint.iteration ?? 0} · {checkpoint.screens_visited ?? 0} screen(s) ·{' '}
        {goals} goal(s) already satisfied · {checkpoint.evidence_count ?? 0} evidence record(s)
      </span>
      <button
        type="button"
        onClick={onRestore}
        disabled={busy === 'restore'}
        className="inline-flex items-center gap-1.5 rounded-md bg-blue-600 px-2.5 py-1 text-xs font-semibold text-white hover:bg-blue-700 disabled:opacity-50"
      >
        <RotateCcw className="h-3.5 w-3.5" />
        {busy === 'restore' ? 'Restoring…' : 'Restore session'}
      </button>
    </div>
  );
}

/** Which of the sample's fraud preconditions the run actually reached. */
function AssertionMatrix({
  assertions,
}: {
  assertions: ReturnType<typeof useResilience>['assertions'];
}) {
  if (!assertions?.assertions?.length) return null;

  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <h4 className="text-sm font-semibold text-slate-900">Execution Triggers</h4>
        <span className="text-xs text-slate-600">
          {assertions.fired_count}/{assertions.total_count} triggers activated
        </span>
      </div>

      {assertions.incomplete_exercise && (
        <div className="mb-3 rounded-md border border-amber-200 bg-amber-50/50 px-3 py-2.5 shadow-sm">
          <div className="flex items-start gap-2">
            <ShieldAlert className="h-4 w-4 text-amber-600 mt-0.5 shrink-0" />
            <div>
              <p className="text-xs font-semibold text-amber-900">
                Incomplete Analysis: The sample remained dormant
              </p>
              <p className="mt-1 text-xs leading-relaxed text-amber-800/90">
                We didn't observe any malicious behavior, but that doesn't necessarily mean it's safe. Many banking trojans wait for a specific trigger—like an OTP SMS, a targeted banking app opening, or an accessibility permission—before waking up. Our confidence in this scan is lower because no triggers fired.
              </p>
            </div>
          </div>
        </div>
      )}

      <ul className="divide-y divide-slate-100 rounded-md border border-slate-200">
        {assertions.assertions.map((a) => (
          <li key={a.key} className="flex items-start gap-2.5 px-3 py-2">
            {a.fired ? (
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600" />
            ) : (
              <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600" />
            )}
            <div className="min-w-0">
              <p className="text-xs font-semibold text-slate-900">{a.label}</p>
              <p className="mt-0.5 break-words text-xs text-slate-600">
                {a.fired ? a.evidence || 'Observed' : a.remediation}
              </p>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

/**
 * The sequence as it executes, one line per step.
 *
 * Driven by the live event stream rather than by a timer: every line the
 * analyst reads corresponds to a device command that has already returned, so
 * a step that the device refused shows as failed at the moment it fails
 * instead of at the end.
 */
function AntiEvasionProgressList({ steps }: { steps: AntiEvasionStepState[] }) {
  if (!steps.length) return null;

  const ICONS = {
    pending: <Circle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-300" />,
    running: <Loader2 className="mt-0.5 h-3.5 w-3.5 shrink-0 animate-spin text-blue-600" />,
    done: <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-600" />,
    failed: <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-red-600" />,
  } as const;

  return (
    <ul className="mt-2 space-y-1.5 rounded-md border border-slate-200 bg-slate-50 px-3 py-2">
      {steps.map((s) => (
        <li key={s.key} className="flex items-start gap-2">
          {ICONS[s.status]}
          <div className="min-w-0">
            <p
              className={`text-xs font-semibold ${
                s.status === 'pending' ? 'text-slate-400' : 'text-slate-800'
              }`}
            >
              {s.label}
            </p>
            {(s.detail || s.description) && (
              <p className="text-xs text-slate-600">{s.detail || s.description}</p>
            )}
          </div>
        </li>
      ))}
    </ul>
  );
}

const VERDICT_STYLE: Record<
  string,
  { border: string; title: string; icon: JSX.Element }
> = {
  MALWARE_DETONATED: {
    border: 'border-red-300 bg-red-50 text-red-900',
    title: 'MALWARE DETONATED (dormancy broken)',
    icon: <ShieldAlert className="h-4 w-4 shrink-0 text-red-700" />,
  },
  NO_CHANGES_OBSERVED: {
    border: 'border-emerald-200 bg-emerald-50 text-emerald-900',
    title: 'NO SUSPICIOUS BEHAVIOUR OBSERVED',
    icon: <ShieldCheck className="h-4 w-4 shrink-0 text-emerald-700" />,
  },
  NO_RUNTIME_TELEMETRY: {
    border: 'border-slate-300 bg-slate-50 text-slate-800',
    title: 'NOT OBSERVED - no hook stream was attached',
    icon: <EyeOff className="h-4 w-4 shrink-0 text-slate-600" />,
  },
};

/** Device-local clock reading, with the date when the warp crosses midnight. */
function clockLabel(ms: number, showDate: boolean): string {
  const d = new Date(ms);
  return d.toLocaleString(undefined, {
    ...(showDate ? { weekday: 'short' as const } : {}),
    hour: '2-digit',
    minute: '2-digit',
  });
}

const SEEDED_LABEL: Record<string, string> = {
  contacts: 'contacts',
  calls: 'call-log entries',
  sms: 'bank SMS',
  photos: 'photos',
};

/**
 * What the sequence did to the device, before what the sample did about it.
 *
 * This block is the answer to "did the button work?". The verdict below it can
 * legitimately be "nothing observed" - a benign app really does ignore all of
 * this - and without the applied changes beside it there is no way to tell
 * that from a control that silently failed.
 */
function AppliedChangesBlock({ applied }: { applied: AntiEvasionApplied }) {
  const crossesDay =
    new Date(applied.clock_before_ms).getDate() !== new Date(applied.clock_after_ms).getDate();

  // What the device *holds* is the fact that matters - an emptiness check does
  // not care which run wrote the rows. What this run wrote is reported second,
  // because on a sandbox that is reused it is legitimately zero.
  const held = ['contacts', 'calls', 'sms', 'photos']
    .map((key) => ({
      key,
      total: (applied.seeded[key] ?? 0) + (applied.already_present[key] ?? 0),
      written: applied.seeded[key] ?? 0,
    }))
    .filter((row) => row.total > 0);
  const writtenNow = held.filter((row) => row.written > 0);
  const attempted = Object.keys(applied.seeded).length + Object.keys(applied.already_present).length;

  return (
    <div className="mb-2 rounded-md border border-slate-200 bg-white/70 px-3 py-2">
      <p className="text-[13px] font-semibold uppercase tracking-wide text-slate-500">
        Applied to the device
      </p>

      {applied.clock_before_ms > 0 && (
        <p className="mt-1 text-xs text-slate-800">
          <Clock className="mr-1 inline h-3.5 w-3.5 text-slate-500 align-[-2px]" />
          Clock{' '}
          <span className="font-mono">{clockLabel(applied.clock_before_ms, crossesDay)}</span>
          {' → '}
          <span className="font-mono font-semibold">
            {clockLabel(applied.clock_after_ms, crossesDay)}
          </span>{' '}
          ({applied.clock_shift_hours >= 0 ? '+' : ''}
          {applied.clock_shift_hours.toFixed(1)}h)
          {applied.jobs_forced > 0 && ` · ${applied.jobs_forced} scheduled job(s) forced`}
          {applied.doze_cycled && ' · Doze cycled'}
        </p>
      )}

      {applied.battery_level !== null && (
        <p className="mt-0.5 text-xs text-slate-800">
          <BatteryMedium className="mr-1 inline h-3.5 w-3.5 text-slate-500 align-[-2px]" />
          Battery pinned to {applied.battery_level}%, discharging
        </p>
      )}

      {held.length > 0 && (
        <p className="mt-0.5 text-xs text-slate-800">
          <UserPlus className="mr-1 inline h-3.5 w-3.5 text-slate-500 align-[-2px]" />
          Device history:{' '}
          {held.map((row) => `${row.total} ${SEEDED_LABEL[row.key] ?? row.key}`).join(' · ')}
        </p>
      )}

      {held.length > 0 && (
        <p className="mt-0.5 pl-[18px] text-[13px] text-slate-500">
          {writtenNow.length > 0
            ? `${writtenNow
                .map((row) => `+${row.written} ${SEEDED_LABEL[row.key] ?? row.key}`)
                .join(' · ')} written by this run`
            : 'already present from an earlier seed - nothing re-written'}
        </p>
      )}

      {held.length === 0 && attempted > 0 && (
        <p className="mt-0.5 text-xs text-red-800">
          No provider accepted a write - the device history is unchanged.
        </p>
      )}
    </div>
  );
}

/** Short column headings for the delta chips - the full labels are a sentence each. */
const METRIC_SHORT: Record<string, string> = {
  sms_reads: 'SMS reads',
  c2_requests: 'C2 calls',
  accessibility_events: 'A11y scrapes',
  overlay_events: 'Overlay draws',
  overlay_windows: 'Overlay windows',
  accessibility_service_bound: 'A11y bound',
  network_connections: 'TCP conns',
};

/**
 * The before/after result, in one block.
 *
 * Chips rather than a four-column table: the analyst needs to see at a glance
 * which counter moved, and seven rows of before/after/delta buried that under
 * arithmetic. The numbers are all still here - `2 → 8` is the evidence for the
 * verdict, and a clean run showing `0 → 0` is the evidence that the zeros were
 * measured rather than assumed.
 *
 * Metrics the device would not surface are collapsed into a single trailing
 * line instead of taking a chip each. They still may not read as zero: a gap in
 * observation is not a finding about the sample.
 */
function AntiEvasionVerdictCard({
  result,
  fromRun = false,
}: {
  result: AntiEvasionResult;
  fromRun?: boolean;
}) {
  const style = VERDICT_STYLE[result.verdict] ?? VERDICT_STYLE.NO_RUNTIME_TELEMETRY;
  const observable = result.deltas.filter((d) => d.observable);
  const unavailable = result.deltas.filter((d) => !d.observable);
  const stepsRun = result.steps.filter((s) => s.ok).length;

  return (
    <div className={`mt-2 rounded-md border px-3 py-2.5 ${style.border}`}>
      <div className="mb-2 flex items-start gap-2">
        {style.icon}
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline justify-between gap-x-3">
            <p className="text-xs font-semibold tracking-wide">{style.title}</p>
            <span className="text-[13px] font-medium opacity-70">
              {fromRun ? 'measured during the analysis run' : 'measured just now'}
            </span>
          </div>
          <p className="mt-1 text-xs leading-relaxed opacity-90">{result.summary}</p>
        </div>
      </div>

      {result.applied_changes && <AppliedChangesBlock applied={result.applied_changes} />}

      {observable.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {observable.map((d) => {
            const moved = (d.delta ?? 0) > 0;
            return (
              <span
                key={d.key}
                title={`${d.label} - ${d.meaning}`}
                className={`inline-flex items-baseline gap-1.5 rounded border px-2 py-1 text-[13px] ${
                  moved && d.threat_class
                    ? 'border-red-400 bg-white/70 font-semibold text-red-800'
                    : 'border-current/20 bg-white/50'
                }`}
              >
                <span className="opacity-80">{METRIC_SHORT[d.key] ?? d.label}</span>
                <span className="font-mono tabular-nums">
                  {d.before} → {d.after}
                </span>
                {moved && <span className="font-mono">(+{d.delta})</span>}
              </span>
            );
          })}
        </div>
      )}

      <p className="mt-2 text-[13px] leading-relaxed opacity-75">
        {stepsRun}/{result.steps.length} step(s) accepted · {result.duration_seconds.toFixed(1)}s ·{' '}
        {result.device_serial}
        {result.package_name ? ` · ${result.package_name}` : ''}
        {unavailable.length > 0 && (
          <>
            {' · '}
            {unavailable.length} metric(s) not readable on this device (
            {unavailable.map((d) => METRIC_SHORT[d.key] ?? d.key).join(', ')})
          </>
        )}
      </p>

      {result.errors.length > 0 && (
        <p className="mt-1 text-[13px] leading-relaxed opacity-80">
          {result.errors.slice(0, 2).join(' ')}
        </p>
      )}
    </div>
  );
}

/** AI forensic suggestions with one-click actions. */
function SuggestionsDrawer({
  suggestions,
  busy,
  onAntiEvade,
}: {
  suggestions: Suggestion[];
  busy: string | null;
  onAntiEvade: (personaId: string) => void;
}) {
  const [open, setOpen] = useState(true);
  if (!suggestions.length) return null;

  // Both executable remediations - "warp the clock" and "seed a persona" - are
  // steps of the one sequence now, and running either alone is what made an
  // evasive sample look inert. The button runs the whole thing.
  const runAction = (s: Suggestion) =>
    onAntiEvade(String(s.action?.persona_id ?? 'default_retail_user'));

  // Only actions the backend can actually execute get a button. The rest are
  // advisory - offering a dead button would be worse than offering none.
  const executable = new Set(['time_warp', 'seed_persona']);

  return (
    <div>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="mb-2 flex w-full items-center justify-between gap-2 text-left hover:bg-slate-50 rounded p-1 -ml-1 transition-colors"
      >
        <span className="flex items-center gap-1.5 text-sm font-semibold text-slate-900">
          <Lightbulb className="h-4 w-4 text-amber-500" />
          Recommended Actions ({suggestions.length})
        </span>
        <ChevronDown
          className={`h-4 w-4 text-slate-500 transition-transform ${open ? 'rotate-180' : ''}`}
        />
      </button>

      {open && (
        <ul className="space-y-2">
          {suggestions.map((s) => (
            <li
              key={s.suggestion_id}
              className={`rounded-md border px-3 py-2.5 shadow-sm transition-colors ${
                PRIORITY_STYLE[s.priority] ?? PRIORITY_STYLE.MEDIUM
              }`}
            >
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded-sm ${
                      s.priority === 'CRITICAL' ? 'bg-red-200/50 text-red-900' :
                      s.priority === 'HIGH' ? 'bg-amber-200/50 text-amber-900' :
                      'bg-slate-200/50 text-slate-700'
                    }`}>
                      {s.priority}
                    </span>
                    <p className="text-xs font-semibold">
                      {s.title}
                    </p>
                  </div>
                  <p className="mt-1 text-xs leading-relaxed opacity-90 text-slate-700">{s.rationale}</p>
                  {s.threat_context && (
                    <p className="mt-1 text-[11px] font-medium text-slate-500">{s.threat_context}</p>
                  )}
                </div>
                {executable.has(s.action?.type) && (
                  <button
                    type="button"
                    onClick={() => runAction(s)}
                    disabled={busy !== null}
                    className="inline-flex shrink-0 items-center gap-1 rounded bg-slate-900 px-2 py-1 text-xs font-semibold text-white hover:bg-slate-700 disabled:opacity-50"
                  >
                    <Zap className="h-3 w-3" />
                    Run
                  </button>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/**
 * Investigation resilience controls.
 *
 * Grouped into one panel because they are one workflow: the analyst reads the
 * assertion matrix, sees which precondition was never met, and reaches for the
 * control that meets it.
 */
export default function ResiliencePanel({
  sessionId,
  packageName = '',
  antiEvasion = null,
}: {
  sessionId?: string;
  packageName?: string;
  /**
   * The sequence the sandbox already ran during dynamic analysis.
   *
   * Shown without the analyst asking, because that run is the one with real
   * numbers in it: it happened while the sample's process was live and its
   * hooks were counting. Re-running the sequence from this panel afterwards
   * measures a device the sample is no longer on.
   */
  antiEvasion?: AntiEvasionResult | null;
}) {
  const r = useResilience(sessionId, packageName);
  const [persona, setPersona] = useState('default_retail_user');

  if (!sessionId) return null;

  // A sequence the analyst just ran wins over the stored one - it is the more
  // recent measurement of the same device.
  const antiEvasionResult = r.antiEvasion ?? antiEvasion;

  return (
    <SocCard>
      <div className="space-y-4 px-4 py-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-sm font-semibold text-slate-900">Investigation resilience</h3>
          <span
            className={`inline-flex items-center gap-1 text-xs ${
              r.live ? 'text-emerald-700' : 'text-slate-500'
            }`}
            title={r.live ? 'Live event stream connected' : 'Polling for updates'}
          >
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                r.live ? 'bg-emerald-500' : 'bg-slate-400'
              }`}
            />
            {r.live ? 'Live' : 'Polling'}
          </span>
        </div>

        {r.error && (
          <p className="rounded border border-red-200 bg-red-50 px-2.5 py-1.5 text-xs text-red-800">
            {r.error}
          </p>
        )}

        <CheckpointPill checkpoint={r.checkpoint} busy={r.busy} onRestore={r.restore} />

        <AssertionMatrix assertions={r.assertions} />

        {/* Time warp and persona seeding, as one sequence.
            They were separate buttons, which made the case they exist for -
            a sample that unpacks only when BOTH a timer has elapsed and the
            device looks used - the one case an analyst had to assemble by
            hand, in the right order, before the observation window closed. */}
        <div>
          <h4 className="mb-2 flex items-center gap-1.5 text-sm font-semibold text-slate-900">
            <Zap className="h-4 w-4 text-indigo-500" />
            Automated Evasion Tests
          </h4>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => r.antiEvade(persona)}
              disabled={r.busy !== null}
              className="inline-flex items-center gap-1.5 rounded bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700 disabled:opacity-50 shadow-sm transition-colors"
            >
              {r.busy === 'anti-evasion' ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Zap className="h-3.5 w-3.5" />
              )}
              {r.busy === 'anti-evasion'
                ? 'Running tests…'
                : 'Run Automated Evasion Tests (Time Skip & Fake Data)'}
            </button>
            <select
              value={persona}
              onChange={(e) => setPersona(e.target.value)}
              disabled={r.busy !== null}
              className="rounded border border-slate-300 px-2 py-1 text-xs text-slate-700 disabled:opacity-50"
            >
              {(r.personas.length
                ? r.personas
                : [
                    {
                      persona_id: 'default_retail_user',
                      display_name: 'Retail banking customer (default)',
                      contacts: 0,
                      messages: 0,
                      calls: 0,
                      photos: 0,
                      description: '',
                    },
                  ]
              ).map((p) => (
                <option key={p.persona_id} value={p.persona_id}>
                  {p.display_name}
                </option>
              ))}
            </select>
          </div>
          <p className="mt-1.5 text-xs text-slate-500 leading-relaxed max-w-4xl">
            Fast-forwards the device clock by 24 hours to bypass timers, and simulates a real user by adding fake contacts, calls, messages, and photos. This helps wake up malware that checks if the device is a real phone before attacking.
          </p>

          {(r.busy === 'anti-evasion' || (!r.antiEvasion && r.antiEvasionSteps.length > 0)) && (
            <AntiEvasionProgressList steps={r.antiEvasionSteps} />
          )}
          {antiEvasionResult && r.busy !== 'anti-evasion' && (
            <AntiEvasionVerdictCard
              result={antiEvasionResult}
              fromRun={antiEvasionResult === antiEvasion}
            />
          )}
        </div>

        <SuggestionsDrawer
          suggestions={r.suggestions}
          busy={r.busy}
          onAntiEvade={(personaId) => r.antiEvade(personaId)}
        />

        {r.events.length > 0 && (
          <div>
            <h4 className="mb-1.5 text-sm font-semibold text-slate-900">Recent activity</h4>
            <ul className="space-y-1">
              {r.events.slice(0, 6).map((e, i) => (
                <li key={`${e.timestamp}-${i}`} className="text-xs text-slate-600">
                  <span className="font-mono text-slate-800">{e.event}</span>
                  {' · '}
                  {new Date(e.timestamp * 1000).toLocaleTimeString()}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </SocCard>
  );
}

