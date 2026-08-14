import { useState } from 'react';
import {
  AlarmClock,
  CheckCircle2,
  ChevronDown,
  Clock,
  Lightbulb,
  RotateCcw,
  Save,
  UserPlus,
  XCircle,
  Zap,
} from 'lucide-react';
import SocCard from '../ui/Card';
import { useResilience } from '../../hooks/useResilience';
import type { Suggestion } from '../../lib/resilience';

const PRIORITY_STYLE: Record<string, string> = {
  CRITICAL: 'bg-red-50 text-red-800 border-red-200',
  HIGH: 'bg-amber-50 text-amber-900 border-amber-200',
  MEDIUM: 'bg-slate-50 text-slate-700 border-slate-200',
};

const WARP_PRESETS = [1, 6, 24];

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
        <h4 className="text-sm font-semibold text-slate-900">Execution assertion matrix</h4>
        <span className="text-xs text-slate-600">
          {assertions.fired_count}/{assertions.total_count} trigger conditions reached
        </span>
      </div>

      {assertions.incomplete_exercise && (
        <div className="mb-3 rounded-md border border-amber-300 bg-amber-50 px-3 py-2">
          <p className="text-xs font-semibold text-amber-900">
            INCOMPLETE EXERCISE — this run did not exercise the sample
          </p>
          <p className="mt-1 text-xs leading-relaxed text-amber-900/90">
            No trigger condition was reached and no threat behaviour was observed.
            Absence of evidence is not evidence of absence: a trojan waiting on a
            target app, an OTP, an accessibility grant or a dormancy timer produces
            exactly this result. Confidence is reduced by 50%.
          </p>
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

/** AI forensic suggestions with one-click actions. */
function SuggestionsDrawer({
  suggestions,
  busy,
  onWarp,
  onSeed,
}: {
  suggestions: Suggestion[];
  busy: string | null;
  onWarp: (hours: number, force: boolean) => void;
  onSeed: (personaId: string) => void;
}) {
  const [open, setOpen] = useState(true);
  if (!suggestions.length) return null;

  const runAction = (s: Suggestion) => {
    const action = s.action || { type: 'none' };
    if (action.type === 'time_warp') {
      onWarp(Number(action.hours ?? 24), Boolean(action.force_jobs ?? true));
    } else if (action.type === 'seed_persona') {
      onSeed(String(action.persona_id ?? 'default_retail_user'));
    }
  };

  // Only actions the backend can actually execute get a button. The rest are
  // advisory - offering a dead button would be worse than offering none.
  const executable = new Set(['time_warp', 'seed_persona']);

  return (
    <div>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="mb-2 flex w-full items-center justify-between gap-2 text-left"
      >
        <span className="flex items-center gap-1.5 text-sm font-semibold text-slate-900">
          <Lightbulb className="h-4 w-4 text-amber-500" />
          Forensic suggestions ({suggestions.length})
        </span>
        <ChevronDown
          className={`h-4 w-4 text-slate-400 transition-transform ${open ? 'rotate-180' : ''}`}
        />
      </button>

      {open && (
        <ul className="space-y-2">
          {suggestions.map((s) => (
            <li
              key={s.suggestion_id}
              className={`rounded-md border px-3 py-2 ${
                PRIORITY_STYLE[s.priority] ?? PRIORITY_STYLE.MEDIUM
              }`}
            >
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0">
                  <p className="text-xs font-semibold">
                    [{s.priority}] {s.title}
                  </p>
                  <p className="mt-1 text-xs leading-relaxed opacity-90">{s.rationale}</p>
                  {s.threat_context && (
                    <p className="mt-1 text-xs italic opacity-75">{s.threat_context}</p>
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
}: {
  sessionId?: string;
  packageName?: string;
}) {
  const r = useResilience(sessionId, packageName);
  const [persona, setPersona] = useState('default_retail_user');

  if (!sessionId) return null;

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

        {/* Time warp */}
        <div>
          <h4 className="mb-2 flex items-center gap-1.5 text-sm font-semibold text-slate-900">
            <Clock className="h-4 w-4 text-slate-500" />
            Time warp
          </h4>
          <div className="flex flex-wrap items-center gap-2">
            {WARP_PRESETS.map((h) => (
              <button
                key={h}
                type="button"
                onClick={() => r.warp(h, false)}
                disabled={r.busy !== null}
                className="rounded border border-slate-300 px-2.5 py-1 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-50"
              >
                +{h}h
              </button>
            ))}
            <button
              type="button"
              onClick={() => r.warp(24, true)}
              disabled={r.busy !== null}
              className="inline-flex items-center gap-1 rounded bg-amber-600 px-2.5 py-1 text-xs font-semibold text-white hover:bg-amber-700 disabled:opacity-50"
            >
              <AlarmClock className="h-3.5 w-3.5" />
              {r.busy === 'warp' ? 'Warping…' : '+24h & force jobs'}
            </button>
          </div>
          <p className="mt-1 text-xs text-slate-500">
            Advances the device clock and releases deferred WorkManager /
            AlarmManager work.
          </p>
        </div>

        {/* Persona seeding */}
        <div>
          <h4 className="mb-2 flex items-center gap-1.5 text-sm font-semibold text-slate-900">
            <UserPlus className="h-4 w-4 text-slate-500" />
            Device persona
          </h4>
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={persona}
              onChange={(e) => setPersona(e.target.value)}
              className="rounded border border-slate-300 px-2 py-1 text-xs text-slate-700"
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
                  {p.contacts ? ` — ${p.contacts} contacts, ${p.messages} SMS` : ''}
                </option>
              ))}
            </select>
            <button
              type="button"
              onClick={() => r.seed(persona)}
              disabled={r.busy !== null}
              className="rounded bg-slate-900 px-2.5 py-1 text-xs font-semibold text-white hover:bg-slate-700 disabled:opacity-50"
            >
              {r.busy === 'seed' ? 'Seeding…' : 'Seed device'}
            </button>
          </div>
          <p className="mt-1 text-xs text-slate-500">
            Populates contacts, SMS, call log and photos. An empty device is a
            sandbox tell that evasive families check for.
          </p>
        </div>

        <SuggestionsDrawer
          suggestions={r.suggestions}
          busy={r.busy}
          onWarp={r.warp}
          onSeed={r.seed}
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
