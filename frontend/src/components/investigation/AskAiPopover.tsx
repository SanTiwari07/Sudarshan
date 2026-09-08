import { useState } from 'react';
import { Sparkles, Loader2 } from 'lucide-react';
import { API_BASE, authHeaders } from '../../config';

/**
 * "What is this?" for one technical artifact.
 *
 * An analyst reading `Ldalvik/system/DexClassLoader;` in a table either
 * already knows what it means or leaves the tool to find out. This asks in
 * place.
 *
 * Fetched on click, never on render. Pre-computing an explanation for every
 * row would bill a model call for the majority of rows nobody ever asks
 * about, and would slow the initial page load to do it.
 *
 * The response is model commentary about attacker-controlled input, so it is
 * rendered as plain text inside a panel that says so. It is never presented as
 * a finding and never contributes to the risk score.
 */

interface ExplainResponse {
  text: string;
  source: 'model' | 'decoded' | 'refused' | 'unavailable';
  decoded?: string;
  encoding?: string;
  advisory?: boolean;
  notes?: string[];
}

const SOURCE_LABEL: Record<ExplainResponse['source'], string> = {
  model: 'AI-generated explanation — advisory, not a finding',
  decoded: 'Decoded locally — exact',
  refused: 'Not sent to the model',
  unavailable: 'Explanation unavailable',
};

export function AskAiPopover({
  value,
  kind = 'api',
  className = '',
}: {
  value: string;
  kind?: 'api' | 'string';
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ExplainResponse | null>(null);
  const [error, setError] = useState('');

  const load = async () => {
    if (result || loading) return;
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${API_BASE}/explain/artifact`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ value, kind }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setResult((await res.json()) as ExplainResponse);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Request failed');
    } finally {
      setLoading(false);
    }
  };

  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (next) void load();
  };

  return (
    <span className={`relative inline-flex ${className}`}>
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          e.preventDefault();
          toggle();
        }}
        aria-expanded={open}
        aria-label={`Ask AI about ${value}`}
        title="Ask AI what this is"
        className="inline-flex shrink-0 rounded-full p-0.5 text-slate-500 hover:text-violet-600 focus:outline-none focus-visible:ring-2 focus-visible:ring-violet-500/40"
      >
        {loading ? (
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
        ) : (
          <Sparkles className="h-3.5 w-3.5" />
        )}
      </button>

      {open && (
        <div
          role="dialog"
          className="absolute left-0 top-6 z-40 w-80 rounded-md border border-slate-200 bg-white shadow-lg p-3"
        >
          <div className="flex items-start justify-between gap-2 mb-1.5">
            <span className="font-mono text-[13px] text-slate-500 break-all">
              {value.length > 80 ? `${value.slice(0, 78)}…` : value}
            </span>
            <button
              type="button"
              onClick={() => setOpen(false)}
              className="text-slate-500 hover:text-slate-700 text-xs shrink-0"
              aria-label="Close"
            >
              ✕
            </button>
          </div>

          {loading && <p className="text-xs text-slate-500">Asking…</p>}
          {error && <p className="text-xs text-red-600">Could not load: {error}</p>}

          {result && (
            <>
              {result.decoded && (
                <div className="mb-2">
                  <div className="text-[13px] font-semibold uppercase tracking-wider text-slate-500">
                    Decoded ({result.encoding})
                  </div>
                  <code className="block text-[13px] bg-slate-50 border border-slate-200 rounded p-1.5 break-all text-slate-800">
                    {result.decoded}
                  </code>
                </div>
              )}

              <p className="text-xs text-slate-700 leading-relaxed whitespace-pre-line">
                {result.text}
              </p>

              {result.notes?.map((note, i) => (
                <p key={i} className="mt-1 text-[13px] text-slate-500">
                  · {note}
                </p>
              ))}

              {/*
                Always shown. The distinction between an observed finding and a
                model's commentary on it is the whole reason this panel is
                separate from the tables around it.
              */}
              <p
                className={`mt-2 pt-1.5 border-t border-slate-100 text-[13px] ${
                  result.source === 'refused' ? 'text-amber-700' : 'text-slate-500'
                }`}
              >
                {SOURCE_LABEL[result.source] ?? 'Advisory'}
              </p>
            </>
          )}
        </div>
      )}
    </span>
  );
}

export default AskAiPopover;
