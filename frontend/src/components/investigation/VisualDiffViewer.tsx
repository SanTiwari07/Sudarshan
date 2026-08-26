import { useMemo, useState } from 'react';
import { GitCompare, Palette, Type as TypeIcon, Layers } from 'lucide-react';
import type { VideAstNode, VideColorMatch, VideResult } from '../../App';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';

/**
 * Side-by-side comparison of the suspect UI against the matched banking
 * baseline: brand palette, structural signatures, screen labels, and the
 * normalised view-hierarchy AST.
 *
 * Everything rendered here comes from the deterministic comparer. The advisory
 * LLM assessment is shown separately and clearly labelled, so an analyst is
 * never reading a model's opinion as though it were the engine's verdict.
 */

type Props = {
  vide: VideResult;
};

function pct(value: number | undefined | null): string {
  if (value == null || Number.isNaN(value)) return '—';
  return `${Math.round(value * 100)}%`;
}

function Swatch({ hex, label }: { hex: string; label?: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span
        className="h-4 w-4 rounded border border-slate-300 shrink-0"
        style={{ backgroundColor: hex }}
        aria-hidden
      />
      <code className="text-[11px] font-mono text-slate-700">{hex}</code>
      {label && <span className="text-[11px] text-slate-500">{label}</span>}
    </span>
  );
}

/** Distance is on the redmean scale (0 = identical, ~765 = maximally far). */
function ColorRow({ match }: { match: VideColorMatch }) {
  const exact = match.distance <= 1;
  return (
    <li className="flex items-center justify-between gap-3 py-1.5 border-b border-slate-100 last:border-0">
      <Swatch hex={match.baseline} label="baseline" />
      <span className="text-slate-500 text-[11px] shrink-0">→</span>
      <Swatch hex={match.suspect} label="suspect" />
      <span
        className={`text-[11px] font-medium shrink-0 ${
          match.score >= 0.9 ? 'text-rose-700' : 'text-amber-700'
        }`}
      >
        {exact ? 'exact' : `Δ${match.distance}`} · {pct(match.score)}
      </span>
    </li>
  );
}

function AstTree({ node, depth = 0 }: { node: VideAstNode; depth?: number }) {
  const [open, setOpen] = useState(depth < 3);
  const children = node.children ?? [];
  const hasChildren = children.length > 0;

  return (
    <li className="leading-tight">
      <div className="flex items-baseline gap-1.5" style={{ paddingLeft: depth * 10 }}>
        {hasChildren ? (
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            className="text-slate-500 hover:text-slate-700 text-[10px] w-3 shrink-0"
            aria-label={open ? 'Collapse' : 'Expand'}
          >
            {open ? '▾' : '▸'}
          </button>
        ) : (
          <span className="w-3 shrink-0" />
        )}
        <code className="text-[11px] font-mono font-semibold text-slate-700">{node.role}</code>
        {node.tag && <span className="text-[10px] text-slate-500">{node.tag}</span>}
        {node.text && (
          <span className="text-[10px] text-slate-500 truncate max-w-[180px]" title={node.text}>
            “{node.text}”
          </span>
        )}
      </div>
      {hasChildren && open && (
        <ul>
          {children.map((child, i) => (
            <AstTree key={`${child.role}-${i}`} node={child} depth={depth + 1} />
          ))}
        </ul>
      )}
    </li>
  );
}

function Column({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="min-w-0 flex-1">
      <div className="mb-2">
        <p className="text-[11px] font-bold text-slate-700">{title}</p>
        {subtitle && <p className="text-[11px] text-slate-500 truncate">{subtitle}</p>}
      </div>
      {children}
    </div>
  );
}

export default function VisualDiffViewer({ vide }: Props) {
  const corpus = vide.corpus_compare;
  const semantic = vide.semantic_match;

  const ranked = useMemo(() => (corpus?.ranked ?? []).slice(0, 5), [corpus]);
  const colorMatches = corpus?.color_matches ?? [];
  const matchedStrings = corpus?.matched_strings ?? [];
  const signatures = corpus?.suspect_signatures ?? [];
  const ambiguous = corpus?.attribution?.ambiguous ?? false;
  const candidates = corpus?.attribution?.candidates ?? [];

  if (!corpus || (!corpus.institution_id && !ambiguous && ranked.length === 0)) {
    return null;
  }

  const bankLabel = corpus.institution_display || corpus.bank || corpus.institution_id || '—';

  return (
    <SocCard>
      <SectionHeader
        icon={<GitCompare className="h-4 w-4" />}
        title="Visual Diff — suspect vs banking baseline"
        subtitle={
          ambiguous
            ? 'Banking UI shape confirmed; brand attribution inconclusive'
            : `Matched against ${bankLabel}`
        }
        badge={
          <span
            className={`text-[11px] font-semibold px-2 py-0.5 rounded ${
              corpus.detected
                ? 'bg-rose-50 text-rose-700 border border-rose-200'
                : 'bg-slate-100 text-slate-600 border border-slate-200'
            }`}
          >
            {pct(corpus.confidence)} confidence
          </span>
        }
      />

      <div className="p-3.5 space-y-4 text-xs">
        {/* Attribution honesty banner. The corpus banks ship identical strings
            and structure, so colour is the only discriminator; when it does not
            separate them we say so instead of naming a bank. */}
        {ambiguous && (
          <div className="rounded border border-amber-200 bg-amber-50 p-2.5">
            <p className="font-semibold text-amber-900 text-[11px]">
              Attribution inconclusive
            </p>
            <p className="text-[11px] text-amber-800 mt-0.5">
              The suspect reproduces banking UI structure, but its brand palette did not
              separate one institution from the others
              {corpus.attribution?.margin != null
                ? ` (margin ${pct(corpus.attribution.margin)})`
                : ''}
              . No single bank is being asserted.
            </p>
            {candidates.length > 0 && (
              <p className="text-[11px] text-amber-800 mt-1">
                Candidates: <span className="font-mono">{candidates.join(', ')}</span>
              </p>
            )}
          </div>
        )}

        {/* Score axes */}
        <div className="grid grid-cols-3 gap-2">
          {[
            { label: 'Screen labels', value: corpus.scores?.string_containment, weight: '40%' },
            { label: 'Structure', value: corpus.scores?.structural, weight: '35%' },
            { label: 'Brand colour', value: corpus.scores?.color, weight: '25%' },
          ].map((axis) => (
            <div key={axis.label} className="rounded border border-slate-200 p-2">
              <p className="text-[10px] uppercase tracking-wide text-slate-500">
                {axis.label} <span className="text-slate-500">({axis.weight})</span>
              </p>
              <p className="text-sm font-bold text-slate-800 mt-0.5">{pct(axis.value)}</p>
            </div>
          ))}
        </div>

        {/* Palette + structure, side by side */}
        <div className="flex flex-col md:flex-row gap-5">
          <Column title="Brand palette" subtitle={`${colorMatches.length} colour(s) reproduced`}>
            {colorMatches.length > 0 ? (
              <ul className="space-y-0">
                {colorMatches.map((m) => (
                  <ColorRow key={`${m.baseline}-${m.suspect}`} match={m} />
                ))}
              </ul>
            ) : (
              <p className="text-[11px] text-slate-500">
                No brand colours from this baseline were found in the suspect.
              </p>
            )}
          </Column>

          <Column title="Structural signatures" subtitle="Screen archetypes detected">
            {signatures.length > 0 ? (
              <ul className="space-y-1">
                {signatures.map((sig) => (
                  <li key={sig}>
                    <code className="text-[11px] font-mono bg-slate-100 border border-slate-200 rounded px-1.5 py-0.5 text-slate-700">
                      {sig}
                    </code>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-[11px] text-slate-500">No screen archetype inferred.</p>
            )}
          </Column>
        </div>

        {/* Reproduced labels */}
        {matchedStrings.length > 0 && (
          <div>
            <p className="text-[11px] font-bold text-slate-700 mb-1.5 flex items-center gap-1.5">
              <TypeIcon className="h-3 w-3" /> Baseline labels reproduced ({matchedStrings.length})
            </p>
            <div className="flex flex-wrap gap-1">
              {matchedStrings.slice(0, 20).map((s) => (
                <span
                  key={s}
                  className="text-[11px] bg-rose-50 border border-rose-200 text-rose-800 rounded px-1.5 py-0.5"
                >
                  {s}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Ranked candidates */}
        {ranked.length > 1 && (
          <div>
            <p className="text-[11px] font-bold text-slate-700 mb-1.5 flex items-center gap-1.5">
              <Palette className="h-3 w-3" /> Baseline ranking
            </p>
            <table className="w-full text-[11px]">
              <thead>
                <tr className="text-slate-500 text-left border-b border-slate-200">
                  <th className="py-1 font-medium">Baseline</th>
                  <th className="py-1 font-medium text-right">Colour</th>
                  <th className="py-1 font-medium text-right">Confidence</th>
                </tr>
              </thead>
              <tbody>
                {ranked.map((row, i) => (
                  <tr
                    key={row.institution_id}
                    className={`border-b border-slate-100 last:border-0 ${
                      i === 0 ? 'font-semibold text-slate-900' : 'text-slate-600'
                    }`}
                  >
                    <td className="py-1">{row.display_name || row.institution_id}</td>
                    <td className="py-1 text-right">{pct(row.scores?.color)}</td>
                    <td className="py-1 text-right">{pct(row.confidence)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Suspect AST */}
        {vide.suspect_ast && (
          <details className="rounded border border-slate-200">
            <summary className="cursor-pointer select-none px-2.5 py-1.5 text-[11px] font-bold text-slate-700 flex items-center gap-1.5">
              <Layers className="h-3 w-3" /> Suspect view hierarchy
              {vide.suspect_profile_summary?.ast_node_count
                ? ` (${vide.suspect_profile_summary.ast_node_count} nodes, depth ${
                    vide.suspect_profile_summary.ast_depth ?? '?'
                  })`
                : ''}
            </summary>
            <div className="px-2.5 py-2 max-h-72 overflow-auto border-t border-slate-200 bg-slate-50/50">
              <ul>
                <AstTree node={vide.suspect_ast} />
              </ul>
            </div>
          </details>
        )}

        {/* Advisory LLM assessment - explicitly separated from the verdict. */}
        {semantic && semantic.status === 'OK' && (
          <div className="rounded border border-sky-200 bg-sky-50/60 p-2.5">
            <p className="text-[11px] font-bold text-sky-900">
              AI design assessment
              <span className="ml-1.5 font-normal normal-case text-sky-700">
                advisory — does not affect the verdict
              </span>
            </p>
            {semantic.impersonation_rationale && (
              <p className="text-[11px] text-sky-900 mt-1">{semantic.impersonation_rationale}</p>
            )}
            {(semantic.matched_design_elements ?? []).length > 0 && (
              <p className="text-[11px] text-sky-800 mt-1">
                <span className="font-medium">Matches:</span>{' '}
                {semantic.matched_design_elements!.join('; ')}
              </p>
            )}
            {(semantic.divergences ?? []).length > 0 && (
              <p className="text-[11px] text-sky-800 mt-0.5">
                <span className="font-medium">Divergences:</span>{' '}
                {semantic.divergences!.join('; ')}
              </p>
            )}
            {semantic.injection_suspected && (
              <p className="text-[11px] text-rose-800 mt-1 font-medium">
                Prompt-injection markers were present in this sample's UI strings; treat the
                assessment above with caution.
              </p>
            )}
          </div>
        )}
      </div>
    </SocCard>
  );
}
