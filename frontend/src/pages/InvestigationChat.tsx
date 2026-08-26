import { useState, useRef, useEffect, useMemo } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  Shield, Square, AlertTriangle, CheckCircle2,
  Copy, CopyCheck, Info, AlertOctagon, Terminal, ArrowUpRight, BarChart2, HelpCircle, RotateCcw, ArrowUp
} from 'lucide-react';
import type { FraudCardData } from '../App';
import { API_BASE, authHeaders } from '../config';
import { useAnalysis } from '../context/AnalysisContext';
import { useInvestigationUI } from '../context/InvestigationUIContext';
import { buildCaseQuestions, buildChatGreeting } from '../lib/caseQuestions';
import { TYPOGRAPHY } from '../theme/typography';

/** How long a stream may go silent before the client calls the answer finished. */
const IDLE_TIMEOUT_MS = 45_000;

/*
 * How often a growing answer is painted, in ms.
 *
 * Every token used to call setMessages, and every render re-ran
 * autoFormatInvestigationText over the *whole* accumulated answer - a code
 * fence extraction, twenty section-heading regexes, a per-line pass and a
 * paragraph split. Cost per token therefore grew with the length of the answer
 * already on screen, so the work to render one reply was quadratic in its
 * size. Short replies looked fine; long ones froze the tab partway through,
 * which is what "it hangs after some lines" was.
 *
 * Painting on a 60ms floor caps that at ~16 renders a second no matter how
 * fast the tokens arrive, and no reader can tell the difference.
 */
const STREAM_PAINT_MS = 60;

const GROUP_LABEL = {
  decision: 'The verdict',
  evidence: 'The evidence',
  action: 'Next steps',
} as const;

const STARTER_KINDS = ['decision', 'evidence', 'action'] as const;
import { useCaseLinks } from '../hooks/useCaseLinks';
import type { CaseSection } from '../lib/caseRoutes';

// ─── Interfaces ──────────────────────────────────────────────────────────────

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  streaming?: boolean;
  sectionsUsed?: string[];
  followUps?: string[];
  timestamp: Date;
}

// ─── Component 3: Callout ──────────────────────────────────────────────────────

function Callout({ type, title, children }: { type: 'info' | 'warning' | 'critical' | 'success'; title?: string; children: React.ReactNode }) {
  const configs = {
    info: { bg: 'bg-blue-50/80', border: 'border-blue-200', text: 'text-blue-900', icon: <Info className="h-4 w-4 text-blue-600 flex-shrink-0 mt-0.5" /> },
    warning: { bg: 'bg-amber-50/80', border: 'border-amber-200', text: 'text-amber-900', icon: <AlertTriangle className="h-4 w-4 text-amber-600 flex-shrink-0 mt-0.5" /> },
    critical: { bg: 'bg-red-50/80', border: 'border-red-200', text: 'text-red-900', icon: <AlertOctagon className="h-4 w-4 text-red-600 flex-shrink-0 mt-0.5" /> },
    success: { bg: 'bg-emerald-50/80', border: 'border-emerald-200', text: 'text-emerald-900', icon: <CheckCircle2 className="h-4 w-4 text-emerald-600 flex-shrink-0 mt-0.5" /> },
  };
  const cfg = configs[type] || configs.info;

  return (
    <div className={`my-4 p-4 rounded-xl border ${cfg.border} ${cfg.bg} flex items-start gap-3 shadow-[0_1px_2px_rgba(0,0,0,0.02)]`}>
      {cfg.icon}
      <div className="space-y-1 text-xs leading-relaxed flex-1">
        {title && <div className={`font-semibold ${cfg.text} text-sm`}>{title}</div>}
        <div className="text-slate-800">{children}</div>
      </div>
    </div>
  );
}

// ─── Component 4: CodeBlock ────────────────────────────────────────────────────

function CodeBlock({ code, language }: { code: string; language?: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="my-4 rounded-xl overflow-hidden border border-slate-800 bg-slate-900 text-slate-100 shadow-[0_1px_2px_rgba(0,0,0,0.02)]">
      <div className="flex items-center justify-between px-4 py-2 bg-slate-950/80 border-b border-slate-800 text-[13px] font-mono text-slate-400">
        <span className="text-[13px] font-semibold uppercase tracking-[0.06em] flex items-center gap-1.5">
          <Terminal className="h-3.5 w-3.5 text-blue-400" />
          {language || 'code'}
        </span>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
        >
          {copied ? (
            <>
              <CopyCheck className="h-3 w-3 text-emerald-400" />
              <span className="text-emerald-400 font-semibold">Copied!</span>
            </>
          ) : (
            <>
              <Copy className="h-3 w-3" />
              <span>Copy</span>
            </>
          )}
        </button>
      </div>
      <pre className="p-4 text-xs font-mono overflow-x-auto whitespace-pre leading-relaxed text-emerald-400">
        <code>{code}</code>
      </pre>
    </div>
  );
}

// ─── Component 5: TableRenderer ────────────────────────────────────────────────

function TableRenderer({ headers, rows }: { headers: string[]; rows: string[][] }) {
  return (
    <div className="answer-block my-5 overflow-hidden rounded-xl border border-slate-200">
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead className="bg-slate-100/90 border-b border-slate-200">
            <tr>
              {headers.map((h, i) => (
                <th key={i} className="px-4 py-2.5 text-left font-sans text-[13px] font-medium text-slate-500">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 font-sans">
            {rows.map((row, rIdx) => (
              <tr key={rIdx} className="hover:bg-blue-50/50 transition-colors odd:bg-white even:bg-slate-50/50">
                {row.map((cell, cIdx) => (
                  <td key={cIdx} className="px-4 py-2.5 text-slate-800 whitespace-nowrap">
                    {cell.startsWith('`') && cell.endsWith('`') ? (
                      <code className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[13px] font-medium text-slate-700">
                        {cell.slice(1, -1)}
                      </code>
                    ) : (
                      cell
                    )}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Component 6: MarkdownRenderer ─────────────────────────────────────────────

// ─── Formatting Helpers ────────────────────────────────────────────────────────

function autoFormatInvestigationText(text: string): string {
  if (!text) return text;

  // 1. Preserve code blocks and embedded cards
  const codeBlockMatches: string[] = [];
  let processed = text.replace(/```[\s\S]*?```/g, match => {
    codeBlockMatches.push(match);
    return `__CODE_BLOCK_${codeBlockMatches.length - 1}__`;
  });

  // 2. Automatically detect section titles and convert to H2 headings
  const sectionKeywords = [
    'Investigation Summary', 'Executive Summary', 'Direct Answer',
    'Risk Scores', 'Risk Assessment', 'Key Decision Evidence',
    'Static Analysis Findings', 'Static Analysis',
    'Dynamic Analysis Findings', 'Dynamic Analysis',
    'Network Behaviour', 'Network Indicators', 'Network & C2',
    'Threat Intelligence', 'MITRE ATT&CK Mapping', 'MITRE Mapping',
    'Recommendation', 'Recommended Action', 'Conclusion',
    'Suggested Follow-up Questions', 'Suggested Questions'
  ];

  sectionKeywords.forEach(kw => {
    const regex = new RegExp(`(?:^|\\n)(?:---)?\\s*(${kw})\\s*:?\\s*(?:---)?(?=\\n|$)`, 'gi');
    processed = processed.replace(regex, `\n\n## $1\n\n`);
  });

  // 3. Convert inline comma lists into bullet lists if line matches item,item,item
  processed = processed.split('\n').map(line => {
    const trimmed = line.trim();
    if (!trimmed.startsWith('*') && !trimmed.startsWith('-') && !trimmed.startsWith('•') && !trimmed.startsWith('#')) {
      if (trimmed.includes(',') && trimmed.split(',').length >= 3 && trimmed.length < 150) {
        const items = trimmed.split(',').map(i => i.trim()).filter(Boolean);
        return items.map(item => `• ${item}`).join('\n');
      }
    }
    return line;
  }).join('\n');

  // 4. Auto-split long paragraphs (> 220 characters without line breaks)
  const paragraphs = processed.split(/\n\s*\n/);
  const formattedParagraphs = paragraphs.map(para => {
    const trimmed = para.trim();
    if (
      trimmed.includes('__CODE_BLOCK_') ||
      trimmed.startsWith('#') ||
      trimmed.startsWith('*') ||
      trimmed.startsWith('-') ||
      trimmed.startsWith('•') ||
      trimmed.startsWith('|') ||
      trimmed.startsWith('>') ||
      trimmed.startsWith('__PACKAGE_CARD') ||
      trimmed.startsWith('__RISK_CARD')
    ) {
      return para;
    }

    if (trimmed.length > 220) {
      const sentences = trimmed.match(/[^.!?]+[.!?]+(?:\s+|$)/g) || [trimmed];
      const chunks: string[] = [];
      let current = '';

      sentences.forEach(sentence => {
        if ((current + sentence).length > 200 && current.length > 0) {
          chunks.push(current.trim());
          current = sentence;
        } else {
          current += sentence;
        }
      });
      if (current.trim()) {
        chunks.push(current.trim());
      }
      return chunks.join('\n\n');
    }

    return para;
  });

  processed = formattedParagraphs.join('\n\n');

  // 5. Restore code blocks
  codeBlockMatches.forEach((code, idx) => {
    processed = processed.replace(`__CODE_BLOCK_${idx}__`, code);
  });

  return processed;
}

/*
 * What is worth marking inside a sentence, and how.
 *
 * The previous single pattern put an amber highlighter-pen fill behind every
 * match, which had three consequences worth naming:
 *
 * - Amber is the warning colour in this file's callouts, so a perfectly
 *   ordinary "0.0" read as a caution.
 * - It matched bare `Critical|High|Moderate|Low`, so the adjective in "a low
 *   final risk score" was marked as though it were a verdict.
 * - It matched `Sudarshan`, so the assistant highlighted its own name in its
 *   own greeting - visible in every conversation's first line.
 *
 * Two categories survive, because only two earn it. A measurement is set in
 * medium weight with tabular figures, so columns of scores line up and the eye
 * finds them without a colour telling it to. An identifier a reader may need
 * to copy - a MITRE technique, an Android permission - gets a quiet mono chip.
 * Neither is a fill, and neither carries a severity colour it has not earned.
 */
const MEASUREMENT = String.raw`\d{1,3}\.\d{1,2}\s*\/\s*100|\d{1,3}\.\d{1,2}%?|\d{1,3}%`;
const IDENTIFIER = String.raw`T\d{4}(?:\.\d{3})?|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+`;
/*
 * Boundaries, not `\b`.
 *
 * The old pattern was wrapped in `\b...\b`, and a trailing `\b` cannot match
 * after a `%` - both sides of that position are non-word characters. So the
 * `\d{1,3}%` alternative never fired: "a 60% confidence rating" went unmarked
 * for as long as the rule has existed. A lookahead for a word character does
 * what the `\b` was meant to do, and the lookbehind stops a version number
 * from being chopped up mid-string.
 */
const HIGHLIGHT_PATTERNS = new RegExp(
  `(?<![\\w.])(?:${MEASUREMENT}|${IDENTIFIER})(?!\\w)`,
  'g'
);

function highlightKeywords(text: string): React.ReactNode[] {
  if (!text) return [];

  const parts = text.split(HIGHLIGHT_PATTERNS);
  const matches = text.match(HIGHLIGHT_PATTERNS) || [];

  const result: React.ReactNode[] = [];
  parts.forEach((part, i) => {
    result.push(part);
    if (i < matches.length) {
      const match = matches[i];
      const isIdentifier = /^[A-Z]/.test(match);
      result.push(
        isIdentifier ? (
          <code
            key={i}
            className="mx-0.5 rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[13px] font-medium text-slate-700"
          >
            {match}
          </code>
        ) : (
          <span key={i} className="font-medium tabular-nums text-slate-900">
            {match}
          </span>
        )
      );
    }
  });

  return result;
}

// ─── Component 6: MarkdownRenderer ─────────────────────────────────────────────

function MarkdownRenderer({ content, isStreaming }: { content: string; isStreaming?: boolean }) {
  if (!content) return null;

  // Keyed on the text alone: a caret blinking on and off must not re-run the
  // whole formatting pass over the answer behind it.
  const blocks = useMemo(
    () => autoFormatInvestigationText(content).split(/(```[\s\S]*?```)/g),
    [content]
  );

  return (
    <div className="w-full min-w-0 space-y-3 font-sans text-[16px] leading-[1.7] text-slate-700">
      {blocks.map((block, bIdx) => {
        if (block.startsWith('```') && block.endsWith('```')) {
          const match = block.match(/^```(\w+)?\n([\s\S]*?)```$/);
          const lang = match ? match[1] : 'code';
          const code = match ? match[2] : block.slice(3, -3);
          return <CodeBlock key={bIdx} code={code.trim()} language={lang} />;
        }

        const lines = block.split('\n');
        const elements: React.ReactNode[] = [];
        let inTable = false;
        let tableHeaders: string[] = [];
        let tableRows: string[][] = [];
        let inList = false;
        let listItems: React.ReactNode[] = [];

        const flushTable = (key: string) => {
          if (inTable && tableHeaders.length > 0) {
            elements.push(<TableRenderer key={key} headers={tableHeaders} rows={tableRows} />);
            tableHeaders = [];
            tableRows = [];
            inTable = false;
          }
        };

        const flushList = (key: string) => {
          if (inList && listItems.length > 0) {
            elements.push(
              <ul key={key} className="answer-block my-4 max-w-[68ch] list-disc space-y-1.5 pl-5 font-normal leading-[1.7] text-slate-700 marker:text-slate-400">
                {listItems}
              </ul>
            );
            listItems = [];
            inList = false;
          }
        };

        lines.forEach((line, lIdx) => {
          const trimmed = line.trim();

          if (trimmed.startsWith('|') && trimmed.endsWith('|')) {
            flushList(`list-before-table-${lIdx}`);
            const cols = trimmed.split('|').slice(1, -1).map(c => c.trim());
            if (cols.every(c => /^[-:]+$/.test(c))) return;

            if (!inTable) {
              inTable = true;
              tableHeaders = cols;
            } else {
              tableRows.push(cols);
            }
            return;
          } else if (inTable) {
            flushTable(`table-${lIdx}`);
          }

          if (trimmed.startsWith('* ') || trimmed.startsWith('- ') || trimmed.startsWith('• ')) {
            flushTable(`table-before-list-${lIdx}`);
            inList = true;
            const itemText = trimmed.replace(/^[*•-]\s*/, '');
            listItems.push(
              <li key={`li-${lIdx}`} className="leading-relaxed my-1">
                {renderFormattedInline(itemText)}
              </li>
            );
            return;
          } else if (inList && trimmed) {
            flushList(`list-${lIdx}`);
          }

          if (!trimmed) {
            flushList(`list-empty-${lIdx}`);
            flushTable(`table-empty-${lIdx}`);
            return;
          }

          // Automatic Warning Callout Detection
          if (
            trimmed.toLowerCase().includes('no runtime events') ||
            trimmed.toLowerCase().includes('no malicious activity was observed') ||
            trimmed.toLowerCase().includes('anti-analysis detected') ||
            trimmed.toLowerCase().includes('instrumentation failed') ||
            trimmed.toLowerCase().includes('application crashed')
          ) {
            elements.push(
              <Callout key={lIdx} type="warning" title="Analysis Warning">
                {renderFormattedInline(trimmed)}
              </Callout>
            );
            return;
          }

          // Headings
          if (trimmed.startsWith('# ')) {
            elements.push(<h1 key={lIdx} className="font-sans text-xl font-semibold tracking-[-0.02em] text-slate-900 mt-6 mb-3 border-b border-slate-200 pb-2">{renderFormattedInline(trimmed.slice(2))}</h1>);
            return;
          }
          /*
           * A section heading is a heading.
           *
           * Every `##` used to become a filled, bordered, shadowed pill with a
           * shield icon on it, so "Direct Answer", "Executive Summary" and
           * "Key Decision Evidence" arrived as three identical blue banners
           * stacked down the page. Everything shouted at one volume, so
           * nothing ranked, and the shield - repeated verbatim on each - said
           * nothing at all. Rank now comes from weight, size and the space
           * above the line, which is what ranks a heading in any document a
           * bank would otherwise be reading.
           */
          if (trimmed.startsWith('## ') || trimmed.startsWith('### ')) {
            const headingTitle = trimmed.replace(/^#{2,3}\s*/, '');
            return void elements.push(
              <h2
                key={lIdx}
                className="answer-block mt-8 mb-3 max-w-[68ch] font-sans text-[19px] font-semibold tracking-[-0.02em] leading-snug text-slate-900 first:mt-0"
              >
                {renderFormattedInline(headingTitle)}
              </h2>
            );
          }

          if (trimmed.startsWith('> [!NOTE]') || trimmed.startsWith('> [!INFO]')) {
            elements.push(<Callout key={lIdx} type="info" title="Information">{renderFormattedInline(trimmed.replace(/^>\s*\[!(NOTE|INFO)\]\s*/, ''))}</Callout>);
            return;
          }
          if (trimmed.startsWith('> [!WARNING]')) {
            elements.push(<Callout key={lIdx} type="warning" title="Warning">{renderFormattedInline(trimmed.replace(/^>\s*\[!WARNING\]\s*/, ''))}</Callout>);
            return;
          }
          if (trimmed.startsWith('> [!CRITICAL]')) {
            elements.push(<Callout key={lIdx} type="critical" title="Critical Threat">{renderFormattedInline(trimmed.replace(/^>\s*\[!CRITICAL\]\s*/, ''))}</Callout>);
            return;
          }

          if (trimmed === '---' || trimmed === '***' || trimmed === '___') {
            elements.push(<hr key={lIdx} className="answer-block my-7 border-slate-200" />);
            return;
          }

          // Regular Paragraph with clean spacing
          elements.push(
            // `text-wrap: pretty` keeps a paragraph from ending on a single
            // orphaned word, which is the kind of thing that reads as careless
            // in a document somebody is about to forward to a bank.
            <p
              key={lIdx}
              className="answer-block my-4 max-w-[68ch] font-normal leading-[1.7] text-slate-700 [text-wrap:pretty]"
            >
              {renderFormattedInline(trimmed)}
            </p>
          );
        });

        flushTable(`table-end-${bIdx}`);
        flushList(`list-end-${bIdx}`);

        return <div key={bIdx}>{elements}</div>;
      })}

      {isStreaming && (
        // A caret sized to the text it writes: a 2px rule on the baseline, not
        // a filled block glyph with a second block character inside it.
        <span
          aria-hidden
          className="answer-caret ml-0.5 inline-block h-[1.05em] w-[2px] translate-y-[0.18em] rounded-full bg-blue-600 align-baseline"
        />
      )}
    </div>
  );
}

function renderFormattedInline(text: string): React.ReactNode {
  const parts = text.split(/(`[^`]+`)/g);

  return parts.map((part, i) => {
    if (part.startsWith('`') && part.endsWith('`')) {
      const val = part.slice(1, -1);
      return (
        // Purple appears nowhere else in this product. A package name is not a
        // different kind of thing from the sentence around it - it is the same
        // sentence, in a face you can copy accurately.
        <code key={i} className="mx-0.5 rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[13px] font-medium text-slate-700">
          {val}
        </code>
      );
    }

    const boldParts = part.split(/(\*\*[^*]+\*\*)/g);
    return boldParts.map((bPart, j) => {
      if (bPart.startsWith('**') && bPart.endsWith('**')) {
        const boldVal = bPart.slice(2, -2);
        return <strong key={j} className="font-semibold text-slate-950">{boldVal}</strong>;
      }
      return <span key={j}>{highlightKeywords(bPart)}</span>;
    });
  });
}

const SECTION_LABELS: Record<string, string> = {
  verdict: 'Verdict',
  risk_engine: 'Risk Engine',
  fraud_workflow: 'Fraud Workflow',
  static_findings: 'Static Findings',
  dynamic_findings: 'Dynamic Findings',
  threat_intelligence: 'Threat Intel',
  mitre: 'MITRE ATT&CK',
  recommendations: 'Recommended Actions',
};

/**
 * Where each evidence section can actually be inspected.
 *
 * The chips already named the sections the answer was drawn from, but as inert
 * text - which asks the reader to take the grounding on trust. A citation you
 * can open is the difference between an assistant bolted onto the product and
 * one wired into it, so every chip is now a link into the panel that holds the
 * underlying records.
 */
type SectionTarget = { section: CaseSection; hash?: string };

/**
 * Where each cited evidence section can actually be inspected.
 *
 * These citations are the difference between an assistant bolted onto the
 * product and one wired into it, so they resolve to the case the answer is
 * about rather than to a case-less path that would show the reader whatever
 * sample they happened to have loaded.
 */
const SECTION_TARGETS: Record<string, SectionTarget> = {
  verdict: { section: 'summary' },
  risk_engine: { section: 'summary' },
  fraud_workflow: { section: 'summary', hash: 'attack-story' },
  static_findings: { section: 'evidence', hash: 'manifest-findings' },
  dynamic_findings: { section: 'evidence', hash: 'dynamic-analysis' },
  threat_intelligence: { section: 'intel' },
  mitre: { section: 'evidence', hash: 'mitre' },
  recommendations: { section: 'summary', hash: 'recommended-action' },
};

function SectionChips({ sections }: { sections: string[] }) {
  const links = useCaseLinks();
  if (!sections || !sections.length) return null;
  return (
    <div className="flex flex-wrap items-center gap-1.5 mt-3 pt-3 border-t border-slate-100">
      <span className="text-[13px] font-medium text-slate-500 flex items-center gap-1.5">
        <Shield className="h-3 w-3" aria-hidden /> Grounded in
      </span>
      {sections.map(s => {
        const label = SECTION_LABELS[s] || s;
        const target = SECTION_TARGETS[s];
        const to = target
          ? `${links[target.section]}${target.hash ? `#${target.hash}` : ''}`
          : undefined;
        if (!to) {
          return (
            <span
              key={s}
              className="text-[13px] px-2 py-0.5 bg-slate-100 border border-slate-200 rounded text-slate-600"
            >
              {label}
            </span>
          );
        }
        return (
          <Link
            key={s}
            to={to}
            title={`Open ${label} evidence`}
            className="text-[13px] px-2 py-0.5 bg-white border border-slate-200 rounded text-slate-600 hover:border-blue-300 hover:text-blue-700 hover:bg-blue-50/50 transition-colors inline-flex items-center gap-1"
          >
            {label}
            <ArrowUpRight className="h-3 w-3" aria-hidden />
          </Link>
        );
      })}
    </div>
  );
}

// ─── Component 8: Structured Investigation Response Renderer ──────────────────

function InvestigationResponseRenderer({
  content,
  isStreaming,
  onSendMessage,
}: {
  content: string;
  isStreaming?: boolean;
  onSendMessage: (q: string) => void;
}) {
  if (!content) return null;

  const followUpPattern = /(?:#{2,3}\s*(?:Suggested\s*)?(?:Follow-up\s*)?Questions|---FOLLOW-UP QUESTIONS---)([\s\S]*)/i;
  const match = content.match(followUpPattern);

  let bodyContent = content;
  let followUps: string[] = [];

  if (match) {
    bodyContent = content.slice(0, match.index).trim();
    const rawFollow = match[1].trim();

    try {
      const matchJson = rawFollow.match(/\[[\s\S]*\]/);
      if (matchJson) {
        const parsed = JSON.parse(matchJson[0]);
        if (Array.isArray(parsed)) {
          followUps = parsed.map(q => String(q).trim()).filter(Boolean);
        }
      }
    } catch {
      // ignore
    }

    if (followUps.length === 0) {
      followUps = rawFollow
        .split('\n')
        .map(l => l.replace(/^[*•-]\s*/, '').replace(/^\d+\.\s*/, '').replace(/^"\s*/, '').replace(/"\s*$/, '').trim())
        .filter(l => l.length > 5 && (l.endsWith('?') || l.includes('?')));
    }
  }

  return (
    <div className="space-y-4 w-full min-w-0">
      <MarkdownRenderer content={bodyContent} isStreaming={isStreaming} />

      {followUps.length > 0 && (
        <div className="mt-6 pt-4 border-t border-slate-200/80 space-y-2.5">
          <div className={`${TYPOGRAPHY.label} flex items-center gap-1.5`}>
            <HelpCircle className="h-3.5 w-3.5 text-slate-400" aria-hidden />
            Suggested follow-up questions
          </div>
          <div className="flex flex-wrap gap-2">
            {followUps.map((q, idx) => (
              <button
                key={idx}
                onClick={() => onSendMessage(q)}
                disabled={isStreaming}
                className="flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-left font-sans text-[13px] font-medium text-slate-700 transition-all duration-150 hover:-translate-y-px hover:border-blue-300 hover:bg-blue-50 hover:text-blue-800 active:translate-y-0 active:scale-[0.98] disabled:opacity-50 disabled:hover:translate-y-0"
              >
                <span>{q}</span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/*
 * What you can do with an answer, once it has finished arriving.
 *
 * Icon-only and ghost-weight, because these sit under every reply and a row of
 * labelled buttons repeated down a transcript becomes the loudest recurring
 * element on the page. Each one still carries a real label for a screen reader
 * and a tooltip for a pointer.
 *
 * There is deliberately no thumbs-up/thumbs-down pair here. Nothing in this
 * product receives a rating - a control that swallows a judgement and does
 * nothing with it is worse than no control, particularly on a screen whose
 * whole claim is that findings are traceable.
 */
function MessageActions({
  content,
  onRetry,
  disabled,
}: {
  content: string;
  onRetry?: () => void;
  disabled?: boolean;
}) {
  const [copied, setCopied] = useState(false);

  const action =
    'inline-flex h-7 w-7 items-center justify-center rounded-lg text-slate-400 transition-[color,background-color,transform] duration-100 hover:bg-slate-100 hover:text-slate-700 active:scale-90 disabled:opacity-40 disabled:hover:bg-transparent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500';

  return (
    <div className="mt-2 flex items-center gap-0.5">
      <button
        type="button"
        title={copied ? 'Copied' : 'Copy answer'}
        aria-label={copied ? 'Answer copied' : 'Copy answer'}
        onClick={() => {
          navigator.clipboard.writeText(content);
          setCopied(true);
          window.setTimeout(() => setCopied(false), 2000);
        }}
        className={action}
      >
        {copied ? (
          <CopyCheck className="h-3.5 w-3.5 text-emerald-600" aria-hidden />
        ) : (
          <Copy className="h-3.5 w-3.5" aria-hidden />
        )}
      </button>

      {onRetry && (
        <button
          type="button"
          title="Ask again"
          aria-label="Ask this question again"
          onClick={onRetry}
          disabled={disabled}
          className={action}
        >
          <RotateCcw className="h-3.5 w-3.5" aria-hidden />
        </button>
      )}

      <span aria-live="polite" className="sr-only">
        {copied ? 'Answer copied to clipboard' : ''}
      </span>
    </div>
  );
}

// ─── Main InvestigationChat Component ───────────────────────────────────────────

export default function InvestigationChat({ data }: { data: FraudCardData | null }) {
  const { investigationBundle } = useAnalysis();
  const { openLedger } = useInvestigationUI();

  if (!data) return null;

  /*
   * The grounding strip.
   *
   * This printed "STEI 46.0, Dynamic 0.0, Correlation 71.0" - three acronyms
   * and three bare axis scores, above the fold, to a reader who has not yet
   * asked a question. The count of records is the part that says "this is
   * grounded"; the arithmetic belongs in the ledger it links to.
   */
  const evidenceCount = investigationBundle?.counts.evidenceRecords ?? 0;
  const ledgerSummary = evidenceCount
    ? `Grounded in ${evidenceCount} verified evidence record${evidenceCount === 1 ? '' : 's'} from this case.`
    : '';

  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'welcome',
      role: 'assistant',
      content: buildChatGreeting(data),
      timestamp: new Date(),
    },
  ]);
  const questions = buildCaseQuestions(data);
  /*
   * Three openers, one per kind, and only kinds this case actually produced -
   * a partial run may yield no runtime evidence to ask about, and an opener
   * pointing at nothing is worse than one fewer card.
   */
  const starters = STARTER_KINDS.flatMap((kind) => {
    const first = questions.find((q) => q.kind === kind);
    return first ? [{ title: GROUP_LABEL[kind], question: first.text }] : [];
  });
  const [input, setInput] = useState('');
  const [isStreaming, setIsStreaming] = useState(false);
  const [searchParams, setSearchParams] = useSearchParams();
  const prefilledHandled = useRef(false);
  const abortRef = useRef<AbortController | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  /*
   * Follow the answer, but only while the reader is already at the bottom.
   *
   * This fired `scrollIntoView({ behavior: 'smooth' })` on every message
   * change - so once per token. Hundreds of overlapping smooth-scroll
   * animations queue against each other, and worse, every one of them yanked
   * the viewport back down: an analyst who scrolled up to re-read a line was
   * dragged to the foot of the page again on the next token, which is
   * indistinguishable from the page having seized.
   *
   * Scrolling up now means the transcript leaves you alone until you come
   * back down to the end of it.
   */
  useEffect(() => {
    const end = bottomRef.current;
    const viewport = end?.closest('[data-chat-scroll]');
    if (!end || !(viewport instanceof HTMLElement)) return;

    const distanceFromBottom =
      viewport.scrollHeight - viewport.scrollTop - viewport.clientHeight;
    if (distanceFromBottom > 120) return;

    end.scrollIntoView({ block: 'end', behavior: 'auto' });
  }, [messages]);

  const handleStop = () => {
    if (abortRef.current) {
      abortRef.current.abort();
      setIsStreaming(false);
    }
  };

  const sendMessage = async (text: string) => {
    if (!text.trim() || isStreaming) return;

    const userMsg: Message = {
      id: String(Date.now()),
      role: 'user',
      content: text.trim(),
      timestamp: new Date(),
    };

    const assistantId = String(Date.now() + 1);
    const assistantMsg: Message = {
      id: assistantId,
      role: 'assistant',
      content: '',
      streaming: true,
      timestamp: new Date(),
    };

    setMessages(prev => [...prev, userMsg, assistantMsg]);
    setInput('');
    // The composer grows with its content, so clearing the value is not enough
    // to shrink it back - the inline height set on the last keystroke survives.
    if (inputRef.current) inputRef.current.style.height = 'auto';
    setIsStreaming(true);

    const history = messages
      .filter(m => m.id !== 'welcome')
      .map(m => ({ role: m.role, content: m.content }));

    const controller = new AbortController();
    abortRef.current = controller;
    let paintHandle: number | null = null;

    try {
      const res = await fetch(`${API_BASE}/chat/stream`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...authHeaders(),
        },
        body: JSON.stringify({
          sha256: data.sha256,
          question: text.trim(),
          history,
          ledger_summary: ledgerSummary,
        }),
        signal: controller.signal,
      });

      if (!res.ok) {
        throw new Error(`Chat error (${res.status})`);
      }

      const reader = res.body?.getReader();
      const decoder = new TextDecoder('utf-8');
      let currentEvent = 'token';
      let accumulated = '';
      let sectionsUsed: string[] = [];

      if (!reader) throw new Error('No readable stream');

      /*
       * The stream ends when the server says it ends.
       *
       * The loop used to run until the socket closed, and `break` on [DONE]
       * only left the inner per-line loop. A server that holds the connection
       * open after the last token - keep-alive, a slow write in the persist
       * step - left `isStreaming` true forever, which locked the composer: the
       * answer was on screen and the analyst could not ask the next question.
       * A `done` event, or [DONE], now ends the read for real.
       */
      /*
       * A read that never returns is not a conversation.
       *
       * The backend persists the assistant turn in a `finally` after the last
       * token, so the socket can stay open well past the answer. If that write
       * stalls, `read()` never settles and the composer stays locked behind a
       * spinner over a finished answer. Silence this long ends the read.
       */
      let stalled = false;
      const readWithIdleGuard = () =>
        new Promise<ReadableStreamReadResult<Uint8Array>>((resolve, reject) => {
          const timer = window.setTimeout(() => {
            stalled = true;
            resolve({ done: true, value: undefined });
          }, IDLE_TIMEOUT_MS);
          reader
            .read()
            .then(resolve, reject)
            .finally(() => window.clearTimeout(timer));
        });

      const paint = () => {
        paintHandle = null;
        setMessages(prev =>
          prev.map(m =>
            m.id === assistantId ? { ...m, content: accumulated, sectionsUsed } : m
          )
        );
      };
      const schedulePaint = () => {
        if (paintHandle === null) paintHandle = window.setTimeout(paint, STREAM_PAINT_MS);
      };

      let streamDone = false;
      let buffer = '';
      while (!streamDone) {
        const { done, value } = await readWithIdleGuard();
        if (done || !value) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (!line.trim() || line.startsWith(':')) continue;

          if (line.startsWith('event: ')) {
            currentEvent = line.slice(7).trim();
            if (currentEvent === 'done' || currentEvent === 'end') {
              streamDone = true;
            }
            continue;
          }

          if (line.startsWith('data: ')) {
            const rawData = line.slice(6);
            if (rawData.trim() === '[DONE]') {
              streamDone = true;
              break;
            }

            let dataStr = rawData;
            try {
              const parsed = JSON.parse(rawData);
              dataStr = typeof parsed === 'string' ? parsed : rawData;
            } catch {
              dataStr = rawData;
            }

            if (currentEvent === 'sections') {
              try {
                const parsed = JSON.parse(rawData.trim());
                sectionsUsed = Array.isArray(parsed) ? parsed : (parsed.data || []);
              } catch {
                // ignore
              }
            } else if (currentEvent === 'token') {
              accumulated += dataStr;
              schedulePaint();
            } else if (currentEvent === 'error') {
              accumulated += (accumulated ? '\n\n' : '') + `> [!CRITICAL]\n> ${dataStr.trim()}`;
              schedulePaint();
            } else if (currentEvent === 'done' || currentEvent === 'end') {
              // Terminator payload, not answer text.
            } else {
              accumulated += dataStr;
              schedulePaint();
            }
          }
        }
      }

      /*
       * The answer is finished the moment the server says it is.
       *
       * `await reader.cancel()` was the second half of the same bug: the done
       * event arrived, the loop exited, and then the teardown await hung on a
       * socket the backend had not closed yet - so the state that unlocks the
       * composer never ran. Release the UI first, tear the socket down after,
       * and do not wait on it.
       */
      if (paintHandle !== null) {
        window.clearTimeout(paintHandle);
        paintHandle = null;
      }
      /*
       * A truncated answer must say it is truncated.
       *
       * When the idle guard ends the read, the reply simply stopped
       * mid-sentence and was then rendered as though it were complete - on a
       * console whose whole claim is that findings are traceable, an answer
       * that silently loses its last paragraph is the worst possible failure.
       */
      if (stalled && accumulated.trim()) {
        accumulated +=
          `\n\n> [!WARNING]\n> The answer stopped early - the assistant went quiet for ` +
          `${Math.round(IDLE_TIMEOUT_MS / 1000)} seconds. Ask again to get the rest.`;
      }
      paint();
      setIsStreaming(false);
      setMessages(prev =>
        prev.map(m => (m.id === assistantId ? { ...m, streaming: false } : m))
      );
      void reader.cancel().catch(() => {});
      controller.abort();
    } catch (err: any) {
      if (err.name !== 'AbortError') {
        setMessages(prev =>
          prev.map(m =>
            m.id === assistantId
              ? {
                  ...m,
                  content: `Investigation Assistant encountered an error: ${err.message || 'Connection failed'}. Please retry your question.`,
                  streaming: false,
                }
              : m
          )
        );
      }
    } finally {
      if (paintHandle !== null) {
        window.clearTimeout(paintHandle);
        paintHandle = null;
      }
      setIsStreaming(false);
      setMessages(prev =>
        prev.map(m => (m.id === assistantId ? { ...m, streaming: false } : m))
      );
    }
  };

  useEffect(() => {
    const q = searchParams.get('q')?.trim();
    if (!q || prefilledHandled.current) return;
    prefilledHandled.current = true;
    setSearchParams({}, { replace: true });
    const timer = window.setTimeout(() => {
      void sendMessage(q);
    }, 400);
    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- one-shot URL prefill only
  }, [searchParams, setSearchParams]);

  /*
   * One scroll region, and it is the transcript.
   *
   * The frame carried `minHeight: calc(100vh - header - 1.5rem)` while sitting
   * inside a case page that already spends height on the case bar, so the card
   * was taller than the space it had: the page scrolled, and the message list
   * scrolled inside it. Two scrollbars for one conversation. The frame now
   * takes exactly the height its flex parent gives it and only the transcript
   * moves.
   */
  return (
    <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
      {/*
        One context strip.

        A dark slate banner announced "Ask SUDARSHAN about this case" directly
        under a case bar whose active tab already reads "Ask SUDARSHAN", and a
        second strip below it carried the grounding count. Both said where the
        answers come from; one line does.
      */}
      {/* The visible heading is the case bar's active tab; keep one for readers. */}
      <h1 className="sr-only">Ask SUDARSHAN about this case</h1>

      <div className="flex shrink-0 flex-wrap items-center justify-between gap-x-4 gap-y-1 px-1 pb-3 sm:px-2">
        <p className={TYPOGRAPHY.caption}>
          {ledgerSummary || "Answers cite this case's evidence only."}
        </p>
        {ledgerSummary && (
          <button type="button" onClick={() => openLedger('full')} className={TYPOGRAPHY.linkAction}>
            <BarChart2 className="h-3.5 w-3.5" aria-hidden />
            How the score was calculated
          </button>
        )}
      </div>

      {/*
        The transcript uses the width it is given, but prose does not.

        The column is wide because an evidence table needs to be. A paragraph
        set to the same width runs past 120 characters a line, which is roughly
        twice what an eye tracks comfortably - the reader loses the start of
        the next line on every return sweep. Paragraphs, headings and lists
        carry a 68ch measure of their own; tables and cards still spend the
        whole column.

        `max-w-3xl` on a full-width case page left a band of empty white down
        both sides wider than some of the answers, and evidence tables wrapped
        inside a column narrower than the page they sat on. The reading column
        is now `max-w-5xl`: wide enough for a table, still short enough a line
        of prose does not run away from the eye.
      */}
      <div data-chat-scroll className="flex min-h-0 flex-1 flex-col overflow-y-auto px-1 py-2 sm:px-2 [mask-image:linear-gradient(to_bottom,transparent_0,black_20px,black_calc(100%-20px),transparent_100%)]">
        {/*
          An empty conversation fills from the bottom.

          With nothing asked yet, a greeting and a row of openers pinned to the
          top of a tall panel leaves the reader looking at a screen of white
          with the thing they are meant to touch furthest from the composer
          they will touch it with. `mt-auto` drops the opening move down beside
          the input; once the first answer arrives the column has real content
          and fills normally, top-down, the way a transcript must.
        */}
        <div
          className={`mx-auto w-full max-w-5xl space-y-7 ${
            messages.length <= 1 ? 'mt-auto' : ''
          }`}
        >
          {messages.map((msg, msgIdx) => (
            <div key={msg.id} className={msg.role === 'user' ? 'flex flex-col items-end' : ''}>
              {/*
                The mark is the assistant's avatar, and it is also its status
                light: `sudarshan-thinking` turns it while the reply is in
                flight, so the reader can tell from the speaker's own byline
                whether the answer has finished arriving.
              */}
              <div className="mb-2 flex items-center gap-2">
                {msg.role === 'assistant' && (
                  <img
                    src="/brand/sudarshan-mark-colour.png"
                    alt=""
                    className={`h-[26px] w-[26px] shrink-0 select-none ${
                      msg.streaming ? 'sudarshan-thinking' : ''
                    }`}
                  />
                )}
                <span className="font-sans text-xs font-semibold tracking-[-0.01em] text-slate-500">
                  {msg.role === 'user' ? 'You' : 'SUDARSHAN'}
                </span>
                <span className="font-sans text-xs text-slate-400 tabular-nums">
                  {msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </span>
              </div>

              {/*
                The assistant answers on the page, not inside a chat bubble.

                Its replies carry tables, callouts and evidence chips - a
                rounded speech balloon around an evidence table is a costume.
                The reader's own questions stay in a bubble, because they are
                short and want to be scannable down the right edge.
              */}
              {msg.role === 'assistant' ? (
                <div className="min-w-0">
                  {/*
                    Before the first token there is nothing to render, and an
                    empty block under a byline reads as a failed answer. One
                    honest word - not a fabricated progress stage, since the
                    stream reports none.
                  */}
                  {msg.streaming && !msg.content ? (
                    <p
                      aria-live="polite"
                      className="sudarshan-thinking-label py-0.5 font-sans text-[16px] font-medium"
                    >
                      Thinking…
                    </p>
                  ) : (
                    <InvestigationResponseRenderer
                      content={msg.content}
                      isStreaming={msg.streaming}
                      onSendMessage={sendMessage}
                    />
                  )}
                  {msg.sectionsUsed && msg.sectionsUsed.length > 0 && (
                    <SectionChips sections={msg.sectionsUsed} />
                  )}
                  {/*
                    An answer here is something an analyst pastes into a case
                    note or a mail to the bank, so it needs to leave the page
                    intact. Held back until the stream finishes - copying half
                    an answer is worse than not offering to.
                  */}
                  {!msg.streaming && msg.content && msg.id !== 'welcome' && (
                    <MessageActions
                      content={msg.content}
                      onRetry={
                        messages[msgIdx - 1]?.role === 'user'
                          ? () => sendMessage(messages[msgIdx - 1].content)
                          : undefined
                      }
                      disabled={isStreaming}
                    />
                  )}
                </div>
              ) : (
                /*
                 * The reader's own question is the quietest thing on the page.
                 *
                 * It used to be a saturated blue block, which made the loudest
                 * element in the transcript the one part nobody needs to read -
                 * they wrote it. Blue is this product's action colour; spending
                 * it here weakens it everywhere it actually means "press this".
                 * A white surface on the tinted page reads as "yours" without
                 * competing with the answer underneath it.
                 */
                <p className="max-w-[80%] rounded-2xl rounded-br-md border border-slate-200 bg-white px-4 py-2.5 font-sans text-[16px] leading-relaxed text-slate-800 shadow-[0_1px_2px_rgba(15,23,42,0.04)]">
                  {msg.content}
                </p>
              )}
            </div>
          ))}

          {/*
            The opening move, as cards rather than a chip row.

            One card per kind of question this case supports, each carrying the
            name of the thing it answers and the question itself. A chip row
            made every opener the same size and shape regardless of what it
            did; a card gives the reader a heading to scan and a sentence to
            commit to.
          */}
          {messages.length <= 1 && starters.length > 0 && (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              {starters.map((card) => (
                <button
                  key={card.question}
                  type="button"
                  onClick={() => sendMessage(card.question)}
                  disabled={isStreaming}
                  className="group rounded-xl border border-slate-200 bg-white p-4 text-left shadow-[0_1px_2px_rgba(15,23,42,0.04)] transition-[transform,border-color,box-shadow] duration-150 hover:-translate-y-0.5 hover:border-slate-300 hover:shadow-[0_4px_12px_rgba(15,23,42,0.06)] active:translate-y-0 active:scale-[0.99] disabled:opacity-50 disabled:hover:translate-y-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                >
                  <span className="block font-sans text-[15px] font-semibold tracking-[-0.01em] text-slate-900">
                    {card.title}
                  </span>
                  <span className="mt-1.5 block font-sans text-[13px] leading-relaxed tracking-[0.01em] text-slate-500">
                    {card.question}
                  </span>
                </button>
              ))}
            </div>
          )}

          <div ref={bottomRef} />
        </div>
      </div>

      {/*
        The composer stays open.

        It used to disable the field while an answer streamed, so an analyst
        who had already read the verdict had to wait on the cursor before
        typing the next question - and if the stream never closed cleanly, they
        waited forever. The field is always live; only the send is held back
        while a reply is in flight, and the stop button is right there.
      */}
      <div className="shrink-0 px-1 pb-1 pt-3 sm:px-2">
        {/*
          A question about an investigation is often two sentences, and a
          single-line input hid the first one as soon as the second was typed.
          The field grows with the text to a six-line ceiling and then scrolls
          inside itself, so the composer can never push the transcript off
          screen. Enter sends; Shift+Enter breaks the line.
        */}
        {/*
          One surface, holding everything the composer needs.

          The field, who is answering, and the commit all used to be three
          separate things stacked down the page - a box, then a caption row
          under it. Pulling the chip and the button inside makes the composer
          read as a single object you write into and press, and it is the only
          raised surface on the page, which is what makes it the obvious place
          to start.
        */}
        <div className="mx-auto max-w-5xl rounded-2xl border border-slate-200 bg-white px-4 pb-3 pt-3.5 shadow-[0_1px_2px_rgba(15,23,42,0.04)] transition-[border-color,box-shadow] focus-within:border-blue-500 focus-within:ring-2 focus-within:ring-blue-500/25">
          <textarea
            ref={inputRef}
            rows={1}
            value={input}
            onChange={(e) => {
              setInput(e.target.value);
              const el = e.currentTarget;
              el.style.height = 'auto';
              el.style.height = `${Math.min(el.scrollHeight, 168)}px`;
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage(input);
                const el = e.currentTarget;
                el.style.height = 'auto';
              }
            }}
            placeholder={isStreaming ? 'Type your next question...' : 'Ask about this investigation...'}
            className="block w-full resize-none border-0 bg-transparent p-0 font-sans text-[16px] leading-relaxed text-slate-900 placeholder-slate-400 focus:outline-none"
          />

          <div className="mt-3 flex items-end justify-between gap-3">
            <span className={`inline-flex items-center gap-1.5 ${TYPOGRAPHY.caption}`}>
              <img
                src="/brand/sudarshan-mark-colour.png"
                alt=""
                className="h-4 w-4 shrink-0 select-none"
              />
              SUDARSHAN · answers only from this case&apos;s evidence
            </span>

            {isStreaming ? (
              <button
                type="button"
                onClick={handleStop}
                className="shrink-0 rounded-full bg-slate-900 p-2.5 text-white transition-transform duration-100 hover:bg-slate-800 active:scale-90"
                title="Stop generating"
                aria-label="Stop generating"
              >
                <Square className="h-4 w-4 fill-current" aria-hidden />
              </button>
            ) : (
              <button
                type="button"
                onClick={() => sendMessage(input)}
                disabled={!input.trim()}
                className="shrink-0 rounded-full bg-slate-900 p-2.5 text-white transition-transform duration-100 hover:bg-slate-800 active:scale-90 disabled:bg-slate-300 disabled:active:scale-100"
                title="Send question"
                aria-label="Send question"
              >
                <ArrowUp className="h-4 w-4" aria-hidden />
              </button>
            )}
          </div>
        </div>

        <p className={`mx-auto mt-2 max-w-5xl text-right ${TYPOGRAPHY.caption}`}>
          Enter to send · Shift+Enter for a new line
        </p>
      </div>
    </div>
  );
}
