import { useState, useRef, useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  Send, Shield, RefreshCw, AlertTriangle, CheckCircle2,
  Copy, CopyCheck, Info, AlertOctagon, Terminal, ArrowUpRight, BarChart2, HelpCircle
} from 'lucide-react';
import type { FraudCardData } from '../App';
import { API_BASE, authHeaders } from '../config';
import { useAnalysis } from '../context/AnalysisContext';
import { useInvestigationUI } from '../context/InvestigationUIContext';
import { buildCaseQuestions, buildChatGreeting } from '../lib/caseQuestions';
import { TYPOGRAPHY } from '../theme/typography';

/** How long a stream may go silent before the client calls the answer finished. */
const IDLE_TIMEOUT_MS = 15_000;

const GROUP_LABEL = {
  decision: 'Decide',
  evidence: 'Evidence',
  action: 'Act',
} as const;
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
    <div className={`my-4 p-4 rounded-xl border ${cfg.border} ${cfg.bg} flex items-start gap-3 shadow-2xs`}>
      {cfg.icon}
      <div className="space-y-1 text-xs leading-relaxed flex-1">
        {title && <div className={`font-bold ${cfg.text} text-sm`}>{title}</div>}
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
    <div className="my-4 rounded-xl overflow-hidden border border-slate-800 bg-slate-900 text-slate-100 shadow-md">
      <div className="flex items-center justify-between px-4 py-2 bg-slate-950/80 border-b border-slate-800 text-[13px] font-mono text-slate-400">
        <span className="text-[12px] font-semibold uppercase tracking-[0.06em] flex items-center gap-1.5">
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
    <div className="my-4 rounded-xl border border-slate-200 overflow-hidden shadow-2xs">
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
                      <code className="bg-slate-100 border border-slate-200 px-1.5 py-0.5 rounded text-purple-700 font-mono text-[13px]">
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

const HIGHLIGHT_PATTERNS = /\b(?:\d{1,3}\.\d{1,2}\s*\/\s*100|\d{1,3}\.\d{1,2}%?|\d{1,3}%|T\d{4}(?:\.\d{3})?|READ_SMS|SYSTEM_ALERT_WINDOW|ACCESSIBILITY_SERVICE|BIND_ACCESSIBILITY_SERVICE|RECORD_AUDIO|RECEIVE_SMS|CAMERA|READ_CONTACTS|Critical|High|Moderate|Low|Suspicious|Anatsa|Hook|Hydra|Teabot|Sudarshan|Cerberus|Alien|Vultun)\b/gi;

function highlightKeywords(text: string): React.ReactNode[] {
  if (!text) return [];

  const parts = text.split(HIGHLIGHT_PATTERNS);
  const matches = text.match(HIGHLIGHT_PATTERNS) || [];

  const result: React.ReactNode[] = [];
  parts.forEach((part, i) => {
    result.push(part);
    if (i < matches.length) {
      const match = matches[i];
      result.push(
        <strong key={i} className="font-bold text-slate-950 bg-amber-100/70 px-1 py-0.5 rounded shadow-2xs">
          {match}
        </strong>
      );
    }
  });

  return result;
}

// ─── Component 6: MarkdownRenderer ─────────────────────────────────────────────

function MarkdownRenderer({ content, isStreaming }: { content: string; isStreaming?: boolean }) {
  if (!content) return null;

  const formattedContent = autoFormatInvestigationText(content);
  const blocks = formattedContent.split(/(```[\s\S]*?```)/g);

  return (
    <div className="w-full min-w-0 space-y-4 font-sans text-[16px] leading-[1.75] text-slate-800">
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
              <ul key={key} className="my-4 pl-5 space-y-2 list-disc text-slate-800 font-normal leading-relaxed">
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
          if (trimmed.startsWith('## ') || trimmed.startsWith('### ')) {
            const headingTitle = trimmed.replace(/^#{2,3}\s*/, '');
            const isDirectAnswer = headingTitle.toLowerCase().includes('direct answer') || headingTitle.toLowerCase().includes('summary');
            const isAction = headingTitle.toLowerCase().includes('recommend');

            elements.push(
              <div
                key={lIdx}
                className={`mt-6 mb-3.5 px-4 py-2.5 rounded-xl border flex items-center gap-2.5 font-bold text-[15px] shadow-2xs ${
                  isDirectAnswer
                    ? 'bg-blue-50/90 border-blue-200 text-blue-900'
                    : isAction
                    ? 'bg-amber-50/90 border-amber-200 text-amber-900'
                    : 'bg-slate-100/80 border-slate-200 text-slate-800'
                }`}
              >
                <Shield className="h-4 w-4 text-blue-600 flex-shrink-0" />
                <span>{renderFormattedInline(headingTitle)}</span>
              </div>
            );
            return;
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
            elements.push(<hr key={lIdx} className="my-6 border-slate-200" />);
            return;
          }

          // Regular Paragraph with clean spacing
          elements.push(
            <p key={lIdx} className="my-4 leading-[1.85] text-slate-800 font-normal">
              {renderFormattedInline(trimmed)}
            </p>
          );
        });

        flushTable(`table-end-${bIdx}`);
        flushList(`list-end-${bIdx}`);

        return <div key={bIdx}>{elements}</div>;
      })}

      {isStreaming && (
        <span className="inline-block w-2 h-4 bg-blue-600 ml-1 animate-pulse font-mono font-bold">▋</span>
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
        <code key={i} className="mx-0.5 bg-slate-100 border border-slate-200/80 px-2 py-0.5 rounded-md text-purple-700 font-mono text-xs font-semibold shadow-2xs">
          {val}
        </code>
      );
    }

    const boldParts = part.split(/(\*\*[^*]+\*\*)/g);
    return boldParts.map((bPart, j) => {
      if (bPart.startsWith('**') && bPart.endsWith('**')) {
        const boldVal = bPart.slice(2, -2);
        return <strong key={j} className="font-bold text-slate-950">{boldVal}</strong>;
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
                className="flex items-center gap-1.5 rounded-md border border-slate-200 bg-white px-3 py-1.5 text-left font-sans text-[13px] font-medium text-slate-700 transition-colors hover:border-blue-300 hover:bg-blue-50 hover:text-blue-800 disabled:opacity-50"
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
  const [input, setInput] = useState('');
  const [isStreaming, setIsStreaming] = useState(false);
  const [searchParams, setSearchParams] = useSearchParams();
  const prefilledHandled = useRef(false);
  const abortRef = useRef<AbortController | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
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
    setIsStreaming(true);

    const history = messages
      .filter(m => m.id !== 'welcome')
      .map(m => ({ role: m.role, content: m.content }));

    const controller = new AbortController();
    abortRef.current = controller;

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
      const readWithIdleGuard = () =>
        new Promise<ReadableStreamReadResult<Uint8Array>>((resolve, reject) => {
          const timer = window.setTimeout(
            () => resolve({ done: true, value: undefined }),
            IDLE_TIMEOUT_MS
          );
          reader
            .read()
            .then(resolve, reject)
            .finally(() => window.clearTimeout(timer));
        });

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
              setMessages(prev =>
                prev.map(m =>
                  m.id === assistantId
                    ? { ...m, content: accumulated, sectionsUsed }
                    : m
                )
              );
            } else if (currentEvent === 'error') {
              accumulated += (accumulated ? '\n\n' : '') + `> [!CRITICAL]\n> ${dataStr.trim()}`;
              setMessages(prev =>
                prev.map(m =>
                  m.id === assistantId
                    ? { ...m, content: accumulated, sectionsUsed }
                    : m
                )
              );
            } else if (currentEvent === 'done' || currentEvent === 'end') {
              // Terminator payload, not answer text.
            } else {
              accumulated += dataStr;
              setMessages(prev =>
                prev.map(m =>
                  m.id === assistantId
                    ? { ...m, content: accumulated, sectionsUsed }
                    : m
                )
              );
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
    <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-lg border border-slate-200 bg-white">
      {/*
        One context strip.

        A dark slate banner announced "Ask SUDARSHAN about this case" directly
        under a case bar whose active tab already reads "Ask SUDARSHAN", and a
        second strip below it carried the grounding count. Both said where the
        answers come from; one line does.
      */}
      {/* The visible heading is the case bar's active tab; keep one for readers. */}
      <h1 className="sr-only">Ask SUDARSHAN about this case</h1>

      <div className="flex shrink-0 flex-wrap items-center justify-between gap-x-4 gap-y-1 border-b border-slate-200 bg-slate-50/70 px-5 py-2.5">
        <p className={TYPOGRAPHY.caption}>
          {ledgerSummary
            ? `Answers cite this case's evidence only. ${ledgerSummary}`
            : "Answers cite this case's evidence only."}
        </p>
        {ledgerSummary && (
          <button type="button" onClick={() => openLedger('full')} className={TYPOGRAPHY.linkAction}>
            <BarChart2 className="h-3.5 w-3.5" aria-hidden />
            How the score was calculated
          </button>
        )}
      </div>

      {/*
        The transcript uses the width it is given.

        `max-w-3xl` on a full-width case page left a band of empty white down
        both sides wider than some of the answers, and evidence tables wrapped
        inside a column narrower than the page they sat on. The reading column
        is now `max-w-5xl`: wide enough for a table, still short enough a line
        of prose does not run away from the eye.
      */}
      <div className="min-h-0 flex-1 overflow-y-auto px-6 py-6 sm:px-8">
        <div className="mx-auto max-w-5xl space-y-7">
          {messages.map((msg) => (
            <div key={msg.id} className={msg.role === 'user' ? 'flex flex-col items-end' : ''}>
              <div className="mb-1.5 flex items-baseline gap-2">
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
                  <InvestigationResponseRenderer
                    content={msg.content}
                    isStreaming={msg.streaming}
                    onSendMessage={sendMessage}
                  />
                  {msg.sectionsUsed && msg.sectionsUsed.length > 0 && (
                    <SectionChips sections={msg.sectionsUsed} />
                  )}
                </div>
              ) : (
                <p className="max-w-[80%] rounded-2xl rounded-br-md bg-blue-700 px-4 py-2.5 font-sans text-[16px] leading-relaxed text-white">
                  {msg.content}
                </p>
              )}
            </div>
          ))}

          {/*
            Suggested questions, derived from this case, and inside the
            transcript rather than pinned above it: they are the opening move of
            the conversation, and as a fixed band they cost the message list a
            third of its height on every case.
          */}
          {messages.length <= 1 && questions.length > 0 && (
            <div className="space-y-2.5 border-t border-slate-200 pt-5">
              {(['decision', 'evidence', 'action'] as const).map((kind) => {
                const group = questions.filter((q) => q.kind === kind);
                if (group.length === 0) return null;
                return (
                  <div key={kind} className="flex flex-wrap items-center gap-2">
                    <span className={`${TYPOGRAPHY.label} w-full sm:w-16 shrink-0`}>
                      {GROUP_LABEL[kind]}
                    </span>
                    {group.map((q) => (
                      <button
                        key={q.text}
                        type="button"
                        onClick={() => sendMessage(q.text)}
                        disabled={isStreaming}
                        className="rounded-md border border-slate-200 bg-white px-3 py-1.5 font-sans text-[13px] font-medium text-slate-700 transition-colors hover:border-blue-300 hover:bg-blue-50 hover:text-blue-800 disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                      >
                        {q.text}
                      </button>
                    ))}
                  </div>
                );
              })}
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
      <div className="shrink-0 border-t border-slate-200 bg-white px-6 py-4 sm:px-8">
        <div className="mx-auto flex max-w-5xl items-center gap-2.5 rounded-2xl border border-slate-200 bg-slate-50 px-2 py-1.5 transition-colors focus-within:border-blue-500 focus-within:bg-white focus-within:ring-2 focus-within:ring-blue-500/30">
          <input
            ref={inputRef}
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage(input);
              }
            }}
            placeholder={isStreaming ? 'Type your next question...' : 'Ask about this investigation...'}
            className="min-w-0 flex-1 border-0 bg-transparent px-3 py-2 font-sans text-[16px] leading-relaxed text-slate-900 placeholder-slate-400 focus:outline-none"
          />

          {isStreaming ? (
            <button
              type="button"
              onClick={handleStop}
              className="shrink-0 rounded-xl bg-slate-900 p-2.5 text-white transition-colors hover:bg-slate-800"
              title="Stop generating"
            >
              <RefreshCw className="h-4 w-4 animate-spin" />
            </button>
          ) : (
            <button
              type="button"
              onClick={() => sendMessage(input)}
              disabled={!input.trim()}
              className="shrink-0 rounded-xl bg-blue-700 p-2.5 text-white transition-colors hover:bg-blue-800 disabled:opacity-40"
              title="Send question"
            >
              <Send className="h-4 w-4" />
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
