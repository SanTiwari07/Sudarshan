import { useState, useRef, useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  Cpu, Send, Shield, User, RefreshCw, AlertTriangle, CheckCircle2,
  HelpCircle, FileText, Lock, Eye, Check,
  Copy, CopyCheck, Info, AlertOctagon, Terminal, Package, ArrowUpRight
} from 'lucide-react';
import type { FraudCardData } from '../App';
import { API_BASE, authHeaders } from '../config';
import { useAnalysis } from '../context/AnalysisContext';
import { useInvestigationUI } from '../context/InvestigationUIContext';

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

const QUICK_QUESTIONS = [
  { icon: <Shield className="h-3.5 w-3.5" />, label: "Is this APK safe?" },
  { icon: <AlertTriangle className="h-3.5 w-3.5" />, label: "Explain the risk score" },
  { icon: <FileText className="h-3.5 w-3.5" />, label: "Did it steal OTP messages?" },
  { icon: <Lock className="h-3.5 w-3.5" />, label: "Did it abuse Accessibility?" },
  { icon: <Eye className="h-3.5 w-3.5" />, label: "Which MITRE techniques apply?" },
  { icon: <Check className="h-3.5 w-3.5" />, label: "Should I block this APK?" },
  { icon: <FileText className="h-3.5 w-3.5" />, label: "Generate executive summary" },
  { icon: <HelpCircle className="h-3.5 w-3.5" />, label: "Show network indicators" },
];

// ─── Component 1: PackageCard ──────────────────────────────────────────────────

function PackageCard({ packageName }: { packageName: string }) {
  return (
    <div className="my-4 bg-gradient-to-r from-blue-50/80 to-indigo-50/80 border border-blue-200/80 rounded-xl p-4 shadow-2xs space-y-2">
      <div className="flex items-center gap-2 text-blue-900 font-bold text-xs">
        <Package className="h-4 w-4 text-blue-700" />
        <span className="uppercase tracking-wider">Investigation Loaded</span>
      </div>
      <div className="flex items-center gap-2 text-xs text-slate-700">
        <span>📦 Package:</span>
        <code className="bg-white px-2.5 py-1 rounded-md border border-blue-200 text-blue-900 font-mono font-bold text-xs shadow-2xs">
          {packageName || 'Unknown'}
        </code>
      </div>
      <p className="text-xs text-slate-600">Ready for interactive cybersecurity investigation.</p>
    </div>
  );
}

// ─── Component 2: RiskCard ─────────────────────────────────────────────────────

function RiskCard({ score, band }: { score: number; band: string }) {
  const numScore = Number(score) || 0;
  const isCritical = numScore >= 75 || band.toLowerCase().includes('critical');
  const isHigh = numScore >= 50 && !isCritical || band.toLowerCase().includes('high');
  const isSuspicious = numScore >= 20 && !isHigh && !isCritical || band.toLowerCase().includes('suspicious');

  const theme = isCritical
    ? { border: 'border-red-300', bg: 'bg-red-50/70', badgeBg: 'bg-red-100', badgeText: 'text-red-700 border-red-300', bar: 'from-red-500 to-red-600', icon: '🔴' }
    : isHigh
    ? { border: 'border-orange-300', bg: 'bg-orange-50/70', badgeBg: 'bg-orange-100', badgeText: 'text-orange-700 border-orange-300', bar: 'from-orange-500 to-orange-600', icon: '🟠' }
    : isSuspicious
    ? { border: 'border-amber-300', bg: 'bg-amber-50/70', badgeBg: 'bg-amber-100', badgeText: 'text-amber-700 border-amber-300', bar: 'from-amber-400 to-amber-500', icon: '🟡' }
    : { border: 'border-emerald-300', bg: 'bg-emerald-50/70', badgeBg: 'bg-emerald-100', badgeText: 'text-emerald-700 border-emerald-300', bar: 'from-emerald-500 to-emerald-600', icon: '🟢' };

  return (
    <div className={`my-4 border ${theme.border} ${theme.bg} rounded-xl p-4 shadow-2xs space-y-3`}>
      <div className="flex items-center justify-between">
        <span className="text-xs font-bold uppercase tracking-wider text-slate-700">Risk Assessment</span>
        <span className={`px-2.5 py-1 text-xs font-bold rounded-lg border shadow-2xs ${theme.badgeBg} ${theme.badgeText}`}>
          {theme.icon} {band || 'Suspicious'}
        </span>
      </div>

      <div className="flex items-baseline justify-between">
        <div className="flex items-baseline gap-1">
          <span className="text-3xl font-black text-slate-900 tracking-tight">{numScore.toFixed(1)}</span>
          <span className="text-sm font-medium text-slate-500">/ 100</span>
        </div>
      </div>

      {/* Animated progress bar */}
      <div className="w-full h-2.5 bg-slate-200/80 rounded-full overflow-hidden p-0.5">
        <div
          className={`h-full rounded-full bg-gradient-to-r ${theme.bar} transition-all duration-700 ease-out`}
          style={{ width: `${Math.min(100, Math.max(5, numScore))}%` }}
        />
      </div>
    </div>
  );
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
      <div className="flex items-center justify-between px-4 py-2 bg-slate-950/80 border-b border-slate-800 text-[11px] font-mono text-slate-400">
        <span className="uppercase tracking-wider flex items-center gap-1.5">
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
                <th key={i} className="px-4 py-2.5 text-left font-bold uppercase tracking-wider text-slate-700 text-[10px]">
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
                      <code className="bg-slate-100 border border-slate-200 px-1.5 py-0.5 rounded text-purple-700 font-mono text-[11px]">
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
    <div className="space-y-4 text-slate-800 text-[15px] leading-[1.85] font-sans w-full min-w-0">
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

          if (trimmed.startsWith('__PACKAGE_CARD__:')) {
            const pkg = trimmed.replace('__PACKAGE_CARD__:', '').replace('__', '');
            elements.push(<PackageCard key={`pkg-${lIdx}`} packageName={pkg} />);
            return;
          }

          if (trimmed.startsWith('__RISK_CARD__:')) {
            const parts = trimmed.replace('__RISK_CARD__:', '').replace('__', '').split(':');
            elements.push(<RiskCard key={`risk-${lIdx}`} score={parseFloat(parts[0]) || 0} band={parts[1] || 'Suspicious'} />);
            return;
          }

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
            elements.push(<h1 key={lIdx} className="text-xl font-black text-slate-900 mt-6 mb-3 border-b pb-2">{renderFormattedInline(trimmed.slice(2))}</h1>);
            return;
          }
          if (trimmed.startsWith('## ') || trimmed.startsWith('### ')) {
            const headingTitle = trimmed.replace(/^#{2,3}\s*/, '');
            const isDirectAnswer = headingTitle.toLowerCase().includes('direct answer') || headingTitle.toLowerCase().includes('summary');
            const isAction = headingTitle.toLowerCase().includes('recommend');

            elements.push(
              <div
                key={lIdx}
                className={`mt-6 mb-3.5 px-4 py-2.5 rounded-xl border flex items-center gap-2.5 font-bold text-sm shadow-2xs ${
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

// ─── Component 7: RiskBadge ────────────────────────────────────────────────────

function RiskBadge({ band, score }: { band: string; score: number }) {
  const isHigh = score >= 50 || band.toLowerCase().includes('critical') || band.toLowerCase().includes('high');
  return (
    <div className={`px-3 py-1 rounded-xl border font-mono flex items-center gap-2 shadow-2xs ${
      isHigh ? 'bg-red-50 border-red-200 text-red-700' : 'bg-emerald-50 border-emerald-200 text-emerald-700'
    }`}>
      <span className="text-[11px] font-bold uppercase tracking-wider">{band}</span>
      <span className="text-sm font-black">{score.toFixed(1)}/100</span>
    </div>
  );
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
const SECTION_ROUTES: Record<string, string> = {
  verdict: '/fraud-card',
  risk_engine: '/fraud-card',
  fraud_workflow: '/technical',
  static_findings: '/technical',
  dynamic_findings: '/technical#dynamic-analysis',
  threat_intelligence: '/threat-intel',
  mitre: '/technical',
  recommendations: '/fraud-card',
};

function SectionChips({ sections }: { sections: string[] }) {
  if (!sections || !sections.length) return null;
  return (
    <div className="flex flex-wrap items-center gap-1.5 mt-3 pt-3 border-t border-slate-100">
      <span className="text-[11px] font-medium text-slate-400 flex items-center gap-1.5">
        <Shield className="h-3 w-3" aria-hidden /> Grounded in
      </span>
      {sections.map(s => {
        const label = SECTION_LABELS[s] || s;
        const to = SECTION_ROUTES[s];
        if (!to) {
          return (
            <span
              key={s}
              className="text-[11px] px-2 py-0.5 bg-slate-100 border border-slate-200 rounded text-slate-600"
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
            className="text-[11px] px-2 py-0.5 bg-white border border-slate-200 rounded text-slate-600 hover:border-blue-300 hover:text-blue-700 hover:bg-blue-50/50 transition-colors inline-flex items-center gap-1"
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
          <div className="text-xs font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
            <HelpCircle className="h-4 w-4 text-blue-600" /> Suggested Follow-up Questions
          </div>
          <div className="flex flex-wrap gap-2">
            {followUps.map((q, idx) => (
              <button
                key={idx}
                onClick={() => onSendMessage(q)}
                disabled={isStreaming}
                className="text-xs bg-white border border-slate-200 hover:border-blue-400 hover:bg-blue-50/80 text-slate-800 font-medium px-3.5 py-2 rounded-xl transition-all text-left shadow-2xs disabled:opacity-50 flex items-center gap-1.5"
              >
                <span className="text-blue-600 font-bold">•</span>
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

  const ledgerSummary = investigationBundle
    ? `Deterministic ledger: ${investigationBundle.counts.evidenceRecords} evidence records, ` +
      `STEI ${data.frs_breakdown?.stei?.toFixed(1) ?? '-'}, ` +
      `Dynamic ${data.frs_breakdown?.dynamic?.toFixed(1) ?? '-'}, ` +
      `Correlation ${data.frs_breakdown?.correlation?.toFixed(1) ?? '-'}.`
    : '';

  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'welcome',
      role: 'assistant',
      content: `__PACKAGE_CARD__:${data.package_name}__
__RISK_CARD__:${data.final_risk_score}:${data.risk_band}__

### Investigation Evidence Indexed

The investigation evidence for \`${data.package_name}\` has been successfully indexed.

You can now ask questions about:

* **Malware behaviour** & runtime hooks
* **Risk Score explanation** & decision breakdown
* **Permissions** & critical privilege abuse
* **Indicators of Compromise** (IOCs) & network C2
* **Dynamic Analysis** & screen captures
* **Static Analysis** & decompiled findings
* **Network activity** & mitmproxy flows
* **Threat Intelligence** (VT, OTX, AbuseIPDB)
* **Recommendation** & quarantine actions

Everything is grounded strictly in investigation evidence.`,
      timestamp: new Date(),
    },
  ]);
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

      let buffer = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (!line.trim() || line.startsWith(':')) continue;

          if (line.startsWith('event: ')) {
            currentEvent = line.slice(7).trim();
            continue;
          }

          if (line.startsWith('data: ')) {
            const rawData = line.slice(6);
            if (rawData.trim() === '[DONE]') break;

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

  return (
    <div
      className="flex flex-col flex-1 min-h-0 bg-white border border-slate-200 rounded-xl shadow-xs overflow-hidden"
      style={{ minHeight: 'calc(100vh - var(--app-header-height) - 1.5rem)' }}
    >

      {/* Top Header */}
      <div className="flex items-center justify-between px-5 py-3.5 bg-slate-900 text-white border-b border-slate-800 flex-shrink-0">
        <div className="flex items-center gap-3">
          <div className="relative">
            <Cpu className="h-6 w-6 text-blue-400" />
            <div className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          </div>
          <div>
            <h1 className="text-sm font-bold tracking-wide">SUDARSHAN AI Investigation Assistant</h1>
            <p className="text-[11px] text-slate-400 font-mono mt-0.5">
              {data.package_name} · SHA256: {data.sha256.slice(0, 12)}…
            </p>
          </div>
        </div>
        <RiskBadge band={data.risk_band} score={data.final_risk_score} />
      </div>

      {ledgerSummary && (
        <div className="px-5 py-2 bg-amber-50 border-b border-amber-100 text-xs flex flex-wrap items-center justify-between gap-2">
          <span className="text-amber-900">{ledgerSummary}</span>
          <button type="button" onClick={() => openLedger('full')} className="font-semibold text-blue-700">
            Open score ledger
          </button>
        </div>
      )}

      {/* Quick Prompts Bar */}
      {messages.length <= 1 && (
        <div className="px-5 py-3 bg-slate-50 border-b border-slate-200 flex-shrink-0">
          <p className="text-[11px] font-bold uppercase text-slate-500 tracking-wider mb-2">Quick Investigation Prompts</p>
          <div className="flex flex-wrap gap-2">
            {QUICK_QUESTIONS.map(q => (
              <button
                key={q.label}
                onClick={() => sendMessage(q.label)}
                disabled={isStreaming}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-white border border-slate-200 rounded-lg text-slate-700 font-medium hover:bg-blue-50 hover:border-blue-300 hover:text-blue-700 transition-colors shadow-2xs disabled:opacity-50"
              >
                <span className="text-slate-400">{q.icon}</span>
                {q.label}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Chat Messages */}
      <div className="flex-1 overflow-y-auto px-5 py-6 space-y-6 min-h-0 bg-slate-50/40">
        {messages.map(msg => (
          <div key={msg.id} className={`flex gap-4 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}>

            {/* Avatar */}
            <div className={`flex-shrink-0 w-8 h-8 rounded-xl flex items-center justify-center shadow-2xs ${
              msg.role === 'user'
                ? 'bg-blue-700 text-white'
                : 'bg-slate-900 text-blue-400 border border-slate-800'
            }`}>
              {msg.role === 'user' ? <User className="h-4 w-4" /> : <Shield className="h-4 w-4" />}
            </div>

            {/* Message Box */}
            <div className={`flex flex-col gap-1.5 ${msg.role === 'user' ? 'items-end' : 'items-start'} w-full max-w-4xl`}>
              <div className={`rounded-2xl ${
                msg.role === 'user'
                  ? 'bg-blue-700 text-white px-5 py-3.5 shadow-sm max-w-2xl text-xs font-medium leading-relaxed'
                  : 'bg-white border border-slate-200/90 p-5 shadow-sm text-slate-800 w-full'
              }`}>
                {msg.role === 'assistant' ? (
                  <InvestigationResponseRenderer content={msg.content} isStreaming={msg.streaming} onSendMessage={sendMessage} />
                ) : (
                  <p className="text-xs font-medium leading-relaxed">{msg.content}</p>
                )}
              </div>

              {msg.sectionsUsed && msg.sectionsUsed.length > 0 && (
                <SectionChips sections={msg.sectionsUsed} />
              )}

              <span className="text-[10px] text-slate-400 font-mono px-1">
                {msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </span>
            </div>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      {/* Input Footer */}
      <div className="px-5 py-3.5 bg-white border-t border-slate-200 flex-shrink-0 space-y-2">
        <div className="flex gap-2.5 items-center">
          <input
            ref={inputRef}
            type="text"
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage(input);
              }
            }}
            placeholder="Ask about this investigation... (e.g. Did it steal OTP messages?)"
            disabled={isStreaming}
            className="flex-1 bg-slate-50 border border-slate-200 rounded-xl px-4 py-2.5 text-xs text-slate-900 placeholder-slate-400 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 disabled:opacity-50 transition-all"
          />

          {isStreaming ? (
            <button
              onClick={handleStop}
              className="p-2.5 rounded-xl bg-red-600 text-white hover:bg-red-700 transition-colors shadow-2xs"
              title="Stop generating"
            >
              <RefreshCw className="h-4 w-4 animate-spin" />
            </button>
          ) : (
            <button
              onClick={() => sendMessage(input)}
              disabled={!input.trim()}
              className="p-2.5 rounded-xl bg-blue-700 text-white hover:bg-blue-800 transition-colors disabled:opacity-40 shadow-2xs"
              title="Send question"
            >
              <Send className="h-4 w-4" />
            </button>
          )}
        </div>

        <p className="text-[10px] text-slate-400 text-center font-mono">
          RAG-Grounded Evidence Engine · AI explains, deterministic engine decides
        </p>
      </div>
    </div>
  );
}
