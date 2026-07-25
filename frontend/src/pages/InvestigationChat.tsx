import React, { useState, useRef, useEffect, useCallback } from 'react';
import {
  Shield, Send, MessageSquare, ChevronRight, AlertTriangle,
  CheckCircle2, XCircle, Info, Zap, Globe, Activity, FileText,
  Target, Lock, BarChart2, User, Clock, RefreshCw, Cpu
} from 'lucide-react';
import type { FraudCardData } from '../App';
import { getToken } from './Login';

// ─── Types ────────────────────────────────────────────────────────────────────

type MessageRole = 'user' | 'assistant' | 'system';

interface ChatMessage {
  id: string;
  role: MessageRole;
  content: string;
  sectionsUsed?: string[];
  followUps?: string[];
  timestamp: Date;
  streaming?: boolean;
}

interface InvestigationChatProps {
  data: FraudCardData | null;
}

// ─── Quick Start Questions ─────────────────────────────────────────────────────

const QUICK_QUESTIONS = [
  { label: 'Is this APK safe?', icon: <Shield className="h-3.5 w-3.5" /> },
  { label: 'Explain the risk score', icon: <BarChart2 className="h-3.5 w-3.5" /> },
  { label: 'Did it steal OTP messages?', icon: <MessageSquare className="h-3.5 w-3.5" /> },
  { label: 'Did it abuse Accessibility?', icon: <Activity className="h-3.5 w-3.5" /> },
  { label: 'Which MITRE techniques apply?', icon: <Target className="h-3.5 w-3.5" /> },
  { label: 'Should I block this APK?', icon: <Lock className="h-3.5 w-3.5" /> },
  { label: 'Generate executive summary', icon: <FileText className="h-3.5 w-3.5" /> },
  { label: 'Show network indicators', icon: <Globe className="h-3.5 w-3.5" /> },
];

// ─── Parsing & Formatting ─────────────────────────────────────────────────────

function parseFollowUps(content: string): { text: string; followUps: string[] } {
  // Extract JSON array of follow-up questions from response
  const match = content.match(/\[([^\]]+)\]/s);
  if (match) {
    try {
      const arr = JSON.parse(`[${match[1]}]`);
      if (Array.isArray(arr) && arr.every(x => typeof x === 'string')) {
        const cleanText = content.replace(match[0], '').replace(/---FOLLOW-UP QUESTIONS---\s*/g, '').trim();
        return { text: cleanText, followUps: arr };
      }
    } catch {
      // not valid JSON array, continue
    }
  }
  return { text: content, followUps: [] };
}

function formatMessageContent(content: string): React.ReactNode {
  // Split by section headers and render them styled
  const sections = [
    { key: '---DIRECT ANSWER---', label: 'Direct Answer', color: 'text-cyan-300', bg: 'bg-cyan-950/40', border: 'border-cyan-700/40' },
    { key: '---SIMPLE ENGLISH---', label: 'Simple English', color: 'text-emerald-300', bg: 'bg-emerald-950/40', border: 'border-emerald-700/40' },
    { key: '---WHY---', label: 'Why We Reached This Decision', color: 'text-yellow-300', bg: 'bg-yellow-950/30', border: 'border-yellow-700/40' },
    { key: '---DETAILED FINDINGS---', label: 'Detailed Findings', color: 'text-blue-300', bg: 'bg-blue-950/30', border: 'border-blue-700/40' },
    { key: '---CONFIDENCE---', label: 'Confidence', color: 'text-purple-300', bg: 'bg-purple-950/40', border: 'border-purple-700/40' },
    { key: '---RECOMMENDATION---', label: 'Recommendation', color: 'text-orange-300', bg: 'bg-orange-950/30', border: 'border-orange-700/40' },
    { key: '---SOURCES USED---', label: 'Evidence Sources', color: 'text-slate-300', bg: 'bg-slate-800/50', border: 'border-slate-600/40' },
  ];

  // Find all section positions
  let remaining = content;
  const parts: { label: string; text: string; color: string; bg: string; border: string }[] = [];

  // Extract follow-ups first
  const { text: cleanContent } = parseFollowUps(remaining);
  remaining = cleanContent;

  for (const section of sections) {
    const idx = remaining.indexOf(section.key);
    if (idx !== -1) {
      // text before this section
      const before = remaining.slice(0, idx).trim();
      if (before && parts.length === 0) {
        parts.push({ label: '', text: before, color: 'text-slate-200', bg: '', border: '' });
      }
      // find next section start
      let nextIdx = remaining.length;
      for (const other of sections) {
        if (other.key !== section.key) {
          const ni = remaining.indexOf(other.key, idx + section.key.length);
          if (ni !== -1 && ni < nextIdx) nextIdx = ni;
        }
      }
      // Also stop before follow-up
      const fuIdx = remaining.indexOf('---FOLLOW-UP QUESTIONS---', idx);
      if (fuIdx !== -1 && fuIdx < nextIdx) nextIdx = fuIdx;

      const sectionText = remaining.slice(idx + section.key.length, nextIdx).trim();
      parts.push({ label: section.label, text: sectionText, color: section.color, bg: section.bg, border: section.border });
      remaining = remaining.slice(nextIdx);
    }
  }

  // If no sections found, just render plain text
  if (parts.length === 0) {
    return <pre className="whitespace-pre-wrap text-sm text-slate-200 font-sans leading-relaxed">{content}</pre>;
  }

  return (
    <div className="space-y-3">
      {parts.map((part, i) => (
        <div key={i} className={`rounded-lg border ${part.border || 'border-slate-700/40'} ${part.bg} overflow-hidden`}>
          {part.label && (
            <div className={`px-3 py-1.5 text-xs font-bold uppercase tracking-wider ${part.color} border-b border-current/10 opacity-80`}>
              {part.label}
            </div>
          )}
          <div className="px-3 py-2.5">
            <FormattedText text={part.text} />
          </div>
        </div>
      ))}
    </div>
  );
}

function FormattedText({ text }: { text: string }) {
  const lines = text.split('\n');
  return (
    <div className="space-y-1">
      {lines.map((line, i) => {
        if (!line.trim()) return <div key={i} className="h-1" />;

        // Bullet with check mark
        if (line.trim().startsWith('✔') || line.trim().startsWith('✓')) {
          return (
            <div key={i} className="flex items-start gap-2 text-sm text-emerald-300">
              <CheckCircle2 className="h-3.5 w-3.5 mt-0.5 flex-shrink-0" />
              <span>{line.replace(/^[✔✓]\s*/, '')}</span>
            </div>
          );
        }
        // Bullet with X mark
        if (line.trim().startsWith('✗') || line.trim().startsWith('✘') || line.trim().startsWith('✕')) {
          return (
            <div key={i} className="flex items-start gap-2 text-sm text-red-400">
              <XCircle className="h-3.5 w-3.5 mt-0.5 flex-shrink-0" />
              <span>{line.replace(/^[✗✘✕]\s*/, '')}</span>
            </div>
          );
        }
        // Bullet
        if (line.trim().startsWith('•') || line.trim().startsWith('-') || line.trim().startsWith('*')) {
          return (
            <div key={i} className="flex items-start gap-2 text-sm text-slate-300">
              <ChevronRight className="h-3.5 w-3.5 mt-0.5 flex-shrink-0 text-slate-500" />
              <span>{line.replace(/^[•\-*]\s*/, '')}</span>
            </div>
          );
        }
        // Bold header line (ends with :)
        if (line.trim().endsWith(':') && line.length < 60) {
          return <p key={i} className="text-sm font-semibold text-slate-200 mt-2">{line}</p>;
        }
        // Default
        return <p key={i} className="text-sm text-slate-300 leading-relaxed">{line}</p>;
      })}
    </div>
  );
}

// ─── Risk Badge ───────────────────────────────────────────────────────────────

function RiskBadge({ band, score }: { band: string; score: number }) {
  const configs: Record<string, { bg: string; text: string; glow: string }> = {
    'Critical':  { bg: 'bg-red-950/60 border-red-500/50',    text: 'text-red-400',    glow: 'shadow-red-900/50' },
    'High Risk': { bg: 'bg-orange-950/60 border-orange-500/50', text: 'text-orange-400', glow: 'shadow-orange-900/50' },
    'Suspicious': { bg: 'bg-yellow-950/60 border-yellow-500/50', text: 'text-yellow-400', glow: 'shadow-yellow-900/50' },
    'Safe':      { bg: 'bg-emerald-950/60 border-emerald-500/50', text: 'text-emerald-400', glow: 'shadow-emerald-900/50' },
  };
  const cfg = configs[band] || configs['Suspicious'];
  return (
    <div className={`px-3 py-1.5 rounded-lg border ${cfg.bg} shadow-lg ${cfg.glow}`}>
      <div className={`text-xs font-bold uppercase tracking-wider ${cfg.text}`}>{band}</div>
      <div className={`text-xl font-black ${cfg.text}`}>{score.toFixed(1)}<span className="text-xs font-normal opacity-60">/100</span></div>
    </div>
  );
}

// ─── Section Chips ─────────────────────────────────────────────────────────────

const SECTION_LABELS: Record<string, string> = {
  verdict: 'Verdict', risk_engine: 'Risk Engine', permissions: 'Permissions',
  static_findings: 'Static', dynamic_findings: 'Dynamic', threat_intelligence: 'Threat Intel',
  mitre: 'MITRE', malware_family: 'Family', network: 'Network',
  manifest: 'Manifest', timeline: 'Timeline', runtime_events: 'Runtime',
  recommendations: 'Actions',
};

function SectionChips({ sections }: { sections: string[] }) {
  if (!sections.length) return null;
  return (
    <div className="flex flex-wrap gap-1 mt-2">
      {sections.map(s => (
        <span key={s} className="text-xs px-2 py-0.5 bg-slate-800/80 border border-slate-700/60 rounded-full text-slate-400 font-mono">
          {SECTION_LABELS[s] || s}
        </span>
      ))}
    </div>
  );
}

// ─── Streaming Indicator ───────────────────────────────────────────────────────

function StreamingDots() {
  return (
    <div className="flex items-center gap-1 px-3 py-2">
      {[0, 1, 2].map(i => (
        <div
          key={i}
          className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-bounce"
          style={{ animationDelay: `${i * 0.15}s` }}
        />
      ))}
      <span className="ml-2 text-xs text-slate-500">Analyzing evidence...</span>
    </div>
  );
}

// ─── Main Component ────────────────────────────────────────────────────────────

export default function InvestigationChat({ data }: InvestigationChatProps) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [isStreaming, setIsStreaming] = useState(false);
  const [streamingId, setStreamingId] = useState<string | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  // Initialize with welcome message
  useEffect(() => {
    if (data) {
      const welcome: ChatMessage = {
        id: 'welcome',
        role: 'assistant',
        content: `Investigation loaded for **${data.package_name || 'this APK'}**.\n\nRisk Score: **${data.final_risk_score.toFixed(1)}/100** (${data.risk_band})\n\nI have indexed ${data.sha256 ? 'the complete' : 'available'} investigation evidence. Ask me anything about this APK — what it does, why it's classified this way, which threats were found, or what action to take.`,
        timestamp: new Date(),
      };
      setMessages([welcome]);
    }
  }, [data?.sha256]);

  // Auto-scroll
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const sendMessage = useCallback(async (question: string) => {
    if (!question.trim() || isStreaming || !data) return;

    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: question,
      timestamp: new Date(),
    };

    const assistantId = `assistant-${Date.now()}`;
    const assistantMsg: ChatMessage = {
      id: assistantId,
      role: 'assistant',
      content: '',
      streaming: true,
      timestamp: new Date(),
    };

    setMessages(prev => [...prev, userMsg, assistantMsg]);
    setInput('');
    setIsStreaming(true);
    setStreamingId(assistantId);

    // Build history for context (last 6 messages)
    const history = messages.slice(-6).map(m => ({
      role: m.role,
      content: m.content.slice(0, 400),
    }));

    try {
      const token = getToken();
      abortRef.current = new AbortController();

      const response = await fetch('/api/v1/chat/stream', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          sha256: data.sha256,
          question,
          history,
        }),
        signal: abortRef.current.signal,
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const reader = response.body?.getReader();
      if (!reader) throw new Error('No response body');

      const decoder = new TextDecoder();
      let buffer = '';
      let fullText = '';
      let sectionsUsed: string[] = [];

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        let currentEvent = '';
        for (const line of lines) {
          if (line.startsWith('event: ')) {
            currentEvent = line.slice(7).trim();
          } else if (line.startsWith('data: ')) {
            const data_str = line.slice(6);
            if (currentEvent === 'sections') {
              try { sectionsUsed = JSON.parse(data_str); } catch {}
            } else if (currentEvent === 'token') {
              fullText += data_str;
              setMessages(prev => prev.map(m =>
                m.id === assistantId
                  ? { ...m, content: fullText }
                  : m
              ));
            } else if (currentEvent === 'error') {
              fullText = `I encountered an error: ${data_str}`;
              setMessages(prev => prev.map(m =>
                m.id === assistantId
                  ? { ...m, content: fullText, streaming: false }
                  : m
              ));
            }
            // Reset after data line
            currentEvent = '';
          }
        }
      }

      // Parse follow-ups from the final content
      const { followUps } = parseFollowUps(fullText);

      setMessages(prev => prev.map(m =>
        m.id === assistantId
          ? { ...m, content: fullText, streaming: false, sectionsUsed, followUps }
          : m
      ));

    } catch (err: any) {
      if (err.name === 'AbortError') return;
      const errMsg = `I couldn't retrieve a response. Please check that the backend is running and try again.\n\nError: ${err.message}`;
      setMessages(prev => prev.map(m =>
        m.id === assistantId
          ? { ...m, content: errMsg, streaming: false }
          : m
      ));
    } finally {
      setIsStreaming(false);
      setStreamingId(null);
      inputRef.current?.focus();
    }
  }, [data, isStreaming, messages]);

  const handleStop = () => {
    abortRef.current?.abort();
    setIsStreaming(false);
    setStreamingId(null);
    setMessages(prev => prev.map(m =>
      m.streaming ? { ...m, streaming: false } : m
    ));
  };

  if (!data) {
    return (
      <div className="flex flex-col items-center justify-center h-96 text-center space-y-4">
        <Shield className="h-16 w-16 text-slate-600" />
        <p className="text-slate-400 text-lg font-medium">No investigation loaded</p>
        <p className="text-slate-600 text-sm">Analyze an APK first, then return to this page.</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full min-h-0 bg-slate-950 rounded-xl overflow-hidden" style={{ height: 'calc(100vh - 80px)' }}>

      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 bg-slate-900/80 backdrop-blur border-b border-slate-700/50 flex-shrink-0">
        <div className="flex items-center gap-3">
          <div className="relative">
            <Cpu className="h-7 w-7 text-cyan-400" />
            <div className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          </div>
          <div>
            <h1 className="text-sm font-bold text-white tracking-wide">SUDARSHAN Investigation Assistant</h1>
            <p className="text-xs text-slate-500 font-mono">
              {data.package_name} · SHA256: {data.sha256.slice(0, 12)}…
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <RiskBadge band={data.risk_band} score={data.final_risk_score} />
        </div>
      </div>

      {/* Quick questions bar */}
      {messages.length <= 1 && (
        <div className="px-4 py-2.5 bg-slate-900/60 border-b border-slate-800/50 flex-shrink-0">
          <p className="text-xs text-slate-500 mb-2 font-medium">Quick Questions</p>
          <div className="flex flex-wrap gap-1.5">
            {QUICK_QUESTIONS.map(q => (
              <button
                key={q.label}
                onClick={() => sendMessage(q.label)}
                disabled={isStreaming}
                className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs bg-slate-800/80 border border-slate-700/60 rounded-full text-slate-300 hover:bg-slate-700/80 hover:border-cyan-600/50 hover:text-cyan-300 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <span className="text-slate-500">{q.icon}</span>
                {q.label}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Messages */}
      <div className="flex-1 overflow-y-auto px-4 py-4 space-y-5 min-h-0 scrollbar-thin scrollbar-track-slate-900 scrollbar-thumb-slate-700">
        {messages.map(msg => (
          <div key={msg.id} className={`flex gap-3 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}>

            {/* Avatar */}
            <div className={`flex-shrink-0 w-7 h-7 rounded-full flex items-center justify-center
              ${msg.role === 'user'
                ? 'bg-gradient-to-br from-blue-600 to-blue-800 shadow-lg shadow-blue-900/40'
                : 'bg-gradient-to-br from-cyan-700 to-slate-800 shadow-lg shadow-cyan-900/30 border border-cyan-700/40'
              }`}
            >
              {msg.role === 'user'
                ? <User className="h-3.5 w-3.5 text-white" />
                : <Shield className="h-3.5 w-3.5 text-cyan-300" />
              }
            </div>

            {/* Bubble */}
            <div className={`max-w-2xl ${msg.role === 'user' ? 'items-end' : 'items-start'} flex flex-col gap-1`}>
              <div className={`rounded-2xl px-4 py-3 ${
                msg.role === 'user'
                  ? 'bg-blue-600/80 text-white rounded-tr-sm border border-blue-500/30 shadow-lg shadow-blue-900/30'
                  : 'bg-slate-800/70 rounded-tl-sm border border-slate-700/50 shadow-lg shadow-slate-900/40 backdrop-blur'
              }`}>
                {msg.streaming && !msg.content
                  ? <StreamingDots />
                  : msg.role === 'assistant'
                    ? formatMessageContent(msg.content)
                    : <p className="text-sm leading-relaxed">{msg.content}</p>
                }
              </div>

              {/* Metadata */}
              {msg.sectionsUsed && msg.sectionsUsed.length > 0 && (
                <SectionChips sections={msg.sectionsUsed} />
              )}

              {/* Follow-up questions */}
              {msg.followUps && msg.followUps.length > 0 && !isStreaming && (
                <div className="flex flex-wrap gap-1.5 mt-1">
                  {msg.followUps.map((q, i) => (
                    <button
                      key={i}
                      onClick={() => sendMessage(q)}
                      className="text-xs px-2.5 py-1 bg-slate-900/80 border border-slate-700/50 rounded-full text-slate-400 hover:text-cyan-300 hover:border-cyan-700/50 hover:bg-slate-800/80 transition-all duration-200"
                    >
                      {q}
                    </button>
                  ))}
                </div>
              )}

              <span className="text-xs text-slate-600">
                {msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </span>
            </div>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      {/* Input bar */}
      <div className="px-4 py-3 bg-slate-900/80 backdrop-blur border-t border-slate-700/50 flex-shrink-0">
        <div className="flex gap-2 items-end">
          <div className="flex-1 relative">
            <input
              ref={inputRef}
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
              className="w-full bg-slate-800/70 border border-slate-700/60 rounded-xl px-4 py-2.5 text-sm text-slate-200 placeholder-slate-500
                focus:outline-none focus:ring-2 focus:ring-cyan-600/50 focus:border-cyan-600/50
                disabled:opacity-50 disabled:cursor-not-allowed transition-all"
            />
          </div>

          {isStreaming ? (
            <button
              onClick={handleStop}
              className="flex-shrink-0 p-2.5 rounded-xl bg-red-900/60 border border-red-700/50 text-red-400 hover:bg-red-800/60 transition-colors"
              title="Stop generating"
            >
              <RefreshCw className="h-4 w-4" />
            </button>
          ) : (
            <button
              onClick={() => sendMessage(input)}
              disabled={!input.trim()}
              className="flex-shrink-0 p-2.5 rounded-xl bg-cyan-700/80 border border-cyan-600/50 text-cyan-100
                hover:bg-cyan-600/80 transition-colors disabled:opacity-40 disabled:cursor-not-allowed
                shadow-lg shadow-cyan-900/30"
              title="Send (Enter)"
            >
              <Send className="h-4 w-4" />
            </button>
          )}
        </div>

        <p className="text-xs text-slate-600 mt-1.5 text-center">
          Answers are generated from investigation evidence only — Gemini explains, the deterministic engine decides.
        </p>
      </div>
    </div>
  );
}
