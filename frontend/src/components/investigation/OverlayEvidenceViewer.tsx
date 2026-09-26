import { useMemo, useState } from 'react';
import { Download, FileCode2, ShieldAlert } from 'lucide-react';
import type { VideOverlayPayload, VideResult } from '../../types/case';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';

/**
 * Raw HTML overlays intercepted from WebView.loadData / loadDataWithBaseURL at
 * runtime - the actual phishing markup an ATS trojan renders over the real
 * banking app.
 *
 * The payload is attacker-authored markup. It is displayed as escaped source
 * text and downloaded as a .txt attachment; it is never injected into the DOM,
 * never put in an iframe, and never rendered as HTML. An analyst dashboard that
 * executed captured phishing pages would be an own-goal.
 */

type Props = {
  vide: VideResult;
};

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

/** Credential-harvesting markers worth surfacing without reading the whole dump. */
function inspectPayload(html: string): string[] {
  const signals: string[] = [];
  const lower = html.toLowerCase();
  if (/<input[^>]+type=['"]?password/i.test(html)) signals.push('Password field');
  if (/\b(otp|one[\s-]?time)\b/i.test(lower)) signals.push('OTP prompt');
  if (/\b(mpin|pin|passcode)\b/i.test(lower)) signals.push('PIN entry');
  if (/\b(card\s*number|cvv|expiry)\b/i.test(lower)) signals.push('Card details');
  if (/<form[^>]+action=/i.test(html)) signals.push('Form submission');
  if (/\b(upi|ifsc|account\s*number)\b/i.test(lower)) signals.push('Bank identifiers');
  return signals;
}

function PayloadCard({ payload, index }: { payload: VideOverlayPayload; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const signals = useMemo(() => inspectPayload(payload.html ?? ''), [payload.html]);

  const download = () => {
    // text/plain, not text/html: the browser must never be asked to render it.
    const blob = new Blob([payload.html ?? ''], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `overlay-${payload.sha256?.slice(0, 12) ?? index}.html.txt`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <li className="rounded border border-slate-200">
      <div className="flex items-center justify-between gap-2 px-2.5 py-1.5 bg-slate-50/70 border-b border-slate-200">
        <div className="min-w-0">
          <p className="text-[13px] font-semibold text-slate-800 truncate">
            {payload.hook || payload.source || 'WebView payload'}
          </p>
          <p className="text-[13px] text-slate-500 font-mono truncate">
            {payload.sha256?.slice(0, 24)}… · {formatBytes(payload.length ?? 0)}
            {payload.truncated ? ' · truncated' : ''}
          </p>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            className="text-[13px] px-2 py-0.5 rounded border border-slate-300 text-slate-700 hover:bg-white"
          >
            {expanded ? 'Hide' : 'View source'}
          </button>
          <button
            type="button"
            onClick={download}
            className="text-[13px] px-2 py-0.5 rounded border border-slate-300 text-slate-700 hover:bg-white inline-flex items-center gap-1"
          >
            <Download className="h-3 w-3" /> Download
          </button>
        </div>
      </div>

      {signals.length > 0 && (
        <div className="px-2.5 py-1.5 flex flex-wrap gap-1 border-b border-slate-100">
          {signals.map((s) => (
            <span
              key={s}
              className="text-[13px] bg-rose-50 border border-rose-200 text-rose-800 rounded px-1.5 py-0.5"
            >
              {s}
            </span>
          ))}
        </div>
      )}

      {expanded && (
        // Escaped source text. React escapes this automatically; it is never
        // set as innerHTML.
        <pre className="px-2.5 py-2 max-h-72 overflow-auto text-[13px] font-mono text-slate-700 whitespace-pre-wrap break-all bg-slate-50/40">
          {payload.html}
        </pre>
      )}
    </li>
  );
}

export default function OverlayEvidenceViewer({ vide }: Props) {
  const payloads = vide.overlay_payloads ?? [];
  if (payloads.length === 0) return null;

  return (
    <SocCard>
      <SectionHeader
        icon={<FileCode2 className="h-4 w-4" />}
        title="Overlay evidence - intercepted WebView payloads"
        subtitle="Raw HTML captured from WebView.loadData / loadDataWithBaseURL at runtime"
        badge={
          <span className="text-[13px] font-semibold px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200">
            {payloads.length} payload{payloads.length === 1 ? '' : 's'}
          </span>
        }
      />
      <div className="p-3.5 space-y-2">
        <p className="text-[13px] text-slate-600 flex items-start gap-1.5">
          <ShieldAlert className="h-3.5 w-3.5 text-amber-600 shrink-0 mt-px" />
          <span>
            Attacker-authored markup, shown as escaped source and downloaded as plain text.
            It is never rendered as HTML by this dashboard.
          </span>
        </p>
        <ul className="space-y-2">
          {payloads.map((p, i) => (
            <PayloadCard key={p.sha256 ?? i} payload={p} index={i} />
          ))}
        </ul>
      </div>
    </SocCard>
  );
}

