import { useState } from 'react';
import { ChevronDown, Info } from 'lucide-react';
import type { FraudCardData } from '../../App';
import { TYPOGRAPHY } from '../../theme/typography';
import { extractAppMetadata } from '../../lib/analystCopy';
import CopyButton from '../ui/CopyButton';

/**
 * Case metadata, collapsed.
 *
 * Eight label/value rows that used to sit at the top of the page in the same
 * typographic register as the verdict, half of them reading as a dash. None of
 * it answers "is this app dangerous"; all of it matters once you have decided
 * it is. So it lives one click down, below the findings rather than above them.
 *
 * Lifted out of FraudRiskHero unchanged when that component was replaced by
 * VerdictBlock - it was the one part of the hero that was already in the right
 * register, it just needed to stop being attached to the verdict.
 */
export default function CaseDetails({ data }: { data: FraudCardData }) {
  const [open, setOpen] = useState(false);
  const meta = extractAppMetadata(data);

  const clean = (v: unknown) => {
    const s = typeof v === 'string' ? v.trim() : '';
    return s && s !== '—' && s !== '-' && s !== 'Unknown' ? s : null;
  };

  const rows: Array<{ label: string; value: string; mono?: boolean; copy?: boolean }> = [];
  const push = (
    label: string,
    value: string | null,
    opts: { mono?: boolean; copy?: boolean } = {},
  ) => {
    if (value) rows.push({ label, value, ...opts });
  };

  push('App name', clean(data.app_name));
  push('Package', clean(data.package_name), { mono: true, copy: true });
  push('Version', clean(meta.version) ?? clean(data.version_name));
  push('Size', clean(meta.size) ?? clean(data.apk_size));
  push('SHA-256', clean(data.sha256), { mono: true, copy: true });
  push('Platform', 'Android (APK)');
  push('Family', clean(data.family_classification));
  push('Analysis mode', clean(data.analysis_mode));

  if (data.created_at) {
    push(
      'Analysed',
      new Date(data.created_at).toLocaleString('en-GB', {
        day: '2-digit',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: true,
      }),
    );
  }

  if (rows.length === 0) return null;

  const subject = data.package_name || data.sha256 || '';

  return (
    <section
      aria-label="Case details"
      className="bg-white border border-slate-200 rounded-lg overflow-hidden"
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="w-full flex items-center justify-between gap-2 px-5 py-3 text-left hover:bg-slate-50/70 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
      >
        <span className={`${TYPOGRAPHY.label} flex items-center gap-2`}>
          <Info className="h-3.5 w-3.5 text-slate-400" aria-hidden />
          Case details
          <span className="font-mono text-slate-500">
            {subject.slice(0, 28)}
            {subject.length > 28 ? '…' : ''}
          </span>
        </span>
        <ChevronDown
          className={`h-4 w-4 text-slate-500 transition-transform ${open ? 'rotate-180' : ''}`}
          aria-hidden
        />
      </button>

      {open && (
        <dl className="px-5 pb-4 grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-0">
          {rows.map((row) => (
            <div
              key={row.label}
              className={`flex items-baseline justify-between gap-3 py-1.5 border-b border-slate-100 ${
                row.label === 'SHA-256' ? 'sm:col-span-2' : ''
              }`}
            >
              <dt className={TYPOGRAPHY.label}>{row.label}</dt>
              <dd className="flex items-center gap-1.5 min-w-0">
                <span
                  className={`${row.mono ? TYPOGRAPHY.codeSm : TYPOGRAPHY.bodySmall} text-right truncate`}
                  title={row.value}
                >
                  {row.value}
                </span>
                {row.copy && (
                  <CopyButton
                    value={row.value}
                    className="h-4 w-4 p-0 shrink-0 text-slate-300 hover:text-slate-600"
                  />
                )}
              </dd>
            </div>
          ))}
        </dl>
      )}
    </section>
  );
}
