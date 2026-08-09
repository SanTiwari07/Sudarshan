import { useEffect } from 'react';
import { X } from 'lucide-react';
import type { ReactNode } from 'react';

type FindingDrawerShellProps = {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  headerExtra?: ReactNode;
  children: ReactNode;
};

export default function FindingDrawerShell({
  open,
  onClose,
  title,
  subtitle,
  headerExtra,
  children,
}: FindingDrawerShellProps) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true" aria-labelledby="finding-drawer-title">
      <div className="absolute inset-0 bg-slate-900/40" onClick={onClose} aria-hidden />
      <div className="relative w-full max-w-lg sm:max-w-xl bg-white h-full shadow-2xl border-l border-slate-200 flex flex-col">
        <div className="px-5 py-4 border-b flex justify-between items-start shrink-0 gap-3">
          <div className="min-w-0">
            <h2 id="finding-drawer-title" className="text-sm font-bold text-slate-900">
              {title}
            </h2>
            {subtitle && <p className="text-xs text-slate-500 mt-1">{subtitle}</p>}
            {headerExtra}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded hover:bg-slate-100 shrink-0"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-5">{children}</div>
      </div>
    </div>
  );
}

export function FindingSection({ label, children }: { label: string; children: ReactNode }) {
  return (
    <section className="mb-5">
      <h3 className="text-[10px] font-bold uppercase tracking-wide text-slate-500 mb-2">{label}</h3>
      <div className="text-xs text-slate-700 leading-relaxed">{children}</div>
    </section>
  );
}
