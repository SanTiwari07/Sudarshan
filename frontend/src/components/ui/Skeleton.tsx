import { Loader2, AlertTriangle } from 'lucide-react';

export function LoadingSpinner({ label = 'Loading...' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center py-16 text-slate-500 gap-3" role="status" aria-live="polite">
      <Loader2 className="h-6 w-6 animate-spin text-blue-600" />
      <span className="text-sm font-medium">{label}</span>
    </div>
  );
}

export function ErrorState({ title = 'An error occurred', message, onRetry }: { title?: string; message: string; onRetry?: () => void }) {
  return (
    <div className="bg-red-50 border border-red-200 rounded-xl p-5 flex items-start gap-3">
      <AlertTriangle className="h-5 w-5 text-red-500 flex-shrink-0 mt-0.5" />
      <div className="flex-1">
        <h3 className="text-sm font-semibold text-red-800">{title}</h3>
        <p className="text-xs text-red-700 mt-1">{message}</p>
        {onRetry && (
          <button
            onClick={onRetry}
            className="mt-3 px-3 py-1 text-xs font-semibold text-red-700 bg-red-100 hover:bg-red-200 border border-red-300 rounded-md transition-colors"
          >
            Retry
          </button>
        )}
      </div>
    </div>
  );
}

export function EmptyState({ label = 'No records found' }: { label?: string }) {
  return (
    <div className="p-8 text-center text-slate-500 text-sm">
      {label}
    </div>
  );
}
