import { useCallback, useRef, useState } from 'react';
import { UploadCloud, FileArchive, AlertCircle, X } from 'lucide-react';

const MAX_BYTES = 200 * 1024 * 1024;

type UploadDropZoneProps = {
  file: File | null;
  onFile: (file: File | null) => void;
  disabled: boolean;
  disabledMessage?: string;
};

function formatSize(bytes: number) {
  return bytes >= 1024 * 1024
    ? `${(bytes / (1024 * 1024)).toFixed(2)} MB`
    : `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

export default function UploadDropZone({
  file,
  onFile,
  disabled,
  disabledMessage,
}: UploadDropZoneProps) {
  const [dragOver, setDragOver] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const validate = useCallback((f: File) => {
    if (!f.name.toLowerCase().endsWith('.apk')) {
      return 'Only .apk packages are supported.';
    }
    if (f.size > MAX_BYTES) {
      return 'Maximum file size is 200 MB.';
    }
    return null;
  }, []);

  const acceptFile = useCallback(
    (f: File | null) => {
      if (!f) {
        onFile(null);
        return;
      }
      const err = validate(f);
      if (err) {
        setLocalError(err);
        return;
      }
      setLocalError(null);
      onFile(f);
    },
    [onFile, validate],
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      if (disabled) return;
      const f = e.dataTransfer.files?.[0];
      if (f) acceptFile(f);
    },
    [acceptFile, disabled],
  );

  return (
    <div className="space-y-3">
      <div
        role="button"
        tabIndex={disabled ? -1 : 0}
        aria-label="Drop APK file here or browse"
        aria-disabled={disabled}
        onClick={() => !disabled && inputRef.current?.click()}
        onKeyDown={(e) => {
          if (disabled) return;
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            inputRef.current?.click();
          }
        }}
        onDragOver={(e) => {
          e.preventDefault();
          if (!disabled) setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={onDrop}
        className={`group relative rounded-2xl border-2 border-dashed text-center transition-all duration-200 px-6 py-12 min-h-[280px] flex flex-col justify-center items-center focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 ${
          disabled
            ? 'opacity-60 cursor-not-allowed border-slate-200 bg-slate-50'
            : dragOver
              ? 'cursor-copy border-blue-500 bg-blue-50'
              : 'cursor-pointer border-slate-300 bg-slate-50/60 hover:border-blue-400 hover:bg-blue-50/40'
        }`}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".apk,application/vnd.android.package-archive"
          className="sr-only"
          id="apk-upload-input"
          disabled={disabled}
          onChange={(e) => acceptFile(e.target.files?.[0] || null)}
        />
        <div
          className={`flex h-16 w-16 items-center justify-center rounded-2xl mb-5 transition-all duration-200 ${
            dragOver
              ? 'bg-blue-600 text-white scale-110'
              : 'bg-white text-blue-600 shadow-sm ring-1 ring-slate-200 group-hover:scale-105'
          }`}
        >
          <UploadCloud className="h-8 w-8 stroke-[1.75]" aria-hidden />
        </div>
        <p className="text-xl font-semibold text-slate-900 tracking-[-0.015em]">
          {dragOver ? 'Drop to upload' : 'Drop an APK here'}
        </p>
        <p className="text-sm text-slate-500 mt-1.5">
          or <span className="font-semibold text-blue-600 group-hover:underline">browse your files</span>
          <span className="mx-2 text-slate-300">·</span>
          .apk up to 200 MB
        </p>
      </div>

      {file && (
        <div className="flex items-center gap-3 rounded-xl border border-slate-200 bg-white p-3 pr-2">
          <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-emerald-50 text-emerald-600">
            <FileArchive className="h-5 w-5" aria-hidden />
          </span>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-semibold text-slate-900 truncate" title={file.name}>
              {file.name}
            </p>
            <p className="text-xs text-slate-500">{formatSize(file.size)} · Ready to analyse</p>
          </div>
          {!disabled && (
            <button
              type="button"
              onClick={() => acceptFile(null)}
              aria-label="Remove file"
              className="h-8 w-8 shrink-0 flex items-center justify-center rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors"
            >
              <X className="h-4 w-4" aria-hidden />
            </button>
          )}
        </div>
      )}

      {disabled && disabledMessage && (
        <p className="text-center text-xs text-amber-900/90 bg-amber-50 border border-amber-200/80 rounded-lg py-2 px-3">
          {disabledMessage}
        </p>
      )}

      {localError && (
        <div className="flex items-start gap-2 text-sm text-red-700 bg-red-50 border border-red-200 rounded-xl p-3">
          <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" aria-hidden />
          {localError}
        </div>
      )}
    </div>
  );
}
