import { useCallback, useRef, useState } from 'react';
import { UploadCloud, FileArchive, AlertCircle } from 'lucide-react';

const MAX_BYTES = 200 * 1024 * 1024;

type UploadDropZoneProps = {
  file: File | null;
  onFile: (file: File | null) => void;
  disabled: boolean;
  disabledMessage?: string;
};

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
    <div className="space-y-4">
      <div
        role="button"
        tabIndex={disabled ? -1 : 0}
        aria-label="Drop APK file here or browse"
        aria-disabled={disabled}
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
        className={`rounded-2xl border-2 border-dashed text-center transition-all duration-300 px-6 py-14 sm:py-16 ${
          disabled
            ? 'opacity-60 cursor-not-allowed border-slate-200 bg-slate-50/80'
            : dragOver
              ? 'border-blue-400 bg-blue-50/50 shadow-sm'
              : 'border-blue-200/90 bg-blue-50/30 hover:border-blue-300 hover:bg-blue-50/50'
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
        <UploadCloud
          className="h-[4.5rem] w-[4.5rem] sm:h-20 sm:w-20 text-blue-600 mx-auto mb-6 stroke-[1.25]"
          aria-hidden
        />
        <p className="text-xl sm:text-2xl font-semibold text-slate-900 tracking-tight">
          Drag &amp; drop your APK
        </p>
        <p className="text-sm sm:text-base text-slate-500 mt-2 max-w-md mx-auto">
          or browse to select a file from your workstation
        </p>
        <button
          type="button"
          disabled={disabled}
          onClick={() => inputRef.current?.click()}
          className="mt-8 inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-blue-700 text-white text-sm font-medium hover:bg-blue-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 disabled:bg-slate-400 transition-colors"
        >
          <FileArchive className="h-4 w-4" aria-hidden />
          Browse APK
        </button>
        {file && (
          <p className="mt-6 text-sm font-medium text-blue-900 bg-white/80 border border-blue-100 inline-block px-4 py-2 rounded-xl shadow-sm">
            <span className="font-mono">{file.name}</span>
            <span className="text-blue-600/80"> · {(file.size / (1024 * 1024)).toFixed(2)} MB</span>
          </p>
        )}
      </div>

      <div className="flex flex-wrap justify-center gap-x-8 gap-y-2 text-sm text-slate-500">
        <span>
          <span className="text-slate-700 font-medium">Supported formats</span>
          <span className="text-slate-500"> · Android APK</span>
        </span>
        <span>
          <span className="text-slate-700 font-medium">Maximum size</span>
          <span className="text-slate-500"> · 200 MB</span>
        </span>
      </div>

      {disabled && disabledMessage && (
        <p className="text-center text-sm text-amber-900/90 bg-amber-50 border border-amber-200/80 rounded-xl py-3 px-4">
          {disabledMessage}
        </p>
      )}

      {localError && (
        <div className="flex items-start gap-2 text-sm text-red-700 bg-red-50 border border-red-200 rounded-xl p-4">
          <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" aria-hidden />
          {localError}
        </div>
      )}
    </div>
  );
}
