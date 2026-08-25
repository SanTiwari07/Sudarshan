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
    <div className="space-y-3.5">
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
        className={`rounded-2xl border-2 border-dashed text-center transition-all duration-300 px-6 py-10 sm:py-14 lg:py-16 min-h-[260px] sm:min-h-[300px] flex flex-col justify-center items-center ${
          disabled
            ? 'opacity-60 cursor-not-allowed border-slate-200 bg-slate-50/80'
            : dragOver
              ? 'border-blue-500 bg-blue-50/60 shadow-md scale-[0.995]'
              : 'border-blue-200 bg-blue-50/20 hover:border-blue-400 hover:bg-blue-50/40 hover:shadow-sm'
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
        <div className="p-3 sm:p-4 rounded-2xl bg-blue-50 text-blue-600 mb-3 sm:mb-4 border border-blue-100/80 shadow-2xs">
          <UploadCloud
            className="h-10 w-10 sm:h-12 sm:w-12 stroke-[1.75]"
            aria-hidden
          />
        </div>
        <p className="text-lg sm:text-2xl font-extrabold text-slate-900 tracking-tight">
          Drag &amp; drop your APK
        </p>
        <p className="text-xs sm:text-sm text-slate-500 mt-1 max-w-md mx-auto">
          or browse to select a file from your workstation
        </p>
        <button
          type="button"
          disabled={disabled}
          onClick={() => inputRef.current?.click()}
          className="mt-4 sm:mt-5 inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-blue-700 text-white text-xs sm:text-sm font-semibold shadow-sm hover:bg-blue-800 hover:shadow-md focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 disabled:bg-slate-400 transition-all cursor-pointer"
        >
          <FileArchive className="h-4 w-4" aria-hidden />
          Browse APK
        </button>
        {file && (
          <p className="mt-3 text-xs sm:text-sm font-semibold text-blue-900 bg-white border border-blue-200 inline-block px-4 py-2 rounded-xl shadow-xs">
            <span className="font-mono">{file.name}</span>
            <span className="text-blue-600 font-normal"> · {(file.size / (1024 * 1024)).toFixed(2)} MB</span>
          </p>
        )}
      </div>

      <div className="flex flex-wrap justify-center gap-x-6 gap-y-1 text-xs text-slate-500 font-mono">
        <span>
          <span className="text-slate-700 font-semibold">Supported formats:</span>
          <span className="text-slate-500"> Android APK (.apk)</span>
        </span>
        <span>
          <span className="text-slate-700 font-semibold">Maximum size:</span>
          <span className="text-slate-500"> 200 MB</span>
        </span>
      </div>

      {disabled && disabledMessage && (
        <p className="text-center text-xs text-amber-900/90 bg-amber-50 border border-amber-200/80 rounded-lg py-2 px-3">
          {disabledMessage}
        </p>
      )}

      {localError && (
        <div className="flex items-start gap-2 text-xs text-red-700 bg-red-50 border border-red-200 rounded-lg p-3">
          <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" aria-hidden />
          {localError}
        </div>
      )}
    </div>
  );
}
