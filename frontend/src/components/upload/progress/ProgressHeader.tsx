type ProgressHeaderProps = {
  fileName: string;
  progress: number;
};

export default function ProgressHeader({ fileName, progress }: ProgressHeaderProps) {
  const pct = Math.min(100, Math.round(progress));

  return (
    <header className="text-center space-y-5">
      <div className="space-y-2">
        <p className="text-sm text-slate-500">Investigating APK</p>
        <h1 className="text-2xl sm:text-3xl font-semibold text-slate-900 tracking-tight">{fileName}</h1>
        <p className="text-base text-slate-600 font-medium">Banking malware investigation in progress</p>
      </div>

      <p className="text-sm text-slate-500 leading-relaxed max-w-xl mx-auto">
        Sudarshan is performing a multi-stage investigation using static intelligence, runtime behaviour
        analysis, threat correlation, and deterministic risk assessment.
      </p>

      <div className="pt-2 max-w-lg mx-auto">
        <div className="flex items-center gap-4">
          <div
            className="flex-1 h-1 rounded-full bg-slate-200 overflow-hidden"
            role="progressbar"
            aria-valuenow={pct}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label="Investigation progress"
          >
            <div
              className="h-full rounded-full bg-blue-600 transition-[width] duration-500 ease-out"
              style={{ width: `${pct}%` }}
            />
          </div>
          <span className="text-sm font-medium text-slate-600 tabular-nums w-10 text-right">{pct}%</span>
        </div>
      </div>
    </header>
  );
}
