import { AlertOctagon, ChevronRight, FileCode } from 'lucide-react';
import type { FraudCardData } from '../../types/case';
import { useNavigate } from 'react-router-dom';

export default function ConcealedPayload({ data }: { data: FraudCardData }) {
  const navigate = useNavigate();

  const hasConcealedPayload = Boolean(data.frs_breakdown?.concealed_payload);
  const hasReflection = Boolean(data.has_reflection);

  // Check for dynamic class loading or reflection APIs fired
  const apis = data.technical_view?.apis_fired || [];
  const classLoaderApis = apis.filter((a) =>
    /classloader|dexclassloader|pathclassloader/i.test(a),
  );
  const reflectionApis = apis.filter((a) =>
    /reflect|getmethod|invok/i.test(a),
  );

  if (!hasConcealedPayload && !hasReflection && classLoaderApis.length === 0 && reflectionApis.length === 0) {
    return null;
  }

  const signals = [
    ...(hasConcealedPayload ? [{ label: 'Dynamic Class Loading', type: 'loader' }] : []),
    ...(hasReflection ? [{ label: 'Reflection Execution', type: 'reflection' }] : []),
    ...classLoaderApis.slice(0, 2).map((api) => ({ label: api, type: 'api' })),
    ...reflectionApis.slice(0, 2).map((api) => ({ label: api, type: 'api' })),
  ];

  const handleSignalClick = () => {
    navigate(`/case/${data.sha256}/evidence?section=static`);
  };

  return (
    <div className="rounded-2xl border border-amber-300 bg-amber-50/70 p-5 shadow-xs h-full flex flex-col justify-between">
      <div>
        <div className="flex items-center gap-2 mb-2">
          <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-amber-200 text-amber-800">
            <AlertOctagon className="h-3.5 w-3.5" />
          </div>
          <h2 className="text-xs font-bold text-amber-950 uppercase tracking-wider">
            CONCEALED / DYNAMIC PAYLOAD DETECTED
          </h2>
        </div>

        <p className="text-xs text-amber-900/90 leading-relaxed font-medium mb-3">
          Static analysis indicates evasive multi-stage execution. Secondary payloads or encrypted assets may be unpacked at runtime.
        </p>

        <div className="flex flex-wrap gap-1.5 mb-3">
          {signals.map((sig, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => handleSignalClick(sig)}
              className="inline-flex items-center gap-1 rounded-md bg-white hover:bg-amber-100 px-2 py-1 text-[11px] font-mono font-medium text-amber-900 border border-amber-300 transition-colors cursor-pointer shadow-2xs"
              title="Click to jump to static concealment evidence"
            >
              <FileCode className="h-3 w-3 text-amber-600" />
              <span>{sig.label}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="pt-2.5 border-t border-amber-200/80 flex items-center justify-between text-xs">
        <span className="text-amber-800 text-[11px] font-medium">Secondary payload evasion risk</span>
        <button
          type="button"
          onClick={() => navigate(`/case/${data.sha256}/evidence?section=static`)}
          className="inline-flex items-center gap-1 font-semibold text-amber-900 hover:text-amber-950 transition-colors cursor-pointer"
        >
          <span>Static evidence</span>
          <ChevronRight className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
}
