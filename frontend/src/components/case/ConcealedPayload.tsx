import { AlertOctagon, ChevronRight } from 'lucide-react';
import type { FraudCardData } from '../../types/case';
import { Link } from 'react-router-dom';

export default function ConcealedPayload({ data }: { data: FraudCardData }) {
  // Check if there is a concealed payload
  const hasConcealedPayload = data.frs_breakdown?.concealed_payload;
  
  // Also check if MobSF or other static findings indicate concealment
  const hasReflection = data.has_reflection;
  
  if (!hasConcealedPayload && !hasReflection) {
    return null; // Do not show if no concealed payload exists
  }

  return (
    <div className="rounded-xl border border-amber-200 bg-amber-50 p-4 shadow-sm mb-6">
      <div className="flex items-start gap-3">
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-amber-100 text-amber-600 mt-0.5">
          <AlertOctagon className="h-4 w-4" />
        </div>
        <div className="flex-1">
          <h2 className="text-sm font-bold text-amber-900 mb-1">
            CONCEALED PAYLOAD DETECTED
          </h2>
          <p className="text-sm text-amber-800 mb-3">
            Static analysis may not represent the full application. The true intent of this application is likely hidden.
          </p>
          
          <div className="flex flex-wrap gap-2 mb-3">
            {hasConcealedPayload && (
              <span className="inline-flex items-center rounded-md bg-amber-100/50 px-2 py-1 text-xs font-medium text-amber-800 border border-amber-200">
                Dynamic Class Loading
              </span>
            )}
            {hasReflection && (
              <span className="inline-flex items-center rounded-md bg-amber-100/50 px-2 py-1 text-xs font-medium text-amber-800 border border-amber-200">
                Reflection APIs
              </span>
            )}
          </div>
          
          <Link 
            to={`/case/${data.sha256}/evidence`} 
            className="inline-flex items-center text-xs font-semibold text-amber-700 hover:text-amber-900 transition-colors"
          >
            View concealment evidence
            <ChevronRight className="h-3.5 w-3.5 ml-0.5" />
          </Link>
        </div>
      </div>
    </div>
  );
}
