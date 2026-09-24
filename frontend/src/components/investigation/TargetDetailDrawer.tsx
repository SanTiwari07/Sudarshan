import { useInvestigationUI } from '../../context/InvestigationUIContext';
import DrawerShell from '../ui/DrawerShell';
import type { FraudCardData } from '../../types/case';
import type { InvestigationBundle } from '../../types/investigation';
import { useNavigate } from 'react-router-dom';
import {
  Building2,
  Eye,
  ShieldAlert,
  Percent,
  Image as ImageIcon,
  ArrowRight,
  ExternalLink,
} from 'lucide-react';

export default function TargetDetailDrawer({
  data,
  bundle,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle;
}) {
  const { closeDrawer, openEvidence } = useInvestigationUI();
  const navigate = useNavigate();

  const vide = data.vide;
  const bankName =
    vide?.matched_bank ||
    (data as any).target_bank ||
    data.intelligence_report?.targeted_brand ||
    'Target Financial Institution';

  const similarity = vide?.similarity_score ? Math.round(vide.similarity_score * 100) : null;
  const screenshots = data.dynamic_analysis?.screenshots || [];

  return (
    <DrawerShell
      open={true}
      onClose={closeDrawer}
      title="Target Impersonation Analysis"
      subtitle={`Visual & Overlay Forensic Evaluation for ${bankName}`}
    >
      <div className="space-y-6">
        {/* Banner */}
        <div className="rounded-xl bg-red-50 border border-red-200 p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-100 rounded-lg text-red-700 shrink-0">
              <Building2 className="h-5 w-5" />
            </div>
            <div>
              <span className="text-[11px] font-bold uppercase tracking-wider text-red-700 block">
                Target Entity
              </span>
              <h3 className="text-base font-bold text-slate-900">{bankName}</h3>
            </div>
          </div>
          <p className="mt-3 text-xs text-red-900/80 leading-relaxed">
            {vide?.visual_impersonation_detected
              ? `Visual impersonation and logo spoofing detected. The application presents fraudulent UI interfaces matching genuine ${bankName} mobile applications to capture credentials.`
              : `Application manifests indicators targeting customers of ${bankName}.`}
          </p>
        </div>

        {/* Metrics Grid */}
        <div className="grid grid-cols-2 gap-3 text-xs">
          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
            <span className="text-slate-500 font-medium block">Detection Method</span>
            <span className="text-sm font-semibold text-slate-900 mt-0.5 block">
              {vide?.detection_method || 'VIDE Visual + Layout Matching'}
            </span>
          </div>
          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
            <span className="text-slate-500 font-medium block">Visual Similarity</span>
            <span className="text-sm font-semibold text-red-600 mt-0.5 block">
              {similarity !== null ? `${similarity}% match` : 'High Structural Match'}
            </span>
          </div>
        </div>

        {/* Screenshots if available */}
        {screenshots.length > 0 && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 flex items-center gap-2">
                <ImageIcon className="h-3.5 w-3.5 text-blue-600" />
                Captured Overlay Screenshots ({screenshots.length})
              </h3>
              <button
                type="button"
                onClick={() => {
                  closeDrawer();
                  navigate(`/case/${data.sha256}/evidence?section=visual`);
                }}
                className="text-xs font-semibold text-blue-600 hover:text-blue-800 flex items-center gap-1"
              >
                <span>View in Evidence</span>
                <ArrowRight className="h-3 w-3" />
              </button>
            </div>
            <div className="grid grid-cols-2 gap-2">
              {screenshots.slice(0, 4).map((imgUrl, idx) => (
                <div
                  key={idx}
                  className="rounded-lg border border-slate-200 overflow-hidden bg-slate-900 aspect-video flex items-center justify-center cursor-pointer hover:opacity-90 transition-opacity"
                  onClick={() => {
                    closeDrawer();
                    navigate(`/case/${data.sha256}/evidence?section=visual`);
                  }}
                >
                  <img
                    src={imgUrl}
                    alt={`Capture ${idx + 1}`}
                    className="h-full w-full object-contain"
                  />
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Supporting Evidence Records */}
        <div className="space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 flex items-center gap-2">
            <ShieldAlert className="h-3.5 w-3.5 text-blue-600" />
            Supporting Target Evidence
          </h3>

          <div className="space-y-2">
            {bundle.evidenceRecords
              .filter(
                (r) =>
                  r.category.toLowerCase().includes('visual') ||
                  r.title.toLowerCase().includes('bank') ||
                  r.title.toLowerCase().includes('impersonation') ||
                  r.title.toLowerCase().includes('overlay'),
              )
              .slice(0, 5)
              .map((record) => (
                <button
                  key={record.id}
                  type="button"
                  onClick={() => openEvidence(record.id)}
                  className="w-full text-left p-3 rounded-lg border border-slate-200 hover:border-blue-300 hover:bg-blue-50/30 transition-all flex items-center justify-between group shadow-2xs"
                >
                  <div className="min-w-0 pr-3">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-blue-700 bg-blue-50 px-1.5 py-0.5 rounded border border-blue-200">
                        {record.id}
                      </span>
                      <span className="text-xs font-semibold text-slate-900 truncate">
                        {record.title}
                      </span>
                    </div>
                    {record.description && (
                      <p className="text-xs text-slate-500 truncate mt-1">
                        {record.description}
                      </p>
                    )}
                  </div>
                  <ArrowRight className="h-4 w-4 text-slate-400 group-hover:text-blue-600 group-hover:translate-x-0.5 transition-all shrink-0" />
                </button>
              ))}
          </div>
        </div>
      </div>
    </DrawerShell>
  );
}
