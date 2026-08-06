import { useState } from 'react';
import type { FraudCardData } from '../../App';
import { dynamicRuntimeLabel } from '../../lib/analystCopy';
import { API_BASE, authHeaders, downloadAuthed } from '../../config';
import CopyButton from '../ui/CopyButton';
import Badge from '../ui/Badge';
import { Download, Package } from 'lucide-react';

export default function CaseHeader({ data }: { data: FraudCardData }) {
  const displayName = data.app_name || data.package_name || 'Unknown application';
  const runtimeLabel = dynamicRuntimeLabel(data);
  const [downloading, setDownloading] = useState(false);

  const downloadReport = async () => {
    if (downloading) return;
    setDownloading(true);
    try {
      const res = await fetch(`${API_BASE}/report/pdf/${data.sha256}`, {
        headers: authHeaders(),
      });
      if (!res.ok) {
        throw new Error(res.status === 401 ? 'Session expired' : `Report download failed (${res.status})`);
      }
      const htmlBlob = await res.blob();
      const blobUrl = URL.createObjectURL(htmlBlob);
      const win = window.open(blobUrl, '_blank');
      if (!win) {
        await downloadAuthed(
          `${API_BASE}/report/html/${data.sha256}`,
          `sudarshan_report_${data.sha256.slice(0, 8)}.html`,
        );
      }
    } catch {
      try {
        await downloadAuthed(
          `${API_BASE}/report/html/${data.sha256}`,
          `sudarshan_report_${data.sha256.slice(0, 8)}.html`,
        );
      } catch {
        // user sees no file — avoid toast infra for minimal change
      }
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className="bg-white border border-slate-200 rounded-xl shadow-sm px-5 py-4 mb-4">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex items-start gap-3">
          <span className="p-2.5 rounded-xl bg-blue-50 text-blue-700 border border-blue-100">
            <Package className="h-5 w-5" />
          </span>
          <div className="min-w-0">
            <h1 className="text-lg font-bold text-slate-900">Fraud Analyst Intelligence</h1>
            <p className="text-sm text-slate-700 font-medium truncate mt-0.5">{displayName}</p>
            <p className="text-xs text-slate-500 mt-1">
              Bank of India fraud investigation workspace — evidence-backed assessment.
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2 ml-auto">
          <span className="text-[10px] font-semibold text-slate-600 uppercase px-2.5 py-2 bg-slate-100 rounded-lg border border-slate-200">
            {runtimeLabel}
          </span>
          <button
            type="button"
            onClick={() => void downloadReport()}
            disabled={downloading}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-semibold text-white bg-blue-700 rounded-lg hover:bg-blue-800 disabled:opacity-60 transition-colors shadow-sm"
          >
            <Download className="h-3.5 w-3.5" />
            {downloading ? 'Preparing…' : 'Download Report'}
          </button>
        </div>
      </div>
      <div className="mt-3 pt-3 border-t border-slate-100 flex flex-wrap items-center gap-3 text-xs text-slate-600">
        <span className="font-mono truncate max-w-[min(100%,28rem)]" title={data.sha256}>
          SHA256 {data.sha256.slice(0, 16)}…
        </span>
        <CopyButton value={data.sha256} />
        <Badge label={data.analysis_mode} className="bg-blue-50 text-blue-700 border border-blue-200" />
        {data.family_classification !== 'Unknown' && (
          <span>
            Family: <strong className="text-slate-800">{data.family_classification}</strong>
          </span>
        )}
      </div>
    </div>
  );
}
