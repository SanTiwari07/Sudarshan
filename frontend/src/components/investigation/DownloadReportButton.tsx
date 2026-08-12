import { useState } from 'react';
import { Download } from 'lucide-react';
import { API_BASE, authHeaders, downloadAuthed } from '../../config';

export default function DownloadReportButton({ sha256, className }: { sha256: string; className?: string }) {
  const [downloading, setDownloading] = useState(false);

  const downloadReport = async () => {
    if (downloading) return;
    setDownloading(true);
    try {
      const res = await fetch(`${API_BASE}/report/pdf/${sha256}`, {
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
          `${API_BASE}/report/html/${sha256}`,
          `sudarshan_report_${sha256.slice(0, 8)}.html`,
        );
      }
    } catch {
      try {
        await downloadAuthed(
          `${API_BASE}/report/html/${sha256}`,
          `sudarshan_report_${sha256.slice(0, 8)}.html`,
        );
      } catch {
        // user sees no file
      }
    } finally {
      setDownloading(false);
    }
  };

  return (
    <button
      type="button"
      onClick={() => void downloadReport()}
      disabled={downloading}
      className={
        className ||
        'inline-flex items-center justify-center gap-2.5 px-6 py-3 bg-blue-700 hover:bg-blue-800 text-white text-xs sm:text-sm font-mono font-extrabold uppercase tracking-wider rounded-lg shadow-sm transition-all cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 disabled:opacity-60'
      }
    >
      <Download className="h-4 w-4 sm:h-5 sm:w-5" />
      {downloading ? 'Preparing Report…' : 'Download Executive Report'}
    </button>
  );
}
