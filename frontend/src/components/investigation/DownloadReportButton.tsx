import { useState } from 'react';
import { Download } from 'lucide-react';
import { API_BASE, downloadAuthed } from '../../config';

export default function DownloadReportButton({ sha256, className }: { sha256: string; className?: string }) {
  const [downloading, setDownloading] = useState(false);

  const downloadReport = async () => {
    if (downloading) return;
    setDownloading(true);
    try {
      await downloadAuthed(
        `${API_BASE}/report/pdf/${sha256}`,
        `sudarshan_report_${sha256.slice(0, 12)}.pdf`,
      );
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'PDF Report download failed');
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
        'inline-flex items-center justify-center gap-2.5 px-6 py-3 bg-blue-700 hover:bg-blue-800 text-white text-xs sm:text-sm font-mono font-extrabold rounded-lg shadow-sm transition-all cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 disabled:opacity-60'
      }
    >
      <Download className="h-4 w-4 sm:h-5 sm:w-5" />
      {downloading ? 'Preparing Report…' : 'Download Executive Report'}
    </button>
  );
}
