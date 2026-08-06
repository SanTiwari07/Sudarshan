import { useEffect, useState } from 'react';
import { X } from 'lucide-react';
import { fetchScreenshotBlob } from '../../lib/screenshots';

export default function ScreenshotLightbox({
  sha256,
  filename,
  onClose,
}: {
  sha256: string;
  filename: string;
  onClose: () => void;
}) {
  const [src, setSrc] = useState<string | null>(null);

  useEffect(() => {
    let revoked: string | null = null;
    fetchScreenshotBlob(sha256, filename).then((url) => {
      if (url) {
        revoked = url;
        setSrc(url);
      }
    });
    return () => {
      if (revoked) URL.revokeObjectURL(revoked);
    };
  }, [sha256, filename]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-[60] bg-slate-900/90 flex items-center justify-center p-4" onClick={onClose}>
      <button
        type="button"
        className="absolute top-4 right-4 p-2 text-white/80 hover:text-white"
        onClick={onClose}
        aria-label="Close"
      >
        <X className="h-6 w-6" />
      </button>
      {src ? (
        <img
          src={src}
          alt="Runtime screenshot evidence"
          className="max-h-[90vh] max-w-full rounded border border-slate-600 shadow-2xl"
          onClick={(e) => e.stopPropagation()}
        />
      ) : (
        <div className="text-white text-sm">Loading screenshot…</div>
      )}
    </div>
  );
}
