import { useEffect, useState } from 'react';
import type { FraudCardData } from '../../App';
import type { InvestigationBundle } from '../../types/investigation';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import ScreenshotLightbox from './ScreenshotLightbox';
import { fetchScreenshotBlob } from '../../lib/screenshots';
import { Camera, ImageOff } from 'lucide-react';

function ScreenshotTile({
  sha256,
  filename,
  title,
  mitre,
  evidenceId,
  onZoom,
}: {
  sha256: string;
  filename: string;
  title: string;
  mitre?: string;
  evidenceId?: string;
  onZoom: () => void;
}) {
  const [src, setSrc] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let revoked: string | null = null;
    setLoading(true);
    fetchScreenshotBlob(sha256, filename).then((url) => {
      if (url) {
        revoked = url;
        setSrc(url);
      }
      setLoading(false);
    });
    return () => {
      if (revoked) URL.revokeObjectURL(revoked);
    };
  }, [sha256, filename]);

  return (
    <button
      type="button"
      onClick={onZoom}
      className="group text-left rounded-xl border border-slate-200 overflow-hidden bg-white hover:border-blue-300 hover:shadow-md transition-all"
    >
      <div className="aspect-[9/16] max-h-64 w-full bg-slate-100 relative overflow-hidden">
        {loading && (
          <div className="absolute inset-0 animate-pulse bg-gradient-to-br from-slate-100 to-slate-200" />
        )}
        {!loading && !src && (
          <div className="absolute inset-0 flex items-center justify-center text-slate-400">
            <ImageOff className="h-8 w-8" />
          </div>
        )}
        {src && (
          <img
            src={src}
            alt={title}
            loading="lazy"
            className="w-full h-full object-cover object-top group-hover:scale-[1.02] transition-transform"
          />
        )}
        <div className="absolute top-2 left-2 flex flex-wrap gap-1">
          {evidenceId && (
            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-blue-700 text-white">
              {evidenceId}
            </span>
          )}
          {mitre && (
            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-900/80 text-white">
              {mitre}
            </span>
          )}
        </div>
      </div>
      <div className="p-3 border-t border-slate-100">
        <div className="text-xs font-semibold text-slate-800 line-clamp-2">{title}</div>
        <p className="text-[10px] text-slate-500 mt-1">Captured during runtime</p>
      </div>
    </button>
  );
}

function titleFromFilename(filename: string): string {
  const base = filename.replace(/^screenshots\//, '').replace(/\.[^.]+$/, '');
  return base
    .replace(/[-_]/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

export default function ScreenshotGallery({
  data,
  bundle,
}: {
  data: FraudCardData;
  bundle: InvestigationBundle | null;
}) {
  const shots = data.dynamic_analysis?.screenshots || [];
  const [lightbox, setLightbox] = useState<string | null>(null);

  const evidenceByShot = new Map<string, { id: string; mitre?: string; title?: string }>();
  bundle?.evidenceRecords.forEach((e) => {
    if (!e.screenshotRef) return;
    evidenceByShot.set(e.screenshotRef, {
      id: e.id,
      mitre: e.mitreId,
      title: e.title,
    });
  });

  return (
    <SocCard>
      <SectionHeader
        icon={<Camera className="h-4 w-4" />}
        title="Runtime Screenshots"
        subtitle="Visual proof from sandbox execution — click to zoom."
      />
      <div className="p-5">
        {shots.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 px-4 text-center rounded-xl border border-dashed border-slate-200 bg-slate-50">
            <ImageOff className="h-12 w-12 text-slate-300 mb-3" />
            <p className="text-sm font-medium text-slate-700">No screenshots were captured during execution.</p>
            <p className="text-xs text-slate-500 mt-2 max-w-md">
              The application may have exited before behavioural monitoring completed, or the sandbox run was
              not performed for this case.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {shots.map((filename) => {
              const meta = evidenceByShot.get(filename);
              const title = meta?.title || titleFromFilename(filename);
              return (
                <ScreenshotTile
                  key={filename}
                  sha256={data.sha256}
                  filename={filename}
                  title={title}
                  mitre={meta?.mitre}
                  evidenceId={meta?.id}
                  onZoom={() => setLightbox(filename)}
                />
              );
            })}
          </div>
        )}
      </div>
      {lightbox && (
        <ScreenshotLightbox sha256={data.sha256} filename={lightbox} onClose={() => setLightbox(null)} />
      )}
    </SocCard>
  );
}
