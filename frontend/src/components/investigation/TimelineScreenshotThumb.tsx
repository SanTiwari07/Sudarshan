import { useEffect, useState } from 'react';
import { fetchScreenshotBlob } from '../../lib/screenshots';
import { entryFilename } from '../../lib/screenshotManifest';
import type { ScreenshotManifestEntry } from '../../lib/screenshotManifest';

export default function TimelineScreenshotThumb({
  sha256,
  entry,
}: {
  sha256: string;
  entry: ScreenshotManifestEntry;
}) {
  const [url, setUrl] = useState<string | null>(null);
  const file = entryFilename(entry);

  useEffect(() => {
    if (!file) return;
    let blobUrl: string | null = null;
    fetchScreenshotBlob(sha256, file).then((u) => {
      blobUrl = u;
      setUrl(u);
    });
    return () => {
      if (blobUrl) URL.revokeObjectURL(blobUrl);
    };
  }, [sha256, file]);

  if (!url) {
    return <span className="text-[10px] text-slate-400 mt-1 block">Loading visual…</span>;
  }

  return (
    <img
      src={url}
      alt={entry.screenshot_id || 'Runtime screenshot'}
      className="mt-2 w-20 h-auto rounded border border-slate-200 shadow-sm"
    />
  );
}
