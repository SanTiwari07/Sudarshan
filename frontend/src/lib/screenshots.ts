import { API_BASE, authHeaders } from '../config';

/** Basename only - API route accepts a single path segment. */
export function screenshotBasename(filename: string): string {
  const normalized = filename.replace(/\\/g, '/');
  return normalized.split('/').pop() || normalized;
}

export function screenshotUrl(sha256: string, filename: string): string {
  const base = screenshotBasename(filename);
  return `${API_BASE}/screenshots/${sha256}/${encodeURIComponent(base)}`;
}

export async function fetchScreenshotBlob(sha256: string, filename: string): Promise<string | null> {
  const base = screenshotBasename(filename);
  const candidates = [base];
  const stripped = filename.replace(/^screenshots\//, '');
  if (stripped !== base) candidates.push(stripped);

  for (const name of candidates) {
    try {
      const res = await fetch(
        `${API_BASE}/screenshots/${sha256}/${encodeURIComponent(name)}`,
        { headers: authHeaders() },
      );
      if (!res.ok) continue;
      const blob = await res.blob();
      if (!blob.size) continue;
      return URL.createObjectURL(blob);
    } catch {
      // try next candidate
    }
  }
  return null;
}
