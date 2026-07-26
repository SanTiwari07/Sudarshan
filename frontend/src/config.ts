// Single source of truth for the API origin.
//
// Previously this expression was duplicated in Login.tsx and History.tsx, and
// ThreatIntelView.tsx hardcoded http://localhost:8000 outright — which silently
// broke STIX/IOC export in any deployment that wasn't localhost.
export const API_BASE: string =
  import.meta.env.VITE_API_URL ?? 'http://localhost:8000/api/v1';

/** Bearer header for authenticated calls, or {} when there is no token. */
export function authHeaders(): Record<string, string> {
  const token = localStorage.getItem('sudarshan_token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

/**
 * Fetch a protected endpoint and save the response as a file.
 *
 * The export endpoints now require a Bearer token, so a plain <a href> no
 * longer works — the browser won't attach the Authorization header.
 */
export async function downloadAuthed(url: string, filename: string): Promise<void> {
  const res = await fetch(url, { headers: authHeaders() });
  if (!res.ok) {
    throw new Error(
      res.status === 401 ? 'Session expired — sign in again.' : `Export failed (${res.status})`,
    );
  }
  const blob = await res.blob();
  const objectUrl = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = objectUrl;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(objectUrl);
}
