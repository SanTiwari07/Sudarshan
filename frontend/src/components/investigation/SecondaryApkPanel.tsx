
import SocCard from '../ui/Card';
import type { FraudCardData } from '../../App';

/**
 * Secondary payloads: the second APK a dropper fetched.
 *
 * The status ladder is the point of this panel, so it is rendered literally
 * rather than collapsed into a verdict. "Installation requested" and
 * "installed" are different claims and only one of them is usually supported;
 * a panel that showed a single "malicious payload installed" line would be
 * asserting something the run did not observe.
 */

const STATUS_STYLE: Record<string, string> = {
  DETECTED: 'bg-slate-100 text-slate-700',
  DOWNLOADED: 'bg-sky-100 text-sky-800',
  HASHED: 'bg-indigo-100 text-indigo-800',
  INSTALL_REQUESTED: 'bg-amber-100 text-amber-900',
  INSTALLED: 'bg-red-100 text-red-800',
  ANALYZED: 'bg-emerald-100 text-emerald-800',
  BLOCKED: 'bg-slate-200 text-slate-600',
};

interface PayloadRecord {
  filename?: string;
  device_path?: string;
  sha256?: string;
  size_bytes?: number;
  package_name?: string;
  parent_package?: string;
  status?: string;
  install_requested?: boolean;
  install_confirmed?: boolean;
  blocked_by_policy?: boolean;
  notes?: string[];
}

export function SecondaryApkPanel({ data }: { data: FraudCardData }) {
  const dynamic = data.dynamic_analysis as Record<string, any> | undefined;
  const payloads: PayloadRecord[] = dynamic?.secondary_apks ?? [];

  if (payloads.length === 0) {
    return (
      <SocCard severity="info">
        <div className="px-4 py-3 border-b border-slate-100">
          <h3 className="text-sm font-semibold text-slate-800">
            Secondary payloads
          </h3>
        </div>
        <div className="px-4 py-6 text-sm text-slate-500">
          No secondary APK was observed during this run.
          {!data.dynamic_available && (
            <span className="block mt-1 text-slate-500">
              Dynamic analysis did not run for this sample, so a dropper
              could not have been observed either way.
            </span>
          )}
        </div>
      </SocCard>
    );
  }

  const anyConfirmed = payloads.some((p) => p.install_confirmed);

  return (
    <SocCard severity={anyConfirmed ? 'critical' : 'high'}>
      <div className="px-4 py-3 border-b border-slate-100 flex items-baseline justify-between">
        <h3 className="text-sm font-semibold text-slate-800">
          Secondary payloads
        </h3>
        <span className="text-xs text-slate-500">
          {payloads.length} artifact{payloads.length === 1 ? '' : 's'}
        </span>
      </div>

      <div className="divide-y divide-slate-100">
        {payloads.map((p, i) => (
          <div key={p.sha256 || p.device_path || i} className="px-4 py-3">
            <div className="flex flex-wrap items-center gap-2 mb-1.5">
              <span className="font-mono text-sm text-slate-800">
                {p.filename || p.device_path || 'unnamed.apk'}
              </span>
              <span
                className={`text-[11px] font-semibold px-2 py-0.5 rounded ${
                  STATUS_STYLE[p.status ?? ''] ?? 'bg-slate-100 text-slate-700'
                }`}
              >
                {p.status ?? 'DETECTED'}
              </span>
            </div>

            <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1 text-xs">
              {p.parent_package && (
                <div className="flex gap-2">
                  <dt className="text-slate-500 shrink-0">Dropped by</dt>
                  <dd className="font-mono text-slate-700 break-all">
                    {p.parent_package}
                  </dd>
                </div>
              )}
              {p.package_name && (
                <div className="flex gap-2">
                  <dt className="text-slate-500 shrink-0">Child package</dt>
                  <dd className="font-mono text-slate-700 break-all">
                    {p.package_name}
                  </dd>
                </div>
              )}
              {p.sha256 ? (
                <div className="flex gap-2 sm:col-span-2">
                  <dt className="text-slate-500 shrink-0">SHA-256</dt>
                  <dd className="font-mono text-slate-700 break-all">
                    {p.sha256}
                  </dd>
                </div>
              ) : (
                <div className="flex gap-2 sm:col-span-2">
                  <dt className="text-slate-500 shrink-0">SHA-256</dt>
                  <dd className="text-slate-500">
                    not preserved &mdash; artifact was not retrievable
                  </dd>
                </div>
              )}
              {typeof p.size_bytes === 'number' && p.size_bytes > 0 && (
                <div className="flex gap-2">
                  <dt className="text-slate-500 shrink-0">Size</dt>
                  <dd className="text-slate-700">
                    {p.size_bytes.toLocaleString()} bytes
                  </dd>
                </div>
              )}
            </dl>

            {/*
              Stated as two separate facts. Folding them into one line is how a
              report ends up claiming an installation that was only requested.
            */}
            <div className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-xs">
              <span className="text-slate-600">
                Install requested:{' '}
                <strong
                  className={
                    p.install_requested ? 'text-amber-700' : 'text-slate-500'
                  }
                >
                  {p.install_requested ? 'yes' : 'no'}
                </strong>
              </span>
              <span className="text-slate-600">
                Installation confirmed:{' '}
                <strong
                  className={
                    p.install_confirmed ? 'text-red-700' : 'text-slate-500'
                  }
                >
                  {p.install_confirmed ? 'yes' : 'not confirmed'}
                </strong>
              </span>
            </div>

            {p.notes && p.notes.length > 0 && (
              <ul className="mt-2 space-y-0.5">
                {p.notes.map((note, n) => (
                  <li key={n} className="text-[11px] text-slate-500">
                    &middot; {note}
                  </li>
                ))}
              </ul>
            )}
          </div>
        ))}
      </div>
    </SocCard>
  );
}

export default SecondaryApkPanel;
