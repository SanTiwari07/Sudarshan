
import type { FraudCardData } from '../../App';

/**
 * Capability tags for the persistent header.
 *
 * The header carried a score and a band, so telling whether a sample touches
 * the network or reads SMS meant opening the permission table and reading it.
 * These tags surface the handful of capabilities an analyst triages on, at a
 * glance.
 *
 * Two rules keep them honest:
 *
 *  - A tag states a CAPABILITY the sample has, never a verdict about what it
 *    did with it. `reads-sms` means the SMS capability is present; whether it
 *    intercepted an OTP is a finding, with evidence behind it, and belongs in
 *    the workflow section rather than on a pill.
 *  - Observed runtime behaviour and declared-but-unexercised capability are
 *    marked differently. A permission in the manifest and an API call caught
 *    at runtime are not the same claim.
 */

export type TagBasis = 'observed' | 'declared';

export interface BehaviorTag {
  label: string;
  basis: TagBasis;
  /** Why this tag is present - shown on hover. */
  title: string;
}

const BASIS_STYLE: Record<TagBasis, string> = {
  // Observed at runtime: solid, because something actually happened.
  observed: 'bg-slate-800 text-white border-slate-800',
  // Declared only: outlined, so it reads as potential rather than fact.
  declared: 'bg-white text-slate-600 border-slate-300 border-dashed',
};

function hasAny(list: string[] | undefined, needles: string[]): boolean {
  if (!list?.length) return false;
  return list.some((entry) =>
    needles.some((n) => entry.toLowerCase().includes(n)),
  );
}

export function deriveBehaviorTags(data: FraudCardData): BehaviorTag[] {
  const tags: BehaviorTag[] = [];
  const perms = data.all_permissions ?? [];
  const dynamic = data.dynamic_analysis as Record<string, any> | undefined;
  const ranDynamic = Boolean(data.dynamic_available);

  const add = (label: string, basis: TagBasis, title: string) => {
    if (!tags.some((t) => t.label === label)) tags.push({ label, basis, title });
  };

  // ── Observed at runtime ────────────────────────────────────────────────
  const events: any[] = dynamic?.runtime_events ?? dynamic?.evidence_records ?? [];
  const hooks = new Set(
    events
      .map((e) => String(e?.hook ?? e?.data?.hook ?? ''))
      .filter(Boolean),
  );
  const hookMatches = (fragment: string) =>
    Array.from(hooks).some((h) => h.toLowerCase().includes(fragment));

  if (ranDynamic && hookMatches('sms')) {
    add('reads-sms', 'observed', 'SMS APIs were called at runtime');
  }
  if (ranDynamic && hookMatches('accessibility')) {
    add('uses-accessibility', 'observed', 'Accessibility APIs were called at runtime');
  }
  if (ranDynamic && (hookMatches('url') || hookMatches('okhttp') || hookMatches('socket'))) {
    add('opens-network-connection', 'observed', 'Network calls were observed at runtime');
  }
  if (ranDynamic && (hookMatches('dexclassloader') || hookMatches('classloader'))) {
    add('loads-code-dynamically', 'observed', 'Dynamic code loading was observed at runtime');
  }
  if (ranDynamic && hookMatches('admin')) {
    add('device-admin', 'observed', 'Device-admin APIs were called at runtime');
  }

  const secondary = (dynamic?.secondary_apks ?? []) as any[];
  if (secondary.length > 0) {
    add(
      'drops-apk',
      'observed',
      `${secondary.length} secondary APK(s) detected during the run`,
    );
  }

  // ── Declared but not (yet) observed ────────────────────────────────────
  if (!tags.some((t) => t.label === 'reads-sms') &&
      (data.has_sms_read_write || hasAny(perms, ['sms']))) {
    add('sms-permission', 'declared', 'SMS permissions declared in the manifest');
  }
  if (!tags.some((t) => t.label === 'uses-accessibility') && data.has_accessibility_abuse) {
    add('accessibility-service', 'declared', 'An accessibility service is declared');
  }
  if (data.has_system_alert_window) {
    add('draws-overlay', 'declared', 'SYSTEM_ALERT_WINDOW is declared');
  }
  if (hasAny(perms, ['record_audio'])) {
    add('microphone', 'declared', 'Microphone permission declared');
  }
  if (hasAny(perms, ['location'])) {
    add('location', 'declared', 'Location permission declared');
  }
  if (hasAny(perms, ['read_contacts', 'write_contacts'])) {
    add('contacts', 'declared', 'Contacts permission declared');
  }
  if (hasAny(perms, ['camera'])) {
    add('camera', 'declared', 'Camera permission declared');
  }
  if (hasAny(perms, ['request_install_packages'])) {
    add('installs-packages', 'declared', 'REQUEST_INSTALL_PACKAGES is declared');
  }
  if ((data.obfuscation_score ?? 0) > 0.5) {
    add('obfuscated', 'declared', 'High obfuscation score from static analysis');
  }
  if (data.has_reflection) {
    add('uses-reflection', 'declared', 'Reflection detected in bytecode');
  }
  if (data.targets_indian_banks) {
    add('targets-banking-apps', 'declared', 'Banking package references found in the sample');
  }

  return tags;
}

export function BehaviorTags({
  data,
  max,
}: {
  data: FraudCardData;
  max?: number;
}) {
  const all = deriveBehaviorTags(data);
  if (all.length === 0) return null;
  const shown = typeof max === 'number' ? all.slice(0, max) : all;
  const hidden = all.length - shown.length;

  return (
    <div className="flex flex-wrap items-center gap-1.5" data-testid="behavior-tags">
      {shown.map((tag) => (
        <span
          key={tag.label}
          title={tag.title}
          data-basis={tag.basis}
          className={`text-[13px] font-mono px-2 py-0.5 rounded border ${BASIS_STYLE[tag.basis]}`}
        >
          {tag.label}
        </span>
      ))}
      {hidden > 0 && (
        <span className="text-[13px] text-slate-500">+{hidden} more</span>
      )}
    </div>
  );
}

export default BehaviorTags;
