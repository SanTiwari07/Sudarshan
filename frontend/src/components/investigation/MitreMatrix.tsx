import SocCard from '../ui/Card';
import type { FraudCardData } from '../../App';

/**
 * MITRE ATT&CK Mobile techniques, grouped by tactic.
 *
 * The techniques were rendered as a flat list, which loses the one thing the
 * matrix is for: whether a sample's behaviour clusters. Five techniques spread
 * across five tactics is an app doing ordinary things; five techniques all
 * under Collection is a spyware profile. A flat list cannot show that.
 *
 * Tactic order below follows the ATT&CK Mobile kill chain rather than
 * alphabetical or count order, so the columns read left-to-right as the attack
 * progresses.
 */

export const TACTIC_ORDER = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
] as const;

export type Tactic = (typeof TACTIC_ORDER)[number];

/**
 * Technique -> tactic for the IDs this system actually emits.
 *
 * Deliberately a curated map rather than a fetched one: the artifact must
 * render offline and identically every time, and a wrong tactic is worse than
 * an unknown one. Anything not listed falls into "Other", which is visible
 * rather than silently dropped - an unmapped technique is a gap to close, not
 * a thing to hide.
 */
export const TECHNIQUE_TACTIC: Record<string, Tactic> = {
  'T1401': 'Persistence',              // Device Administrator Permissions
  'T1406': 'Defense Evasion',          // Obfuscated Files or Information
  'T1407': 'Defense Evasion',          // Download New Code at Runtime
  'T1409': 'Collection',               // Stored Application Data
  'T1411': 'Credential Access',        // Input Prompt
  'T1412': 'Collection',               // Capture SMS Messages
  'T1414': 'Collection',               // Clipboard Data
  'T1416': 'Credential Access',        // URI Hijacking
  'T1417': 'Collection',               // Input Capture
  'T1417.001': 'Collection',           // Keylogging
  'T1417.002': 'Credential Access',    // GUI Input Capture
  'T1418': 'Discovery',                // Software Discovery
  'T1420': 'Discovery',                // File and Directory Discovery
  'T1422': 'Discovery',                // System Network Configuration Discovery
  'T1429': 'Collection',               // Audio Capture
  'T1437': 'Command and Control',      // Application Layer Protocol
  'T1437.001': 'Command and Control',  // Web Protocols
  'T1444': 'Initial Access',           // Masquerade as Legitimate Application
  'T1497.001': 'Defense Evasion',      // Virtualization/Sandbox Evasion
  'T1516': 'Defense Evasion',          // Input Injection
  'T1582': 'Impact',                   // SMS Control
  'T1603': 'Execution',                // Scheduled Task/Job
  'T1623': 'Execution',                // Command and Scripting Interpreter
  'T1624': 'Persistence',              // Event Triggered Execution
  'T1626.001': 'Privilege Escalation', // Device Administrator Permissions
  'T1628': 'Defense Evasion',          // Hide Artifacts
  'T1628.001': 'Defense Evasion',      // Suppress Application Icon
  'T1634': 'Collection',               // Protected User Data
  'T1636.003': 'Collection',           // Contact List
  'T1636.004': 'Collection',           // SMS Messages
  'T1637': 'Command and Control',      // Dynamic Resolution
  'T1643': 'Impact',                   // Generate Traffic from Victim
};

export interface MitreEntry {
  id: string;
  label: string;
  tactic: Tactic | 'Other';
}

/** Pull "T1417.001" out of "T1417.001 - Keylogging" or a bare id. */
export function parseTechniqueId(raw: string): string {
  const match = /T\d{4}(\.\d{3})?/.exec(String(raw));
  return match ? match[0] : '';
}

export function groupByTactic(
  techniques: string[],
): Array<{ tactic: Tactic | 'Other'; entries: MitreEntry[] }> {
  const seen = new Set<string>();
  const buckets = new Map<Tactic | 'Other', MitreEntry[]>();

  for (const raw of techniques ?? []) {
    if (typeof raw !== 'string' || !raw.trim()) continue;
    const id = parseTechniqueId(raw);
    if (!id || seen.has(id)) continue;
    seen.add(id);

    const tactic = TECHNIQUE_TACTIC[id] ?? 'Other';
    const label = raw.includes('-')
      ? raw.slice(raw.indexOf('-') + 1).trim()
      : raw.trim();
    const list = buckets.get(tactic) ?? [];
    list.push({ id, label: label || id, tactic });
    buckets.set(tactic, list);
  }

  const ordered: Array<{ tactic: Tactic | 'Other'; entries: MitreEntry[] }> = [];
  for (const tactic of TACTIC_ORDER) {
    const entries = buckets.get(tactic);
    if (entries?.length) ordered.push({ tactic, entries });
  }
  const other = buckets.get('Other');
  if (other?.length) ordered.push({ tactic: 'Other', entries: other });
  return ordered;
}

export function MitreMatrix({ data }: { data: FraudCardData }) {
  const intel = (data as Record<string, any>).intelligence_report ?? {};
  const raw: string[] = intel?.mitre_techniques_used ?? [];
  const groups = groupByTactic(raw);
  const total = groups.reduce((n, g) => n + g.entries.length, 0);

  if (total === 0) {
    return (
      <SocCard severity="info">
        <div className="px-4 py-3 border-b border-slate-100">
          <h3 className="text-sm font-semibold text-slate-800">
            MITRE ATT&amp;CK Mobile
          </h3>
        </div>
        <div className="px-4 py-6 text-sm text-slate-500">
          No ATT&amp;CK techniques were mapped for this sample.
        </div>
      </SocCard>
    );
  }

  // The widest column drives the row height; a tactic with one technique
  // should not stretch to match one with six.
  return (
    <SocCard severity={total >= 6 ? 'high' : 'medium'}>
      <div className="px-4 py-3 border-b border-slate-100 flex items-baseline justify-between">
        <h3 className="text-sm font-semibold text-slate-800">
          MITRE ATT&amp;CK Mobile
        </h3>
        <span className="text-xs text-slate-500">
          {total} technique{total === 1 ? '' : 's'} across {groups.length} tactic
          {groups.length === 1 ? '' : 's'}
        </span>
      </div>

      <div className="p-3 overflow-x-auto">
        <div className="flex gap-2 min-w-max items-start">
          {groups.map((group) => (
            <div key={group.tactic} className="w-44 shrink-0">
              <div
                className={[
                  'text-[13px] font-semibold uppercase tracking-wider px-2 py-1.5 rounded-t',
                  group.tactic === 'Other'
                    ? 'bg-slate-100 text-slate-500'
                    : 'bg-slate-800 text-white',
                ].join(' ')}
              >
                {group.tactic}
                <span className="float-right opacity-70">
                  {group.entries.length}
                </span>
              </div>
              <div className="space-y-1 mt-1">
                {group.entries.map((entry) => (
                  <a
                    key={entry.id}
                    href={`https://attack.mitre.org/techniques/${entry.id.replace('.', '/')}/`}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="block border border-slate-200 rounded px-2 py-1.5 bg-white hover:border-slate-400 hover:bg-slate-50 transition-colors"
                    title={`${entry.id} — ${entry.label}`}
                  >
                    <div className="font-mono text-[13px] text-sky-700">
                      {entry.id}
                    </div>
                    <div className="text-[13px] text-slate-700 leading-tight line-clamp-2">
                      {entry.label}
                    </div>
                  </a>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </SocCard>
  );
}

export default MitreMatrix;
