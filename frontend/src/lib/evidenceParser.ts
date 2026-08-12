/** Parse risk-engine evidence strings like "(+40 CT)" into axis tags. */
export function parseEvidenceAxis(line: string): string | undefined {
  const m = line.match(/\(\+[\d.]+ (CT|BT|PR|OB|IR)\)/i);
  return m ? m[1].toLowerCase() : undefined;
}

export function axisDisplayName(axis: string): string {
  const map: Record<string, string> = {
    ct: 'Credential Theft',
    bt: 'Banking Targeting',
    pr: 'Permission Risk',
    ob: 'Obfuscation',
    ir: 'Infrastructure',
  };
  return map[axis] || axis;
}

export function severityRank(sev: string): number {
  const s = sev.toUpperCase();
  if (s === 'CRITICAL') return 4;
  if (s === 'HIGH') return 3;
  if (s === 'MEDIUM' || s === 'WARNING') return 2;
  if (s === 'LOW' || s === 'INFO') return 1;
  return 0;
}
