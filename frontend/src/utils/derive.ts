// Pure presentation & data export utility helpers for Sudarshan BOI

import type { FraudCardData } from '../types/case';
import type { LedgerLine } from '../types/investigation';

// ─── Export Helpers ─────────────────────────────────────────────────────────────

export function exportJSON(data: FraudCardData): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `sudarshan-report-${data.sha256.slice(0, 8)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export function exportCSV(data: FraudCardData): void {
  const iocs = [
    ...data.hardcoded_urls_ips.map(u => ({ type: 'URL', value: u })),
    ...(data.technical_view?.permissions_fired || []).map(p => ({ type: 'Permission', value: p })),
    ...(data.technical_view?.apis_fired || []).map(a => ({ type: 'API', value: a })),
    { type: 'SHA256', value: data.sha256 },
  ];
  const csv = ['Type,Value', ...iocs.map(i => `${i.type},"${i.value}"`)].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `sudarshan-ioc-${data.sha256.slice(0, 8)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

export function exportLedgerCSV(data: FraudCardData, lines: LedgerLine[]): void {
  const header = 'id,component,label,detail,contribution';
  const rows = lines.map((l) =>
    [
      l.id,
      l.component,
      `"${l.label.replace(/"/g, '""')}"`,
      `"${l.detail.replace(/"/g, '""')}"`,
      l.contribution ?? '',
    ].join(','),
  );
  const csv = [header, ...rows].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `sudarshan-ledger-${data.sha256.slice(0, 8)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Formatting Helpers ─────────────────────────────────────────────────────────

export function fmtScore(score: number | null | undefined): string {
  if (score === null || score === undefined) return '-';
  return score.toFixed(1);
}

export function fmtDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString('en-IN', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch {
    return iso;
  }
}
