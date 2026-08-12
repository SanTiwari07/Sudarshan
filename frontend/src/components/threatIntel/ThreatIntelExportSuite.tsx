import { useState } from 'react';
import { FileText, Globe, Database, Code, Layers, Download, RefreshCw } from 'lucide-react';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import { API_BASE, authHeaders, downloadAuthed } from '../../config';

export default function ThreatIntelExportSuite({ sha256 }: { sha256: string }) {
  const [activeExport, setActiveExport] = useState<string | null>(null);

  const runExport = async (name: string, path: string, filename: string, isWindowOpen = false) => {
    try {
      setActiveExport(name);
      if (isWindowOpen) {
        const res = await fetch(`${API_BASE}${path}`, { headers: authHeaders() });
        if (!res.ok) throw new Error(`Export failed (${res.status})`);
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const win = window.open(url, '_blank');
        if (!win) await downloadAuthed(`${API_BASE}${path}`, filename);
      } else {
        await downloadAuthed(`${API_BASE}${path}`, filename);
      }
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Export error');
    } finally {
      setTimeout(() => setActiveExport(null), 1500);
    }
  };

  return (
    <SocCard>
      <SectionHeader icon={<FileText className="h-4 w-4" />} title="Export suite" subtitle="STIX, IOC, YARA, MITRE" />
      <div className="p-4 grid grid-cols-2 gap-2">
        {[
          { id: 'pdf', label: 'PDF Report', path: `/report/pdf/${sha256}`, file: `sudarshan_report_${sha256.slice(0, 8)}.pdf`, icon: FileText },
          { id: 'html', label: 'HTML Report', path: `/report/html/${sha256}`, file: `sudarshan_report_${sha256.slice(0, 8)}.html`, icon: FileText },
          { id: 'stix', label: 'STIX 2.1', path: `/report/stix/${sha256}`, file: `sudarshan_stix_${sha256.slice(0, 8)}.json`, icon: Globe },
          { id: 'csv', label: 'IOC CSV', path: `/report/iocs/${sha256}`, file: `sudarshan_iocs_${sha256.slice(0, 8)}.csv`, icon: Database },
          { id: 'yara', label: 'YARA', path: `/report/yara/${sha256}`, file: `sudarshan_rule_${sha256.slice(0, 8)}.yar`, icon: Code },
          { id: 'mitre', label: 'MITRE JSON', path: `/report/mitre/${sha256}`, file: `sudarshan_mitre_${sha256.slice(0, 8)}.json`, icon: Layers },
        ].map((ex) => (
          <button
            key={ex.id}
            type="button"
            disabled={!!activeExport}
            onClick={() => runExport(ex.id, ex.path, ex.file)}
            className="flex items-center justify-between px-3 py-2 text-xs font-medium bg-slate-50 border border-slate-200 rounded-lg hover:bg-white hover:border-slate-400 transition-colors disabled:opacity-50"
          >
            <span className="flex items-center gap-1.5">
              <ex.icon className="h-3.5 w-3.5" /> {ex.label}
            </span>
            {activeExport === ex.id ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Download className="h-3 w-3" />}
          </button>
        ))}
      </div>
    </SocCard>
  );
}
