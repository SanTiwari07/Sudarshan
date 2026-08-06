import { useState } from 'react';
import { Download, FileText, Target, Database, Globe } from 'lucide-react';
import type { FraudCardData } from '../App';
import { useAnalysis } from '../context/AnalysisContext';
import { exportJSON, exportCSV } from '../utils/derive';
import { API_BASE, authHeaders, downloadAuthed } from '../config';
import SocCard from '../components/ui/Card';
import SectionHeader from '../components/ui/SectionHeader';
import HelpTerm from '../components/investigation/HelpTerm';
import CoreFindingsList from '../components/investigation/CoreFindingsList';
import GroundedNarrativeCard from '../components/investigation/GroundedNarrativeCard';
import ScoreEntryCard from '../components/investigation/ScoreEntryCard';
import InvestigationTimeline from '../components/investigation/InvestigationTimeline';
import ThreatScenarioTable from '../components/investigation/ThreatScenarioTable';
import ProvenanceBanner from '../components/investigation/ProvenanceBanner';
import ExecutiveBriefing from '../components/investigation/ExecutiveBriefing';
import RiskScorePanel from '../components/investigation/RiskScorePanel';
import CaseSummaryStrip from '../components/investigation/CaseSummaryStrip';
import IntelligencePhaseCards from '../components/investigation/IntelligencePhaseCards';
import ScreenshotGallery from '../components/investigation/ScreenshotGallery';
import ApplicationInfoCard from '../components/investigation/ApplicationInfoCard';

function MitrePanel({ data }: { data: FraudCardData }) {
  const techniques = data.intelligence_report?.mitre_techniques_used || [];

  return (
    <SocCard>
      <SectionHeader
        icon={<Target className="h-4 w-4" />}
        title="Attack Techniques (MITRE)"
        subtitle={
          <>
            <HelpTerm term="MITRE">Industry attack technique mapping</HelpTerm> — {techniques.length} linked to this
            case.
          </>
        }
      />
      <div className="p-5">
        {techniques.length === 0 ? (
          <div className="text-center py-8 px-4 rounded-xl border border-dashed border-slate-200 bg-slate-50">
            <p className="text-sm text-slate-700">No attack techniques were mapped for this application.</p>
            <p className="text-xs text-slate-500 mt-2">Techniques appear when behaviour matches MITRE ATT&CK Mobile.</p>
          </div>
        ) : (
          <div className="flex flex-wrap gap-2">
            {techniques.map((tech, i) => (
              <div
                key={i}
                className="flex items-center gap-2 px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-xs"
              >
                <Target className="h-4 w-4 text-blue-600 flex-shrink-0" />
                <span className="font-mono font-bold text-slate-800">{tech}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </SocCard>
  );
}

function ExportOptions({ data }: { data: FraudCardData }) {
  const [status, setStatus] = useState<string | null>(null);

  const exportStix = async () => {
    try {
      setStatus('Downloading STIX 2.1...');
      await downloadAuthed(`${API_BASE}/report/stix/${data.sha256}`, `sudarshan_stix_${data.sha256.slice(0, 8)}.json`);
      setStatus('STIX export complete');
    } catch (err: unknown) {
      setStatus(err instanceof Error ? err.message : 'STIX export failed');
    }
    setTimeout(() => setStatus(null), 3000);
  };

  const exportIocs = async () => {
    try {
      setStatus('Downloading threat indicators...');
      await downloadAuthed(`${API_BASE}/report/iocs/${data.sha256}`, `sudarshan_iocs_${data.sha256.slice(0, 8)}.csv`);
      setStatus('Export complete');
    } catch (err: unknown) {
      setStatus(err instanceof Error ? err.message : 'Export failed');
    }
    setTimeout(() => setStatus(null), 3000);
  };

  const exportPdfReport = async () => {
    try {
      setStatus('Generating executive PDF report...');
      const res = await fetch(`${API_BASE}/report/pdf/${data.sha256}`, {
        headers: authHeaders(),
      });
      if (!res.ok) {
        throw new Error(res.status === 401 ? 'Session expired' : `PDF export failed (${res.status})`);
      }
      const htmlBlob = await res.blob();
      const blobUrl = URL.createObjectURL(htmlBlob);
      const win = window.open(blobUrl, '_blank');
      if (!win) {
        await downloadAuthed(`${API_BASE}/report/html/${data.sha256}`, `sudarshan_report_${data.sha256.slice(0, 8)}.html`);
      }
      setStatus('PDF report ready');
    } catch (err: unknown) {
      setStatus(err instanceof Error ? err.message : 'PDF export failed');
    }
    setTimeout(() => setStatus(null), 3000);
  };

  return (
    <SocCard className="relative">
      <SectionHeader icon={<Download className="h-4 w-4" />} title="Export & Sharing" subtitle="Reports for fraud ops and SIEM ingestion." />
      <div className="p-4 grid grid-cols-2 gap-2">
        <button
          onClick={exportStix}
          className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-slate-50 border border-slate-200 rounded-lg hover:bg-blue-50 hover:border-blue-300 hover:text-blue-700 transition-colors"
        >
          <Globe className="h-3.5 w-3.5" /> STIX 2.1 JSON
        </button>
        <button
          onClick={exportIocs}
          className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-slate-50 border border-slate-200 rounded-lg hover:bg-blue-50 hover:border-blue-300 hover:text-blue-700 transition-colors"
        >
          <Database className="h-3.5 w-3.5" /> Threat indicators CSV
        </button>
        <button
          onClick={() => exportJSON(data)}
          className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-slate-50 border border-slate-200 rounded-lg hover:bg-blue-50 hover:border-blue-300 hover:text-blue-700 transition-colors"
        >
          <FileText className="h-3.5 w-3.5" /> Full JSON
        </button>
        <button
          onClick={() => exportCSV(data)}
          className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-slate-50 border border-slate-200 rounded-lg hover:bg-blue-50 hover:border-blue-300 hover:text-blue-700 transition-colors"
        >
          <Download className="h-3.5 w-3.5" /> Summary CSV
        </button>
        <button
          onClick={exportPdfReport}
          className="col-span-2 flex items-center justify-center gap-2 px-3 py-2.5 text-xs font-semibold text-white bg-blue-700 rounded-lg hover:bg-blue-800 transition-colors shadow-sm mt-1"
        >
          <FileText className="h-4 w-4" /> Export Executive PDF Report
        </button>
      </div>
      {status && <div className="px-4 pb-3 text-xs text-blue-700 font-medium">{status}</div>}
    </SocCard>
  );
}

export default function FraudCard({ data }: { data: FraudCardData | null }) {
  const { investigationBundle } = useAnalysis();

  if (!data) return null;

  return (
    <div className="space-y-4">
      <ProvenanceBanner data={data} />
      <ExecutiveBriefing data={data} />
      {investigationBundle && (
        <CaseSummaryStrip riskScore={data.final_risk_score} counts={investigationBundle.counts} />
      )}
      <RiskScorePanel data={data} />
      {investigationBundle && <IntelligencePhaseCards data={data} bundle={investigationBundle} />}
      <ScreenshotGallery data={data} bundle={investigationBundle} />
      <CoreFindingsList data={data} bundle={investigationBundle} />
      <GroundedNarrativeCard data={data} />
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 space-y-4">
          <MitrePanel data={data} />
          {data.threat_scenario_table && data.threat_scenario_table.length > 0 && (
            <ThreatScenarioTable rows={data.threat_scenario_table} />
          )}
          {investigationBundle && <InvestigationTimeline bundle={investigationBundle} />}
        </div>
        <div className="space-y-4">
          <ApplicationInfoCard data={data} />
          <ScoreEntryCard data={data} />
          <ExportOptions data={data} />
        </div>
      </div>
    </div>
  );
}
