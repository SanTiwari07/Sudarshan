import type { FraudCardData } from '../../App';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import { Shield } from 'lucide-react';

export default function FamilyEvidenceCard({ data }: { data: FraudCardData }) {
  const { openEvidence, openLedger } = useInvestigationUI();
  const rule = data.technical_view?.matched_rule || 'No rule matched';

  const signals = [
    data.has_accessibility_abuse && { label: 'Accessibility declared', id: 'STAT-A11Y' },
    data.has_system_alert_window && { label: 'SYSTEM_ALERT_WINDOW', id: 'STAT-OVERLAY' },
    data.has_sms_read_write && { label: 'SMS read/write', id: 'STAT-SMS' },
  ].filter(Boolean) as { label: string; id: string }[];

  return (
    <SocCard>
      <SectionHeader icon={<Shield className="h-4 w-4" />} title="Malware family evidence" subtitle="Deterministic classification" />
      <div className="p-4 space-y-3 text-xs">
        <div>
          <span className="text-slate-500">Family</span>
          <div className="text-lg font-bold text-red-700">{data.family_classification}</div>
        </div>
        <div className="p-3 bg-white border border-slate-200 rounded-lg">
          <div className="text-[10px] uppercase text-slate-500">Matched rule</div>
          <div className="mt-1 text-slate-800">{rule}</div>
        </div>
        <div>
          <div className="text-[10px] uppercase text-slate-500 mb-2">Matched signals</div>
          <ul className="space-y-1">
            {signals.map((s) => (
              <li key={s.id}>
                <button type="button" onClick={() => openEvidence(s.id)} className="text-blue-700 hover:underline">
                  {s.label} → {s.id}
                </button>
              </li>
            ))}
          </ul>
        </div>
        {data.threat_correlation?.known_family && (
          <div className="text-slate-600">
            External VT family: <strong>{data.threat_correlation.known_family}</strong>
          </div>
        )}
        <button type="button" onClick={() => openLedger('correlation')} className="text-blue-700 font-semibold">
          Explain correlation score
        </button>
      </div>
    </SocCard>
  );
}
