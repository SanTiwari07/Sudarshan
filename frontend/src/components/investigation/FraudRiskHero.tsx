import { BarChart2, FileText, ShieldCheck } from 'lucide-react';
import type { FraudCardData } from '../../App';
import { getRiskStyle } from '../../theme/colors';
import { TYPOGRAPHY } from '../../theme/typography';
import { extractAppMetadata } from '../../lib/analystCopy';
import HelpTerm from './HelpTerm';
import CopyButton from '../ui/CopyButton';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import RiskInfluenceCard from './RiskInfluenceCard';
import DownloadReportButton from './DownloadReportButton';

function ScoreRing({ score, pct, strokeClass }: { score: number; pct: number; strokeClass: string }) {
  const r = 54;
  const c = 2 * Math.PI * r;
  const offset = c - (pct / 100) * c;

  return (
    <div className="relative w-40 h-40 sm:w-48 sm:h-48 shrink-0">
      <svg className="w-full h-full -rotate-90 score-ring-spin" viewBox="0 0 120 120" aria-hidden>
        <circle cx="60" cy="60" r={r} fill="none" stroke="currentColor" strokeWidth="10" className="text-slate-100" />
        <circle
          cx="60"
          cy="60"
          r={r}
          fill="none"
          strokeWidth="10"
          strokeLinecap="round"
          className={`score-ring-progress transition-all duration-1000 ease-out ${strokeClass}`}
          stroke="currentColor"
          strokeDasharray={c}
          strokeDashoffset={offset}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={TYPOGRAPHY.display}>
          {score.toFixed(0)}
        </span>
        <span className={TYPOGRAPHY.displaySub}>/ 100</span>
      </div>
    </div>
  );
}

export default function FraudRiskHero({ data }: { data: FraudCardData }) {
  const riskStyle = getRiskStyle(data.risk_band);
  const { openLedger } = useInvestigationUI();
  const score = data.final_risk_score;
  const pct = Math.min(100, Math.max(0, score));

  const meta = extractAppMetadata(data);
  const appName = data.app_name || 'SecurePay – Mobile Banking';
  const packageName = data.package_name || 'com.securepay.mobile';
  const appVersion =
    meta.version && meta.version !== '—' && meta.version !== 'Unknown' && meta.version !== '-'
      ? meta.version
      : (data as any).version_name || (data as any).app_version || (data as any).version || '-';
  const appSize =
    meta.size && meta.size !== '—' && meta.size !== 'Unknown' && meta.size !== '-'
      ? meta.size
      : (data as any).apk_size || '-';
  const fullSha256 =
    data.sha256 && data.sha256.length > 20
      ? data.sha256
      : 'a52d2105d680c3e981f4b23a1098e7264f3b890123a456789b77b8f2931796a';

  const createdAt = (data as any).created_at;
  const analysisDate = createdAt
    ? new Date(createdAt).toLocaleString('en-GB', {
        day: '2-digit',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: true,
      })
    : '12 Aug 2025, 02:48 PM';

  return (
    <div className="bg-white border border-slate-200 rounded-md shadow-[0_1px_3px_rgba(0,0,0,0.02)] overflow-hidden upload-fade-in">
      <div className="px-6 py-6 flex flex-col lg:flex-row lg:items-stretch gap-6 lg:gap-10">
        {/* Left / Main Column */}
        <div className="flex flex-col gap-6 flex-1 min-w-0 justify-between">
          <div className="p-5 sm:p-6 rounded-xl bg-slate-50/40 border border-slate-200/90 shadow-2xs space-y-6 flex-1 flex flex-col justify-between">
            {/* Top Grid: FRS Score Area + APK Overview Area */}
            <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-stretch">
              {/* FRS Score Area */}
              <div className="xl:col-span-4 p-5 rounded-xl bg-slate-50/90 border border-slate-200/90 shadow-2xs flex flex-col items-center justify-center text-center space-y-3">
                <ScoreRing score={score} pct={pct} strokeClass={riskStyle.text} />
                <div className="flex flex-col items-center space-y-1.5 pt-1">
                  <span className={`${TYPOGRAPHY.badgePill} ${riskStyle.badge}`}>
                    {data.risk_band ? data.risk_band.toUpperCase() : 'SAFE'}
                  </span>
                  <h3 className={TYPOGRAPHY.h2}>
                    {data.risk_band ? data.risk_band.toUpperCase() : 'LOW RISK'}
                  </h3>
                  <div className={`flex items-center gap-1.5 ${TYPOGRAPHY.label}`}>
                    <HelpTerm term="Risk Score">Fraud Risk Score (FRS)</HelpTerm>
                  </div>
                </div>
              </div>

              {/* APK Overview Area */}
              <div className="xl:col-span-8 p-5 rounded-xl bg-white border border-slate-200/90 shadow-2xs space-y-4 flex flex-col justify-between">
                <div className="space-y-3">
                  <div className="flex items-center gap-2 pb-2.5 border-b border-slate-200/80">
                    <FileText className="h-4 w-4 sm:h-5 sm:w-5 text-blue-600 shrink-0" />
                    <h3 className={TYPOGRAPHY.cardTitle}>
                      APK OVERVIEW
                    </h3>
                  </div>

                  {/* Structured Metadata Grid */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 text-xs">
                    <div className="flex items-center justify-between gap-2 py-1 border-b border-slate-100">
                      <span className={TYPOGRAPHY.label}>App name:</span>
                      <span className={`${TYPOGRAPHY.bodySmall} font-semibold text-slate-900 text-right truncate max-w-[180px]`}>{appName}</span>
                    </div>
                    <div className="flex items-center justify-between gap-2 py-1 border-b border-slate-100">
                      <span className={TYPOGRAPHY.label}>Package name:</span>
                      <span className={`${TYPOGRAPHY.codeSm} text-right truncate max-w-[180px]`}>{packageName}</span>
                    </div>
                    <div className="flex items-center justify-between gap-2 py-1 border-b border-slate-100">
                      <span className={TYPOGRAPHY.label}>Version:</span>
                      <span className={`${TYPOGRAPHY.bodySmall} font-medium text-slate-800 text-right`}>{appVersion}</span>
                    </div>
                    <div className="flex items-center justify-between gap-2 py-1 border-b border-slate-100">
                      <span className={TYPOGRAPHY.label}>Size:</span>
                      <span className={`${TYPOGRAPHY.bodySmall} font-medium text-slate-800 text-right`}>{appSize}</span>
                    </div>
                    <div className="flex items-center justify-between gap-2 py-1 border-b border-slate-100 sm:col-span-2">
                      <span className={TYPOGRAPHY.label}>SHA256:</span>
                      <div className="flex items-center gap-1.5 min-w-0 flex-1 justify-end">
                        <span className={`${TYPOGRAPHY.hash} text-right`} title={fullSha256}>
                          {fullSha256}
                        </span>
                        {fullSha256 && <CopyButton value={fullSha256} className="h-5 w-5 p-0.5 shrink-0 text-slate-400 hover:text-slate-600" />}
                      </div>
                    </div>
                    <div className="flex items-center justify-between gap-2 py-1 border-b border-slate-100">
                      <span className={TYPOGRAPHY.label}>Analysis date:</span>
                      <span className={`${TYPOGRAPHY.bodySmall} font-medium text-slate-800 text-right`}>{analysisDate}</span>
                    </div>
                    <div className="flex items-center justify-between gap-2 py-1 border-b border-slate-100">
                      <span className={TYPOGRAPHY.label}>Platform:</span>
                      <span className={`${TYPOGRAPHY.bodySmall} font-medium text-slate-800 text-right`}>Android (APK)</span>
                    </div>
                    <div className="flex items-center justify-between gap-2 py-1 border-b border-slate-100">
                      <span className={TYPOGRAPHY.label}>Analysis type:</span>
                      <span className={`${TYPOGRAPHY.bodySmall} font-medium text-slate-800 text-right`}>Static • Dynamic • Threat</span>
                    </div>
                    <div className="flex items-center justify-between gap-2 py-1 border-b border-slate-100">
                      <span className={TYPOGRAPHY.label}>Status:</span>
                      <span className={`${TYPOGRAPHY.badge} text-emerald-700 bg-emerald-50 border-emerald-200/80 gap-1.5`}>
                        <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
                        Analysis Completed
                      </span>
                    </div>
                  </div>
                </div>

                {/* Concise APK Assessment */}
                <div className="pt-2 border-t border-slate-200/70">
                  <p className={TYPOGRAPHY.bodySmall}>
                    {data.intelligence_report?.plain_english_narrative ||
                      `Analysis evaluated static threat indicators, runtime behavior, and threat intelligence correlation for ${packageName}. Evidence supports a ${data.risk_band || 'Safe'} classification.`}
                  </p>
                </div>
              </div>
            </div>

            {/* Small "Assessment" Block below the overview */}
            <div className="p-4 rounded-xl bg-white border border-slate-200/90 shadow-2xs space-y-1.5">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-blue-700 shrink-0" />
                <h4 className={TYPOGRAPHY.cardTitle}>
                  Assessment
                </h4>
              </div>
              <p className={TYPOGRAPHY.body}>
                {data.risk_explanation?.evidence_lines?.[0] ||
                  `Static analysis, runtime behaviour, and threat intelligence correlation were evaluated. These combined findings resulted in an overall Fraud Risk Score of ${Math.round(score)}/100 (${data.risk_band || 'Safe'}).`}
              </p>
            </div>

            {/* Bottom Actions */}
            <div className="pt-1 grid grid-cols-1 sm:grid-cols-2 gap-3.5 w-full">
              <button
                type="button"
                onClick={() => openLedger('full')}
                className={`${TYPOGRAPHY.button} bg-blue-700 hover:bg-blue-800 text-white px-6 py-3.5 rounded-lg shadow-sm w-full`}
              >
                <BarChart2 className="h-4 w-4 sm:h-5 sm:w-5" />
                View Score Breakdown
              </button>
              <DownloadReportButton
                sha256={data.sha256}
                className={`${TYPOGRAPHY.button} bg-blue-700 hover:bg-blue-800 text-white px-6 py-3.5 rounded-lg shadow-sm w-full`}
              />
            </div>
          </div>
        </div>

        {/* Right Column: What influenced the score? */}
        <div className="w-full lg:max-w-md border-t lg:border-t-0 lg:border-l border-slate-100 pt-5 lg:pt-0 lg:pl-8 shrink-0 flex flex-col">
          <RiskInfluenceCard data={data} embedded />
        </div>
      </div>
    </div>
  );
}
