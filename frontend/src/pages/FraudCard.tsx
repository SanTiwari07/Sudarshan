import type { FraudCardData } from '../types/case';
import { motion } from 'motion/react';
import CaseHeader from '../components/case/CaseHeader';
import TargetCard from '../components/case/TargetCard';
import ConcealedPayload from '../components/case/ConcealedPayload';
import ScoreGauge from '../components/investigation/ScoreGauge';
import ScoreBreakdown from '../components/case/ScoreBreakdown';
import RuntimeStatus from '../components/case/RuntimeStatus';
import EvidenceSummary from '../components/case/EvidenceSummary';
import AttackWorkflow from '../components/case/AttackWorkflow';
import KeyFindings from '../components/case/KeyFindings';

export default function FraudCard({ data }: { data: FraudCardData | null }) {
  if (!data) return null;

  return (
    <motion.main
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
      className="max-w-6xl mx-auto py-8 px-4 sm:px-6 lg:px-8"
    >
      <div className="space-y-6">
        {/* Top Header Section */}
        <section className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
          <CaseHeader data={data} />
        </section>

        <ConcealedPayload data={data} />

        <section>
          <TargetCard data={data} />
        </section>

        {/* Risk & Score Row */}
        <section className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm flex flex-col items-center justify-center min-h-[300px]">
            <ScoreGauge data={data} />
          </div>
          <div className="min-h-[300px]">
            <ScoreBreakdown data={data} />
          </div>
        </section>

        {/* Dynamic Status & Evidence Summary */}
        <section className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <RuntimeStatus data={data} />
          </div>
          <div>
            <EvidenceSummary sha256={data.sha256} />
          </div>
        </section>

        {/* Workflow & Findings Row */}
        <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div>
            <AttackWorkflow data={data} />
          </div>
          <div>
            <KeyFindings data={data} />
          </div>
        </section>
      </div>
    </motion.main>
  );
}
