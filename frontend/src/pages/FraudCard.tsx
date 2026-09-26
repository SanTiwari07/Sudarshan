import type { FraudCardData } from '../types/case';
import { motion } from 'motion/react';
import CaseHeader from '../components/case/CaseHeader';
import TargetCard from '../components/case/TargetCard';
import ConcealedPayload from '../components/case/ConcealedPayload';
import ScoreBreakdown from '../components/case/ScoreBreakdown';
import RuntimeStatus from '../components/case/RuntimeStatus';
import EvidenceSummary from '../components/case/EvidenceSummary';
import AttackWorkflow from '../components/case/AttackWorkflow';
import KeyFindings from '../components/case/KeyFindings';
import InvestigationActivity from '../components/case/InvestigationActivity';

export default function FraudCard({ data }: { data: FraudCardData | null }) {
  if (!data) return null;

  const hasConcealed = Boolean(
    data.frs_breakdown?.concealed_payload ||
    data.has_reflection ||
    data.technical_view?.apis_fired?.some((a) =>
      /classloader|dexclassloader|pathclassloader|reflect|getmethod/i.test(a),
    ),
  );

  return (
    <motion.main
      initial={{ opacity: 0, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.18 }}
      className="w-full min-w-0 space-y-6"
    >
      {/* ROW 1: Case Identity & Investigation Header (12 cols) */}
      <section className="bg-white rounded-2xl border border-slate-200/80 p-6 sm:p-7 shadow-[0_1px_3px_rgba(15,23,42,0.04)]">
        <CaseHeader data={data} />
      </section>

      {/* ROW 2: what drove the score, and whether the app was run */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        <div className="lg:col-span-7 flex min-w-0 [&>*]:flex-1 [&>*]:min-w-0">
          <ScoreBreakdown data={data} />
        </div>
        <div className="lg:col-span-5 flex min-w-0 [&>*]:flex-1 [&>*]:min-w-0">
          <RuntimeStatus data={data} />
        </div>
      </section>

      {/* ROW 3: Threat Indicators & Target Identity (12 cols) */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {hasConcealed ? (
          <>
            <div className="lg:col-span-6 flex min-w-0 [&>*]:flex-1 [&>*]:min-w-0">
              <ConcealedPayload data={data} />
            </div>
            <div className="lg:col-span-6 flex min-w-0 [&>*]:flex-1 [&>*]:min-w-0">
              <TargetCard data={data} />
            </div>
          </>
        ) : (
          <div className="lg:col-span-12 flex min-w-0 [&>*]:flex-1 [&>*]:min-w-0">
            <TargetCard data={data} />
          </div>
        )}
      </section>

      {/* ROW 4: Key findings lead - they are the answer - with the attack sequence beside them */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        <div className="lg:col-span-7 flex min-w-0 [&>*]:flex-1 [&>*]:min-w-0">
          <KeyFindings data={data} />
        </div>
        <div className="lg:col-span-5 flex min-w-0 [&>*]:flex-1 [&>*]:min-w-0">
          <AttackWorkflow data={data} />
        </div>
      </section>

      {/* ROW 5: Forensic Evidence Summary & Audit Activity (12 cols: 7 + 5) */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        <div className="lg:col-span-7 flex min-w-0 [&>*]:flex-1 [&>*]:min-w-0">
          <EvidenceSummary sha256={data.sha256} />
        </div>
        <div className="lg:col-span-5 flex min-w-0 [&>*]:flex-1 [&>*]:min-w-0">
          <InvestigationActivity data={data} />
        </div>
      </section>
    </motion.main>
  );
}
