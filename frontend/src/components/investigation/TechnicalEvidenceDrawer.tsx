import type { FraudCardData } from '../../App';
import DrawerShell from '../ui/DrawerShell';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import TechnicalView from '../../pages/TechnicalView';

export default function TechnicalEvidenceDrawer({ data }: { data: FraudCardData }) {
  const { activeDrawer, closeDrawer } = useInvestigationUI();
  
  return (
    <DrawerShell
      open={activeDrawer?.kind === 'technical-evidence'}
      onClose={closeDrawer}
      title="Technical Evidence"
      subtitle="Comprehensive technical breakdown of static and dynamic analysis"
    >
      <div className="-mx-5 -my-5 h-full relative">
         <TechnicalView data={data} />
      </div>
    </DrawerShell>
  );
}
