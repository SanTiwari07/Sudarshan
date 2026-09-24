import type { FraudCardData } from '../../App';
import DrawerShell from '../ui/DrawerShell';
import { useInvestigationUI } from '../../context/InvestigationUIContext';
import InvestigationChat from '../../pages/InvestigationChat';

export default function AiAssistantDrawer({ data }: { data: FraudCardData }) {
  const { activeDrawer, closeDrawer } = useInvestigationUI();
  
  return (
    <DrawerShell
      open={activeDrawer?.kind === 'ask-ai'}
      onClose={closeDrawer}
      title="Ask SUDARSHAN"
      subtitle="AI-assisted investigation and plain-language explanation"
    >
      <div className="-mx-5 -my-5 h-[calc(100vh-80px)] relative bg-slate-50">
         <InvestigationChat data={data} />
      </div>
    </DrawerShell>
  );
}
