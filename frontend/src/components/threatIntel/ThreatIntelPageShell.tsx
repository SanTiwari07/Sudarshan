import { INTEL } from './intelTokens';
import { motion } from 'motion/react';

export default function ThreatIntelPageShell({ children }: { children: React.ReactNode }) {
  return (
    <motion.main 
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
      className={`w-full min-w-0 ${INTEL.sectionGap} pb-10 px-4 sm:px-6 lg:px-8 max-w-[1920px] mx-auto`}
    >
      {children}
    </motion.main>
  );
}
