import { motion } from 'motion/react';

export default function ThreatIntelPageShell({ children }: { children: React.ReactNode }) {
  return (
    <motion.main 
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
      className="w-full min-w-0 space-y-6 pb-10"
    >
      {children}
    </motion.main>
  );
}
