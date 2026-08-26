import type { ReactNode } from 'react';
import DrawerShell from '../ui/DrawerShell';
import { TYPOGRAPHY } from '../../theme/typography';
import { useInvestigationUI } from '../../context/InvestigationUIContext';

/**
 * Finding drawers, on the shared shell.
 *
 * This used to be its own overlay implementation - one of five in the product,
 * each with different chrome and none with a focus trap. It now delegates to
 * `ui/DrawerShell` and exists only so the two finding drawers keep their
 * import unchanged.
 *
 * `onBack` is wired here rather than at each call site: a finding drawer is
 * frequently reached from another drawer, and the shell can only offer the
 * affordance if it knows there is something underneath.
 */
export default function FindingDrawerShell({
  open,
  onClose,
  title,
  subtitle,
  headerExtra,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  headerExtra?: ReactNode;
  children: ReactNode;
}) {
  const { canGoBack } = useInvestigationUI();

  return (
    <DrawerShell
      open={open}
      onClose={onClose}
      onBack={canGoBack ? onClose : undefined}
      title={title}
      subtitle={subtitle}
      headerExtra={headerExtra}
      labelledById="finding-drawer-title"
    >
      {children}
    </DrawerShell>
  );
}

export function FindingSection({ label, children }: { label: string; children: ReactNode }) {
  return (
    <section className="mb-5">
      <h3 className={`${TYPOGRAPHY.label} mb-2`}>{label}</h3>
      <div className={TYPOGRAPHY.bodySmall}>{children}</div>
    </section>
  );
}
