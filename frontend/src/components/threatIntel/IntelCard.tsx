import SocCard from '../ui/Card';
import SectionHeader from '../ui/SectionHeader';
import { INTEL, INTEL_THEME } from './intelTokens';

type IntelCardProps = {
  children: React.ReactNode;
  className?: string;
  bodyClassName?: string;
};

/** Full-height intel panel shell - pairs with grid `items-stretch` */
export function IntelCard({ children, className = '', bodyClassName = '' }: IntelCardProps) {
  return (
    <SocCard className={`flex flex-col h-full min-h-0 shadow-sm hover:shadow-md transition-shadow duration-200 ${className}`}>
      <div className={`flex-1 flex flex-col min-h-0 ${bodyClassName}`}>{children}</div>
    </SocCard>
  );
}

export function IntelSectionHeader({
  icon,
  title,
  subtitle,
  action,
}: {
  icon: React.ReactNode;
  title: string;
  subtitle?: string;
  action?: React.ReactNode;
}) {
  return (
    <SectionHeader
      icon={<span className={INTEL_THEME.accentIcon}>{icon}</span>}
      title={title}
      subtitle={subtitle}
      action={action}
      className={`${INTEL.headerPx} bg-slate-50 border-b border-slate-200`}
    />
  );
}

export function IntelCardBody({
  children,
  compact,
  className = '',
}: {
  children: React.ReactNode;
  compact?: boolean;
  className?: string;
}) {
  return <div className={`${compact ? INTEL.cardBodyCompact : INTEL.cardBody} ${className}`}>{children}</div>;
}
