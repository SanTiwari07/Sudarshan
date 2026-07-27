import { getRiskStyle, getSeverityStyle } from '../../theme/colors';

interface BadgeProps {
  label: string;
  variant?: 'risk' | 'severity' | 'custom';
  className?: string;
}

export default function Badge({ label, variant = 'custom', className = '' }: BadgeProps) {
  let styleClass = className;
  if (variant === 'risk') {
    const riskStyle = getRiskStyle(label);
    styleClass = `${riskStyle.badge} ${className}`;
  } else if (variant === 'severity') {
    const sevStyle = getSeverityStyle(label);
    styleClass = `${sevStyle} border ${className}`;
  }

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wide ${styleClass}`}>
      {label}
    </span>
  );
}
