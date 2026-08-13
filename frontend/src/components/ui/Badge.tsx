import { getRiskStyle, getSeverityStyle } from '../../theme/colors';
import { TYPOGRAPHY } from '../../theme/typography';

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
    <span className={`${TYPOGRAPHY.badge} ${styleClass}`.trim()}>
      {label}
    </span>
  );
}
