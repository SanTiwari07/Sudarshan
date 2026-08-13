import React from 'react';
import { TYPOGRAPHY, type TypographyVariant } from '../../theme/typography';

interface TypographyProps extends React.HTMLAttributes<HTMLElement> {
  variant?: TypographyVariant;
  as?: React.ElementType;
  children: React.ReactNode;
  className?: string;
}

export function Typography({
  variant = 'body',
  as,
  children,
  className = '',
  ...props
}: TypographyProps) {
  let Component: React.ElementType = as || 'div';
  if (!as) {
    if (variant === 'h1') Component = 'h1';
    else if (variant === 'h2') Component = 'h2';
    else if (variant === 'h3' || variant === 'drawerTitle') Component = 'h3';
    else if (variant === 'cardTitle' || variant === 'sectionTitle') Component = 'h4';
    else if (variant === 'body' || variant === 'bodySmall') Component = 'p';
    else if (variant === 'label' || variant === 'caption') Component = 'span';
  }

  const defaultClasses = TYPOGRAPHY[variant] || '';

  return (
    <Component className={`${defaultClasses} ${className}`.trim()} {...props}>
      {children}
    </Component>
  );
}

export function PageTitle({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return <h1 className={`${TYPOGRAPHY.h1} ${className}`.trim()}>{children}</h1>;
}

export function SectionTitle({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return <h2 className={`${TYPOGRAPHY.h2} ${className}`.trim()}>{children}</h2>;
}

export function CardTitle({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return <h3 className={`${TYPOGRAPHY.cardTitle} ${className}`.trim()}>{children}</h3>;
}

export function MetadataLabel({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return <span className={`${TYPOGRAPHY.label} ${className}`.trim()}>{children}</span>;
}

export function CodeText({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return <code className={`${TYPOGRAPHY.code} ${className}`.trim()}>{children}</code>;
}

export default Typography;
