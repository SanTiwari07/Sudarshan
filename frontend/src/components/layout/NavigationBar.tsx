import { Link, useLocation } from 'react-router-dom';
import { ENTERPRISE_NAV, ENTERPRISE_NAV_END, ENTERPRISE_NAV_MAIN, isNavActive, type NavItem } from '../../layout/navItems';

type NavigationBarProps = {
  items?: NavItem[];
  /** main = centered primary links; end = right cluster before bell; all = mobile scroll row */
  variant?: 'main' | 'end' | 'all';
  className?: string;
};

function NavLinks({ items }: { items: NavItem[] }) {
  const { pathname } = useLocation();

  return (
    <>
      {items.map((item) => {
        const active = isNavActive(pathname, item);
        const Icon = item.icon;
        const base =
          'flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[11px] font-mono tracking-wider uppercase font-semibold whitespace-nowrap transition-all focus:outline-none shrink-0 border';

        if (item.disabled) {
          return (
            <span
              key={item.label}
              className={`${base} text-slate-600 border-transparent cursor-not-allowed`}
              aria-disabled="true"
            >
              <Icon className="h-3.5 w-3.5 opacity-40" aria-hidden />
              <span className="hidden md:inline">{item.label}</span>
              <span className="md:hidden">{item.shortLabel}</span>
            </span>
          );
        }

        return (
          <Link
            key={`${item.to}-${item.label}`}
            to={item.to}
            aria-current={active ? 'page' : undefined}
            className={
              active
                ? `${base} bg-slate-900 border-slate-800 text-white shadow-[0_1px_2px_rgba(0,0,0,0.2)]`
                : `${base} text-slate-400 border-transparent hover:text-slate-100 hover:bg-slate-900/50`
            }
          >
            <Icon className={`h-3.5 w-3.5 ${active ? 'text-blue-400' : 'text-slate-500'}`} aria-hidden />
            <span className="hidden lg:inline">{item.label}</span>
            <span className="lg:hidden">{item.shortLabel}</span>
          </Link>
        );
      })}
    </>
  );
}

export default function NavigationBar({ items, variant = 'all', className = '' }: NavigationBarProps) {
  const resolved =
    items ??
    (variant === 'main'
      ? ENTERPRISE_NAV_MAIN
      : variant === 'end'
        ? ENTERPRISE_NAV_END
        : ENTERPRISE_NAV);

  const justify =
    variant === 'main' ? 'justify-center' : variant === 'end' ? 'justify-end' : 'justify-start';

  return (
    <nav
      className={`min-w-0 flex items-center ${variant === 'main' ? 'flex-1' : ''} ${className}`}
      aria-label={variant === 'end' ? 'Quick actions' : 'Primary'}
    >
      <div
        className={`flex items-center gap-1 overflow-x-auto max-w-full px-1 py-0.5 scrollbar-hidden ${justify}`}
      >
        <NavLinks items={resolved} />
      </div>
    </nav>
  );
}
