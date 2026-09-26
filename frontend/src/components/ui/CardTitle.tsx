import type { LucideIcon } from 'lucide-react';
import InfoTip from './InfoTip';

export type CardTone = 'blue' | 'red' | 'orange' | 'violet' | 'emerald' | 'slate' | 'sky';

const TONE: Record<CardTone, string> = {
  blue: 'bg-blue-50 text-blue-600',
  red: 'bg-red-50 text-red-600',
  orange: 'bg-orange-50 text-orange-600',
  violet: 'bg-violet-50 text-violet-600',
  emerald: 'bg-emerald-50 text-emerald-600',
  slate: 'bg-slate-100 text-slate-600',
  sky: 'bg-sky-50 text-sky-600',
};

type CardTitleProps = {
  icon: LucideIcon;
  title: string;
  /** What the card shows, in plain language. Renders the "i" button. */
  info?: string;
  tone?: CardTone;
  infoAlign?: 'left' | 'right';
};

/** The one title treatment for case cards: icon chip, title, info button. */
export default function CardTitle({ icon: Icon, title, info, tone = 'blue', infoAlign = 'left' }: CardTitleProps) {
  return (
    <span className="flex items-center gap-2.5 min-w-0">
      <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${TONE[tone]}`}>
        <Icon className="h-4 w-4" aria-hidden />
      </span>
      <span className="text-[15px] font-semibold tracking-[-0.01em] text-slate-900 truncate">{title}</span>
      {info && <InfoTip text={info} label={title} align={infoAlign} />}
    </span>
  );
}
