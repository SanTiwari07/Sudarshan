type NextStepsCardProps = {
  steps: string[];
};

export default function NextStepsCard({ steps }: NextStepsCardProps) {
  if (steps.length === 0) return null;

  return (
    <section className="py-8 border-t border-slate-200/80">
      <h2 className="text-sm font-medium text-slate-900 mb-4">What&apos;s next?</h2>
      <ul className="space-y-2.5">
        {steps.map((step) => (
          <li key={step} className="flex gap-2.5 text-sm text-slate-600">
            <span className="text-slate-400 shrink-0" aria-hidden>
              •
            </span>
            <span>{step}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
