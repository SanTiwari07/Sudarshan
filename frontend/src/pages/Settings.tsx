import { useState, type ReactNode } from 'react';
import { Settings as SettingsIcon, Shield, Sliders, Keyboard, User, Check } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import PageHeader from '../components/ui/PageHeader';

const RISK_WEIGHTS = [
  ['CT', 'Capability', 0.3],
  ['BT', 'Banking target', 0.25],
  ['PR', 'Permissions', 0.15],
  ['OB', 'Obfuscation', 0.15],
  ['IR', 'Infrastructure', 0.15],
] as const;

const SHORTCUTS = [
  ['Open command palette', 'Ctrl + K'],
  ['Close slide-over or dialog', 'Esc'],
  ['Send investigation prompt', 'Enter'],
  ['New line in prompt', 'Shift + Enter'],
] as const;

function Panel({ icon: Icon, title, children }: { icon: typeof User; title: string; children: ReactNode }) {
  return (
    <section className="bg-white rounded-2xl border border-slate-200/80 p-5 sm:p-6 shadow-[0_1px_3px_rgba(15,23,42,0.04)]">
      <div className="flex items-center gap-2.5 mb-5">
        <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-100 text-slate-600">
          <Icon className="h-4 w-4" />
        </span>
        <h2 className="text-base font-semibold text-slate-900">{title}</h2>
      </div>
      {children}
    </section>
  );
}

function Toggle({
  checked,
  onChange,
  title,
  description,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  title: string;
  description: string;
}) {
  return (
    <label className="flex items-center justify-between gap-6 py-4 first:pt-0 last:pb-0 cursor-pointer">
      <div>
        <span className="text-[15px] font-medium text-slate-900 block">{title}</span>
        <span className="text-sm text-slate-500 mt-0.5 block">{description}</span>
      </div>
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="peer sr-only"
      />
      <span
        aria-hidden
        className={`relative h-6 w-11 shrink-0 rounded-full transition-colors peer-focus-visible:ring-2 peer-focus-visible:ring-blue-500 peer-focus-visible:ring-offset-2 ${
          checked ? 'bg-blue-600' : 'bg-slate-300'
        }`}
      >
        <span
          className={`absolute top-0.5 left-0.5 h-5 w-5 rounded-full bg-white shadow transition-transform ${
            checked ? 'translate-x-5' : ''
          }`}
        />
      </span>
    </label>
  );
}

export default function Settings() {
  const { user, role } = useAuth();
  const [autoExpandDrawers, setAutoExpandDrawers] = useState(true);
  const [soundAlerts, setSoundAlerts] = useState(false);
  const [savedFeedback, setSavedFeedback] = useState(false);

  const handleSave = () => {
    setSavedFeedback(true);
    setTimeout(() => setSavedFeedback(false), 2000);
  };

  return (
    <div className="page-frame">
      <PageHeader
        icon={SettingsIcon}
        title="Settings"
        description="Your profile, workspace preferences, and how Sudarshan calculates risk."
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        <div className="lg:col-span-2 space-y-6">
          <Panel icon={User} title="Profile">
            <div className="flex items-center gap-4">
              <span className="h-14 w-14 rounded-2xl bg-blue-600 flex items-center justify-center text-white text-xl font-semibold">
                {(user || 'A')[0].toUpperCase()}
              </span>
              <div className="min-w-0">
                <p className="text-lg font-semibold text-slate-900 truncate">{user || 'SOC Analyst'}</p>
                <span className="mt-1 inline-flex items-center rounded-full bg-blue-50 px-2.5 py-0.5 text-xs font-semibold text-blue-700 capitalize">
                  {(role || 'analyst').replace('_', ' ')}
                </span>
              </div>
            </div>
          </Panel>

          <Panel icon={Sliders} title="Workspace preferences">
            <div className="divide-y divide-slate-100">
              <Toggle
                checked={autoExpandDrawers}
                onChange={setAutoExpandDrawers}
                title="Open evidence automatically"
                description="Slide the evidence panel open when you select a finding or evidence reference."
              />
              <Toggle
                checked={soundAlerts}
                onChange={setSoundAlerts}
                title="Sound on critical verdict"
                description="Play a short alert when an analysis finishes with a critical banking-trojan verdict."
              />
            </div>
            <div className="mt-6 pt-5 border-t border-slate-100 flex justify-end">
              <button
                type="button"
                onClick={handleSave}
                className="inline-flex items-center gap-2 h-10 px-4 rounded-xl bg-blue-600 text-white font-semibold text-sm hover:bg-blue-700 transition-colors shadow-sm"
              >
                {savedFeedback ? (
                  <>
                    <Check className="h-4 w-4" />
                    <span>Saved</span>
                  </>
                ) : (
                  <span>Save preferences</span>
                )}
              </button>
            </div>
          </Panel>
        </div>

        <div className="space-y-6">
          <Panel icon={Shield} title="How risk is scored">
            <p className="text-sm text-slate-600 leading-relaxed">
              Risk scores come only from the deterministic risk engine. Each factor below
              contributes a fixed share of the final score.
            </p>
            <ul className="mt-4 space-y-3">
              {RISK_WEIGHTS.map(([code, name, weight]) => (
                <li key={code}>
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-slate-700">
                      <span className="font-mono text-xs font-semibold text-slate-500 mr-2">{code}</span>
                      {name}
                    </span>
                    <span className="font-semibold text-slate-900 tabular-nums">{Math.round(weight * 100)}%</span>
                  </div>
                  <div className="mt-1.5 h-1.5 rounded-full bg-slate-100 overflow-hidden">
                    <div className="h-full rounded-full bg-blue-500" style={{ width: `${weight * 100 / 0.3}%` }} />
                  </div>
                </li>
              ))}
            </ul>
            <p className="mt-5 text-[13px] text-slate-500 leading-snug rounded-xl bg-slate-50 p-3">
              AI writes the narrative and explanations, but it can never change a risk score.
            </p>
          </Panel>

          <Panel icon={Keyboard} title="Keyboard shortcuts">
            <div className="space-y-3">
              {SHORTCUTS.map(([label, keys]) => (
                <div key={label} className="flex items-center justify-between gap-3 text-sm">
                  <span className="text-slate-600">{label}</span>
                  <kbd className="px-2 py-0.5 rounded-md bg-slate-100 border border-slate-200 font-mono text-xs font-semibold text-slate-700 whitespace-nowrap">
                    {keys}
                  </kbd>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
