import { useState } from 'react';
import { Settings as SettingsIcon, Shield, Sliders, Keyboard, User, Check } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

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
    <div className="w-[92%] max-w-[1550px] mx-auto py-8 px-4 sm:px-6 space-y-8">
      {/* Header */}
      <div>
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-lg bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700">
            <SettingsIcon className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-slate-900 tracking-tight">
              Settings & Preferences
            </h1>
            <p className="text-sm text-slate-500 mt-0.5">
              Configure analyst workspace preferences, review deterministic engine safety thresholds, and reference keyboard shortcuts.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Operator Profile & UI Preferences */}
        <div className="lg:col-span-2 space-y-6">
          {/* Operator Profile */}
          <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
            <div className="flex items-center gap-2 mb-4 pb-3 border-b border-slate-100">
              <User className="h-4 w-4 text-slate-500" />
              <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
                Analyst Session Profile
              </h2>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                <span className="text-slate-500 font-medium block">Active Identity</span>
                <span className="text-sm font-semibold text-slate-900 mt-0.5 block">{user || 'SOC Analyst'}</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                <span className="text-slate-500 font-medium block">Assigned RBAC Role</span>
                <span className="text-sm font-semibold text-blue-700 mt-0.5 block uppercase tracking-wide">
                  {role || 'SOC_ANALYST'}
                </span>
              </div>
            </div>
          </div>

          {/* Workbench Display Options */}
          <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
            <div className="flex items-center gap-2 mb-4 pb-3 border-b border-slate-100">
              <Sliders className="h-4 w-4 text-slate-500" />
              <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
                Investigation Console Preferences
              </h2>
            </div>

            <div className="space-y-4 text-xs">
              <label className="flex items-center justify-between p-3 rounded-lg border border-slate-200 hover:bg-slate-50 transition-colors cursor-pointer">
                <div>
                  <span className="font-semibold text-slate-900 block text-sm">
                    Auto-slide evidence drawer on row selection
                  </span>
                  <span className="text-slate-500 mt-0.5 block">
                    Automatically open forensic slide-over panel when clicking any finding or evidence reference.
                  </span>
                </div>
                <input
                  type="checkbox"
                  checked={autoExpandDrawers}
                  onChange={(e) => setAutoExpandDrawers(e.target.checked)}
                  className="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                />
              </label>

              <label className="flex items-center justify-between p-3 rounded-lg border border-slate-200 hover:bg-slate-50 transition-colors cursor-pointer">
                <div>
                  <span className="font-semibold text-slate-900 block text-sm">
                    Critical Severity Audio Ping
                  </span>
                  <span className="text-slate-500 mt-0.5 block">
                    Play discrete acoustic notification when a critical banking trojan verdict is reached.
                  </span>
                </div>
                <input
                  type="checkbox"
                  checked={soundAlerts}
                  onChange={(e) => setSoundAlerts(e.target.checked)}
                  className="h-4 w-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                />
              </label>

              <div className="pt-2 flex items-center justify-between">
                <button
                  type="button"
                  onClick={handleSave}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 text-white font-semibold text-xs hover:bg-blue-700 transition-colors shadow-sm"
                >
                  {savedFeedback ? (
                    <>
                      <Check className="h-4 w-4 text-emerald-200" />
                      <span>Preferences Saved</span>
                    </>
                  ) : (
                    <span>Save Preferences</span>
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Deterministic Engine Principles & Keyboard Shortcuts */}
        <div className="space-y-6">
          {/* Deterministic Architecture Notice */}
          <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
            <div className="flex items-center gap-2 mb-3 pb-2 border-b border-slate-100">
              <Shield className="h-4 w-4 text-blue-600" />
              <h2 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                Deterministic Risk Authority
              </h2>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              Numerical risk scores and fraud bands are governed exclusively by the Deterministic Risk Engine. Static Threat Evidence Index (STEI) and Behavioral Fraud Component Index (BFCI) formulas are mathematically auditable:
            </p>
            <ul className="mt-3 space-y-1.5 text-xs text-slate-700">
              <li className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-blue-600" />
                <span><strong>CT</strong> (Capability): 0.30 weight</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-blue-600" />
                <span><strong>BT</strong> (Banking Target): 0.25 weight</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-blue-600" />
                <span><strong>PR</strong> (Permissions): 0.15 weight</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-blue-600" />
                <span><strong>OB</strong> (Obfuscation): 0.15 weight</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-blue-600" />
                <span><strong>IR</strong> (Infrastructure): 0.15 weight</span>
              </li>
            </ul>
            <p className="mt-3 text-[11px] text-slate-500 italic border-t border-slate-100 pt-2">
              Note: AI provides narrative and explainability assistance but is strictly prohibited from mutating deterministic risk scores.
            </p>
          </div>

          {/* Keyboard Shortcuts Reference */}
          <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
            <div className="flex items-center gap-2 mb-3 pb-2 border-b border-slate-100">
              <Keyboard className="h-4 w-4 text-slate-500" />
              <h2 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                Keyboard Shortcuts
              </h2>
            </div>
            <div className="space-y-2.5 text-xs">
              <div className="flex items-center justify-between">
                <span className="text-slate-600">Open Command Palette</span>
                <kbd className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[11px] font-semibold text-slate-700">
                  Ctrl + K
                </kbd>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-600">Close Slide-over / Modal</span>
                <kbd className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[11px] font-semibold text-slate-700">
                  Escape
                </kbd>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-600">Send Investigation Prompt</span>
                <kbd className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[11px] font-semibold text-slate-700">
                  Enter
                </kbd>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-600">Prompt Newline</span>
                <kbd className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[11px] font-semibold text-slate-700">
                  Shift + Enter
                </kbd>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
