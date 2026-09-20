import { useState } from 'react';
import { useNavigate, useLocation, Location } from 'react-router-dom';
import {
  LogIn,
  Eye,
  EyeOff,
  AlertCircle,
  UserPlus,
  User,
  KeyRound,
  CheckCircle2,
  Lock,
  FileCode2,
  Radar,
  Network,
  Gauge,
} from 'lucide-react';
import { API_BASE } from '../config';
import { TYPOGRAPHY } from '../theme/typography';
import { useAuth } from '../context/AuthContext';

// Persist JWT token to localStorage (backwards compatibility)
export function saveToken(token: string, username: string, role: string) {
  localStorage.setItem('sudarshan_token', token);
  localStorage.setItem('sudarshan_user', username);
  localStorage.setItem('sudarshan_role', role);
}

export function getToken(): string | null {
  return localStorage.getItem('sudarshan_token');
}

export function getUser(): { username: string; role: string } | null {
  const username = localStorage.getItem('sudarshan_user');
  const role = localStorage.getItem('sudarshan_role');
  if (!username || !role) return null;
  return { username, role };
}

export function clearToken() {
  localStorage.removeItem('sudarshan_token');
  localStorage.removeItem('sudarshan_user');
  localStorage.removeItem('sudarshan_role');
}

// ─── Login Page ───────────────────────────────────────────────────────────────

const STAGES = [
  { label: 'Decompile', Icon: FileCode2 },
  { label: 'Detonate', Icon: Radar },
  { label: 'Correlate', Icon: Network },
  { label: 'Score', Icon: Gauge },
];

const FACTS = [
  { term: 'Analysis axes', detail: 'Static · runtime · intel' },
  { term: 'Every score', detail: 'Traced to evidence' },
  { term: 'Batch mode', detail: 'Portfolio-scale intake' },
];

export default function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const auth = useAuth();
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [capsLock, setCapsLock] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const rawFrom = (location.state as { from?: Location })?.from?.pathname || '/';
  const from = rawFrom === '/login' ? '/' : rawFrom;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setLoading(true);

    try {
      if (mode === 'login') {
        const res = await fetch(`${API_BASE}/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Login failed');
        auth.login(data.access_token, data.username, data.role);
        navigate(from, { replace: true });
      } else {
        const res = await fetch(`${API_BASE}/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Registration failed');
        setSuccess(`Account created for ${data.username}. You can now log in.`);
        setMode('login');
        setPassword('');
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Unexpected error');
    } finally {
      setLoading(false);
    }
  };

  const isLogin = mode === 'login';

  /*
   * The field wrapper is a `group` so the icon and the underline both respond
   * to focus without any state. The underline is a separate span scaled from
   * the left rather than a border-colour swap - a border cannot be animated
   * along its length, and the 200ms sweep is what tells a reader working from
   * the keyboard which of the two fields they have landed in.
   */
  const fieldShell =
    'group relative flex items-center gap-2.5 border-b border-slate-300 transition-colors focus-within:border-blue-600';
  const fieldInput =
    'flex-1 min-w-0 bg-transparent py-2.5 text-[17px] text-slate-900 placeholder-slate-400 outline-none';
  const fieldIcon =
    'h-[18px] w-[18px] shrink-0 text-slate-400 transition-colors group-focus-within:text-blue-600';

  return (
    /*
     * Split layout rather than a centred card on a purple gradient with
     * blurred blobs behind it. That treatment is the default look of a
     * generated page, and it is the first screen anyone sees. The left half
     * says what the product does; the right half is a plain, legible form.
     *
     * The brand half is built around the Sudarshan mark at architectural
     * scale - 125% of the panel, bled off both edges, so what reads is blades
     * sweeping through the panel and never a logo parked in a corner.
     * Gradients are load-bearing here and nowhere else: a diagonal wash for
     * depth, one blue radial behind the mark so the blades emerge from light
     * rather than sitting flat on black, and a left-to-right scrim that keeps
     * the copy legible where it crosses the brightest of them.
     */
    <div className="min-h-screen w-full flex flex-col lg:flex-row bg-white">
      {/* Brand half */}
      <div className="relative isolate overflow-hidden lg:w-[52%] bg-[#070d18] text-white px-8 py-10 lg:px-14 lg:py-14 flex flex-col justify-between gap-16 lg:gap-0">
        <div
          aria-hidden
          className="absolute inset-0 -z-20 bg-gradient-to-br from-[#0b1930] via-[#070d18] to-[#04070e]"
        />
        <div
          aria-hidden
          className="pointer-events-none absolute -z-10 left-[-30%] top-1/2 h-[150%] aspect-square -translate-y-1/2 rounded-full opacity-70 blur-3xl bg-[radial-gradient(circle,rgba(37,99,235,0.38)_0%,rgba(56,189,248,0.10)_45%,transparent_68%)]"
        />
        <div
          aria-hidden
          className="pointer-events-none absolute -z-10 left-[-22%] top-1/2 w-[125%] aspect-square -translate-y-1/2"
        >
          <img
            src="/brand/sudarshan-mark-white.png"
            alt=""
            className="signin-chakra h-full w-full select-none opacity-[0.14]"
          />
        </div>
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 -z-10 bg-gradient-to-r from-[#070d18] via-[#070d18]/70 to-transparent"
        />

        <div className="signin-enter flex items-center gap-3">
          <img
            src="/brand/sudarshan-mark-white.png"
            alt=""
            className="h-9 w-9 select-none"
          />
          <div>
            <div className="font-sans text-base font-semibold tracking-[-0.01em] leading-none">
              Sudarshan
            </div>
            <div className="mt-1.5 text-[13px] leading-none text-slate-400">
              Fraud intelligence console
            </div>
          </div>
        </div>

        <div className="signin-enter">
          <h1 className="font-sans text-3xl lg:text-4xl font-semibold tracking-[-0.03em] leading-[1.15] max-w-md">
            Android banking fraud, evidenced.
          </h1>
          <p className="mt-4 text-[17px] text-slate-400 leading-relaxed max-w-md">
            Static decompilation, an instrumented sandbox and threat-intelligence
            correlation resolved into one scored, auditable case file.
          </p>

          <dl className="mt-10 grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-5 max-w-md">
            {FACTS.map((item) => (
              <div key={item.term} className="border-l border-white/10 pl-3">
                <dt className="text-[13px] font-medium text-slate-500">{item.term}</dt>
                <dd className="mt-1 text-[15px] font-medium text-slate-200 leading-snug">
                  {item.detail}
                </dd>
              </div>
            ))}
          </dl>

          {/*
            * The four stages an APK actually passes through, in order. It sits
            * where the panel was otherwise empty, and it earns the space by
            * telling a first-time reader what the console is going to do to
            * their sample before they have signed in to watch it happen.
            */}
          <div className="mt-14 max-w-md">
            <div className="text-[13px] font-medium text-slate-500">
              What happens to a sample
            </div>
            <div className="relative mt-5">
              <div
                aria-hidden
                className="absolute left-0 right-0 top-5 h-px bg-gradient-to-r from-blue-500/10 via-blue-400/40 to-blue-500/10"
              />
              <ol className="relative grid grid-cols-4 gap-2">
                {STAGES.map((stage) => (
                  <li key={stage.label} className="flex flex-col items-center text-center">
                    {/* The ring in the panel colour punches the connecting
                        hairline out from behind each tile. */}
                    <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-white/10 bg-[#0b1424] text-blue-300 shadow-[0_0_0_5px_#070d18]">
                      <stage.Icon className="h-[18px] w-[18px]" aria-hidden />
                    </div>
                    <div className="mt-2.5 text-[13px] font-medium text-slate-300 leading-tight">
                      {stage.label}
                    </div>
                  </li>
                ))}
              </ol>
            </div>
          </div>
        </div>

        <div className="signin-enter max-w-md">
          <div
            aria-hidden
            className="h-px w-full bg-gradient-to-r from-blue-400/40 via-white/10 to-transparent"
          />
          <p className="mt-5 text-[15px] leading-relaxed text-slate-400">
            No verdict arrives on its own. Every score opens onto the thing
            beneath it - the decompiled call, the captured request, the matched
            indicator.
          </p>
        </div>
      </div>

      {/* Form half */}
      <div className="relative flex-1 flex items-center justify-center px-6 py-12 lg:px-16 bg-gradient-to-b from-white via-white to-slate-50">
        <div
          aria-hidden
          className="pointer-events-none absolute right-0 top-0 h-80 w-80 rounded-full blur-3xl bg-[radial-gradient(circle,rgba(37,99,235,0.07),transparent_70%)]"
        />

        <div className="signin-enter relative w-full max-w-sm">
          <h2 className="font-sans text-[28px] font-semibold tracking-[-0.025em] text-slate-900 leading-tight">
            {isLogin ? 'Sign in' : 'Create an account'}
          </h2>
          <p className={`${TYPOGRAPHY.caption} mt-1.5`}>
            {isLogin
              ? 'Sessions expire after 12 hours.'
              : 'Accounts start with the analyst role.'}
          </p>

          <form onSubmit={handleSubmit} className="mt-8 space-y-6">
            {error && (
              <div
                role="alert"
                className={`flex items-start gap-2 px-3 py-2.5 rounded-md bg-red-50 border border-red-200 text-red-700 ${TYPOGRAPHY.bodySmall}`}
              >
                <AlertCircle className="h-4 w-4 shrink-0 mt-1" aria-hidden />
                {error}
              </div>
            )}
            {success && (
              <div
                role="status"
                className={`flex items-start gap-2 px-3 py-2.5 rounded-md bg-emerald-50 border border-emerald-200 text-emerald-800 ${TYPOGRAPHY.bodySmall}`}
              >
                <CheckCircle2 className="h-4 w-4 shrink-0 mt-1" aria-hidden />
                {success}
              </div>
            )}

            <div>
              <label htmlFor="username" className={`block ${TYPOGRAPHY.label} mb-1`}>
                Username
              </label>
              <div className={fieldShell}>
                <User className={fieldIcon} aria-hidden />
                <input
                  id="username"
                  type="text"
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  required
                  autoFocus
                  autoComplete="username"
                  placeholder="analyst_name"
                  className={fieldInput}
                />
                <span
                  aria-hidden
                  className="absolute -bottom-px left-0 h-0.5 w-full origin-left scale-x-0 rounded-full bg-gradient-to-r from-blue-700 to-sky-400 transition-transform duration-200 group-focus-within:scale-x-100"
                />
              </div>
            </div>

            <div>
              <label htmlFor="password" className={`block ${TYPOGRAPHY.label} mb-1`}>
                Password
              </label>
              <div className={fieldShell}>
                <KeyRound className={fieldIcon} aria-hidden />
                <input
                  id="password"
                  type={showPw ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  onKeyUp={e => setCapsLock(e.getModifierState('CapsLock'))}
                  onBlur={() => setCapsLock(false)}
                  required
                  autoComplete={isLogin ? 'current-password' : 'new-password'}
                  placeholder="••••••••"
                  className={fieldInput}
                />
                <button
                  type="button"
                  onClick={() => setShowPw(!showPw)}
                  aria-label={showPw ? 'Hide password' : 'Show password'}
                  className="shrink-0 -mr-1 p-1 text-slate-400 hover:text-slate-700 transition-colors"
                >
                  {showPw
                    ? <EyeOff className="h-[18px] w-[18px]" aria-hidden />
                    : <Eye className="h-[18px] w-[18px]" aria-hidden />}
                </button>
                <span
                  aria-hidden
                  className="absolute -bottom-px left-0 h-0.5 w-full origin-left scale-x-0 rounded-full bg-gradient-to-r from-blue-700 to-sky-400 transition-transform duration-200 group-focus-within:scale-x-100"
                />
              </div>
              {capsLock && (
                <p className="mt-1.5 flex items-center gap-1.5 text-[13px] text-amber-700">
                  <AlertCircle className="h-3.5 w-3.5 shrink-0" aria-hidden />
                  Caps Lock is on.
                </p>
              )}
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full inline-flex items-center justify-center gap-2 rounded-lg py-3 font-sans text-[17px] font-semibold text-white bg-gradient-to-r from-blue-700 to-blue-600 hover:from-blue-800 hover:to-blue-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 disabled:opacity-70 disabled:cursor-not-allowed transition-all"
            >
              {loading ? (
                <>
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" aria-hidden />
                  {isLogin ? 'Signing in' : 'Creating account'}
                </>
              ) : (
                <>
                  {isLogin ? <LogIn className="h-4 w-4" aria-hidden /> : <UserPlus className="h-4 w-4" aria-hidden />}
                  {isLogin ? 'Sign in' : 'Create account'}
                </>
              )}
            </button>

            {/* Screen readers get the submit state that the spinner conveys visually. */}
            <p aria-live="polite" className="sr-only">
              {loading ? (isLogin ? 'Signing in' : 'Creating account') : ''}
            </p>
          </form>

          <p className={`${TYPOGRAPHY.bodySmall} mt-7`}>
            {isLogin ? "Don't have an account?" : 'Already have an account?'}{' '}
            <button
              type="button"
              onClick={() => {
                setMode(isLogin ? 'register' : 'login');
                setError(null);
                setSuccess(null);
                setPassword('');
                setShowPw(false);
                setCapsLock(false);
              }}
              className="font-medium text-blue-700 hover:text-blue-800 hover:underline"
            >
              {isLogin ? 'Register' : 'Sign in'}
            </button>
          </p>

          <div className="mt-10 flex items-start gap-2 border-t border-slate-200 pt-5">
            <Lock className="h-3.5 w-3.5 shrink-0 mt-0.5 text-slate-400" aria-hidden />
            <span className={TYPOGRAPHY.caption}>
              Internal use only. Access is logged against your analyst account.
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

