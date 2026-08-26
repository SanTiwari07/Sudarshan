import { useState } from 'react';
import { useNavigate, useLocation, Location } from 'react-router-dom';
import { Shield, LogIn, Eye, EyeOff, AlertCircle, UserPlus } from 'lucide-react';
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

export default function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const auth = useAuth();
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
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
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Unexpected error');
    } finally {
      setLoading(false);
    }
  };

  const isLogin = mode === 'login';

  return (
    /*
     * Split layout rather than a centred card on a purple gradient with
     * blurred blobs behind it. That treatment is the default look of a
     * generated page, and it is the first screen anyone sees. The left half
     * says what the product does; the right half is a plain, legible form.
     */
    <div className="min-h-screen w-full flex flex-col lg:flex-row bg-white">
      {/* Brand half */}
      <div className="lg:w-[46%] bg-slate-950 text-white px-8 py-10 lg:px-14 lg:py-16 flex flex-col justify-between">
        <div>
          <div className="flex items-center gap-2.5">
            <Shield className="h-5 w-5 text-blue-500" aria-hidden />
            <span className="font-display text-base font-semibold tracking-[-0.01em]">
              Sudarshan
            </span>
          </div>

          <h1 className="mt-12 lg:mt-20 font-display text-3xl lg:text-4xl font-semibold tracking-[-0.03em] leading-[1.15] max-w-md">
            Android banking fraud, evidenced.
          </h1>
          <p className="mt-4 text-[15px] text-slate-400 leading-relaxed max-w-md">
            Static decompilation, an instrumented sandbox and threat-intelligence
            correlation resolved into one scored, auditable case file.
          </p>

          <dl className="mt-10 grid grid-cols-3 gap-6 max-w-md">
            {[
              { term: 'Analysis axes', detail: 'Static · runtime · intel' },
              { term: 'Every score', detail: 'Traced to evidence' },
              { term: 'Batch mode', detail: 'Portfolio-scale intake' },
            ].map((item) => (
              <div key={item.term}>
                <dt className="text-[11px] font-medium text-slate-500">{item.term}</dt>
                <dd className="mt-1 text-[13px] font-medium text-slate-200 leading-snug">
                  {item.detail}
                </dd>
              </div>
            ))}
          </dl>
        </div>

        <p className="mt-12 text-[11px] text-slate-600">
          Bank of India — Cyber Security Operations
        </p>
      </div>

      {/* Form half */}
      <div className="flex-1 flex items-center justify-center px-6 py-12 lg:px-12">
        <div className="w-full max-w-sm">
          <h2 className={TYPOGRAPHY.h1}>
            {isLogin ? 'Sign in' : 'Create an account'}
          </h2>
          <p className={`${TYPOGRAPHY.caption} mt-1`}>
            {isLogin
              ? 'Sessions expire after 12 hours.'
              : 'Accounts start with the analyst role.'}
          </p>

          <form onSubmit={handleSubmit} className="mt-7 space-y-4">
            {error && (
              <div
                role="alert"
                className={`flex items-start gap-2 px-3 py-2.5 rounded-md bg-red-50 border border-red-200 text-red-700 ${TYPOGRAPHY.bodySmall}`}
              >
                <AlertCircle className="h-4 w-4 shrink-0 mt-px" aria-hidden />
                {error}
              </div>
            )}
            {success && (
              <div
                role="status"
                className={`px-3 py-2.5 rounded-md bg-emerald-50 border border-emerald-200 text-emerald-800 ${TYPOGRAPHY.bodySmall}`}
              >
                {success}
              </div>
            )}

            <div>
              <label htmlFor="username" className={`block ${TYPOGRAPHY.label} mb-1.5`}>
                Username
              </label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                required
                autoComplete="username"
                placeholder="analyst_name"
                className={`w-full px-3 py-2.5 rounded-md bg-white border border-slate-300 text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 ${TYPOGRAPHY.body} transition-colors`}
              />
            </div>

            <div>
              <label htmlFor="password" className={`block ${TYPOGRAPHY.label} mb-1.5`}>
                Password
              </label>
              <div className="relative">
                <input
                  id="password"
                  type={showPw ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  required
                  autoComplete={isLogin ? 'current-password' : 'new-password'}
                  className={`w-full px-3 py-2.5 pr-10 rounded-md bg-white border border-slate-300 text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 ${TYPOGRAPHY.body} transition-colors`}
                />
                <button
                  type="button"
                  onClick={() => setShowPw(!showPw)}
                  aria-label={showPw ? 'Hide password' : 'Show password'}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 transition-colors"
                >
                  {showPw ? <EyeOff className="h-4 w-4" aria-hidden /> : <Eye className="h-4 w-4" aria-hidden />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className={`${TYPOGRAPHY.button} w-full py-2.5 bg-blue-700 hover:bg-blue-800 text-white`}
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
          </form>

          <p className={`${TYPOGRAPHY.bodySmall} mt-6`}>
            {isLogin ? "Don't have an account?" : 'Already have an account?'}{' '}
            <button
              type="button"
              onClick={() => {
                setMode(isLogin ? 'register' : 'login');
                setError(null);
                setSuccess(null);
              }}
              className="font-medium text-blue-700 hover:text-blue-800 hover:underline"
            >
              {isLogin ? 'Register' : 'Sign in'}
            </button>
          </p>
        </div>
      </div>
    </div>
  );
}
