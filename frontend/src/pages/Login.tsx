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
  const [role, setRole] = useState<'analyst' | 'soc_lead'>('analyst');
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
          body: JSON.stringify({ username, password, role }),
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

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-950 via-blue-900 to-slate-900 flex items-center justify-center p-4">
      {/* Background pattern */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 w-72 h-72 bg-indigo-500/10 rounded-full blur-3xl" />
      </div>

      <div className="relative w-full max-w-md">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-blue-600/20 border border-blue-500/30 mb-4">
            <Shield className="h-8 w-8 text-blue-400" />
          </div>
          <h1 className={`${TYPOGRAPHY.h1} text-white font-extrabold tracking-wider`}>SUDARSHAN</h1>
          <p className={`${TYPOGRAPHY.label} text-blue-300 mt-1`}>
            Banking Threat Intelligence Platform
          </p>
          <p className={`${TYPOGRAPHY.caption} text-blue-400/70 mt-2`}>Bank of India - Cyber Security Operations</p>
        </div>

        {/* Card */}
        <div className="bg-white/5 backdrop-blur-sm border border-white/10 rounded-2xl shadow-2xl overflow-hidden">
          {/* Tabs */}
          <div className="flex border-b border-white/10">
            <button
              onClick={() => { setMode('login'); setError(null); setSuccess(null); }}
              className={`flex-1 py-3 ${TYPOGRAPHY.button} transition-colors ${
                mode === 'login'
                  ? 'bg-blue-600/20 text-blue-300 border-b-2 border-blue-400'
                  : 'text-white/50 hover:text-white/80'
              }`}
            >
              <LogIn className="h-4 w-4 inline mr-1.5 -mt-0.5" />
              Sign In
            </button>
            <button
              onClick={() => { setMode('register'); setError(null); setSuccess(null); }}
              className={`flex-1 py-3 ${TYPOGRAPHY.button} transition-colors ${
                mode === 'register'
                  ? 'bg-blue-600/20 text-blue-300 border-b-2 border-blue-400'
                  : 'text-white/50 hover:text-white/80'
              }`}
            >
              <UserPlus className="h-4 w-4 inline mr-1.5 -mt-0.5" />
              Register
            </button>
          </div>

          <form onSubmit={handleSubmit} className="p-6 space-y-4">
            {/* Error / Success banners */}
            {error && (
              <div className={`flex items-center gap-2 px-3 py-2 rounded-lg bg-red-500/20 border border-red-500/30 text-red-300 ${TYPOGRAPHY.bodySmall}`}>
                <AlertCircle className="h-4 w-4 flex-shrink-0" />
                {error}
              </div>
            )}
            {success && (
              <div className={`px-3 py-2 rounded-lg bg-green-500/20 border border-green-500/30 text-green-300 ${TYPOGRAPHY.bodySmall}`}>
                {success}
              </div>
            )}

            {/* Username */}
            <div>
              <label className={`block ${TYPOGRAPHY.label} text-blue-300 mb-1.5`}>
                Username
              </label>
              <input
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                required
                autoComplete="username"
                placeholder="analyst_name"
                className={`w-full px-3 py-2.5 rounded-lg bg-white/5 border border-white/10 text-white placeholder-white/30
                           focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 ${TYPOGRAPHY.bodySmall} transition-colors`}
              />
            </div>

            {/* Password */}
            <div>
              <label className={`block ${TYPOGRAPHY.label} text-blue-300 mb-1.5`}>
                Password
              </label>
              <div className="relative">
                <input
                  type={showPw ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  required
                  autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                  placeholder="••••••••"
                  className={`w-full px-3 py-2.5 pr-10 rounded-lg bg-white/5 border border-white/10 text-white placeholder-white/30
                             focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 ${TYPOGRAPHY.bodySmall} transition-colors`}
                />
                <button
                  type="button"
                  onClick={() => setShowPw(!showPw)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-white/40 hover:text-white/70 transition-colors"
                >
                  {showPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            {/* Role selector (register only) */}
            {mode === 'register' && (
              <div>
                <label className={`block ${TYPOGRAPHY.label} text-blue-300 mb-1.5`}>
                  Role
                </label>
                <select
                  value={role}
                  onChange={e => setRole(e.target.value as 'analyst' | 'soc_lead')}
                  className={`w-full px-3 py-2.5 rounded-lg bg-white/5 border border-white/10 text-white
                             focus:outline-none focus:ring-2 focus:ring-blue-500/50 ${TYPOGRAPHY.bodySmall} transition-colors`}
                >
                  <option value="analyst" className="bg-slate-800">Analyst</option>
                  <option value="soc_lead" className="bg-slate-800">SOC Lead</option>
                </select>
                <p className={`mt-1 ${TYPOGRAPHY.caption} text-white/40`}>
                  Admin accounts can only be created by a current admin.
                </p>
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className={`w-full py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 active:bg-blue-700
                         text-white ${TYPOGRAPHY.button} transition-colors disabled:opacity-60
                         disabled:cursor-not-allowed flex items-center justify-center gap-2`}
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  {mode === 'login' ? 'Signing in…' : 'Registering…'}
                </>
              ) : (
                <>
                  {mode === 'login' ? <LogIn className="h-4 w-4" /> : <UserPlus className="h-4 w-4" />}
                  {mode === 'login' ? 'Sign In' : 'Create Account'}
                </>
              )}
            </button>
          </form>
        </div>

        <p className={`text-center ${TYPOGRAPHY.caption} text-blue-400/40 mt-6`}>
          Protected by JWT - all sessions expire after 12 hours
        </p>
      </div>
    </div>
  );
}
