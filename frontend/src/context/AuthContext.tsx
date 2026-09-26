import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { API_BASE, register401Handler } from '../config';

export type AuthStatus = 'INITIALIZING' | 'AUTHENTICATED' | 'UNAUTHENTICATED';

export type AuthContextType = {
  status: AuthStatus;
  token: string | null;
  user: string | null;
  role: string | null;
  login: (token: string, username: string, role: string) => void;
  logout: () => void;
  handle401: () => void;
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

/**
 * Safely parse a JWT payload without external libraries.
 */
export function parseJwt(token: string): { exp?: number; sub?: string; role?: string; username?: string } | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const base64Url = parts[1];
    let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }
    const jsonPayload = decodeURIComponent(
      window
        .atob(base64)
        .split('')
        .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch {
    return null;
  }
}

/**
 * Check if token is non-empty, well-formed JWT, and not expired.
 */
export function isTokenValid(token: string | null): boolean {
  if (!token) return false;
  const payload = parseJwt(token);
  if (!payload) return false;
  if (payload.exp) {
    const currentTime = Math.floor(Date.now() / 1000);
    if (currentTime >= payload.exp) {
      return false;
    }
  }
  return true;
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>('INITIALIZING');
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<string | null>(null);
  const [role, setRole] = useState<string | null>(null);

  useEffect(() => {
    const storedToken = localStorage.getItem('sudarshan_token');
    const storedUser = localStorage.getItem('sudarshan_user');
    const storedRole = localStorage.getItem('sudarshan_role');

    if (storedToken && isTokenValid(storedToken)) {
      const payload = parseJwt(storedToken);
      setToken(storedToken);
      // `sub` is the numeric user id; prefer a human name when one exists.
      setUser(payload?.username || storedUser || payload?.sub || 'analyst');
      setRole(payload?.role || storedRole || 'analyst');
      setStatus('AUTHENTICATED');
    } else {
      localStorage.removeItem('sudarshan_token');
      localStorage.removeItem('sudarshan_user');
      localStorage.removeItem('sudarshan_role');
      setToken(null);
      setUser(null);
      setRole(null);
      setStatus('UNAUTHENTICATED');
    }
  }, []);

  const login = useCallback((newToken: string, newUsername: string, newRole: string) => {
    localStorage.setItem('sudarshan_token', newToken);
    localStorage.setItem('sudarshan_user', newUsername);
    localStorage.setItem('sudarshan_role', newRole);
    setToken(newToken);
    setUser(newUsername);
    setRole(newRole);
    setStatus('AUTHENTICATED');
  }, []);

  /** Drop client-side auth state. Does not touch the server. */
  const clearLocalAuth = useCallback(() => {
    localStorage.removeItem('sudarshan_token');
    localStorage.removeItem('sudarshan_user');
    localStorage.removeItem('sudarshan_role');
    setToken(null);
    setUser(null);
    setRole(null);
    setStatus('UNAUTHENTICATED');
  }, []);

  /**
   * Sign out.
   *
   * Removing the token locally is not a logout: the token stays valid for the
   * rest of its lifetime, so a copy taken from a shared machine keeps working.
   * POST /auth/logout revokes the session server-side. Local state is cleared
   * regardless of whether that call succeeds - a user who clicks "sign out"
   * must end up signed out of this browser even if the network is down.
   */
  const logout = useCallback(() => {
    const stored = localStorage.getItem('sudarshan_token');
    // Local state goes first so nothing below can leave the browser signed in.
    clearLocalAuth();
    if (stored) {
      try {
        Promise.resolve(
          fetch(`${API_BASE}/auth/logout`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${stored}` },
          }),
        ).catch(() => {
          /* best-effort: the session expires on its own */
        });
      } catch {
        /* best-effort: the session expires on its own */
      }
    }
  }, [clearLocalAuth]);

  /**
   * A 401 means the server already considers the session dead - revoked,
   * expired, or the account was disabled. Calling /auth/logout would just be a
   * second 401, so drop local state only.
   */
  const handle401 = useCallback(() => {
    clearLocalAuth();
  }, [clearLocalAuth]);

  useEffect(() => {
    register401Handler(handle401);
  }, [handle401]);

  return (
    <AuthContext.Provider
      value={{
        status,
        token,
        user,
        role,
        login,
        logout,
        handle401,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
