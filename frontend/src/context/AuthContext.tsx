import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { register401Handler } from '../config';

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
    let base64Url = parts[1];
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
      setUser(payload?.sub || payload?.username || storedUser || 'analyst');
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

  const logout = useCallback(() => {
    localStorage.removeItem('sudarshan_token');
    localStorage.removeItem('sudarshan_user');
    localStorage.removeItem('sudarshan_role');
    setToken(null);
    setUser(null);
    setRole(null);
    setStatus('UNAUTHENTICATED');
  }, []);

  const handle401 = useCallback(() => {
    logout();
  }, [logout]);

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
