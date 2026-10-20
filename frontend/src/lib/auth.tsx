import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { api, setCsrfToken } from './api';
import type { User } from './types';

interface AuthState {
  user: User | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  async function refresh(): Promise<void> {
    try {
      const data = await api.get<{ user: User | null; csrfToken?: string }>('/auth/me');
      setUser(data.user);
      if (data.csrfToken) setCsrfToken(data.csrfToken);
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void refresh(); }, []);

  async function login(username: string, password: string): Promise<void> {
    const data = await api.post<{ user: User; csrfToken: string }>('/auth/login', { username, password });
    setCsrfToken(data.csrfToken);
    setUser(data.user);
  }

  async function logout(): Promise<void> {
    await api.post('/auth/logout');
    setCsrfToken(null);
    setUser(null);
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, refresh }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
