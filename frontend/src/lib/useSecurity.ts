import { useCallback, useEffect, useState } from 'react';
import { api } from './api';
import type { SecurityScore, VulnClassMeta, Finding } from './types';

export function useScore() {
  const [score, setScore] = useState<SecurityScore | null>(null);
  const [history, setHistory] = useState<{ capturedAt: string; overall: number; trigger: string }[]>([]);
  const load = useCallback(async () => {
    const data = await api.get<{ score: SecurityScore; history: typeof history }>('/security/score');
    setScore(data.score); setHistory(data.history);
  }, []);
  useEffect(() => { void load(); }, [load]);
  return { score, history, reloadScore: load };
}

export function useModes() {
  const [classes, setClasses] = useState<VulnClassMeta[]>([]);
  const load = useCallback(async () => {
    const data = await api.get<{ classes: VulnClassMeta[] }>('/security/modes');
    setClasses(data.classes);
  }, []);
  useEffect(() => { void load(); }, [load]);
  const setMode = useCallback(async (key: string, mode: 'vulnerable' | 'secure') => {
    await api.put(`/security/modes/${key}`, { mode });
    await load();
  }, [load]);
  const setAll = useCallback(async (mode: 'vulnerable' | 'secure') => {
    await api.put('/security/modes', { mode });
    await load();
  }, [load]);
  return { classes, reloadModes: load, setMode, setAll };
}

export function useFindings(activeOnly = false) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const load = useCallback(async () => {
    setLoading(true);
    const data = await api.get<{ findings: Finding[] }>(`/security/findings${activeOnly ? '?active=true' : ''}`);
    setFindings(data.findings); setLoading(false);
  }, [activeOnly]);
  useEffect(() => { void load(); }, [load]);
  return { findings, loading, reloadFindings: load };
}
