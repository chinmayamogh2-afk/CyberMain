import { useEffect, useRef, useState } from 'react';
import type { SecurityEvent } from './types';

/**
 * Subscribes to the server's live security event stream (SSE).
 *
 * Events are produced by real activity on the server; this hook only displays
 * them. It reconnects automatically if the stream drops.
 */
export function useEventStream(max = 100): { events: SecurityEvent[]; connected: boolean } {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    const es = new EventSource('/api/security/events/stream', { withCredentials: true });
    esRef.current = es;
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    es.addEventListener('security', (e) => {
      try {
        const event = JSON.parse((e as MessageEvent).data) as SecurityEvent;
        setEvents((prev) => [event, ...prev].slice(0, max));
      } catch { /* ignore malformed frame */ }
    });
    return () => { es.close(); };
  }, [max]);

  return { events, connected };
}
