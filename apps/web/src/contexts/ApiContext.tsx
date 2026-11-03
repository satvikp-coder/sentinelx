/**
 * React context for API state and Server-Sent Events streaming.
 * Provides loading/error state and real-time event updates to all screens.
 */

import {
  createContext, useContext, useEffect, useRef, useState,
  ReactNode, useCallback,
} from "react";
import { api, EventData, HealthData } from "../api";

interface ApiContextType {
  health: HealthData | null;
  healthLoading: boolean;
  healthError: string | null;
  events: EventData[];
  eventsLoading: boolean;
  eventsError: string | null;
  refreshHealth: () => Promise<void>;
  refreshEvents: () => Promise<void>;
  subscribeEvents: () => Promise<void>;
}

const ApiContext = createContext<ApiContextType | null>(null);

export function ApiProvider({ children }: { children: ReactNode }) {
  const [health, setHealth] = useState<HealthData | null>(null);
  const [healthLoading, setHealthLoading] = useState(true);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [events, setEvents] = useState<EventData[]>([]);
  const [eventsLoading, setEventsLoading] = useState(true);
  const [eventsError, setEventsError] = useState<string | null>(null);
  const esRef = useRef<(() => void) | null>(null);

  const refreshHealth = useCallback(async () => {
    setHealthLoading(true);
    setHealthError(null);
    try {
      const h = await api.health();
      setHealth(h);
    } catch (e) {
      setHealthError(e instanceof Error ? e.message : "unknown error");
    } finally {
      setHealthLoading(false);
    }
  }, []);

  const refreshEvents = useCallback(async () => {
    setEventsLoading(true);
    setEventsError(null);
    try {
      const ev = await api.listEvents();
      setEvents(ev);
    } catch (e) {
      setEventsError(e instanceof Error ? e.message : "unknown error");
    } finally {
      setEventsLoading(false);
    }
  }, []);

  const subscribeEvents = useCallback(async () => {
    if (esRef.current) esRef.current();
    await api.createSSESession().catch(() => {}); // cookie set by server
    esRef.current = api.eventStream((ev) => {
      setEvents((prev) => {
        const exists = prev.some((e) => e.id === ev.id);
        if (exists) return prev;
        return [ev, ...prev].slice(0, 200);
      });
    }, 0);
  }, []);

  useEffect(() => {
    refreshHealth();
    refreshEvents();
    let cancelled = false;
    subscribeEvents().then(() => {
      if (!cancelled && esRef.current) {
        // subscription established
      }
    });
    return () => {
      cancelled = true;
      if (esRef.current) {
        esRef.current();
        esRef.current = null;
      }
    };
  }, [refreshHealth, refreshEvents, subscribeEvents]);

  useEffect(() => {
    return () => {
      if (esRef.current) esRef.current();
    };
  }, []);

  const value: ApiContextType = {
    health, healthLoading, healthError,
    events, eventsLoading, eventsError,
    refreshHealth, refreshEvents,
    subscribeEvents,
  };

  return (
    <ApiContext.Provider value={value}>
      {children}
    </ApiContext.Provider>
  );
}

export function useApi() {
  const ctx = useContext(ApiContext);
  if (!ctx) throw new Error("useApi must be used within ApiProvider");
  return ctx;
}
