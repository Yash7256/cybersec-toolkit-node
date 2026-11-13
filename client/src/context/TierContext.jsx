/**
 * TierContext — provides free/paid tier status and per-tool daily usage globally.
 *
 * Fetches /api/user/me with Clerk bearer token and exposes:
 *   { tier, toolUsage, limit, unlimited, loading, refresh, getToolUsage }
 */
import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import { useAuth } from '@clerk/react';
import { apiGet } from '../utils/apiClient';

const TierContext = createContext(null);

const DEFAULT_STATE = {
  tier: 'free',
  toolUsage: {},
  limit: 5,
  unlimited: false,
  loading: true,
};

export function TierProvider({ children }) {
  const { getToken, isLoaded, isSignedIn } = useAuth();
  const [state, setState] = useState(DEFAULT_STATE);
  const fetchingRef = useRef(false);

  const refresh = useCallback(async () => {
    if (fetchingRef.current) return;
    if (!isLoaded || !isSignedIn) {
      setState((prev) => ({ ...prev, loading: false }));
      return;
    }
    fetchingRef.current = true;
    try {
      const res = await apiGet('/api/user/me', null, getToken);
      if (!res || !res.ok) {
        setState((prev) => ({ ...prev, loading: false }));
        return;
      }
      const data = await res.json();
      setState({
        tier: data.tier ?? 'free',
        toolUsage: data.tool_usage ?? {},
        limit: data.daily_limit ?? 5,
        unlimited: data.unlimited ?? false,
        loading: false,
      });
    } catch {
      setState((prev) => ({ ...prev, loading: false }));
    } finally {
      fetchingRef.current = false;
    }
  }, [getToken, isLoaded, isSignedIn]);

  // Fetch on mount and when auth state changes
  useEffect(() => {
    if (!isLoaded) return;
    // eslint-disable-next-line react-hooks/set-state-in-effect
    refresh();
  }, [refresh, isLoaded]);

  // Listen for limit_reached events
  useEffect(() => {
    const handler = () => refresh();
    window.addEventListener('tier:limit_reached', handler);
    return () => window.removeEventListener('tier:limit_reached', handler);
  }, [refresh]);

  const getToolUsage = useCallback((toolName) => {
    const entry = state.toolUsage[toolName];
    if (entry) return entry;
    return { count: 0, remaining: state.limit };
  }, [state.toolUsage, state.limit]);

  return (
    <TierContext.Provider value={{ ...state, refresh, getToolUsage }}>
      {children}
    </TierContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useTier() {
  const ctx = useContext(TierContext);
  if (!ctx) throw new Error('useTier must be used inside <TierProvider>');
  return ctx;
}
