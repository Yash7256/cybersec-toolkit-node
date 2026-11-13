/**
 * useGetToken — returns Clerk's getToken function from useAuth().
 *
 * Used by tool components to attach the Bearer token to API requests.
 */
import { useAuth } from '@clerk/react';

export function useGetToken() {
  const { getToken } = useAuth();
  return getToken;
}

