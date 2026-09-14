import { useCallback, useEffect, useRef, useState } from "react";
import type { Macrosession, Session } from "../types/session";
import { getSessions, getMacrosessionsList, deleteSession as deleteSessionProxy } from "../proxies/sessionsProxy";

export function useSessionList(isAuthenticated: boolean) {
  const [individualSessions, setIndividualSessions] = useState<Session[]>([]);
  const [macrosessions, setMacrosessions] = useState<Macrosession[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const isMountedRef = useRef(true);

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  const refetch = useCallback(async () => {
    if (!isAuthenticated) {
      setIndividualSessions([]);
      setMacrosessions([]);
      setIsLoading(false);
      return;
    }

    setIsLoading(true);
    const [individual, macro] = await Promise.all([
      getSessions("individual"),
      getMacrosessionsList(),
    ]);
    if (isMountedRef.current) {
      setIndividualSessions(individual);
      setMacrosessions(macro);
      setIsLoading(false);
    }
  }, [isAuthenticated]);

  useEffect(() => {
    refetch();
  }, [refetch]);

  async function deleteSession(id: string) {
    await deleteSessionProxy(id);
    setIndividualSessions((current) => current.filter((session) => session.id !== id));
    setMacrosessions((current) => current.filter((session) => session.id !== id));
  }

  return { individualSessions, macrosessions, isLoading, refetch, deleteSession };
}
